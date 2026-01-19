//! Light client implementation.
//!
//! The main entry point for light client functionality.

use std::sync::Arc;

use tokio::sync::RwLock;

use crate::checkpoint::{Checkpoint, CheckpointRegistry, TrustedCheckpoint};
use crate::errors::{LightClientError, Result};
use crate::header::{HeaderStore, TrustedHeader};
use crate::proof::{CompactProof, ProofVerifier};
use crate::sync::{SyncConfig, SyncStatus};

use moloch_core::{EventId, Hash, PublicKey};

/// Light client configuration.
#[derive(Debug, Clone)]
pub struct LightClientConfig {
    /// Sync configuration.
    pub sync: SyncConfig,
    /// Checkpoint registry.
    pub checkpoints: CheckpointRegistry,
    /// Chain ID for verification.
    pub chain_id: String,
    /// Maximum headers to store (for pruning).
    pub max_headers: usize,
}

impl Default for LightClientConfig {
    fn default() -> Self {
        Self {
            sync: SyncConfig::default(),
            checkpoints: CheckpointRegistry::new(),
            chain_id: "moloch-mainnet".to_string(),
            max_headers: 10000,
        }
    }
}

impl LightClientConfig {
    /// Create a new configuration builder.
    pub fn builder() -> LightClientConfigBuilder {
        LightClientConfigBuilder::default()
    }
}

/// Builder for light client configuration.
#[derive(Debug, Default)]
pub struct LightClientConfigBuilder {
    config: LightClientConfig,
}

impl LightClientConfigBuilder {
    /// Set sync configuration.
    pub fn sync(mut self, sync: SyncConfig) -> Self {
        self.config.sync = sync;
        self
    }

    /// Set checkpoint registry.
    pub fn checkpoints(mut self, checkpoints: CheckpointRegistry) -> Self {
        self.config.checkpoints = checkpoints;
        self
    }

    /// Set chain ID.
    pub fn chain_id(mut self, chain_id: impl Into<String>) -> Self {
        self.config.chain_id = chain_id.into();
        self
    }

    /// Set maximum headers to store.
    pub fn max_headers(mut self, max: usize) -> Self {
        self.config.max_headers = max;
        self
    }

    /// Build the configuration.
    pub fn build(self) -> LightClientConfig {
        self.config
    }
}

/// Current state of the light client.
#[derive(Debug, Clone)]
pub struct LightClientState {
    /// Sync status.
    pub sync_status: SyncStatus,
    /// Number of stored headers.
    pub header_count: usize,
    /// Storage size in bytes.
    pub storage_bytes: usize,
    /// Finalized height.
    pub height: u64,
}

/// Light client for Moloch audit chain.
///
/// Provides event verification without full chain storage.
pub struct LightClient {
    /// Configuration.
    config: LightClientConfig,
    /// Header storage.
    headers: Arc<RwLock<HeaderStore>>,
    /// Current validator set.
    validators: Arc<RwLock<Vec<PublicKey>>>,
    /// Sync status.
    status: Arc<RwLock<SyncStatus>>,
}

impl LightClient {
    /// Create a new light client from a trusted checkpoint.
    pub async fn new(
        config: LightClientConfig,
        checkpoint: TrustedCheckpoint,
    ) -> Result<Self> {
        let headers = HeaderStore::with_checkpoint(checkpoint.header);
        let validators = checkpoint.validators;

        Ok(Self {
            config,
            headers: Arc::new(RwLock::new(headers)),
            validators: Arc::new(RwLock::new(validators)),
            status: Arc::new(RwLock::new(SyncStatus::Idle)),
        })
    }

    /// Create a light client starting from genesis.
    pub async fn from_genesis(
        config: LightClientConfig,
        genesis_header: TrustedHeader,
        genesis_validators: Vec<PublicKey>,
    ) -> Result<Self> {
        let checkpoint = Checkpoint::new(
            0,
            genesis_header.hash(),
            genesis_header.mmr_root,
            Hash::ZERO, // TODO: compute validators hash
            0,
        );

        let trusted = TrustedCheckpoint::new(checkpoint, genesis_header, genesis_validators)?;
        Self::new(config, trusted).await
    }

    /// Get current state.
    pub async fn state(&self) -> LightClientState {
        let headers = self.headers.read().await;
        let status = self.status.read().await;

        LightClientState {
            sync_status: status.clone(),
            header_count: headers.len(),
            storage_bytes: headers.storage_size(),
            height: headers.finalized_height(),
        }
    }

    /// Get current synced height.
    pub async fn height(&self) -> u64 {
        self.headers.read().await.finalized_height()
    }

    /// Get sync status.
    pub async fn sync_status(&self) -> SyncStatus {
        self.status.read().await.clone()
    }

    /// Add a new header to the chain.
    pub async fn add_header(&self, header: TrustedHeader) -> Result<()> {
        let validators = self.validators.read().await;
        let threshold = (validators.len() * 2 / 3) + 1;

        // Verify finality
        header.verify_finality(&validators, threshold)?;

        // Insert into store
        let mut headers = self.headers.write().await;
        headers.insert(header)?;

        // Prune if needed
        if headers.len() > self.config.max_headers {
            let prune_height = headers.finalized_height().saturating_sub(self.config.max_headers as u64);
            headers.prune_below(prune_height);
        }

        Ok(())
    }

    /// Verify an event inclusion proof.
    pub async fn verify_proof(&self, proof: &CompactProof) -> Result<()> {
        let headers = self.headers.read().await;
        let verifier = ProofVerifier::new(&headers);
        verifier.verify_event(proof)
    }

    /// Verify multiple proofs.
    pub async fn verify_proofs(&self, proofs: &[CompactProof]) -> Result<()> {
        let headers = self.headers.read().await;
        let verifier = ProofVerifier::new(&headers);
        verifier.verify_batch(proofs)
    }

    /// Check if we have the header for a given height.
    pub async fn has_header(&self, height: u64) -> bool {
        self.headers.read().await.get(height).is_some()
    }

    /// Get header at height.
    pub async fn get_header(&self, height: u64) -> Option<TrustedHeader> {
        self.headers.read().await.get(height).cloned()
    }

    /// Update validator set (e.g., after epoch change).
    pub async fn update_validators(&self, validators: Vec<PublicKey>) {
        *self.validators.write().await = validators;
    }

    /// Get current validators.
    pub async fn validators(&self) -> Vec<PublicKey> {
        self.validators.read().await.clone()
    }
}

/// WASM-compatible light client for browser usage.
#[cfg(target_arch = "wasm32")]
pub mod wasm {
    use super::*;
    use wasm_bindgen::prelude::*;

    /// WASM-compatible light client wrapper.
    #[wasm_bindgen]
    pub struct WasmLightClient {
        inner: LightClient,
    }

    #[wasm_bindgen]
    impl WasmLightClient {
        /// Get current height.
        #[wasm_bindgen(getter)]
        pub async fn height(&self) -> u64 {
            self.inner.height().await
        }

        /// Verify a proof (JSON format).
        pub async fn verify_proof_json(&self, proof_json: &str) -> Result<bool, JsValue> {
            let proof: CompactProof = serde_json::from_str(proof_json)
                .map_err(|e| JsValue::from_str(&e.to_string()))?;

            self.inner
                .verify_proof(&proof)
                .await
                .map(|_| true)
                .map_err(|e| JsValue::from_str(&e.to_string()))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_light_client_config_default() {
        let config = LightClientConfig::default();
        assert_eq!(config.chain_id, "moloch-mainnet");
        assert_eq!(config.max_headers, 10000);
    }

    #[test]
    fn test_light_client_config_builder() {
        let config = LightClientConfig::builder()
            .chain_id("test-chain")
            .max_headers(1000)
            .build();

        assert_eq!(config.chain_id, "test-chain");
        assert_eq!(config.max_headers, 1000);
    }
}
