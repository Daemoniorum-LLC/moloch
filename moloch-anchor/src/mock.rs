//! Mock provider for testing and development.
//!
//! This module provides a configurable mock implementation of the
//! `AnchorProvider` trait for use in tests and development environments.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use async_trait::async_trait;
use parking_lot::RwLock;

use crate::commitment::Commitment;
use crate::errors::{AnchorError, Result};
use crate::proof::{AnchorProof, AnchorStatus, SpvProof};
use crate::provider::{
    AnchorCost, AnchorProvider, AnchorTx, FinalityType, ProviderCapabilities,
    ProviderInfo, ProviderStatus, TxId,
};

/// Configuration for the mock provider.
#[derive(Debug, Clone)]
pub struct MockProviderConfig {
    /// Provider ID.
    pub id: String,
    /// Provider name.
    pub name: String,
    /// Chain ID to simulate.
    pub chain_id: String,
    /// Simulated block time in seconds.
    pub block_time_secs: u64,
    /// Confirmations per block.
    pub confirmations_per_block: u64,
    /// Blocks to finality.
    pub blocks_to_finality: u64,
    /// Simulated fee per anchor.
    pub fee_per_anchor: f64,
    /// Fee currency.
    pub currency: String,
    /// Failure rate (0.0 - 1.0).
    pub failure_rate: f64,
    /// Simulated latency.
    pub latency: Duration,
    /// Maximum data size.
    pub max_data_size: usize,
}

impl Default for MockProviderConfig {
    fn default() -> Self {
        Self {
            id: "mock".to_string(),
            name: "Mock Provider".to_string(),
            chain_id: "mock-testnet".to_string(),
            block_time_secs: 10,
            confirmations_per_block: 1,
            blocks_to_finality: 6,
            fee_per_anchor: 0.0001,
            currency: "MOCK".to_string(),
            failure_rate: 0.0,
            latency: Duration::from_millis(100),
            max_data_size: 80,
        }
    }
}

impl MockProviderConfig {
    /// Create a Bitcoin-like mock.
    pub fn bitcoin_like() -> Self {
        Self {
            id: "mock-btc".to_string(),
            name: "Mock Bitcoin".to_string(),
            chain_id: "bitcoin-testnet".to_string(),
            block_time_secs: 600,
            confirmations_per_block: 1,
            blocks_to_finality: 6,
            fee_per_anchor: 0.0001,
            currency: "BTC".to_string(),
            failure_rate: 0.0,
            latency: Duration::from_secs(1),
            max_data_size: 80,
        }
    }

    /// Create an Ethereum-like mock.
    pub fn ethereum_like() -> Self {
        Self {
            id: "mock-eth".to_string(),
            name: "Mock Ethereum".to_string(),
            chain_id: "ethereum-testnet".to_string(),
            block_time_secs: 12,
            confirmations_per_block: 1,
            blocks_to_finality: 32,
            fee_per_anchor: 0.001,
            currency: "ETH".to_string(),
            failure_rate: 0.0,
            latency: Duration::from_millis(500),
            max_data_size: 32768,
        }
    }

    /// Create a fast mock for testing.
    pub fn fast() -> Self {
        Self {
            id: "mock-fast".to_string(),
            name: "Fast Mock".to_string(),
            chain_id: "mock-fast".to_string(),
            block_time_secs: 1,
            confirmations_per_block: 1,
            blocks_to_finality: 1,
            fee_per_anchor: 0.0,
            currency: "FAST".to_string(),
            failure_rate: 0.0,
            latency: Duration::from_millis(10),
            max_data_size: 1024,
        }
    }
}

/// Stored transaction in the mock.
#[derive(Debug, Clone)]
struct MockTransaction {
    tx_id: TxId,
    commitment: Commitment,
    block_height: u64,
    submitted_at: i64,
}

/// Mock implementation of AnchorProvider.
pub struct MockProvider {
    config: MockProviderConfig,
    status: RwLock<ProviderStatus>,
    block_height: AtomicU64,
    transactions: RwLock<HashMap<String, MockTransaction>>,
    tx_counter: AtomicU64,
}

impl MockProvider {
    /// Create a new mock provider with default config.
    pub fn new() -> Self {
        Self::with_config(MockProviderConfig::default())
    }

    /// Create with custom configuration.
    pub fn with_config(config: MockProviderConfig) -> Self {
        Self {
            config,
            status: RwLock::new(ProviderStatus::Available),
            block_height: AtomicU64::new(1000),
            transactions: RwLock::new(HashMap::new()),
            tx_counter: AtomicU64::new(0),
        }
    }

    /// Create a Bitcoin-like mock.
    pub fn bitcoin() -> Self {
        Self::with_config(MockProviderConfig::bitcoin_like())
    }

    /// Create an Ethereum-like mock.
    pub fn ethereum() -> Self {
        Self::with_config(MockProviderConfig::ethereum_like())
    }

    /// Create a fast mock for testing.
    pub fn fast() -> Self {
        Self::with_config(MockProviderConfig::fast())
    }

    /// Set the provider status.
    pub fn set_status(&self, status: ProviderStatus) {
        *self.status.write() = status;
    }

    /// Advance blocks.
    pub fn advance_blocks(&self, count: u64) {
        self.block_height.fetch_add(count, Ordering::Relaxed);
    }

    /// Set block height.
    pub fn set_block_height(&self, height: u64) {
        self.block_height.store(height, Ordering::Relaxed);
    }

    /// Get all transactions.
    pub fn all_transactions(&self) -> Vec<TxId> {
        self.transactions.read().keys().map(|k| TxId::new(k)).collect()
    }

    /// Clear all transactions.
    pub fn clear(&self) {
        self.transactions.write().clear();
    }

    /// Simulate failure based on configured rate.
    fn should_fail(&self) -> bool {
        if self.config.failure_rate <= 0.0 {
            return false;
        }
        rand::random::<f64>() < self.config.failure_rate
    }

    /// Simulate latency.
    async fn simulate_latency(&self) {
        if self.config.latency > Duration::ZERO {
            tokio::time::sleep(self.config.latency).await;
        }
    }

    /// Generate a mock transaction ID.
    fn next_tx_id(&self) -> TxId {
        let counter = self.tx_counter.fetch_add(1, Ordering::Relaxed);
        TxId::new(format!("mock_tx_{:016x}", counter))
    }

    /// Generate a mock block hash.
    fn mock_block_hash(height: u64) -> String {
        format!("mock_block_{:016x}", height)
    }
}

impl Default for MockProvider {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl AnchorProvider for MockProvider {
    fn info(&self) -> ProviderInfo {
        ProviderInfo {
            id: self.config.id.clone(),
            name: self.config.name.clone(),
            chain_id: self.config.chain_id.clone(),
            status: *self.status.read(),
            capabilities: ProviderCapabilities {
                max_data_size: self.config.max_data_size,
                batch_anchor: true,
                spv_proofs: true,
                smart_contracts: false,
                confirmation_time_secs: self.config.block_time_secs * self.config.blocks_to_finality,
                finality_type: FinalityType::Probabilistic,
            },
            block_height: self.block_height.load(Ordering::Relaxed),
            endpoint: None,
        }
    }

    fn id(&self) -> &str {
        &self.config.id
    }

    async fn status(&self) -> ProviderStatus {
        self.simulate_latency().await;
        *self.status.read()
    }

    async fn submit(&self, commitment: &Commitment) -> Result<AnchorTx> {
        self.simulate_latency().await;

        if self.should_fail() {
            return Err(AnchorError::SubmissionFailed("Simulated failure".into()));
        }

        let status = *self.status.read();
        if !matches!(status, ProviderStatus::Available) {
            return Err(AnchorError::ProviderUnavailable(self.config.id.clone()));
        }

        let tx_id = self.next_tx_id();
        let block_height = self.block_height.load(Ordering::Relaxed);

        let mock_tx = MockTransaction {
            tx_id: tx_id.clone(),
            commitment: commitment.clone(),
            block_height,
            submitted_at: chrono::Utc::now().timestamp(),
        };

        self.transactions.write().insert(tx_id.0.clone(), mock_tx);

        Ok(AnchorTx::pending(tx_id, &self.config.id, &self.config.chain_id))
    }

    async fn verify(&self, proof: &AnchorProof) -> Result<bool> {
        self.simulate_latency().await;

        if self.should_fail() {
            return Err(AnchorError::VerificationFailed("Simulated failure".into()));
        }

        // Check if we have this transaction
        Ok(self.transactions.read().contains_key(&proof.tx_id.0))
    }

    async fn confirmations(&self, tx_id: &TxId) -> Result<u64> {
        self.simulate_latency().await;

        let txs = self.transactions.read();
        if let Some(tx) = txs.get(&tx_id.0) {
            let current_height = self.block_height.load(Ordering::Relaxed);
            let confirmations = current_height.saturating_sub(tx.block_height) + 1;
            Ok(confirmations * self.config.confirmations_per_block)
        } else {
            Err(AnchorError::TxNotFound(tx_id.0.clone()))
        }
    }

    async fn get_proof(&self, tx_id: &TxId) -> Result<AnchorProof> {
        self.simulate_latency().await;

        let txs = self.transactions.read();
        if let Some(tx) = txs.get(&tx_id.0) {
            let current_height = self.block_height.load(Ordering::Relaxed);
            let confirmations = current_height.saturating_sub(tx.block_height) + 1;

            let status = if confirmations >= self.config.blocks_to_finality {
                AnchorStatus::Finalized
            } else if confirmations > 0 {
                AnchorStatus::Confirmed(confirmations)
            } else {
                AnchorStatus::Pending
            };

            // Generate mock SPV proof
            let spv_proof = SpvProof::new(
                vec![moloch_core::Hash::ZERO; 3], // Mock merkle path
                0,
                vec![0u8; 80], // Mock block header
            );

            Ok(AnchorProof::new(
                tx.commitment.clone(),
                &self.config.id,
                &self.config.chain_id,
                tx_id.clone(),
                tx.block_height,
                Self::mock_block_hash(tx.block_height),
            )
            .with_status(status)
            .with_spv_proof(spv_proof))
        } else {
            Err(AnchorError::TxNotFound(tx_id.0.clone()))
        }
    }

    async fn estimate_cost(&self, _commitment: &Commitment) -> Result<AnchorCost> {
        self.simulate_latency().await;

        Ok(AnchorCost::new(self.config.fee_per_anchor, &self.config.currency)
            .with_time(self.config.block_time_secs * self.config.blocks_to_finality))
    }

    async fn block_height(&self) -> Result<u64> {
        self.simulate_latency().await;
        Ok(self.block_height.load(Ordering::Relaxed))
    }
}

/// Builder for creating mock providers.
pub struct MockProviderBuilder {
    config: MockProviderConfig,
}

impl MockProviderBuilder {
    /// Create a new builder.
    pub fn new() -> Self {
        Self {
            config: MockProviderConfig::default(),
        }
    }

    /// Set provider ID.
    pub fn id(mut self, id: impl Into<String>) -> Self {
        self.config.id = id.into();
        self
    }

    /// Set provider name.
    pub fn name(mut self, name: impl Into<String>) -> Self {
        self.config.name = name.into();
        self
    }

    /// Set chain ID.
    pub fn chain_id(mut self, chain_id: impl Into<String>) -> Self {
        self.config.chain_id = chain_id.into();
        self
    }

    /// Set block time.
    pub fn block_time(mut self, secs: u64) -> Self {
        self.config.block_time_secs = secs;
        self
    }

    /// Set blocks to finality.
    pub fn finality_blocks(mut self, blocks: u64) -> Self {
        self.config.blocks_to_finality = blocks;
        self
    }

    /// Set fee.
    pub fn fee(mut self, fee: f64, currency: impl Into<String>) -> Self {
        self.config.fee_per_anchor = fee;
        self.config.currency = currency.into();
        self
    }

    /// Set failure rate.
    pub fn failure_rate(mut self, rate: f64) -> Self {
        self.config.failure_rate = rate.clamp(0.0, 1.0);
        self
    }

    /// Set latency.
    pub fn latency(mut self, latency: Duration) -> Self {
        self.config.latency = latency;
        self
    }

    /// Build the mock provider.
    pub fn build(self) -> MockProvider {
        MockProvider::with_config(self.config)
    }
}

impl Default for MockProviderBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use moloch_core::Hash;

    #[tokio::test]
    async fn test_mock_provider_submit() {
        let provider = MockProvider::fast();
        let commitment = Commitment::new("test", Hash::ZERO, 100);

        let tx = provider.submit(&commitment).await.unwrap();
        assert!(tx.tx_id.0.starts_with("mock_tx_"));
    }

    #[tokio::test]
    async fn test_mock_provider_confirmations() {
        let provider = MockProvider::fast();
        let commitment = Commitment::new("test", Hash::ZERO, 100);

        let tx = provider.submit(&commitment).await.unwrap();

        // Initially 1 confirmation
        let confirmations = provider.confirmations(&tx.tx_id).await.unwrap();
        assert_eq!(confirmations, 1);

        // Advance blocks
        provider.advance_blocks(5);
        let confirmations = provider.confirmations(&tx.tx_id).await.unwrap();
        assert_eq!(confirmations, 6);
    }

    #[tokio::test]
    async fn test_mock_provider_proof() {
        let provider = MockProvider::fast();
        let commitment = Commitment::new("test", Hash::ZERO, 100);

        let tx = provider.submit(&commitment).await.unwrap();
        provider.advance_blocks(10);

        let proof = provider.get_proof(&tx.tx_id).await.unwrap();
        assert!(proof.status.is_finalized());
        assert!(proof.spv_proof.is_some());
    }

    #[tokio::test]
    async fn test_mock_provider_unavailable() {
        let provider = MockProvider::fast();
        provider.set_status(ProviderStatus::Unavailable);

        let commitment = Commitment::new("test", Hash::ZERO, 100);
        let result = provider.submit(&commitment).await;

        assert!(result.is_err());
    }

    #[test]
    fn test_mock_builder() {
        let provider = MockProviderBuilder::new()
            .id("custom")
            .name("Custom Mock")
            .chain_id("custom-chain")
            .block_time(5)
            .finality_blocks(10)
            .fee(0.01, "CUSTOM")
            .build();

        let info = provider.info();
        assert_eq!(info.id, "custom");
        assert_eq!(info.chain_id, "custom-chain");
    }

    #[test]
    fn test_presets() {
        let btc = MockProvider::bitcoin();
        assert_eq!(btc.info().chain_id, "bitcoin-testnet");

        let eth = MockProvider::ethereum();
        assert_eq!(eth.info().chain_id, "ethereum-testnet");
    }
}
