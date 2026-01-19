//! Provider trait and types for blockchain anchoring.
//!
//! This module defines the core abstraction that all blockchain
//! providers must implement.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::commitment::Commitment;
use crate::errors::Result;
use crate::proof::AnchorProof;

/// Transaction ID on an external chain.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TxId(pub String);

impl TxId {
    /// Create a new transaction ID.
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    /// Get the ID as a string.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for TxId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Cost estimate for anchoring.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnchorCost {
    /// Estimated fee in the chain's native currency.
    pub fee: f64,
    /// Currency symbol (e.g., "BTC", "ETH").
    pub currency: String,
    /// Fee in USD (if available).
    pub usd_equivalent: Option<f64>,
    /// Estimated confirmation time in seconds.
    pub estimated_time_secs: u64,
}

impl AnchorCost {
    /// Create a new cost estimate.
    pub fn new(fee: f64, currency: impl Into<String>) -> Self {
        Self {
            fee,
            currency: currency.into(),
            usd_equivalent: None,
            estimated_time_secs: 0,
        }
    }

    /// Set USD equivalent.
    pub fn with_usd(mut self, usd: f64) -> Self {
        self.usd_equivalent = Some(usd);
        self
    }

    /// Set estimated time.
    pub fn with_time(mut self, secs: u64) -> Self {
        self.estimated_time_secs = secs;
        self
    }
}

/// Capabilities supported by a provider.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ProviderCapabilities {
    /// Maximum data size that can be anchored (bytes).
    pub max_data_size: usize,
    /// Supports batch anchoring.
    pub batch_anchor: bool,
    /// Supports SPV proofs.
    pub spv_proofs: bool,
    /// Supports smart contracts.
    pub smart_contracts: bool,
    /// Typical confirmation time (seconds).
    pub confirmation_time_secs: u64,
    /// Finality type (probabilistic, deterministic).
    pub finality_type: FinalityType,
}

/// Type of finality provided by the chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FinalityType {
    /// Probabilistic finality (e.g., Bitcoin).
    Probabilistic,
    /// Deterministic/instant finality (e.g., Tendermint).
    Deterministic,
    /// Optimistic finality with challenge period.
    Optimistic,
}

impl Default for FinalityType {
    fn default() -> Self {
        Self::Probabilistic
    }
}

/// Current status of a provider.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProviderStatus {
    /// Provider is available and healthy.
    Available,
    /// Provider is syncing.
    Syncing,
    /// Provider is degraded (high latency, etc.).
    Degraded,
    /// Provider is unavailable.
    Unavailable,
}

/// Information about a provider.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderInfo {
    /// Provider identifier.
    pub id: String,
    /// Human-readable name.
    pub name: String,
    /// Chain identifier (e.g., "mainnet", "testnet").
    pub chain_id: String,
    /// Current status.
    pub status: ProviderStatus,
    /// Provider capabilities.
    pub capabilities: ProviderCapabilities,
    /// Current block height on the chain.
    pub block_height: u64,
    /// Network endpoint (if public).
    pub endpoint: Option<String>,
}

/// Transaction submitted to anchor.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnchorTx {
    /// Transaction ID.
    pub tx_id: TxId,
    /// Provider that submitted it.
    pub provider: String,
    /// Chain ID.
    pub chain_id: String,
    /// Block height (if confirmed).
    pub block_height: Option<u64>,
    /// Number of confirmations.
    pub confirmations: u64,
    /// Submission timestamp.
    pub submitted_at: i64,
}

impl AnchorTx {
    /// Create a new pending anchor transaction.
    pub fn pending(tx_id: TxId, provider: impl Into<String>, chain_id: impl Into<String>) -> Self {
        Self {
            tx_id,
            provider: provider.into(),
            chain_id: chain_id.into(),
            block_height: None,
            confirmations: 0,
            submitted_at: chrono::Utc::now().timestamp(),
        }
    }

    /// Check if transaction is confirmed.
    pub fn is_confirmed(&self) -> bool {
        self.confirmations > 0
    }
}

/// A blockchain that can anchor Moloch commitments.
///
/// Implement this trait to add support for a new blockchain.
#[async_trait]
pub trait AnchorProvider: Send + Sync {
    /// Get provider information.
    fn info(&self) -> ProviderInfo;

    /// Get provider ID.
    ///
    /// Implementors must provide this method to return a stable reference
    /// to the provider's identifier string.
    fn id(&self) -> &str;

    /// Get current status.
    async fn status(&self) -> ProviderStatus;

    /// Check if provider is available.
    async fn is_available(&self) -> bool {
        matches!(self.status().await, ProviderStatus::Available)
    }

    /// Submit a commitment to the chain.
    ///
    /// Returns the transaction ID on success.
    async fn submit(&self, commitment: &Commitment) -> Result<AnchorTx>;

    /// Verify an anchor proof exists on-chain.
    async fn verify(&self, proof: &AnchorProof) -> Result<bool>;

    /// Get current confirmation count for a transaction.
    async fn confirmations(&self, tx_id: &TxId) -> Result<u64>;

    /// Get the anchor proof for a transaction.
    ///
    /// This fetches the SPV proof or equivalent from the chain.
    async fn get_proof(&self, tx_id: &TxId) -> Result<AnchorProof>;

    /// Estimate the cost to anchor a commitment.
    async fn estimate_cost(&self, commitment: &Commitment) -> Result<AnchorCost>;

    /// Get the current block height on the chain.
    async fn block_height(&self) -> Result<u64>;

    /// Wait for a transaction to reach a confirmation threshold.
    async fn wait_for_confirmations(&self, tx_id: &TxId, confirmations: u64) -> Result<AnchorProof> {
        // Default implementation polls
        loop {
            let current = self.confirmations(tx_id).await?;
            if current >= confirmations {
                return self.get_proof(tx_id).await;
            }
            tokio::time::sleep(tokio::time::Duration::from_secs(10)).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tx_id() {
        let tx_id = TxId::new("abc123");
        assert_eq!(tx_id.as_str(), "abc123");
        assert_eq!(format!("{}", tx_id), "abc123");
    }

    #[test]
    fn test_anchor_cost() {
        let cost = AnchorCost::new(0.0001, "BTC")
            .with_usd(4.50)
            .with_time(600);

        assert_eq!(cost.currency, "BTC");
        assert_eq!(cost.usd_equivalent, Some(4.50));
        assert_eq!(cost.estimated_time_secs, 600);
    }

    #[test]
    fn test_anchor_tx_pending() {
        let tx = AnchorTx::pending(
            TxId::new("tx123"),
            "bitcoin",
            "mainnet",
        );

        assert!(!tx.is_confirmed());
        assert_eq!(tx.confirmations, 0);
    }
}
