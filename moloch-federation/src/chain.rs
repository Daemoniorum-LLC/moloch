//! Chain types and configuration.

use moloch_core::{BlockHash, Hash, PublicKey};
use serde::{Deserialize, Serialize};

/// Configuration for registering a chain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainConfig {
    /// Unique chain identifier.
    pub chain_id: String,
    /// Genesis block hash.
    pub genesis_hash: BlockHash,
    /// Initial validator set.
    pub validators: Vec<PublicKey>,
    /// Chain metadata.
    pub metadata: ChainMetadata,
}

/// Metadata about a chain.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ChainMetadata {
    /// Human-readable name.
    pub name: String,
    /// Description.
    pub description: String,
    /// Network endpoints.
    pub endpoints: Vec<String>,
    /// Chain version.
    pub version: String,
}

/// Runtime information about a federated chain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainInfo {
    /// Chain ID.
    pub chain_id: String,
    /// Genesis hash.
    pub genesis_hash: BlockHash,
    /// Current finalized height.
    pub finalized_height: u64,
    /// Current finalized hash.
    pub finalized_hash: BlockHash,
    /// Last update timestamp.
    pub last_updated: i64,
    /// Chain metadata.
    pub metadata: ChainMetadata,
}

/// Current status of a federated chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ChainStatus {
    /// Chain is healthy and synced.
    Healthy,
    /// Chain is syncing.
    Syncing,
    /// Chain is unreachable.
    Unreachable,
    /// Chain has been deprecated.
    Deprecated,
}

/// A chain participating in the federation.
pub struct FederatedChain {
    /// Chain configuration.
    pub config: ChainConfig,
    /// Current status.
    pub status: ChainStatus,
    /// Light client for this chain.
    light_client: Option<moloch_light::LightClient>,
}

impl FederatedChain {
    /// Create a new federated chain.
    pub fn new(config: ChainConfig) -> Self {
        Self {
            config,
            status: ChainStatus::Syncing,
            light_client: None,
        }
    }

    /// Get chain ID.
    pub fn chain_id(&self) -> &str {
        &self.config.chain_id
    }

    /// Get current status.
    pub fn status(&self) -> ChainStatus {
        self.status
    }

    /// Update chain status.
    pub fn set_status(&mut self, status: ChainStatus) {
        self.status = status;
    }

    /// Check if chain is healthy.
    pub fn is_healthy(&self) -> bool {
        self.status == ChainStatus::Healthy
    }

    /// Get finalized height (if light client is connected).
    pub async fn finalized_height(&self) -> Option<u64> {
        if let Some(ref client) = self.light_client {
            Some(client.height().await)
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_chain_status() {
        let config = ChainConfig {
            chain_id: "test-chain".to_string(),
            genesis_hash: BlockHash(Hash::ZERO),
            validators: vec![],
            metadata: ChainMetadata::default(),
        };

        let mut chain = FederatedChain::new(config);
        assert_eq!(chain.status(), ChainStatus::Syncing);
        assert!(!chain.is_healthy());

        chain.set_status(ChainStatus::Healthy);
        assert!(chain.is_healthy());
    }
}
