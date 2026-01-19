//! Chain registry for federation.

use std::collections::HashMap;
use std::sync::RwLock;

use serde::{Deserialize, Serialize};

use crate::chain::{ChainConfig, ChainInfo, ChainStatus};
use crate::errors::{FederationError, Result};

/// Trust level for a federated chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum TrustLevel {
    /// Untrusted - proofs required for everything.
    Untrusted = 0,
    /// Basic trust - standard verification.
    Basic = 1,
    /// Elevated trust - reduced verification.
    Elevated = 2,
    /// Full trust - minimal verification.
    Full = 3,
}

impl Default for TrustLevel {
    fn default() -> Self {
        Self::Basic
    }
}

/// Entry in the chain registry.
#[derive(Debug, Clone)]
pub struct RegistryEntry {
    /// Chain configuration.
    pub config: ChainConfig,
    /// Chain info.
    pub info: ChainInfo,
    /// Current status.
    pub status: ChainStatus,
    /// Trust level.
    pub trust_level: TrustLevel,
    /// Registration timestamp.
    pub registered_at: i64,
}

/// Registry of federated chains.
pub struct ChainRegistry {
    /// Registered chains.
    chains: RwLock<HashMap<String, RegistryEntry>>,
}

impl ChainRegistry {
    /// Create a new empty registry.
    pub fn new() -> Self {
        Self {
            chains: RwLock::new(HashMap::new()),
        }
    }

    /// Register a new chain.
    pub fn register(&self, config: ChainConfig) -> Result<()> {
        let mut chains = self.chains.write().unwrap();

        if chains.contains_key(&config.chain_id) {
            return Err(FederationError::ChainAlreadyRegistered(
                config.chain_id.clone(),
            ));
        }

        let info = ChainInfo {
            chain_id: config.chain_id.clone(),
            genesis_hash: config.genesis_hash,
            finalized_height: 0,
            finalized_hash: config.genesis_hash,
            last_updated: chrono::Utc::now().timestamp(),
            metadata: config.metadata.clone(),
        };

        let entry = RegistryEntry {
            config,
            info,
            status: ChainStatus::Syncing,
            trust_level: TrustLevel::Basic,
            registered_at: chrono::Utc::now().timestamp(),
        };

        chains.insert(entry.config.chain_id.clone(), entry);
        Ok(())
    }

    /// Get a chain entry.
    pub fn get(&self, chain_id: &str) -> Option<RegistryEntry> {
        self.chains.read().unwrap().get(chain_id).cloned()
    }

    /// Update chain info.
    pub fn update_info(&self, chain_id: &str, info: ChainInfo) -> Result<()> {
        let mut chains = self.chains.write().unwrap();
        let entry = chains.get_mut(chain_id)
            .ok_or_else(|| FederationError::ChainNotFound(chain_id.to_string()))?;

        entry.info = info;
        Ok(())
    }

    /// Update chain status.
    pub fn update_status(&self, chain_id: &str, status: ChainStatus) -> Result<()> {
        let mut chains = self.chains.write().unwrap();
        let entry = chains.get_mut(chain_id)
            .ok_or_else(|| FederationError::ChainNotFound(chain_id.to_string()))?;

        entry.status = status;
        Ok(())
    }

    /// Set trust level for a chain.
    pub fn set_trust_level(&self, chain_id: &str, level: TrustLevel) -> Result<()> {
        let mut chains = self.chains.write().unwrap();
        let entry = chains.get_mut(chain_id)
            .ok_or_else(|| FederationError::ChainNotFound(chain_id.to_string()))?;

        entry.trust_level = level;
        Ok(())
    }

    /// Unregister a chain.
    pub fn unregister(&self, chain_id: &str) -> Result<()> {
        let mut chains = self.chains.write().unwrap();
        chains.remove(chain_id)
            .ok_or_else(|| FederationError::ChainNotFound(chain_id.to_string()))?;
        Ok(())
    }

    /// List all chain IDs.
    pub fn list(&self) -> Vec<String> {
        self.chains.read().unwrap().keys().cloned().collect()
    }

    /// Get all healthy chains.
    pub fn healthy_chains(&self) -> Vec<RegistryEntry> {
        self.chains.read().unwrap()
            .values()
            .filter(|e| e.status == ChainStatus::Healthy)
            .cloned()
            .collect()
    }

    /// Get chains with minimum trust level.
    pub fn chains_with_trust(&self, min_level: TrustLevel) -> Vec<RegistryEntry> {
        self.chains.read().unwrap()
            .values()
            .filter(|e| e.trust_level >= min_level)
            .cloned()
            .collect()
    }
}

impl Default for ChainRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use moloch_core::{BlockHash, Hash};

    fn test_config(id: &str) -> ChainConfig {
        ChainConfig {
            chain_id: id.to_string(),
            genesis_hash: BlockHash(Hash::ZERO),
            validators: vec![],
            metadata: Default::default(),
        }
    }

    #[test]
    fn test_register_chain() {
        let registry = ChainRegistry::new();

        registry.register(test_config("chain-1")).unwrap();
        assert!(registry.get("chain-1").is_some());
        assert!(registry.get("chain-2").is_none());
    }

    #[test]
    fn test_duplicate_registration() {
        let registry = ChainRegistry::new();

        registry.register(test_config("chain-1")).unwrap();
        let result = registry.register(test_config("chain-1"));

        assert!(matches!(result, Err(FederationError::ChainAlreadyRegistered(_))));
    }

    #[test]
    fn test_trust_levels() {
        let registry = ChainRegistry::new();
        registry.register(test_config("chain-1")).unwrap();

        // Default trust level
        let entry = registry.get("chain-1").unwrap();
        assert_eq!(entry.trust_level, TrustLevel::Basic);

        // Update trust level
        registry.set_trust_level("chain-1", TrustLevel::Full).unwrap();
        let entry = registry.get("chain-1").unwrap();
        assert_eq!(entry.trust_level, TrustLevel::Full);
    }
}
