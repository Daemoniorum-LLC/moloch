//! Provider registry for managing anchor providers.
//!
//! The registry maintains a collection of providers and routes
//! anchoring requests to appropriate chains.

use std::collections::HashMap;
use std::sync::Arc;

use parking_lot::RwLock;

use crate::errors::{AnchorError, Result};
use crate::provider::{AnchorProvider, ProviderInfo, ProviderStatus};

/// Strategy for selecting providers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SelectionStrategy {
    /// Use all available providers.
    #[default]
    All,
    /// Use the first available provider.
    First,
    /// Use the cheapest provider.
    Cheapest,
    /// Use the fastest provider.
    Fastest,
    /// Use providers with specific chain IDs.
    ByChain,
}

/// Configuration for the provider registry.
#[derive(Debug, Clone)]
pub struct RegistryConfig {
    /// Default selection strategy.
    pub default_strategy: SelectionStrategy,
    /// Maximum concurrent anchoring operations.
    pub max_concurrent: usize,
    /// Health check interval in seconds.
    pub health_check_interval_secs: u64,
    /// Retry failed providers after this many seconds.
    pub retry_after_secs: u64,
}

impl Default for RegistryConfig {
    fn default() -> Self {
        Self {
            default_strategy: SelectionStrategy::All,
            max_concurrent: 10,
            health_check_interval_secs: 60,
            retry_after_secs: 300,
        }
    }
}

/// Registry entry for a provider.
struct ProviderEntry {
    /// The provider instance.
    provider: Arc<dyn AnchorProvider>,
    /// Whether the provider is enabled.
    enabled: bool,
    /// Priority (higher = preferred).
    priority: u8,
    /// Last health check timestamp.
    last_health_check: i64,
    /// Consecutive failures.
    failure_count: u32,
}

/// Registry of anchor providers.
#[allow(dead_code)]
pub struct ProviderRegistry {
    /// Configuration.
    config: RegistryConfig,
    /// Registered providers by ID.
    providers: RwLock<HashMap<String, ProviderEntry>>,
    /// Chain to provider mapping.
    chain_map: RwLock<HashMap<String, Vec<String>>>,
}

impl ProviderRegistry {
    /// Create a new registry with default configuration.
    pub fn new() -> Self {
        Self::with_config(RegistryConfig::default())
    }

    /// Create a new registry with custom configuration.
    pub fn with_config(config: RegistryConfig) -> Self {
        Self {
            config,
            providers: RwLock::new(HashMap::new()),
            chain_map: RwLock::new(HashMap::new()),
        }
    }

    /// Register a provider.
    pub fn register(&self, provider: Arc<dyn AnchorProvider>) -> Result<()> {
        let info = provider.info();
        let id = info.id.clone();
        let chain_id = info.chain_id.clone();

        let entry = ProviderEntry {
            provider,
            enabled: true,
            priority: 50,
            last_health_check: 0,
            failure_count: 0,
        };

        // Add to providers map
        self.providers.write().insert(id.clone(), entry);

        // Add to chain map
        self.chain_map.write().entry(chain_id).or_default().push(id);

        Ok(())
    }

    /// Register a provider with priority.
    pub fn register_with_priority(
        &self,
        provider: Arc<dyn AnchorProvider>,
        priority: u8,
    ) -> Result<()> {
        let info = provider.info();
        let id = info.id.clone();
        let chain_id = info.chain_id.clone();

        let entry = ProviderEntry {
            provider,
            enabled: true,
            priority,
            last_health_check: 0,
            failure_count: 0,
        };

        self.providers.write().insert(id.clone(), entry);
        self.chain_map.write().entry(chain_id).or_default().push(id);

        Ok(())
    }

    /// Unregister a provider.
    pub fn unregister(&self, id: &str) -> Result<()> {
        let mut providers = self.providers.write();

        if let Some(entry) = providers.remove(id) {
            let chain_id = entry.provider.info().chain_id;
            if let Some(chain_providers) = self.chain_map.write().get_mut(&chain_id) {
                chain_providers.retain(|p| p != id);
            }
            Ok(())
        } else {
            Err(AnchorError::ProviderNotFound(id.to_string()))
        }
    }

    /// Enable a provider.
    pub fn enable(&self, id: &str) -> Result<()> {
        let mut providers = self.providers.write();
        if let Some(entry) = providers.get_mut(id) {
            entry.enabled = true;
            entry.failure_count = 0;
            Ok(())
        } else {
            Err(AnchorError::ProviderNotFound(id.to_string()))
        }
    }

    /// Disable a provider.
    pub fn disable(&self, id: &str) -> Result<()> {
        let mut providers = self.providers.write();
        if let Some(entry) = providers.get_mut(id) {
            entry.enabled = false;
            Ok(())
        } else {
            Err(AnchorError::ProviderNotFound(id.to_string()))
        }
    }

    /// Get a provider by ID.
    pub fn get(&self, id: &str) -> Option<Arc<dyn AnchorProvider>> {
        self.providers
            .read()
            .get(id)
            .filter(|e| e.enabled)
            .map(|e| Arc::clone(&e.provider))
    }

    /// Get provider info by ID.
    pub fn get_info(&self, id: &str) -> Option<ProviderInfo> {
        self.providers.read().get(id).map(|e| e.provider.info())
    }

    /// Get all enabled providers.
    pub fn all_enabled(&self) -> Vec<Arc<dyn AnchorProvider>> {
        self.providers
            .read()
            .values()
            .filter(|e| e.enabled)
            .map(|e| Arc::clone(&e.provider))
            .collect()
    }

    /// Get providers for a specific chain.
    pub fn for_chain(&self, chain_id: &str) -> Vec<Arc<dyn AnchorProvider>> {
        let chain_map = self.chain_map.read();
        let providers = self.providers.read();

        chain_map
            .get(chain_id)
            .map(|ids| {
                ids.iter()
                    .filter_map(|id| providers.get(id))
                    .filter(|e| e.enabled)
                    .map(|e| Arc::clone(&e.provider))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Select providers based on strategy.
    pub fn select(&self, strategy: SelectionStrategy) -> Vec<Arc<dyn AnchorProvider>> {
        let providers = self.providers.read();

        let mut entries: Vec<_> = providers.values().filter(|e| e.enabled).collect();

        match strategy {
            SelectionStrategy::All => {
                entries.sort_by(|a, b| b.priority.cmp(&a.priority));
                entries.iter().map(|e| Arc::clone(&e.provider)).collect()
            }
            SelectionStrategy::First => {
                entries.sort_by(|a, b| b.priority.cmp(&a.priority));
                entries
                    .first()
                    .map(|e| vec![Arc::clone(&e.provider)])
                    .unwrap_or_default()
            }
            SelectionStrategy::Cheapest | SelectionStrategy::Fastest => {
                // These require async cost/speed estimation, return all for now
                entries.iter().map(|e| Arc::clone(&e.provider)).collect()
            }
            SelectionStrategy::ByChain => {
                // Requires chain specification, return all
                entries.iter().map(|e| Arc::clone(&e.provider)).collect()
            }
        }
    }

    /// Get provider count.
    pub fn count(&self) -> usize {
        self.providers.read().len()
    }

    /// Get enabled provider count.
    pub fn enabled_count(&self) -> usize {
        self.providers.read().values().filter(|e| e.enabled).count()
    }

    /// List all provider IDs.
    pub fn list_ids(&self) -> Vec<String> {
        self.providers.read().keys().cloned().collect()
    }

    /// List supported chains.
    pub fn list_chains(&self) -> Vec<String> {
        self.chain_map.read().keys().cloned().collect()
    }

    /// Check health of all providers.
    pub async fn health_check(&self) -> HashMap<String, ProviderStatus> {
        let mut results = HashMap::new();
        let providers: Vec<_> = self
            .providers
            .read()
            .iter()
            .map(|(id, e)| (id.clone(), Arc::clone(&e.provider)))
            .collect();

        for (id, provider) in providers {
            let status = provider.status().await;
            results.insert(id.clone(), status);

            // Update failure count
            let mut providers = self.providers.write();
            if let Some(entry) = providers.get_mut(&id) {
                entry.last_health_check = chrono::Utc::now().timestamp();
                if matches!(status, ProviderStatus::Unavailable) {
                    entry.failure_count += 1;
                    // Disable after too many failures
                    if entry.failure_count >= 5 {
                        entry.enabled = false;
                    }
                } else {
                    entry.failure_count = 0;
                }
            }
        }

        results
    }

    /// Record a failure for a provider.
    pub fn record_failure(&self, id: &str) {
        let mut providers = self.providers.write();
        if let Some(entry) = providers.get_mut(id) {
            entry.failure_count += 1;
            if entry.failure_count >= 5 {
                entry.enabled = false;
            }
        }
    }

    /// Record a success for a provider.
    pub fn record_success(&self, id: &str) {
        let mut providers = self.providers.write();
        if let Some(entry) = providers.get_mut(id) {
            entry.failure_count = 0;
        }
    }
}

impl Default for ProviderRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commitment::Commitment;
    use crate::proof::AnchorProof;
    use crate::provider::{AnchorCost, AnchorTx, ProviderCapabilities, TxId};
    use async_trait::async_trait;
    use moloch_core::Hash;

    struct MockProvider {
        id: String,
        chain_id: String,
    }

    #[async_trait]
    impl AnchorProvider for MockProvider {
        fn info(&self) -> ProviderInfo {
            ProviderInfo {
                id: self.id.clone(),
                name: self.id.clone(),
                chain_id: self.chain_id.clone(),
                status: ProviderStatus::Available,
                capabilities: ProviderCapabilities::default(),
                block_height: 1000,
                endpoint: None,
            }
        }

        fn id(&self) -> &str {
            &self.id
        }

        async fn status(&self) -> ProviderStatus {
            ProviderStatus::Available
        }

        async fn submit(&self, commitment: &Commitment) -> Result<AnchorTx> {
            Ok(AnchorTx::pending(
                TxId::new("mock_tx"),
                &self.id,
                &self.chain_id,
            ))
        }

        async fn verify(&self, _proof: &AnchorProof) -> Result<bool> {
            Ok(true)
        }

        async fn confirmations(&self, _tx_id: &TxId) -> Result<u64> {
            Ok(6)
        }

        async fn get_proof(&self, tx_id: &TxId) -> Result<AnchorProof> {
            let commitment = Commitment::new("test", Hash::ZERO, 100);
            Ok(AnchorProof::new(
                commitment,
                &self.id,
                &self.chain_id,
                tx_id.clone(),
                1000,
                "block_hash",
            ))
        }

        async fn estimate_cost(&self, _commitment: &Commitment) -> Result<AnchorCost> {
            Ok(AnchorCost::new(0.0001, "TEST"))
        }

        async fn block_height(&self) -> Result<u64> {
            Ok(1000)
        }
    }

    #[test]
    fn test_register_provider() {
        let registry = ProviderRegistry::new();
        let provider = Arc::new(MockProvider {
            id: "test".to_string(),
            chain_id: "testnet".to_string(),
        });

        registry.register(provider).unwrap();
        assert_eq!(registry.count(), 1);
        assert!(registry.get("test").is_some());
    }

    #[test]
    fn test_chain_mapping() {
        let registry = ProviderRegistry::new();

        registry
            .register(Arc::new(MockProvider {
                id: "btc1".to_string(),
                chain_id: "bitcoin".to_string(),
            }))
            .unwrap();

        registry
            .register(Arc::new(MockProvider {
                id: "btc2".to_string(),
                chain_id: "bitcoin".to_string(),
            }))
            .unwrap();

        registry
            .register(Arc::new(MockProvider {
                id: "eth1".to_string(),
                chain_id: "ethereum".to_string(),
            }))
            .unwrap();

        assert_eq!(registry.for_chain("bitcoin").len(), 2);
        assert_eq!(registry.for_chain("ethereum").len(), 1);
    }

    #[test]
    fn test_enable_disable() {
        let registry = ProviderRegistry::new();
        registry
            .register(Arc::new(MockProvider {
                id: "test".to_string(),
                chain_id: "testnet".to_string(),
            }))
            .unwrap();

        assert!(registry.get("test").is_some());

        registry.disable("test").unwrap();
        assert!(registry.get("test").is_none());
        assert_eq!(registry.enabled_count(), 0);

        registry.enable("test").unwrap();
        assert!(registry.get("test").is_some());
        assert_eq!(registry.enabled_count(), 1);
    }
}
