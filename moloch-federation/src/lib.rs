//! Multi-Chain Federation for Moloch Audit Chains.
//!
//! Enables cross-chain audit trails where events on one chain can reference
//! and verify events on other federated chains.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────────┐
//! │                      FEDERATION LAYER                                │
//! │                                                                      │
//! │  ┌───────────────────────────────────────────────────────────────┐  │
//! │  │ CHAIN REGISTRY                                                 │  │
//! │  │  - Registered chain metadata (ID, genesis, validators)         │  │
//! │  │  - Trust relationships between chains                          │  │
//! │  │  - Cross-chain routing tables                                  │  │
//! │  └───────────────────────────────────────────────────────────────┘  │
//! │                                                                      │
//! │  ┌───────────────────────────────────────────────────────────────┐  │
//! │  │ BRIDGE PROTOCOL                                                │  │
//! │  │  - Cross-chain event references                                │  │
//! │  │  - Proof relay and verification                                │  │
//! │  │  - Finality tracking across chains                             │  │
//! │  └───────────────────────────────────────────────────────────────┘  │
//! │                                                                      │
//! │  ┌───────────────────────────────────────────────────────────────┐  │
//! │  │ CROSS-CHAIN PROOFS                                             │  │
//! │  │  - Inclusion proofs with chain context                         │  │
//! │  │  - Multi-chain consistency proofs                              │  │
//! │  │  - Atomic cross-chain references                               │  │
//! │  └───────────────────────────────────────────────────────────────┘  │
//! └─────────────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Example
//!
//! ```ignore
//! use moloch_federation::{Federation, ChainConfig};
//!
//! // Create federation hub
//! let federation = Federation::new();
//!
//! // Register chains
//! federation.register_chain(ChainConfig {
//!     chain_id: "audit-chain-us".into(),
//!     genesis_hash: us_genesis,
//!     validators: us_validators,
//! }).await?;
//!
//! federation.register_chain(ChainConfig {
//!     chain_id: "audit-chain-eu".into(),
//!     genesis_hash: eu_genesis,
//!     validators: eu_validators,
//! }).await?;
//!
//! // Create cross-chain reference
//! let reference = federation.create_reference(
//!     "audit-chain-us",
//!     event_id,
//! ).await?;
//!
//! // Verify cross-chain proof
//! let valid = federation.verify_reference(&reference).await?;
//! ```

#![deny(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms)]

pub mod bridge;
pub mod chain;
pub mod errors;
pub mod proof;
pub mod registry;
pub mod routing;

pub use bridge::{Bridge, BridgeConfig, BridgeMessage, BridgeState};
pub use chain::{ChainConfig, ChainInfo, ChainStatus, FederatedChain};
pub use errors::{FederationError, Result};
pub use proof::{CrossChainProof, CrossChainReference, ProofBundle};
pub use registry::{ChainRegistry, RegistryEntry, TrustLevel};
pub use routing::{RouteTable, RoutingPolicy};

/// Main federation coordinator.
pub struct Federation {
    /// Chain registry.
    registry: registry::ChainRegistry,
    /// Active bridges.
    bridges: dashmap::DashMap<String, bridge::Bridge>,
    /// Routing table.
    routes: routing::RouteTable,
}

impl Federation {
    /// Create a new federation coordinator.
    pub fn new() -> Self {
        Self {
            registry: registry::ChainRegistry::new(),
            bridges: dashmap::DashMap::new(),
            routes: routing::RouteTable::new(),
        }
    }

    /// Register a new chain in the federation.
    pub async fn register_chain(&self, config: ChainConfig) -> Result<()> {
        let chain_id = config.chain_id.clone();

        // Add to registry
        self.registry.register(config)?;

        // Create bridge for this chain
        let bridge = Bridge::new(chain_id.clone());
        self.bridges.insert(chain_id.clone(), bridge);

        // Update routing table
        self.routes.add_chain(&chain_id);

        Ok(())
    }

    /// Create a cross-chain reference to an event.
    pub async fn create_reference(
        &self,
        source_chain: &str,
        event_id: moloch_core::EventId,
    ) -> Result<CrossChainReference> {
        let bridge = self.bridges.get(source_chain)
            .ok_or_else(|| FederationError::ChainNotFound(source_chain.to_string()))?;

        bridge.create_reference(event_id).await
    }

    /// Verify a cross-chain reference.
    pub async fn verify_reference(&self, reference: &CrossChainReference) -> Result<bool> {
        let bridge = self.bridges.get(&reference.source_chain)
            .ok_or_else(|| FederationError::ChainNotFound(reference.source_chain.clone()))?;

        bridge.verify_reference(reference).await
    }

    /// Get chain info.
    pub fn chain_info(&self, chain_id: &str) -> Option<ChainInfo> {
        self.registry.get(chain_id).map(|e| e.info.clone())
    }

    /// List all registered chains.
    pub fn chains(&self) -> Vec<String> {
        self.registry.list()
    }
}

impl Default for Federation {
    fn default() -> Self {
        Self::new()
    }
}

/// Prelude for convenient imports.
pub mod prelude {
    pub use crate::bridge::Bridge;
    pub use crate::chain::{ChainConfig, ChainInfo};
    pub use crate::proof::{CrossChainProof, CrossChainReference};
    pub use crate::registry::ChainRegistry;
    pub use crate::Federation;
}
