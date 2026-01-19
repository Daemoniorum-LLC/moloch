//! Provider-Agnostic Blockchain Anchoring for Moloch.
//!
//! This crate provides a unified interface for anchoring Moloch chain state
//! to external blockchains (Bitcoin, Ethereum, Solana, etc.) without
//! coupling to any specific implementation.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────────┐
//! │                      MOLOCH ANCHOR LAYER                             │
//! │                                                                      │
//! │  ┌───────────────────────────────────────────────────────────────┐  │
//! │  │ ANCHOR MANAGER                                                 │  │
//! │  │  - Schedules periodic anchoring                                │  │
//! │  │  - Manages multiple providers                                  │  │
//! │  │  - Tracks anchor confirmations                                 │  │
//! │  └───────────────────────────────────────────────────────────────┘  │
//! │                            │                                         │
//! │           ┌────────────────┼────────────────┐                       │
//! │           ▼                ▼                ▼                       │
//! │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐                 │
//! │  │  Bitcoin    │  │  Ethereum   │  │   Solana    │   ...           │
//! │  │  Provider   │  │  Provider   │  │  Provider   │                 │
//! │  └─────────────┘  └─────────────┘  └─────────────┘                 │
//! │                                                                      │
//! │  ┌───────────────────────────────────────────────────────────────┐  │
//! │  │ PROOF VERIFIER                                                 │  │
//! │  │  - Verifies anchor proofs from any provider                    │  │
//! │  │  - SPV validation for light clients                            │  │
//! │  │  - Cross-chain proof aggregation                               │  │
//! │  └───────────────────────────────────────────────────────────────┘  │
//! └─────────────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Example
//!
//! ```ignore
//! use moloch_anchor::{AnchorManager, Commitment, MockProvider};
//!
//! // Create manager with mock provider for testing
//! let mut manager = AnchorManager::new();
//! manager.register_provider(MockProvider::new("test"));
//!
//! // Create a commitment to anchor
//! let commitment = Commitment::new(mmr_root, height);
//!
//! // Anchor to all registered providers
//! let anchors = manager.anchor(&commitment).await?;
//!
//! // Verify an anchor proof
//! let valid = manager.verify(&anchor_proof).await?;
//! ```

#![deny(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms)]

pub mod commitment;
pub mod errors;
pub mod manager;
pub mod proof;
pub mod provider;
pub mod registry;
pub mod scheduler;

#[cfg(any(test, feature = "mock"))]
pub mod mock;

pub use commitment::{Commitment, CommitmentBuilder, CommitmentData};
pub use errors::{AnchorError, Result};
pub use manager::{AnchorManager, AnchorManagerConfig, AnchorOperation, AnchorStats, OperationStatus};
pub use proof::{AnchorProof, AnchorStatus, ProofBundle, SpvProof, Verification};
pub use provider::{
    AnchorCost, AnchorProvider, AnchorTx, FinalityType, ProviderCapabilities, ProviderInfo,
    ProviderStatus, TxId,
};
pub use registry::{ProviderRegistry, RegistryConfig, SelectionStrategy};
pub use scheduler::{AnchorBatch, AnchorPriority, AnchorRequest, AnchorScheduler, SchedulerConfig};

#[cfg(any(test, feature = "mock"))]
pub use mock::{MockProvider, MockProviderBuilder, MockProviderConfig};

/// Prelude for convenient imports.
pub mod prelude {
    pub use crate::commitment::Commitment;
    pub use crate::errors::{AnchorError, Result};
    pub use crate::manager::AnchorManager;
    pub use crate::proof::{AnchorProof, AnchorStatus};
    pub use crate::provider::{AnchorProvider, TxId};
    pub use crate::registry::ProviderRegistry;
    pub use crate::scheduler::{AnchorPriority, AnchorRequest, AnchorScheduler};

    #[cfg(any(test, feature = "mock"))]
    pub use crate::mock::{MockProvider, MockProviderBuilder};
}
