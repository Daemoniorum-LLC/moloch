//! Light Client Protocol for Moloch Audit Chain.
//!
//! Light clients can verify audit events without downloading the full chain.
//! They sync only block headers and request proofs on-demand.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────────┐
//! │                        LIGHT CLIENT                                  │
//! │                                                                      │
//! │  ┌───────────────────────────────────────────────────────────────┐  │
//! │  │ HEADER STORE                                                   │  │
//! │  │  - Stores only block headers (not full blocks)                 │  │
//! │  │  - Tracks finalized chain tip                                  │  │
//! │  │  - ~200 bytes per block (vs ~100KB for full blocks)            │  │
//! │  └───────────────────────────────────────────────────────────────┘  │
//! │                                                                      │
//! │  ┌───────────────────────────────────────────────────────────────┐  │
//! │  │ SYNC ENGINE                                                    │  │
//! │  │  - Header-only sync protocol                                   │  │
//! │  │  - Checkpoint-based fast sync                                  │  │
//! │  │  - Validator set tracking                                      │  │
//! │  └───────────────────────────────────────────────────────────────┘  │
//! │                                                                      │
//! │  ┌───────────────────────────────────────────────────────────────┐  │
//! │  │ PROOF VERIFIER                                                 │  │
//! │  │  - Event inclusion proofs                                      │  │
//! │  │  - MMR consistency proofs                                      │  │
//! │  │  - Compact proof format for bandwidth efficiency               │  │
//! │  └───────────────────────────────────────────────────────────────┘  │
//! └─────────────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Example
//!
//! ```ignore
//! use moloch_light::{LightClient, LightClientConfig};
//!
//! // Create light client with checkpoint
//! let config = LightClientConfig::builder()
//!     .checkpoint_height(1000000)
//!     .checkpoint_hash(known_hash)
//!     .build();
//!
//! let client = LightClient::new(config).await?;
//!
//! // Sync headers from checkpoint
//! client.sync_headers().await?;
//!
//! // Verify an event exists in the chain
//! let proof = client.request_proof(event_id).await?;
//! assert!(client.verify_proof(&proof)?);
//! ```

#![deny(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms)]

pub mod checkpoint;
pub mod client;
pub mod errors;
pub mod header;
pub mod proof;
pub mod sync;

pub use checkpoint::{Checkpoint, CheckpointRegistry, TrustedCheckpoint};
pub use client::{LightClient, LightClientConfig, LightClientState};
pub use errors::{LightClientError, Result};
pub use header::{HeaderChain, HeaderStore, TrustedHeader};
pub use proof::{CompactProof, ProofRequest, ProofResponse, ProofVerifier};
pub use sync::{SyncConfig, SyncEngine, SyncProgress, SyncStatus};

/// Prelude for convenient imports.
pub mod prelude {
    pub use crate::client::{LightClient, LightClientConfig};
    pub use crate::errors::{LightClientError, Result};
    pub use crate::proof::{CompactProof, ProofVerifier};
    pub use crate::sync::{SyncEngine, SyncStatus};
}
