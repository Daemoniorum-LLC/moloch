//! Chain operations for Moloch audit chain.
//!
//! This crate provides chain management without networking:
//! - Chain state machine (apply/revert blocks)
//! - Validator registry (PoA consensus)
//! - Mempool (pending event queue)
//! - Block producer (timer-based production)
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────┐
//! │                    BlockProducer                        │
//! │  (Timer-based block creation from mempool events)       │
//! └─────────────────────────────────────────────────────────┘
//!                            │
//!                            ▼
//! ┌─────────────────────────────────────────────────────────┐
//! │                      Mempool                            │
//! │  (Pending events: priority queue, dedup, expiration)    │
//! └─────────────────────────────────────────────────────────┘
//!                            │
//!                            ▼
//! ┌─────────────────────────────────────────────────────────┐
//! │                    ChainState                           │
//! │  (Head, height, validator set, apply/revert blocks)     │
//! └─────────────────────────────────────────────────────────┘
//!                            │
//!                            ▼
//! ┌─────────────────────────────────────────────────────────┐
//! │                   ValidatorSet                          │
//! │  (Authorized sealers, round-robin leader selection)     │
//! └─────────────────────────────────────────────────────────┘
//! ```

mod concurrent_mempool;
mod mempool;
mod producer;
mod state;
mod validators;

pub use concurrent_mempool::{ConcurrentMempool, ConcurrentMempoolConfig, ConcurrentMempoolStats};
pub use mempool::{Mempool, MempoolConfig, MempoolEntry};
pub use producer::{BlockProducer, ProducerConfig};
pub use state::{ApplyResult, ChainConfig, ChainError, ChainSnapshot, ChainState};
pub use validators::{
    MisbehaviorKind, SlashingEvidence, ValidatorChange, ValidatorChangeKind, ValidatorSet,
};
