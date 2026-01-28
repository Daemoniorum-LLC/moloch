//! Moloch Core - Fundamental types for the Moloch audit chain.
//!
//! This crate provides the core data structures and cryptographic primitives
//! used throughout the Moloch system:
//!
//! - [`crypto`] - Hashing (BLAKE3) and signatures (Ed25519)
//! - [`event`] - Audit events (the atomic unit of the chain)
//! - [`block`] - Blocks that batch events together
//! - [`proof`] - Merkle proofs for inclusion verification
//!
//! # Example
//!
//! ```rust
//! use moloch_core::{
//!     crypto::SecretKey,
//!     event::{ActorId, ActorKind, AuditEvent, EventType, ResourceId, ResourceKind},
//!     block::BlockBuilder,
//! };
//!
//! // Generate a key for signing
//! let key = SecretKey::generate();
//!
//! // Create an audit event
//! let actor = ActorId::new(key.public_key(), ActorKind::User);
//! let resource = ResourceId::new(ResourceKind::Repository, "myrepo");
//!
//! let event = AuditEvent::builder()
//!     .now()
//!     .event_type(EventType::Push { force: false, commits: 1 })
//!     .actor(actor)
//!     .resource(resource)
//!     .sign(&key)
//!     .unwrap();
//!
//! // Create a block containing the event
//! let sealer = moloch_core::block::SealerId::new(key.public_key());
//! let block = BlockBuilder::new(sealer)
//!     .events(vec![event])
//!     .seal(&key);
//!
//! assert!(block.validate(None).is_ok());
//! ```

pub mod agent;
pub mod aligned;
pub mod arena;
pub mod block;
pub mod crypto;
pub mod error;
pub mod event;
pub mod merkle;
pub mod proof;
pub mod rkyv_types;

#[cfg(test)]
mod proptest;

// Re-exports for convenience
pub use aligned::{AlignedHash, AlignedHashArray, CacheLinePadded, CACHE_LINE_SIZE};
pub use arena::{BatchArena, CanonicalBytesArena, DEFAULT_ARENA_CAPACITY};
pub use block::{
    compute_events_root, compute_events_root_parallel, Block, BlockBuilder, BlockHash, BlockHeader,
    SealerId,
};
pub use crypto::{
    batch_verify, batch_verify_with_fallback, hash, hash_pair, BatchVerifyResult, Hash, PublicKey,
    SecretKey, Sig,
};
pub use error::{Error, Result};
pub use event::{
    ActorId, ActorKind, AuditEvent, EventId, EventType, Outcome, ResourceId, ResourceKind,
};
pub use merkle::{compute_proof, compute_root_optimized, compute_roots_batch, verify_proof};
pub use proof::{
    BlockInclusionProof, ConsistencyProof, InclusionProof, MmrProof, Position, ProofNode,
};

// Agent accountability types
pub use agent::{
    CausalContext, CausalContextBuilder, CrossSessionReference, PrincipalId, PrincipalKind,
    Session, SessionBuilder, SessionEndReason, SessionId, SessionSummary,
};

/// Batch-verify the signatures of multiple events.
///
/// This is 3-8x faster than calling `event.validate()` on each event individually.
///
/// # Example
/// ```ignore
/// let events: Vec<AuditEvent> = ...;
/// batch_verify_events(&events)?;
/// ```
pub fn batch_verify_events(events: &[AuditEvent]) -> Result<()> {
    if events.is_empty() {
        return Ok(());
    }

    // Pre-compute canonical bytes (this is the expensive part)
    let canonical: Vec<Vec<u8>> = events.iter().map(|e| e.canonical_bytes()).collect();

    // Build verification tuples
    let items: Vec<(&PublicKey, &[u8], &Sig)> = events
        .iter()
        .zip(canonical.iter())
        .map(|(e, bytes)| (e.attester(), bytes.as_slice(), e.signature()))
        .collect();

    batch_verify(&items)
}

/// Batch-verify event signatures with parallel canonical bytes computation.
///
/// Uses Rayon to parallelize the canonical bytes serialization across cores,
/// then uses batch verification for signatures. This is optimal for large batches.
///
/// # Performance
/// - 100 events: ~1.5x faster than batch_verify_events
/// - 1000 events: ~2-3x faster than batch_verify_events
/// - Scales with available CPU cores
pub fn batch_verify_events_parallel(events: &[AuditEvent]) -> Result<()> {
    use rayon::prelude::*;

    if events.is_empty() {
        return Ok(());
    }

    // Parallel canonical bytes computation - this is the CPU-intensive part
    let canonical: Vec<Vec<u8>> = events.par_iter().map(|e| e.canonical_bytes()).collect();

    // Build verification tuples (fast, no parallelization needed)
    let items: Vec<(&PublicKey, &[u8], &Sig)> = events
        .iter()
        .zip(canonical.iter())
        .map(|(e, bytes)| (e.attester(), bytes.as_slice(), e.signature()))
        .collect();

    batch_verify(&items)
}
