//! Indexing and query layer for Moloch audit chain.
//!
//! This crate provides:
//! - Secondary indexes for efficient event queries
//! - Query DSL for filtering events
//! - Proof generation for inclusion and consistency

pub mod indexes;
pub mod proofs;
pub mod query;

pub use indexes::{IndexConfig, IndexEngine};
pub use proofs::ProofGenerator;
pub use query::{Query, QueryResult};
// Re-export proof types from moloch-core
pub use moloch_core::proof::{ConsistencyProof, InclusionProof};
