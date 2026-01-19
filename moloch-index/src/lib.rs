//! Indexing and query layer for Moloch audit chain.
//!
//! This crate provides:
//! - Secondary indexes for efficient event queries
//! - Query DSL for filtering events
//! - Proof generation for inclusion and consistency

pub mod indexes;
pub mod query;
pub mod proofs;

pub use indexes::{IndexEngine, IndexConfig};
pub use query::{Query, QueryResult};
pub use proofs::ProofGenerator;
// Re-export proof types from moloch-core
pub use moloch_core::proof::{InclusionProof, ConsistencyProof};
