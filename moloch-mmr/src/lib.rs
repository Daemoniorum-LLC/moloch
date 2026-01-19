//! Merkle Mountain Range (MMR) implementation.
//!
//! An MMR is an append-only data structure that provides:
//! - O(1) amortized append
//! - O(log n) inclusion proofs
//! - O(log n) consistency proofs
//!
//! The structure consists of a series of perfect binary trees ("mountains")
//! of decreasing height. When a new leaf is appended, it may trigger
//! merging of equal-height trees.
//!
//! # Example
//!
//! ```rust
//! use moloch_mmr::{Mmr, MemStore};
//! use moloch_core::hash;
//!
//! let mut mmr = Mmr::new(MemStore::new());
//!
//! // Append some leaves
//! let pos1 = mmr.append(hash(b"event1")).unwrap();
//! let pos2 = mmr.append(hash(b"event2")).unwrap();
//! let pos3 = mmr.append(hash(b"event3")).unwrap();
//!
//! // Get inclusion proof
//! let proof = mmr.proof(pos1).unwrap();
//! assert!(mmr.verify(&proof).unwrap());
//!
//! // Get the root
//! let root = mmr.root();
//! ```

mod mmr;
mod store;

#[cfg(test)]
mod proptest;

pub use mmr::{Mmr, MmrProof};
pub use store::{MemStore, MmrStore};
