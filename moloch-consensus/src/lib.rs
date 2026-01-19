//! Proof-of-Authority consensus for Moloch audit chain.
//!
//! This crate implements Aura-style PoA consensus:
//! - Round-robin leader selection
//! - 2/3+ vote threshold for finality
//! - Slashing for misbehavior
//!
//! # Architecture
//!
//! The consensus layer has three main components:
//!
//! 1. **Round** (`round.rs`) - State machine for consensus rounds
//! 2. **Votes** (`votes.rs`) - Vote collection and aggregation
//! 3. **Finality** (`finality.rs`) - Finality tracking and proofs
//!
//! # Consensus Flow
//!
//! ```text
//! Round N:
//!   1. Leader = validators[N % len(validators)]
//!   2. Leader proposes block
//!   3. Others validate & vote
//!   4. 2/3+ votes = commit
//!   5. Advance to round N+1
//! ```
//!
//! # Example
//!
//! ```ignore
//! use moloch_consensus::{ConsensusConfig, ConsensusEngine};
//!
//! let config = ConsensusConfig::default();
//! let engine = ConsensusEngine::new(config, validator_set, storage);
//!
//! // Process incoming proposal
//! engine.handle_proposal(proposal).await?;
//!
//! // Process incoming vote
//! engine.handle_vote(vote).await?;
//! ```

pub mod finality;
pub mod round;
pub mod votes;

pub use finality::{FinalityGadget, FinalityProof, FinalityStatus};
pub use round::{ConsensusConfig, ConsensusEngine, ConsensusError, RoundState, RoundStep};
pub use votes::{Vote, VoteSet, VoteType};
