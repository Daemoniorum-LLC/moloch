//! Formal Verification for Moloch Audit Chain.
//!
//! Provides compile-time and runtime verification of chain invariants.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────────┐
//! │                     VERIFICATION LAYER                               │
//! │                                                                      │
//! │  ┌───────────────────────────────────────────────────────────────┐  │
//! │  │ INVARIANTS                                                     │  │
//! │  │  - Chain invariants (append-only, monotonic height)            │  │
//! │  │  - Event invariants (valid signatures, unique IDs)             │  │
//! │  │  - MMR invariants (consistent roots, valid proofs)             │  │
//! │  └───────────────────────────────────────────────────────────────┘  │
//! │                                                                      │
//! │  ┌───────────────────────────────────────────────────────────────┐  │
//! │  │ PROPERTY-BASED TESTING                                         │  │
//! │  │  - QuickCheck-style property testing                           │  │
//! │  │  - Shrinking for minimal counterexamples                       │  │
//! │  │  - Deterministic replay                                        │  │
//! │  └───────────────────────────────────────────────────────────────┘  │
//! │                                                                      │
//! │  ┌───────────────────────────────────────────────────────────────┐  │
//! │  │ RUNTIME CHECKS                                                 │  │
//! │  │  - Pre/post condition assertions                               │  │
//! │  │  - State transition validation                                 │  │
//! │  │  - Consistency monitors                                        │  │
//! │  └───────────────────────────────────────────────────────────────┘  │
//! └─────────────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Example
//!
//! ```ignore
//! use moloch_verify::{Invariant, ChainInvariants, verify_transition};
//!
//! // Define chain invariants
//! let invariants = ChainInvariants::new()
//!     .require_monotonic_height()
//!     .require_append_only()
//!     .require_valid_signatures();
//!
//! // Verify a state transition
//! let result = verify_transition(&old_state, &new_state, &invariants);
//! assert!(result.is_ok());
//! ```

#![deny(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms)]

pub mod invariants;
pub mod properties;
pub mod runtime;
pub mod specs;

pub use invariants::{
    BlockInvariant, ChainInvariants, EventInvariant, Invariant, InvariantViolation, MmrInvariant,
};
pub use properties::{Property, PropertyResult, PropertyTest};
pub use runtime::{CheckResult, RuntimeCheck, RuntimeMonitor};
pub use specs::{SpecViolation, Specification};

/// Verify a state transition satisfies all invariants.
pub fn verify_transition<S>(
    old_state: &S,
    new_state: &S,
    invariants: &ChainInvariants,
) -> Result<(), InvariantViolation>
where
    S: ChainState,
{
    invariants.verify_transition(old_state, new_state)
}

/// Trait for chain state that can be verified.
pub trait ChainState {
    /// Get the current height.
    fn height(&self) -> u64;

    /// Get the current block hash.
    fn block_hash(&self) -> moloch_core::BlockHash;

    /// Get the MMR root.
    fn mmr_root(&self) -> moloch_core::Hash;

    /// Get total event count.
    fn event_count(&self) -> u64;
}

/// Prelude for convenient imports.
pub mod prelude {
    pub use crate::invariants::{ChainInvariants, Invariant, InvariantViolation};
    pub use crate::properties::{Property, PropertyTest};
    pub use crate::runtime::{RuntimeCheck, RuntimeMonitor};
    pub use crate::{verify_transition, ChainState};
}
