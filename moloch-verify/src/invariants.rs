//! Chain invariants for formal verification.

use moloch_core::{BlockHash, Hash};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::ChainState;

/// An invariant that must hold for the chain.
pub trait Invariant<S> {
    /// Name of this invariant.
    fn name(&self) -> &str;

    /// Check if the invariant holds for a state.
    fn check(&self, state: &S) -> Result<(), InvariantViolation>;

    /// Check if the invariant holds across a transition.
    fn check_transition(&self, old: &S, new: &S) -> Result<(), InvariantViolation>;
}

/// Violation of an invariant.
#[derive(Debug, Clone, Error, Serialize, Deserialize)]
#[error("invariant '{name}' violated: {message}")]
pub struct InvariantViolation {
    /// Invariant name.
    pub name: String,
    /// Violation message.
    pub message: String,
    /// State at violation (if available).
    pub state_height: Option<u64>,
}

impl InvariantViolation {
    /// Create a new violation.
    pub fn new(name: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            message: message.into(),
            state_height: None,
        }
    }

    /// Add state height context.
    pub fn at_height(mut self, height: u64) -> Self {
        self.state_height = Some(height);
        self
    }
}

/// Invariant: block heights must be monotonically increasing.
#[derive(Debug, Clone, Copy)]
pub struct MonotonicHeight;

impl<S: ChainState> Invariant<S> for MonotonicHeight {
    fn name(&self) -> &str {
        "monotonic_height"
    }

    fn check(&self, _state: &S) -> Result<(), InvariantViolation> {
        // Single state always satisfies
        Ok(())
    }

    fn check_transition(&self, old: &S, new: &S) -> Result<(), InvariantViolation> {
        if new.height() <= old.height() {
            Err(InvariantViolation::new(
                "monotonic_height",
                format!(
                    "height decreased or unchanged: {} -> {}",
                    old.height(),
                    new.height()
                ),
            )
            .at_height(new.height()))
        } else {
            Ok(())
        }
    }
}

/// Invariant: consecutive heights (no gaps).
#[derive(Debug, Clone, Copy)]
pub struct ConsecutiveHeight;

impl<S: ChainState> Invariant<S> for ConsecutiveHeight {
    fn name(&self) -> &str {
        "consecutive_height"
    }

    fn check(&self, _state: &S) -> Result<(), InvariantViolation> {
        Ok(())
    }

    fn check_transition(&self, old: &S, new: &S) -> Result<(), InvariantViolation> {
        if new.height() != old.height() + 1 {
            Err(InvariantViolation::new(
                "consecutive_height",
                format!(
                    "height gap: {} -> {} (expected {})",
                    old.height(),
                    new.height(),
                    old.height() + 1
                ),
            )
            .at_height(new.height()))
        } else {
            Ok(())
        }
    }
}

/// Invariant: event count must be monotonically increasing.
#[derive(Debug, Clone, Copy)]
pub struct MonotonicEvents;

impl<S: ChainState> Invariant<S> for MonotonicEvents {
    fn name(&self) -> &str {
        "monotonic_events"
    }

    fn check(&self, _state: &S) -> Result<(), InvariantViolation> {
        Ok(())
    }

    fn check_transition(&self, old: &S, new: &S) -> Result<(), InvariantViolation> {
        if new.event_count() < old.event_count() {
            Err(InvariantViolation::new(
                "monotonic_events",
                format!(
                    "event count decreased: {} -> {}",
                    old.event_count(),
                    new.event_count()
                ),
            )
            .at_height(new.height()))
        } else {
            Ok(())
        }
    }
}

/// Invariant: MMR root changes on append.
#[derive(Debug, Clone, Copy)]
pub struct MmrConsistency;

impl<S: ChainState> Invariant<S> for MmrConsistency {
    fn name(&self) -> &str {
        "mmr_consistency"
    }

    fn check(&self, _state: &S) -> Result<(), InvariantViolation> {
        Ok(())
    }

    fn check_transition(&self, old: &S, new: &S) -> Result<(), InvariantViolation> {
        // If events increased, MMR root should change
        if new.event_count() > old.event_count() && new.mmr_root() == old.mmr_root() {
            Err(
                InvariantViolation::new("mmr_consistency", "events added but MMR root unchanged")
                    .at_height(new.height()),
            )
        } else {
            Ok(())
        }
    }
}

/// Block-level invariants.
pub enum BlockInvariant {
    /// Height must increase.
    MonotonicHeight,
    /// Heights must be consecutive.
    ConsecutiveHeight,
    /// Block hash must be unique.
    UniqueHash,
}

/// Event-level invariants.
pub enum EventInvariant {
    /// Event IDs must be unique.
    UniqueId,
    /// Signatures must be valid.
    ValidSignature,
    /// Timestamps must be reasonable.
    ValidTimestamp,
}

/// MMR-level invariants.
pub enum MmrInvariant {
    /// Root changes on append.
    ConsistentRoot,
    /// Proofs are valid.
    ValidProofs,
    /// Size matches leaf count.
    CorrectSize,
}

/// Collection of chain invariants.
#[derive(Default)]
pub struct ChainInvariants {
    /// Enable monotonic height check.
    pub monotonic_height: bool,
    /// Enable consecutive height check.
    pub consecutive_height: bool,
    /// Enable monotonic events check.
    pub monotonic_events: bool,
    /// Enable MMR consistency check.
    pub mmr_consistency: bool,
}

impl ChainInvariants {
    /// Create a new invariant set with defaults.
    pub fn new() -> Self {
        Self::default()
    }

    /// Create with all invariants enabled.
    pub fn all() -> Self {
        Self {
            monotonic_height: true,
            consecutive_height: true,
            monotonic_events: true,
            mmr_consistency: true,
        }
    }

    /// Require monotonic height.
    pub fn require_monotonic_height(mut self) -> Self {
        self.monotonic_height = true;
        self
    }

    /// Require consecutive heights.
    pub fn require_consecutive_height(mut self) -> Self {
        self.consecutive_height = true;
        self
    }

    /// Require monotonic events.
    pub fn require_monotonic_events(mut self) -> Self {
        self.monotonic_events = true;
        self
    }

    /// Require MMR consistency.
    pub fn require_mmr_consistency(mut self) -> Self {
        self.mmr_consistency = true;
        self
    }

    /// Verify a state transition.
    pub fn verify_transition<S: ChainState>(
        &self,
        old: &S,
        new: &S,
    ) -> Result<(), InvariantViolation> {
        if self.monotonic_height {
            MonotonicHeight.check_transition(old, new)?;
        }
        if self.consecutive_height {
            ConsecutiveHeight.check_transition(old, new)?;
        }
        if self.monotonic_events {
            MonotonicEvents.check_transition(old, new)?;
        }
        if self.mmr_consistency {
            MmrConsistency.check_transition(old, new)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockState {
        height: u64,
        hash: BlockHash,
        mmr_root: Hash,
        events: u64,
    }

    impl ChainState for MockState {
        fn height(&self) -> u64 {
            self.height
        }

        fn block_hash(&self) -> BlockHash {
            self.hash
        }

        fn mmr_root(&self) -> Hash {
            self.mmr_root
        }

        fn event_count(&self) -> u64 {
            self.events
        }
    }

    fn mock_state(height: u64, events: u64) -> MockState {
        MockState {
            height,
            hash: BlockHash(Hash::ZERO),
            mmr_root: Hash::ZERO,
            events,
        }
    }

    #[test]
    fn test_monotonic_height() {
        let old = mock_state(10, 100);
        let new = mock_state(11, 100);

        let invariant = MonotonicHeight;
        assert!(invariant.check_transition(&old, &new).is_ok());

        let bad_new = mock_state(10, 100);
        assert!(invariant.check_transition(&old, &bad_new).is_err());
    }

    #[test]
    fn test_consecutive_height() {
        let old = mock_state(10, 100);
        let new = mock_state(11, 100);

        let invariant = ConsecutiveHeight;
        assert!(invariant.check_transition(&old, &new).is_ok());

        let gap_new = mock_state(13, 100);
        assert!(invariant.check_transition(&old, &gap_new).is_err());
    }

    #[test]
    fn test_chain_invariants_all() {
        let invariants = ChainInvariants::all();

        let old = mock_state(10, 100);
        let new = mock_state(11, 105);

        // This should fail because MMR root didn't change with events
        let result = invariants.verify_transition(&old, &new);
        assert!(result.is_err());
    }
}
