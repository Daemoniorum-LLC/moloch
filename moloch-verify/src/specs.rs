//! Formal specifications for chain behavior.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// A formal specification of expected behavior.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Specification {
    /// Specification name.
    pub name: String,
    /// Description.
    pub description: String,
    /// Preconditions that must hold.
    pub preconditions: Vec<Condition>,
    /// Postconditions that must hold after execution.
    pub postconditions: Vec<Condition>,
    /// Invariants that must hold throughout.
    pub invariants: Vec<Condition>,
}

impl Specification {
    /// Create a new specification.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            description: String::new(),
            preconditions: Vec::new(),
            postconditions: Vec::new(),
            invariants: Vec::new(),
        }
    }

    /// Add a description.
    pub fn with_description(mut self, desc: impl Into<String>) -> Self {
        self.description = desc.into();
        self
    }

    /// Add a precondition.
    pub fn requires(mut self, condition: Condition) -> Self {
        self.preconditions.push(condition);
        self
    }

    /// Add a postcondition.
    pub fn ensures(mut self, condition: Condition) -> Self {
        self.postconditions.push(condition);
        self
    }

    /// Add an invariant.
    pub fn maintains(mut self, condition: Condition) -> Self {
        self.invariants.push(condition);
        self
    }
}

/// A condition in a specification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Condition {
    /// Condition name.
    pub name: String,
    /// Condition expression (human-readable).
    pub expression: String,
    /// Variables used in the condition.
    pub variables: Vec<String>,
}

impl Condition {
    /// Create a new condition.
    pub fn new(name: impl Into<String>, expression: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            expression: expression.into(),
            variables: Vec::new(),
        }
    }

    /// Add a variable.
    pub fn with_var(mut self, var: impl Into<String>) -> Self {
        self.variables.push(var.into());
        self
    }
}

/// Violation of a specification.
#[derive(Debug, Clone, Error, Serialize, Deserialize)]
#[error("specification '{spec}' violated: {condition} - {message}")]
pub struct SpecViolation {
    /// Specification name.
    pub spec: String,
    /// Violated condition.
    pub condition: String,
    /// Violation message.
    pub message: String,
    /// Context values.
    pub context: HashMap<String, String>,
}

impl SpecViolation {
    /// Create a new violation.
    pub fn new(
        spec: impl Into<String>,
        condition: impl Into<String>,
        message: impl Into<String>,
    ) -> Self {
        Self {
            spec: spec.into(),
            condition: condition.into(),
            message: message.into(),
            context: HashMap::new(),
        }
    }

    /// Add context.
    pub fn with_context(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.context.insert(key.into(), value.into());
        self
    }
}

/// Well-known specifications for Moloch.
pub mod specs {
    use super::*;

    /// Specification for block production.
    pub fn block_production() -> Specification {
        Specification::new("block_production")
            .with_description("Block production must follow consensus rules")
            .requires(Condition::new(
                "valid_proposer",
                "proposer == validators[height % len(validators)]",
            ).with_var("proposer").with_var("validators").with_var("height"))
            .requires(Condition::new(
                "valid_parent",
                "block.parent == chain.tip",
            ))
            .ensures(Condition::new(
                "height_incremented",
                "new_height == old_height + 1",
            ))
            .ensures(Condition::new(
                "hash_unique",
                "!chain.contains(block.hash)",
            ))
            .maintains(Condition::new(
                "monotonic_time",
                "block.timestamp >= parent.timestamp",
            ))
    }

    /// Specification for event creation.
    pub fn event_creation() -> Specification {
        Specification::new("event_creation")
            .with_description("Events must be properly signed and unique")
            .requires(Condition::new(
                "valid_signature",
                "verify(event.signature, event.pubkey, event.hash)",
            ))
            .requires(Condition::new(
                "valid_timestamp",
                "event.timestamp <= now + max_drift",
            ))
            .ensures(Condition::new(
                "id_unique",
                "!chain.has_event(event.id)",
            ))
            .ensures(Condition::new(
                "in_mmr",
                "mmr.contains(event.id)",
            ))
    }

    /// Specification for MMR operations.
    pub fn mmr_append() -> Specification {
        Specification::new("mmr_append")
            .with_description("MMR append must maintain consistency")
            .requires(Condition::new(
                "valid_leaf",
                "leaf.len() == 32",
            ))
            .ensures(Condition::new(
                "size_increased",
                "new_size == old_size + 1",
            ))
            .ensures(Condition::new(
                "root_changed",
                "new_root != old_root",
            ))
            .maintains(Condition::new(
                "proofs_valid",
                "forall pos: verify_proof(mmr, pos)",
            ))
    }

    /// Specification for finality.
    pub fn finality() -> Specification {
        Specification::new("finality")
            .with_description("Finality requires 2/3+ validator signatures")
            .requires(Condition::new(
                "sufficient_votes",
                "votes.len() >= (validators.len() * 2 / 3) + 1",
            ))
            .requires(Condition::new(
                "valid_votes",
                "forall v in votes: verify(v.sig, v.pubkey, block.hash)",
            ))
            .ensures(Condition::new(
                "block_finalized",
                "chain.finalized.contains(block)",
            ))
            .maintains(Condition::new(
                "no_revert",
                "!chain.can_revert(block)",
            ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_specification_builder() {
        let spec = Specification::new("test_spec")
            .with_description("A test specification")
            .requires(Condition::new("pre1", "x > 0"))
            .ensures(Condition::new("post1", "y == x + 1"));

        assert_eq!(spec.name, "test_spec");
        assert_eq!(spec.preconditions.len(), 1);
        assert_eq!(spec.postconditions.len(), 1);
    }

    #[test]
    fn test_spec_violation() {
        let violation = SpecViolation::new("test_spec", "pre1", "precondition failed")
            .with_context("x", "-1");

        assert_eq!(violation.spec, "test_spec");
        assert_eq!(violation.context.get("x"), Some(&"-1".to_string()));
    }

    #[test]
    fn test_builtin_specs() {
        let block_spec = specs::block_production();
        assert!(!block_spec.preconditions.is_empty());
        assert!(!block_spec.postconditions.is_empty());

        let mmr_spec = specs::mmr_append();
        assert!(!mmr_spec.invariants.is_empty());
    }
}
