//! Validator registry for PoA consensus.
//!
//! Manages the set of authorized block producers:
//! - Ordered list of validators
//! - Round-robin leader selection
//! - Validator rotation (add/remove)

use moloch_core::{
    block::SealerId,
    crypto::PublicKey,
    Hash,
};
use serde::{Deserialize, Deserializer, Serialize};
use std::collections::HashSet;

/// A set of validators authorized to produce blocks.
#[derive(Debug, Clone, Serialize)]
pub struct ValidatorSet {
    /// Ordered list of validators.
    validators: Vec<SealerId>,
    /// Set for O(1) lookup (rebuilt on deserialize).
    #[serde(skip)]
    lookup: HashSet<SealerId>,
}

// Custom Deserialize to rebuild lookup HashSet
impl<'de> Deserialize<'de> for ValidatorSet {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        // Deserialize just the validators vec
        #[derive(Deserialize)]
        struct ValidatorSetData {
            validators: Vec<SealerId>,
        }

        let data = ValidatorSetData::deserialize(deserializer)?;
        let lookup = data.validators.iter().cloned().collect();

        Ok(ValidatorSet {
            validators: data.validators,
            lookup,
        })
    }
}

impl ValidatorSet {
    /// Create a new validator set.
    pub fn new(validators: Vec<SealerId>) -> Self {
        let lookup = validators.iter().cloned().collect();
        Self { validators, lookup }
    }

    /// Create an empty validator set.
    pub fn empty() -> Self {
        Self {
            validators: Vec::new(),
            lookup: HashSet::new(),
        }
    }

    /// Get the number of validators.
    pub fn len(&self) -> usize {
        self.validators.len()
    }

    /// Check if the set is empty.
    pub fn is_empty(&self) -> bool {
        self.validators.is_empty()
    }

    /// Check if a sealer is a valid validator.
    pub fn contains(&self, sealer: &SealerId) -> bool {
        self.lookup.contains(sealer)
    }

    /// Get the leader for a given round (round-robin).
    ///
    /// Returns None if the set is empty.
    pub fn leader_for_round(&self, round: u64) -> Option<&SealerId> {
        if self.validators.is_empty() {
            return None;
        }
        let idx = (round as usize) % self.validators.len();
        Some(&self.validators[idx])
    }

    /// Get the leader for a given block height.
    ///
    /// This is the same as `leader_for_round` but more semantically clear
    /// when used in block production context.
    pub fn leader_for_height(&self, height: u64) -> Option<&SealerId> {
        self.leader_for_round(height)
    }

    /// Get validator at index.
    pub fn get(&self, index: usize) -> Option<&SealerId> {
        self.validators.get(index)
    }

    /// Get all validators.
    pub fn validators(&self) -> &[SealerId] {
        &self.validators
    }

    /// Iterator over validators.
    pub fn iter(&self) -> impl Iterator<Item = &SealerId> {
        self.validators.iter()
    }

    /// Add a validator to the set.
    ///
    /// Returns true if the validator was added, false if already present.
    pub fn add(&mut self, validator: SealerId) -> bool {
        if self.lookup.contains(&validator) {
            return false;
        }
        self.lookup.insert(validator.clone());
        self.validators.push(validator);
        true
    }

    /// Remove a validator from the set.
    ///
    /// Returns true if the validator was removed, false if not present.
    pub fn remove(&mut self, validator: &SealerId) -> bool {
        if !self.lookup.remove(validator) {
            return false;
        }
        self.validators.retain(|v| v != validator);
        true
    }

    /// Compute a commitment hash of the validator set.
    ///
    /// This can be included in block headers for validator set verification.
    pub fn commitment(&self) -> Hash {
        let mut data = Vec::new();
        for v in &self.validators {
            data.extend_from_slice(&v.as_pubkey().as_bytes());
        }
        moloch_core::hash(&data)
    }

    /// Check if this validator set has supermajority (2/3+) of another set.
    ///
    /// Used for validator set transitions.
    pub fn has_supermajority_of(&self, other: &ValidatorSet) -> bool {
        if other.is_empty() {
            return true;
        }
        let common = self
            .validators
            .iter()
            .filter(|v| other.contains(v))
            .count();
        // 2/3 majority
        common * 3 > other.len() * 2
    }

    /// Get the threshold for supermajority (2/3 + 1).
    pub fn supermajority_threshold(&self) -> usize {
        if self.validators.is_empty() {
            return 0;
        }
        (self.validators.len() * 2 / 3) + 1
    }

    /// Get the threshold for simple majority (1/2 + 1).
    pub fn majority_threshold(&self) -> usize {
        if self.validators.is_empty() {
            return 0;
        }
        (self.validators.len() / 2) + 1
    }
}

impl PartialEq for ValidatorSet {
    fn eq(&self, other: &Self) -> bool {
        self.validators == other.validators
    }
}

impl Eq for ValidatorSet {}

impl std::hash::Hash for ValidatorSet {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.validators.hash(state);
    }
}

/// A pending validator set change.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatorChange {
    /// The change type.
    pub kind: ValidatorChangeKind,
    /// The validator being added or removed.
    pub validator: SealerId,
    /// Height at which this change takes effect.
    pub effective_height: u64,
}

/// Type of validator set change.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ValidatorChangeKind {
    /// Add a new validator.
    Add,
    /// Remove an existing validator.
    Remove,
}

/// Evidence of validator misbehavior (for slashing).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlashingEvidence {
    /// The misbehaving validator.
    pub validator: SealerId,
    /// The type of misbehavior.
    pub kind: MisbehaviorKind,
    /// Height at which misbehavior occurred.
    pub height: u64,
    /// First conflicting block/vote.
    pub evidence_a: Vec<u8>,
    /// Second conflicting block/vote (for double-sign).
    pub evidence_b: Option<Vec<u8>>,
}

/// Types of validator misbehavior.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MisbehaviorKind {
    /// Signed two different blocks at the same height.
    DoubleSign,
    /// Produced block out of turn.
    OutOfTurn,
    /// Included invalid transaction.
    InvalidBlock,
}

#[cfg(test)]
mod tests {
    use super::*;
    use moloch_core::crypto::SecretKey;

    fn make_sealer() -> SealerId {
        let key = SecretKey::generate();
        SealerId::new(key.public_key())
    }

    #[test]
    fn test_validator_set_new() {
        let v1 = make_sealer();
        let v2 = make_sealer();
        let set = ValidatorSet::new(vec![v1.clone(), v2.clone()]);

        assert_eq!(set.len(), 2);
        assert!(set.contains(&v1));
        assert!(set.contains(&v2));
    }

    #[test]
    fn test_validator_set_empty() {
        let set = ValidatorSet::empty();
        assert!(set.is_empty());
        assert_eq!(set.len(), 0);
    }

    #[test]
    fn test_round_robin_leader() {
        let v1 = make_sealer();
        let v2 = make_sealer();
        let v3 = make_sealer();
        let set = ValidatorSet::new(vec![v1.clone(), v2.clone(), v3.clone()]);

        assert_eq!(set.leader_for_round(0), Some(&v1));
        assert_eq!(set.leader_for_round(1), Some(&v2));
        assert_eq!(set.leader_for_round(2), Some(&v3));
        assert_eq!(set.leader_for_round(3), Some(&v1)); // Wraps around
        assert_eq!(set.leader_for_round(4), Some(&v2));
    }

    #[test]
    fn test_leader_for_height() {
        let v1 = make_sealer();
        let v2 = make_sealer();
        let set = ValidatorSet::new(vec![v1.clone(), v2.clone()]);

        assert_eq!(set.leader_for_height(0), Some(&v1));
        assert_eq!(set.leader_for_height(1), Some(&v2));
        assert_eq!(set.leader_for_height(100), Some(&v1));
        assert_eq!(set.leader_for_height(101), Some(&v2));
    }

    #[test]
    fn test_add_validator() {
        let v1 = make_sealer();
        let v2 = make_sealer();
        let mut set = ValidatorSet::new(vec![v1.clone()]);

        assert!(!set.contains(&v2));
        assert!(set.add(v2.clone()));
        assert!(set.contains(&v2));
        assert_eq!(set.len(), 2);

        // Adding again returns false
        assert!(!set.add(v2));
    }

    #[test]
    fn test_remove_validator() {
        let v1 = make_sealer();
        let v2 = make_sealer();
        let mut set = ValidatorSet::new(vec![v1.clone(), v2.clone()]);

        assert!(set.remove(&v1));
        assert!(!set.contains(&v1));
        assert_eq!(set.len(), 1);

        // Removing again returns false
        assert!(!set.remove(&v1));
    }

    #[test]
    fn test_commitment_deterministic() {
        let v1 = make_sealer();
        let v2 = make_sealer();

        let set1 = ValidatorSet::new(vec![v1.clone(), v2.clone()]);
        let set2 = ValidatorSet::new(vec![v1.clone(), v2.clone()]);

        assert_eq!(set1.commitment(), set2.commitment());
    }

    #[test]
    fn test_commitment_order_matters() {
        let v1 = make_sealer();
        let v2 = make_sealer();

        let set1 = ValidatorSet::new(vec![v1.clone(), v2.clone()]);
        let set2 = ValidatorSet::new(vec![v2, v1]);

        assert_ne!(set1.commitment(), set2.commitment());
    }

    #[test]
    fn test_supermajority() {
        let validators: Vec<_> = (0..9).map(|_| make_sealer()).collect();
        let full_set = ValidatorSet::new(validators.clone());

        // 7 of 9 = 77% > 66%
        let partial = ValidatorSet::new(validators[0..7].to_vec());
        assert!(partial.has_supermajority_of(&full_set));

        // 6 of 9 = 66% = 66% (not strictly greater)
        let partial = ValidatorSet::new(validators[0..6].to_vec());
        assert!(!partial.has_supermajority_of(&full_set));

        // 5 of 9 = 55% < 66%
        let partial = ValidatorSet::new(validators[0..5].to_vec());
        assert!(!partial.has_supermajority_of(&full_set));
    }

    #[test]
    fn test_thresholds() {
        let validators: Vec<_> = (0..9).map(|_| make_sealer()).collect();
        let set = ValidatorSet::new(validators);

        // 9 validators: 2/3 + 1 = 6 + 1 = 7
        assert_eq!(set.supermajority_threshold(), 7);
        // 9 validators: 1/2 + 1 = 4 + 1 = 5
        assert_eq!(set.majority_threshold(), 5);
    }

    #[test]
    fn test_thresholds_small_set() {
        let v1 = make_sealer();
        let set = ValidatorSet::new(vec![v1]);

        assert_eq!(set.supermajority_threshold(), 1);
        assert_eq!(set.majority_threshold(), 1);
    }

    #[test]
    fn test_empty_set_no_leader() {
        let set = ValidatorSet::empty();
        assert!(set.leader_for_round(0).is_none());
        assert!(set.leader_for_height(100).is_none());
    }

    #[test]
    fn test_serde_roundtrip_rebuilds_lookup() {
        let v1 = make_sealer();
        let v2 = make_sealer();
        let v3 = make_sealer();
        let set = ValidatorSet::new(vec![v1.clone(), v2.clone(), v3.clone()]);

        // Serialize
        let bytes = bincode::serialize(&set).expect("serialize should work");

        // Deserialize
        let restored: ValidatorSet = bincode::deserialize(&bytes).expect("deserialize should work");

        // Verify lookup was rebuilt (contains() uses lookup)
        assert!(restored.contains(&v1));
        assert!(restored.contains(&v2));
        assert!(restored.contains(&v3));
        assert_eq!(restored.len(), 3);

        // Verify order preserved
        assert_eq!(restored.validators(), set.validators());
    }
}
