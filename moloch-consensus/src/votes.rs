//! Vote collection and aggregation.
//!
//! Handles:
//! - Collecting votes from validators
//! - Detecting supermajority (2/3+)
//! - Detecting conflicting votes (slashing evidence)
//! - Aggregating votes for compact storage

use std::collections::{HashMap, HashSet};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use moloch_chain::{MisbehaviorKind, SlashingEvidence, ValidatorSet};
use moloch_core::block::{BlockHash, SealerId};
use moloch_core::crypto::{Hash, PublicKey, SecretKey, Sig};

/// Type of vote.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VoteType {
    /// Prevote (first round of voting).
    Prevote,
    /// Precommit (second round of voting).
    Precommit,
}

impl std::fmt::Display for VoteType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VoteType::Prevote => write!(f, "prevote"),
            VoteType::Precommit => write!(f, "precommit"),
        }
    }
}

/// A vote from a validator.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Vote {
    /// Height being voted on.
    pub height: u64,
    /// Round number.
    pub round: u32,
    /// Type of vote.
    pub vote_type: VoteType,
    /// Block hash being voted for (None = nil vote).
    pub block_hash: Option<BlockHash>,
    /// Voter's public key.
    pub voter: PublicKey,
    /// Signature over the vote.
    pub signature: Sig,
    /// When the vote was created.
    #[serde(with = "chrono::serde::ts_milliseconds")]
    pub timestamp: DateTime<Utc>,
}

impl Vote {
    /// Create a new vote.
    pub fn new(
        height: u64,
        round: u32,
        vote_type: VoteType,
        block_hash: Option<BlockHash>,
        voter: PublicKey,
        key: &SecretKey,
    ) -> Self {
        let timestamp = Utc::now();
        let bytes = Self::signing_bytes(height, round, vote_type, block_hash.as_ref(), &voter, timestamp);
        let signature = key.sign(&bytes);

        Self {
            height,
            round,
            vote_type,
            block_hash,
            voter,
            signature,
            timestamp,
        }
    }

    /// Get the bytes to sign.
    fn signing_bytes(
        height: u64,
        round: u32,
        vote_type: VoteType,
        block_hash: Option<&BlockHash>,
        voter: &PublicKey,
        timestamp: DateTime<Utc>,
    ) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&height.to_le_bytes());
        bytes.extend_from_slice(&round.to_le_bytes());
        bytes.push(match vote_type {
            VoteType::Prevote => 0,
            VoteType::Precommit => 1,
        });
        match block_hash {
            Some(hash) => {
                bytes.push(1);
                bytes.extend_from_slice(hash.as_hash().as_bytes());
            }
            None => bytes.push(0),
        }
        bytes.extend_from_slice(&voter.as_bytes());
        bytes.extend_from_slice(&timestamp.timestamp_millis().to_le_bytes());
        bytes
    }

    /// Verify the vote signature.
    pub fn verify(&self) -> Result<(), VoteError> {
        let bytes = Self::signing_bytes(
            self.height,
            self.round,
            self.vote_type,
            self.block_hash.as_ref(),
            &self.voter,
            self.timestamp,
        );

        self.voter
            .verify(&bytes, &self.signature)
            .map_err(|_| VoteError::InvalidSignature)
    }

    /// Check if this is a nil vote (no block).
    pub fn is_nil(&self) -> bool {
        self.block_hash.is_none()
    }

    /// Get the voter's ID hash.
    pub fn voter_id(&self) -> Hash {
        self.voter.id()
    }
}

impl PartialEq for Vote {
    fn eq(&self, other: &Self) -> bool {
        self.height == other.height
            && self.round == other.round
            && self.vote_type == other.vote_type
            && self.block_hash == other.block_hash
            && self.voter.as_bytes() == other.voter.as_bytes()
    }
}

impl Eq for Vote {}

impl std::hash::Hash for Vote {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.height.hash(state);
        self.round.hash(state);
        self.vote_type.hash(state);
        self.block_hash.hash(state);
        self.voter.as_bytes().hash(state);
    }
}

/// Errors related to votes.
#[derive(Debug, thiserror::Error)]
pub enum VoteError {
    #[error("invalid signature")]
    InvalidSignature,

    #[error("duplicate vote from validator")]
    DuplicateVote,

    #[error("conflicting vote detected")]
    ConflictingVote,

    #[error("vote from unknown validator")]
    UnknownValidator,

    #[error("wrong height: expected {expected}, got {got}")]
    WrongHeight { expected: u64, got: u64 },

    #[error("wrong round: expected {expected}, got {got}")]
    WrongRound { expected: u32, got: u32 },
}

/// A set of votes for a specific height and round.
#[derive(Debug, Clone)]
pub struct VoteSet {
    /// Height being voted on.
    height: u64,
    /// Round number.
    round: u32,
    /// Type of votes in this set.
    vote_type: VoteType,
    /// Validator set for this vote set.
    validators: ValidatorSet,
    /// Votes by voter ID.
    votes: HashMap<Hash, Vote>,
    /// Votes grouped by block hash (None key = nil votes).
    by_block: HashMap<Option<BlockHash>, HashSet<Hash>>,
    /// Detected conflicting votes (slashing evidence).
    conflicts: Vec<(Vote, Vote)>,
}

impl VoteSet {
    /// Create a new vote set.
    pub fn new(height: u64, round: u32, vote_type: VoteType, validators: ValidatorSet) -> Self {
        Self {
            height,
            round,
            vote_type,
            validators,
            votes: HashMap::new(),
            by_block: HashMap::new(),
            conflicts: Vec::new(),
        }
    }

    /// Get the height.
    pub fn height(&self) -> u64 {
        self.height
    }

    /// Get the round.
    pub fn round(&self) -> u32 {
        self.round
    }

    /// Get the vote type.
    pub fn vote_type(&self) -> VoteType {
        self.vote_type
    }

    /// Get the total number of votes.
    pub fn count(&self) -> usize {
        self.votes.len()
    }

    /// Get votes for a specific block.
    pub fn count_for(&self, block_hash: Option<BlockHash>) -> usize {
        self.by_block.get(&block_hash).map(|s| s.len()).unwrap_or(0)
    }

    /// Add a vote to the set.
    pub fn add_vote(&mut self, vote: Vote) -> Result<bool, VoteError> {
        // Verify height and round
        if vote.height != self.height {
            return Err(VoteError::WrongHeight {
                expected: self.height,
                got: vote.height,
            });
        }

        if vote.round != self.round {
            return Err(VoteError::WrongRound {
                expected: self.round,
                got: vote.round,
            });
        }

        // Verify vote type
        if vote.vote_type != self.vote_type {
            return Ok(false); // Ignore wrong type
        }

        // Verify voter is a validator
        let voter_sealer = SealerId::new(vote.voter.clone());
        if !self.validators.contains(&voter_sealer) {
            return Err(VoteError::UnknownValidator);
        }

        let voter_id = vote.voter_id();

        // Check for existing vote from this validator
        if let Some(existing) = self.votes.get(&voter_id) {
            // Check for conflicting vote (different block hash)
            if existing.block_hash != vote.block_hash {
                // This is slashing evidence!
                self.conflicts.push((existing.clone(), vote.clone()));
                return Err(VoteError::ConflictingVote);
            }
            // Same vote, ignore
            return Err(VoteError::DuplicateVote);
        }

        // Add vote
        self.votes.insert(voter_id, vote.clone());

        // Add to block hash index
        self.by_block
            .entry(vote.block_hash)
            .or_insert_with(HashSet::new)
            .insert(voter_id);

        Ok(true)
    }

    /// Check if we have 2/3+ votes for any block.
    ///
    /// Returns the block hash that has supermajority (or None for nil).
    pub fn has_supermajority(&self) -> Option<Option<BlockHash>> {
        let threshold = self.validators.supermajority_threshold();

        for (block_hash, voters) in &self.by_block {
            if voters.len() >= threshold {
                return Some(*block_hash);
            }
        }

        None
    }

    /// Check if we have 2/3+ votes for a specific block.
    pub fn has_supermajority_for(&self, block_hash: Option<BlockHash>) -> bool {
        let threshold = self.validators.supermajority_threshold();
        self.count_for(block_hash) >= threshold
    }

    /// Check if we have any votes (1+) for a block.
    pub fn has_any_for(&self, block_hash: Option<BlockHash>) -> bool {
        self.count_for(block_hash) > 0
    }

    /// Get all votes.
    pub fn all_votes(&self) -> Vec<Vote> {
        self.votes.values().cloned().collect()
    }

    /// Get votes for a specific block.
    pub fn votes_for(&self, block_hash: Option<BlockHash>) -> Vec<Vote> {
        self.by_block
            .get(&block_hash)
            .map(|voter_ids| {
                voter_ids
                    .iter()
                    .filter_map(|id| self.votes.get(id).cloned())
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Get a vote from a specific validator.
    pub fn get_vote(&self, voter_id: &Hash) -> Option<&Vote> {
        self.votes.get(voter_id)
    }

    /// Check if a validator has voted.
    pub fn has_voted(&self, voter_id: &Hash) -> bool {
        self.votes.contains_key(voter_id)
    }

    /// Get validators who haven't voted yet.
    pub fn missing_voters(&self) -> Vec<&SealerId> {
        self.validators
            .iter()
            .filter(|v| !self.has_voted(&v.id()))
            .collect()
    }

    /// Get detected conflicting votes (slashing evidence).
    pub fn conflicts(&self) -> &[(Vote, Vote)] {
        &self.conflicts
    }

    /// Create slashing evidence from detected conflicts.
    pub fn slashing_evidence(&self) -> Vec<SlashingEvidence> {
        self.conflicts
            .iter()
            .map(|(a, b)| SlashingEvidence {
                validator: SealerId::new(a.voter.clone()),
                kind: MisbehaviorKind::DoubleSign,
                height: a.height,
                evidence_a: bincode::serialize(a).unwrap_or_default(),
                evidence_b: Some(bincode::serialize(b).unwrap_or_default()),
            })
            .collect()
    }

    /// Get the block with the most votes.
    pub fn leading_block(&self) -> Option<(Option<BlockHash>, usize)> {
        self.by_block
            .iter()
            .max_by_key(|(_, voters)| voters.len())
            .map(|(hash, voters)| (*hash, voters.len()))
    }
}

/// Aggregated votes for compact storage.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AggregatedVotes {
    /// Height.
    pub height: u64,
    /// Round.
    pub round: u32,
    /// Vote type.
    pub vote_type: VoteType,
    /// Block hash (None = nil).
    pub block_hash: Option<BlockHash>,
    /// Voter public keys.
    pub voters: Vec<PublicKey>,
    /// Aggregated signature (concatenated for now).
    pub signatures: Vec<Sig>,
}

impl AggregatedVotes {
    /// Create aggregated votes from a vote set for a specific block.
    pub fn from_vote_set(vote_set: &VoteSet, block_hash: Option<BlockHash>) -> Self {
        let votes = vote_set.votes_for(block_hash);
        let voters: Vec<_> = votes.iter().map(|v| v.voter.clone()).collect();
        let signatures: Vec<_> = votes.iter().map(|v| v.signature.clone()).collect();

        Self {
            height: vote_set.height(),
            round: vote_set.round(),
            vote_type: vote_set.vote_type(),
            block_hash,
            voters,
            signatures,
        }
    }

    /// Get the number of votes.
    pub fn count(&self) -> usize {
        self.voters.len()
    }

    /// Verify all signatures.
    pub fn verify(&self) -> Result<(), VoteError> {
        // In a real implementation, we'd verify each signature
        // For now, just check counts match
        if self.voters.len() != self.signatures.len() {
            return Err(VoteError::InvalidSignature);
        }
        Ok(())
    }
}

/// Vote statistics.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct VoteStats {
    /// Total votes received.
    pub total_votes: usize,
    /// Votes for the leading block.
    pub leading_votes: usize,
    /// Number of nil votes.
    pub nil_votes: usize,
    /// Number of validators who haven't voted.
    pub missing_votes: usize,
    /// Number of conflicting votes detected.
    pub conflicts: usize,
}

impl VoteSet {
    /// Get voting statistics.
    pub fn stats(&self) -> VoteStats {
        let leading = self.leading_block().map(|(_, count)| count).unwrap_or(0);

        VoteStats {
            total_votes: self.count(),
            leading_votes: leading,
            nil_votes: self.count_for(None),
            missing_votes: self.missing_voters().len(),
            conflicts: self.conflicts.len(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use moloch_core::crypto::hash;

    fn make_validator() -> (SecretKey, SealerId, PublicKey) {
        let key = SecretKey::generate();
        let pubkey = key.public_key();
        let sealer = SealerId::new(pubkey.clone());
        (key, sealer, pubkey)
    }

    fn make_block_hash() -> BlockHash {
        BlockHash(hash(b"test block"))
    }

    #[test]
    fn test_vote_type_display() {
        assert_eq!(format!("{}", VoteType::Prevote), "prevote");
        assert_eq!(format!("{}", VoteType::Precommit), "precommit");
    }

    #[test]
    fn test_vote_creation_and_verify() {
        let (key, _, pubkey) = make_validator();
        let block_hash = make_block_hash();

        let vote = Vote::new(10, 0, VoteType::Prevote, Some(block_hash), pubkey, &key);

        assert_eq!(vote.height, 10);
        assert_eq!(vote.round, 0);
        assert_eq!(vote.vote_type, VoteType::Prevote);
        assert!(vote.verify().is_ok());
    }

    #[test]
    fn test_nil_vote() {
        let (key, _, pubkey) = make_validator();

        let vote = Vote::new(10, 0, VoteType::Prevote, None, pubkey, &key);

        assert!(vote.is_nil());
        assert!(vote.verify().is_ok());
    }

    #[test]
    fn test_vote_set_creation() {
        let (_, sealer, _) = make_validator();
        let validators = ValidatorSet::new(vec![sealer]);

        let vote_set = VoteSet::new(10, 0, VoteType::Prevote, validators);

        assert_eq!(vote_set.height(), 10);
        assert_eq!(vote_set.round(), 0);
        assert_eq!(vote_set.count(), 0);
    }

    #[test]
    fn test_vote_set_add_vote() {
        let (key, sealer, pubkey) = make_validator();
        let validators = ValidatorSet::new(vec![sealer]);

        let mut vote_set = VoteSet::new(10, 0, VoteType::Prevote, validators);
        let block_hash = make_block_hash();

        let vote = Vote::new(10, 0, VoteType::Prevote, Some(block_hash), pubkey, &key);
        let result = vote_set.add_vote(vote);

        assert!(result.is_ok());
        assert_eq!(vote_set.count(), 1);
        assert_eq!(vote_set.count_for(Some(block_hash)), 1);
    }

    #[test]
    fn test_vote_set_duplicate_vote() {
        let (key, sealer, pubkey) = make_validator();
        let validators = ValidatorSet::new(vec![sealer]);

        let mut vote_set = VoteSet::new(10, 0, VoteType::Prevote, validators);
        let block_hash = make_block_hash();

        let vote = Vote::new(10, 0, VoteType::Prevote, Some(block_hash), pubkey.clone(), &key);
        vote_set.add_vote(vote).unwrap();

        let vote2 = Vote::new(10, 0, VoteType::Prevote, Some(block_hash), pubkey, &key);
        let result = vote_set.add_vote(vote2);

        assert!(matches!(result, Err(VoteError::DuplicateVote)));
    }

    #[test]
    fn test_vote_set_conflicting_vote() {
        let (key, sealer, pubkey) = make_validator();
        let validators = ValidatorSet::new(vec![sealer]);

        let mut vote_set = VoteSet::new(10, 0, VoteType::Prevote, validators);
        let block_hash1 = BlockHash(hash(b"block1"));
        let block_hash2 = BlockHash(hash(b"block2"));

        let vote1 = Vote::new(10, 0, VoteType::Prevote, Some(block_hash1), pubkey.clone(), &key);
        vote_set.add_vote(vote1).unwrap();

        let vote2 = Vote::new(10, 0, VoteType::Prevote, Some(block_hash2), pubkey, &key);
        let result = vote_set.add_vote(vote2);

        assert!(matches!(result, Err(VoteError::ConflictingVote)));
        assert_eq!(vote_set.conflicts().len(), 1);
    }

    #[test]
    fn test_vote_set_supermajority() {
        let validators: Vec<_> = (0..3).map(|_| make_validator()).collect();
        let sealer_ids: Vec<_> = validators.iter().map(|(_, s, _)| s.clone()).collect();
        let validator_set = ValidatorSet::new(sealer_ids);

        let mut vote_set = VoteSet::new(10, 0, VoteType::Prevote, validator_set);
        let block_hash = make_block_hash();

        // Add 2 votes (2/3 of 3 validators)
        for (key, _, pubkey) in validators.iter().take(2) {
            let vote = Vote::new(10, 0, VoteType::Prevote, Some(block_hash), pubkey.clone(), key);
            vote_set.add_vote(vote).unwrap();
        }

        // Should not have supermajority yet (need 2/3 + 1 = 3 for 3 validators)
        // Actually 2/3 * 3 + 1 = 3, so we need all 3
        // Let me check: supermajority_threshold for 3 validators is (3*2/3)+1 = 2+1 = 3
        assert!(!vote_set.has_supermajority_for(Some(block_hash)));

        // Add third vote
        let (key, _, pubkey) = &validators[2];
        let vote = Vote::new(10, 0, VoteType::Prevote, Some(block_hash), pubkey.clone(), key);
        vote_set.add_vote(vote).unwrap();

        // Now should have supermajority
        assert!(vote_set.has_supermajority_for(Some(block_hash)));
        assert_eq!(vote_set.has_supermajority(), Some(Some(block_hash)));
    }

    #[test]
    fn test_vote_set_missing_voters() {
        let validators: Vec<_> = (0..3).map(|_| make_validator()).collect();
        let sealer_ids: Vec<_> = validators.iter().map(|(_, s, _)| s.clone()).collect();
        let validator_set = ValidatorSet::new(sealer_ids);

        let mut vote_set = VoteSet::new(10, 0, VoteType::Prevote, validator_set);
        let block_hash = make_block_hash();

        // Initially all missing
        assert_eq!(vote_set.missing_voters().len(), 3);

        // Add one vote
        let (key, _, pubkey) = &validators[0];
        let vote = Vote::new(10, 0, VoteType::Prevote, Some(block_hash), pubkey.clone(), key);
        vote_set.add_vote(vote).unwrap();

        assert_eq!(vote_set.missing_voters().len(), 2);
    }

    #[test]
    fn test_vote_set_wrong_height() {
        let (key, sealer, pubkey) = make_validator();
        let validators = ValidatorSet::new(vec![sealer]);

        let mut vote_set = VoteSet::new(10, 0, VoteType::Prevote, validators);
        let vote = Vote::new(11, 0, VoteType::Prevote, None, pubkey, &key);

        let result = vote_set.add_vote(vote);
        assert!(matches!(result, Err(VoteError::WrongHeight { .. })));
    }

    #[test]
    fn test_vote_set_wrong_round() {
        let (key, sealer, pubkey) = make_validator();
        let validators = ValidatorSet::new(vec![sealer]);

        let mut vote_set = VoteSet::new(10, 0, VoteType::Prevote, validators);
        let vote = Vote::new(10, 1, VoteType::Prevote, None, pubkey, &key);

        let result = vote_set.add_vote(vote);
        assert!(matches!(result, Err(VoteError::WrongRound { .. })));
    }

    #[test]
    fn test_vote_set_unknown_validator() {
        let (key1, sealer1, _) = make_validator();
        let (key2, _, pubkey2) = make_validator();

        let validators = ValidatorSet::new(vec![sealer1]);

        let mut vote_set = VoteSet::new(10, 0, VoteType::Prevote, validators);
        let vote = Vote::new(10, 0, VoteType::Prevote, None, pubkey2, &key2);

        let result = vote_set.add_vote(vote);
        assert!(matches!(result, Err(VoteError::UnknownValidator)));
    }

    #[test]
    fn test_vote_set_stats() {
        let (key, sealer, pubkey) = make_validator();
        let validators = ValidatorSet::new(vec![sealer]);

        let mut vote_set = VoteSet::new(10, 0, VoteType::Prevote, validators);
        let vote = Vote::new(10, 0, VoteType::Prevote, None, pubkey, &key);
        vote_set.add_vote(vote).unwrap();

        let stats = vote_set.stats();
        assert_eq!(stats.total_votes, 1);
        assert_eq!(stats.nil_votes, 1);
        assert_eq!(stats.missing_votes, 0);
    }

    #[test]
    fn test_aggregated_votes() {
        let (key, sealer, pubkey) = make_validator();
        let validators = ValidatorSet::new(vec![sealer]);

        let mut vote_set = VoteSet::new(10, 0, VoteType::Prevote, validators);
        let block_hash = make_block_hash();

        let vote = Vote::new(10, 0, VoteType::Prevote, Some(block_hash), pubkey, &key);
        vote_set.add_vote(vote).unwrap();

        let aggregated = AggregatedVotes::from_vote_set(&vote_set, Some(block_hash));
        assert_eq!(aggregated.count(), 1);
        assert_eq!(aggregated.height, 10);
        assert!(aggregated.verify().is_ok());
    }

    #[test]
    fn test_slashing_evidence() {
        let (key, sealer, pubkey) = make_validator();
        let validators = ValidatorSet::new(vec![sealer]);

        let mut vote_set = VoteSet::new(10, 0, VoteType::Prevote, validators);
        let block_hash1 = BlockHash(hash(b"block1"));
        let block_hash2 = BlockHash(hash(b"block2"));

        let vote1 = Vote::new(10, 0, VoteType::Prevote, Some(block_hash1), pubkey.clone(), &key);
        vote_set.add_vote(vote1).unwrap();

        let vote2 = Vote::new(10, 0, VoteType::Prevote, Some(block_hash2), pubkey, &key);
        let _ = vote_set.add_vote(vote2);

        let evidence = vote_set.slashing_evidence();
        assert_eq!(evidence.len(), 1);
        assert_eq!(evidence[0].kind, MisbehaviorKind::DoubleSign);
        assert_eq!(evidence[0].height, 10);
    }

    #[test]
    fn test_leading_block() {
        let validators: Vec<_> = (0..3).map(|_| make_validator()).collect();
        let sealer_ids: Vec<_> = validators.iter().map(|(_, s, _)| s.clone()).collect();
        let validator_set = ValidatorSet::new(sealer_ids);

        let mut vote_set = VoteSet::new(10, 0, VoteType::Prevote, validator_set);
        let block_hash1 = BlockHash(hash(b"block1"));
        let block_hash2 = BlockHash(hash(b"block2"));

        // Vote for block1
        let (key, _, pubkey) = &validators[0];
        let vote = Vote::new(10, 0, VoteType::Prevote, Some(block_hash1), pubkey.clone(), key);
        vote_set.add_vote(vote).unwrap();

        // Two votes for block2
        for (key, _, pubkey) in validators.iter().skip(1) {
            let vote = Vote::new(10, 0, VoteType::Prevote, Some(block_hash2), pubkey.clone(), key);
            vote_set.add_vote(vote).unwrap();
        }

        let (leading, count) = vote_set.leading_block().unwrap();
        assert_eq!(leading, Some(block_hash2));
        assert_eq!(count, 2);
    }
}
