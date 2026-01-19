//! Finality tracking and proofs.
//!
//! Handles:
//! - Tracking finalized vs tentative blocks
//! - Generating finality proofs for light clients
//! - Finality notifications
//! - Finality lag monitoring

use std::collections::{HashMap, VecDeque};
use std::sync::Arc;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

use moloch_chain::ValidatorSet;
use moloch_core::block::{BlockHash, BlockHeader, SealerId};
use moloch_core::crypto::{Hash, PublicKey, Sig};

use crate::votes::{AggregatedVotes, Vote, VoteType};

/// Status of a block's finality.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FinalityStatus {
    /// Block is tentative (may be reverted).
    Tentative,
    /// Block is finalized (cannot be reverted).
    Finalized,
    /// Block has been orphaned (different chain finalized).
    Orphaned,
}

impl std::fmt::Display for FinalityStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FinalityStatus::Tentative => write!(f, "tentative"),
            FinalityStatus::Finalized => write!(f, "finalized"),
            FinalityStatus::Orphaned => write!(f, "orphaned"),
        }
    }
}

/// A finality proof for a block.
///
/// Contains the aggregated precommit votes that prove 2/3+ validators
/// agreed on this block. Used by light clients to verify finality
/// without replaying the full consensus.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FinalityProof {
    /// Height of the finalized block.
    pub height: u64,
    /// Hash of the finalized block.
    pub block_hash: BlockHash,
    /// Round in which finality was achieved.
    pub round: u32,
    /// Aggregated precommit votes.
    pub votes: AggregatedVotes,
    /// When finality was achieved.
    #[serde(with = "chrono::serde::ts_milliseconds")]
    pub finalized_at: DateTime<Utc>,
}

impl FinalityProof {
    /// Create a new finality proof from precommit votes.
    pub fn new(
        height: u64,
        block_hash: BlockHash,
        round: u32,
        votes: Vec<Vote>,
    ) -> Self {
        let voters: Vec<_> = votes.iter().map(|v| v.voter.clone()).collect();
        let signatures: Vec<_> = votes.iter().map(|v| v.signature.clone()).collect();

        Self {
            height,
            block_hash,
            round,
            votes: AggregatedVotes {
                height,
                round,
                vote_type: VoteType::Precommit,
                block_hash: Some(block_hash),
                voters,
                signatures,
            },
            finalized_at: Utc::now(),
        }
    }

    /// Verify the finality proof against a validator set.
    pub fn verify(&self, validators: &ValidatorSet) -> Result<(), FinalityError> {
        // Check vote count meets supermajority
        let threshold = validators.supermajority_threshold();
        if self.votes.count() < threshold {
            return Err(FinalityError::InsufficientVotes {
                have: self.votes.count(),
                need: threshold,
            });
        }

        // Verify all voters are validators
        for voter in &self.votes.voters {
            let sealer = SealerId::new(voter.clone());
            if !validators.contains(&sealer) {
                return Err(FinalityError::InvalidValidator(voter.id()));
            }
        }

        // Verify vote metadata matches
        if self.votes.height != self.height {
            return Err(FinalityError::HeightMismatch {
                proof: self.height,
                votes: self.votes.height,
            });
        }

        if self.votes.round != self.round {
            return Err(FinalityError::RoundMismatch {
                proof: self.round,
                votes: self.votes.round,
            });
        }

        if self.votes.block_hash != Some(self.block_hash) {
            return Err(FinalityError::HashMismatch);
        }

        // In production, we'd verify signatures here
        self.votes.verify()
            .map_err(|_| FinalityError::InvalidSignature)?;

        Ok(())
    }

    /// Get the number of votes in this proof.
    pub fn vote_count(&self) -> usize {
        self.votes.count()
    }

    /// Get the voting validators.
    pub fn voters(&self) -> &[PublicKey] {
        &self.votes.voters
    }
}

/// Errors related to finality.
#[derive(Debug, thiserror::Error)]
pub enum FinalityError {
    #[error("insufficient votes: have {have}, need {need}")]
    InsufficientVotes { have: usize, need: usize },

    #[error("invalid validator: {0:?}")]
    InvalidValidator(Hash),

    #[error("height mismatch: proof {proof}, votes {votes}")]
    HeightMismatch { proof: u64, votes: u64 },

    #[error("round mismatch: proof {proof}, votes {votes}")]
    RoundMismatch { proof: u32, votes: u32 },

    #[error("block hash mismatch")]
    HashMismatch,

    #[error("invalid signature")]
    InvalidSignature,

    #[error("block not found: {0:?}")]
    BlockNotFound(BlockHash),

    #[error("finality already exists for height {0}")]
    AlreadyFinalized(u64),

    #[error("finality gap: expected height {expected}, got {got}")]
    FinalityGap { expected: u64, got: u64 },
}

/// Configuration for the finality gadget.
#[derive(Debug, Clone)]
pub struct FinalityConfig {
    /// Maximum number of finality proofs to keep in memory.
    pub max_proofs_in_memory: usize,
    /// Maximum finality lag before warning.
    pub max_finality_lag: u64,
    /// Enable finality notifications.
    pub enable_notifications: bool,
}

impl Default for FinalityConfig {
    fn default() -> Self {
        Self {
            max_proofs_in_memory: 1000,
            max_finality_lag: 10,
            enable_notifications: true,
        }
    }
}

/// A finality notification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FinalityNotification {
    /// Height that was finalized.
    pub height: u64,
    /// Hash of the finalized block.
    pub block_hash: BlockHash,
    /// Round in which finality was achieved.
    pub round: u32,
    /// Number of validators that voted.
    pub vote_count: usize,
    /// When finality was achieved.
    #[serde(with = "chrono::serde::ts_milliseconds")]
    pub finalized_at: DateTime<Utc>,
}

impl From<&FinalityProof> for FinalityNotification {
    fn from(proof: &FinalityProof) -> Self {
        Self {
            height: proof.height,
            block_hash: proof.block_hash,
            round: proof.round,
            vote_count: proof.vote_count(),
            finalized_at: proof.finalized_at,
        }
    }
}

/// Finality gadget for tracking and proving finality.
pub struct FinalityGadget {
    /// Configuration.
    config: FinalityConfig,
    /// Last finalized height.
    last_finalized: RwLock<u64>,
    /// Last finalized block hash.
    last_finalized_hash: RwLock<Option<BlockHash>>,
    /// Finality proofs by height.
    proofs: RwLock<HashMap<u64, FinalityProof>>,
    /// Recent proofs for quick access (FIFO).
    recent_proofs: RwLock<VecDeque<u64>>,
    /// Pending notifications.
    notifications: RwLock<VecDeque<FinalityNotification>>,
    /// Block status cache.
    status_cache: RwLock<HashMap<BlockHash, FinalityStatus>>,
}

impl FinalityGadget {
    /// Create a new finality gadget.
    pub fn new(config: FinalityConfig, genesis_height: u64) -> Self {
        Self {
            config,
            last_finalized: RwLock::new(genesis_height),
            last_finalized_hash: RwLock::new(None),
            proofs: RwLock::new(HashMap::new()),
            recent_proofs: RwLock::new(VecDeque::new()),
            notifications: RwLock::new(VecDeque::new()),
            status_cache: RwLock::new(HashMap::new()),
        }
    }

    /// Create with default config.
    pub fn with_default_config(genesis_height: u64) -> Self {
        Self::new(FinalityConfig::default(), genesis_height)
    }

    /// Get the last finalized height.
    pub async fn last_finalized_height(&self) -> u64 {
        *self.last_finalized.read().await
    }

    /// Get the last finalized block hash.
    pub async fn last_finalized_hash(&self) -> Option<BlockHash> {
        *self.last_finalized_hash.read().await
    }

    /// Record finality for a block.
    ///
    /// Creates a finality proof from the precommit votes and updates state.
    pub async fn record_finality(
        &self,
        height: u64,
        block_hash: BlockHash,
        round: u32,
        votes: Vec<Vote>,
        validators: &ValidatorSet,
    ) -> Result<FinalityProof, FinalityError> {
        // Check for duplicate finality first
        let proofs = self.proofs.read().await;
        if proofs.contains_key(&height) {
            return Err(FinalityError::AlreadyFinalized(height));
        }
        drop(proofs);

        let mut last_finalized = self.last_finalized.write().await;

        // Check for finality gap (must finalize sequentially)
        if height != *last_finalized + 1 {
            return Err(FinalityError::FinalityGap {
                expected: *last_finalized + 1,
                got: height,
            });
        }

        // Verify supermajority
        let threshold = validators.supermajority_threshold();
        if votes.len() < threshold {
            return Err(FinalityError::InsufficientVotes {
                have: votes.len(),
                need: threshold,
            });
        }

        // Create proof
        let proof = FinalityProof::new(height, block_hash, round, votes);

        // Verify the proof
        proof.verify(validators)?;

        // Store proof
        let mut proofs = self.proofs.write().await;
        let mut recent = self.recent_proofs.write().await;

        proofs.insert(height, proof.clone());
        recent.push_back(height);

        // Prune old proofs if needed
        while recent.len() > self.config.max_proofs_in_memory {
            if let Some(old_height) = recent.pop_front() {
                proofs.remove(&old_height);
            }
        }

        // Update state
        *last_finalized = height;
        *self.last_finalized_hash.write().await = Some(block_hash);

        // Update status cache
        self.status_cache.write().await.insert(block_hash, FinalityStatus::Finalized);

        // Create notification
        if self.config.enable_notifications {
            let notification = FinalityNotification::from(&proof);
            self.notifications.write().await.push_back(notification);
        }

        info!(
            "Block finalized: height={}, hash={:?}, round={}, votes={}",
            height, block_hash, round, proof.vote_count()
        );

        Ok(proof)
    }

    /// Get the finality proof for a height.
    pub async fn get_proof(&self, height: u64) -> Option<FinalityProof> {
        self.proofs.read().await.get(&height).cloned()
    }

    /// Check if a height is finalized.
    pub async fn is_finalized(&self, height: u64) -> bool {
        height <= *self.last_finalized.read().await
    }

    /// Get the finality status of a block.
    pub async fn status(&self, block_hash: &BlockHash) -> FinalityStatus {
        self.status_cache
            .read()
            .await
            .get(block_hash)
            .copied()
            .unwrap_or(FinalityStatus::Tentative)
    }

    /// Mark a block as orphaned.
    pub async fn mark_orphaned(&self, block_hash: BlockHash) {
        self.status_cache.write().await.insert(block_hash, FinalityStatus::Orphaned);
    }

    /// Get pending finality notifications.
    pub async fn drain_notifications(&self) -> Vec<FinalityNotification> {
        self.notifications.write().await.drain(..).collect()
    }

    /// Get the finality lag (difference between tip and last finalized).
    pub async fn finality_lag(&self, tip_height: u64) -> u64 {
        let last = *self.last_finalized.read().await;
        tip_height.saturating_sub(last)
    }

    /// Check if finality lag is within acceptable bounds.
    pub async fn is_healthy(&self, tip_height: u64) -> bool {
        self.finality_lag(tip_height).await <= self.config.max_finality_lag
    }

    /// Get finality statistics.
    pub async fn stats(&self) -> FinalityStats {
        let last_finalized = *self.last_finalized.read().await;
        let proofs = self.proofs.read().await;
        let notifications = self.notifications.read().await;

        FinalityStats {
            last_finalized_height: last_finalized,
            proofs_in_memory: proofs.len(),
            pending_notifications: notifications.len(),
        }
    }

    /// Verify a finality proof from an external source.
    pub fn verify_proof(
        &self,
        proof: &FinalityProof,
        validators: &ValidatorSet,
    ) -> Result<(), FinalityError> {
        proof.verify(validators)
    }

    /// Get proofs in a height range (inclusive).
    pub async fn get_proofs_range(&self, from: u64, to: u64) -> Vec<FinalityProof> {
        let proofs = self.proofs.read().await;
        (from..=to)
            .filter_map(|h| proofs.get(&h).cloned())
            .collect()
    }
}

/// Finality statistics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FinalityStats {
    /// Last finalized height.
    pub last_finalized_height: u64,
    /// Number of proofs in memory.
    pub proofs_in_memory: usize,
    /// Number of pending notifications.
    pub pending_notifications: usize,
}

/// Builder for finality proofs (for testing and serialization).
#[derive(Debug, Clone)]
pub struct FinalityProofBuilder {
    height: u64,
    block_hash: BlockHash,
    round: u32,
    votes: Vec<Vote>,
}

impl FinalityProofBuilder {
    /// Create a new builder.
    pub fn new(height: u64, block_hash: BlockHash) -> Self {
        Self {
            height,
            block_hash,
            round: 0,
            votes: Vec::new(),
        }
    }

    /// Set the round.
    pub fn round(mut self, round: u32) -> Self {
        self.round = round;
        self
    }

    /// Add a vote.
    pub fn vote(mut self, vote: Vote) -> Self {
        self.votes.push(vote);
        self
    }

    /// Add multiple votes.
    pub fn votes(mut self, votes: Vec<Vote>) -> Self {
        self.votes.extend(votes);
        self
    }

    /// Build the finality proof.
    pub fn build(self) -> FinalityProof {
        FinalityProof::new(self.height, self.block_hash, self.round, self.votes)
    }
}

/// Finality proof serialization for compact storage.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompactFinalityProof {
    /// Height of the finalized block.
    pub height: u64,
    /// Hash of the finalized block (32 bytes).
    pub block_hash: [u8; 32],
    /// Round in which finality was achieved.
    pub round: u32,
    /// Voter indices in the validator set.
    pub voter_indices: Vec<u16>,
    /// Concatenated signatures.
    pub signatures: Vec<u8>,
    /// Timestamp (millis since epoch).
    pub finalized_at_ms: i64,
}

impl CompactFinalityProof {
    /// Create from a full finality proof and validator set.
    pub fn from_proof(proof: &FinalityProof, validators: &ValidatorSet) -> Self {
        let voter_indices: Vec<u16> = proof
            .votes
            .voters
            .iter()
            .filter_map(|v| {
                let sealer = SealerId::new(v.clone());
                validators.iter().position(|s| s == &sealer).map(|i| i as u16)
            })
            .collect();

        let signatures: Vec<u8> = proof
            .votes
            .signatures
            .iter()
            .flat_map(|s| s.to_bytes().to_vec())
            .collect();

        Self {
            height: proof.height,
            block_hash: *proof.block_hash.as_hash().as_bytes(),
            round: proof.round,
            voter_indices,
            signatures,
            finalized_at_ms: proof.finalized_at.timestamp_millis(),
        }
    }

    /// Convert back to full proof with validator set.
    pub fn to_proof(&self, validators: &ValidatorSet) -> Option<FinalityProof> {
        let voters: Vec<PublicKey> = self
            .voter_indices
            .iter()
            .filter_map(|&i| validators.iter().nth(i as usize))
            .map(|s| s.as_pubkey().clone())
            .collect();

        if voters.len() != self.voter_indices.len() {
            return None;
        }

        // Reconstruct signatures (assuming 64-byte signatures)
        let sig_size = 64;
        let signatures: Vec<Sig> = self
            .signatures
            .chunks(sig_size)
            .filter_map(|chunk| {
                if chunk.len() == sig_size {
                    let arr: [u8; 64] = chunk.try_into().ok()?;
                    Sig::from_bytes(&arr).ok()
                } else {
                    None
                }
            })
            .collect();

        if signatures.len() != voters.len() {
            return None;
        }

        Some(FinalityProof {
            height: self.height,
            block_hash: BlockHash(Hash::from_bytes(self.block_hash)),
            round: self.round,
            votes: AggregatedVotes {
                height: self.height,
                round: self.round,
                vote_type: VoteType::Precommit,
                block_hash: Some(BlockHash(Hash::from_bytes(self.block_hash))),
                voters,
                signatures,
            },
            finalized_at: DateTime::from_timestamp(
                self.finalized_at_ms / 1000,
                ((self.finalized_at_ms % 1000) * 1_000_000) as u32,
            )
            .unwrap_or_else(Utc::now),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use moloch_core::crypto::{hash, SecretKey};

    fn make_validator() -> (SecretKey, SealerId, PublicKey) {
        let key = SecretKey::generate();
        let pubkey = key.public_key();
        let sealer = SealerId::new(pubkey.clone());
        (key, sealer, pubkey)
    }

    fn make_block_hash() -> BlockHash {
        BlockHash(hash(b"test block"))
    }

    fn make_vote(key: &SecretKey, pubkey: &PublicKey, height: u64, round: u32, block_hash: BlockHash) -> Vote {
        Vote::new(height, round, VoteType::Precommit, Some(block_hash), pubkey.clone(), key)
    }

    #[test]
    fn test_finality_status_display() {
        assert_eq!(format!("{}", FinalityStatus::Tentative), "tentative");
        assert_eq!(format!("{}", FinalityStatus::Finalized), "finalized");
        assert_eq!(format!("{}", FinalityStatus::Orphaned), "orphaned");
    }

    #[test]
    fn test_finality_proof_creation() {
        let (key, _, pubkey) = make_validator();
        let block_hash = make_block_hash();
        let vote = make_vote(&key, &pubkey, 1, 0, block_hash);

        let proof = FinalityProof::new(1, block_hash, 0, vec![vote]);

        assert_eq!(proof.height, 1);
        assert_eq!(proof.round, 0);
        assert_eq!(proof.block_hash, block_hash);
        assert_eq!(proof.vote_count(), 1);
    }

    #[test]
    fn test_finality_proof_verify_valid() {
        let (key, sealer, pubkey) = make_validator();
        let validators = ValidatorSet::new(vec![sealer]);
        let block_hash = make_block_hash();
        let vote = make_vote(&key, &pubkey, 1, 0, block_hash);

        let proof = FinalityProof::new(1, block_hash, 0, vec![vote]);

        // With 1 validator, threshold is 1, so this should pass
        assert!(proof.verify(&validators).is_ok());
    }

    #[test]
    fn test_finality_proof_verify_insufficient_votes() {
        let validators_data: Vec<_> = (0..3).map(|_| make_validator()).collect();
        let sealers: Vec<_> = validators_data.iter().map(|(_, s, _)| s.clone()).collect();
        let validators = ValidatorSet::new(sealers);

        let (key, _, pubkey) = &validators_data[0];
        let block_hash = make_block_hash();
        let vote = make_vote(key, pubkey, 1, 0, block_hash);

        let proof = FinalityProof::new(1, block_hash, 0, vec![vote]);

        // With 3 validators, threshold is 3, so 1 vote is insufficient
        let result = proof.verify(&validators);
        assert!(matches!(result, Err(FinalityError::InsufficientVotes { .. })));
    }

    #[test]
    fn test_finality_proof_verify_invalid_validator() {
        let (key1, sealer1, _) = make_validator();
        let (key2, _, pubkey2) = make_validator();

        let validators = ValidatorSet::new(vec![sealer1]);
        let block_hash = make_block_hash();

        // Vote from unknown validator
        let vote = make_vote(&key2, &pubkey2, 1, 0, block_hash);
        let proof = FinalityProof::new(1, block_hash, 0, vec![vote]);

        let result = proof.verify(&validators);
        assert!(matches!(result, Err(FinalityError::InvalidValidator(_))));
    }

    #[test]
    fn test_finality_proof_builder() {
        let (key, _, pubkey) = make_validator();
        let block_hash = make_block_hash();
        let vote = make_vote(&key, &pubkey, 5, 2, block_hash);

        let proof = FinalityProofBuilder::new(5, block_hash)
            .round(2)
            .vote(vote)
            .build();

        assert_eq!(proof.height, 5);
        assert_eq!(proof.round, 2);
        assert_eq!(proof.vote_count(), 1);
    }

    #[tokio::test]
    async fn test_finality_gadget_creation() {
        let gadget = FinalityGadget::with_default_config(0);

        assert_eq!(gadget.last_finalized_height().await, 0);
        assert!(gadget.last_finalized_hash().await.is_none());
    }

    #[tokio::test]
    async fn test_finality_gadget_record_finality() {
        let (key, sealer, pubkey) = make_validator();
        let validators = ValidatorSet::new(vec![sealer]);
        let gadget = FinalityGadget::with_default_config(0);

        let block_hash = make_block_hash();
        let vote = make_vote(&key, &pubkey, 1, 0, block_hash);

        let result = gadget.record_finality(1, block_hash, 0, vec![vote], &validators).await;
        assert!(result.is_ok());

        assert_eq!(gadget.last_finalized_height().await, 1);
        assert_eq!(gadget.last_finalized_hash().await, Some(block_hash));
        assert!(gadget.is_finalized(1).await);
    }

    #[tokio::test]
    async fn test_finality_gadget_finality_gap() {
        let (key, sealer, pubkey) = make_validator();
        let validators = ValidatorSet::new(vec![sealer]);
        let gadget = FinalityGadget::with_default_config(0);

        let block_hash = make_block_hash();
        let vote = make_vote(&key, &pubkey, 5, 0, block_hash);

        // Skip heights 1-4
        let result = gadget.record_finality(5, block_hash, 0, vec![vote], &validators).await;
        assert!(matches!(result, Err(FinalityError::FinalityGap { .. })));
    }

    #[tokio::test]
    async fn test_finality_gadget_already_finalized() {
        let (key, sealer, pubkey) = make_validator();
        let validators = ValidatorSet::new(vec![sealer]);
        let gadget = FinalityGadget::with_default_config(0);

        let block_hash = make_block_hash();
        let vote = make_vote(&key, &pubkey, 1, 0, block_hash);

        // First finality succeeds
        gadget.record_finality(1, block_hash, 0, vec![vote.clone()], &validators).await.unwrap();

        // Second attempt fails
        let result = gadget.record_finality(1, block_hash, 0, vec![vote], &validators).await;
        assert!(matches!(result, Err(FinalityError::AlreadyFinalized(1))));
    }

    #[tokio::test]
    async fn test_finality_gadget_get_proof() {
        let (key, sealer, pubkey) = make_validator();
        let validators = ValidatorSet::new(vec![sealer]);
        let gadget = FinalityGadget::with_default_config(0);

        let block_hash = make_block_hash();
        let vote = make_vote(&key, &pubkey, 1, 0, block_hash);

        gadget.record_finality(1, block_hash, 0, vec![vote], &validators).await.unwrap();

        let proof = gadget.get_proof(1).await;
        assert!(proof.is_some());
        assert_eq!(proof.unwrap().height, 1);

        // Non-existent proof
        assert!(gadget.get_proof(999).await.is_none());
    }

    #[tokio::test]
    async fn test_finality_gadget_status() {
        let (key, sealer, pubkey) = make_validator();
        let validators = ValidatorSet::new(vec![sealer]);
        let gadget = FinalityGadget::with_default_config(0);

        let block_hash = make_block_hash();
        let vote = make_vote(&key, &pubkey, 1, 0, block_hash);

        // Before finality
        assert_eq!(gadget.status(&block_hash).await, FinalityStatus::Tentative);

        // After finality
        gadget.record_finality(1, block_hash, 0, vec![vote], &validators).await.unwrap();
        assert_eq!(gadget.status(&block_hash).await, FinalityStatus::Finalized);
    }

    #[tokio::test]
    async fn test_finality_gadget_mark_orphaned() {
        let gadget = FinalityGadget::with_default_config(0);
        let block_hash = make_block_hash();

        gadget.mark_orphaned(block_hash).await;
        assert_eq!(gadget.status(&block_hash).await, FinalityStatus::Orphaned);
    }

    #[tokio::test]
    async fn test_finality_gadget_notifications() {
        let (key, sealer, pubkey) = make_validator();
        let validators = ValidatorSet::new(vec![sealer]);
        let gadget = FinalityGadget::with_default_config(0);

        let block_hash = make_block_hash();
        let vote = make_vote(&key, &pubkey, 1, 0, block_hash);

        gadget.record_finality(1, block_hash, 0, vec![vote], &validators).await.unwrap();

        let notifications = gadget.drain_notifications().await;
        assert_eq!(notifications.len(), 1);
        assert_eq!(notifications[0].height, 1);

        // Notifications should be drained
        assert!(gadget.drain_notifications().await.is_empty());
    }

    #[tokio::test]
    async fn test_finality_gadget_finality_lag() {
        let gadget = FinalityGadget::with_default_config(0);

        assert_eq!(gadget.finality_lag(0).await, 0);
        assert_eq!(gadget.finality_lag(5).await, 5);
        assert!(gadget.is_healthy(5).await); // Within default max_finality_lag of 10
        assert!(gadget.is_healthy(10).await);
        assert!(!gadget.is_healthy(11).await); // Exceeds max_finality_lag
    }

    #[tokio::test]
    async fn test_finality_gadget_stats() {
        let (key, sealer, pubkey) = make_validator();
        let validators = ValidatorSet::new(vec![sealer]);
        let gadget = FinalityGadget::with_default_config(0);

        let stats = gadget.stats().await;
        assert_eq!(stats.last_finalized_height, 0);
        assert_eq!(stats.proofs_in_memory, 0);

        let block_hash = make_block_hash();
        let vote = make_vote(&key, &pubkey, 1, 0, block_hash);
        gadget.record_finality(1, block_hash, 0, vec![vote], &validators).await.unwrap();

        let stats = gadget.stats().await;
        assert_eq!(stats.last_finalized_height, 1);
        assert_eq!(stats.proofs_in_memory, 1);
        assert_eq!(stats.pending_notifications, 1);
    }

    #[tokio::test]
    async fn test_finality_gadget_proofs_range() {
        let (key, sealer, pubkey) = make_validator();
        let validators = ValidatorSet::new(vec![sealer]);
        let gadget = FinalityGadget::with_default_config(0);

        // Record multiple finalities
        for height in 1u64..=5 {
            let block_hash = BlockHash(hash(&height.to_le_bytes()));
            let vote = make_vote(&key, &pubkey, height, 0, block_hash);
            gadget.record_finality(height, block_hash, 0, vec![vote], &validators).await.unwrap();
        }

        let proofs = gadget.get_proofs_range(2, 4).await;
        assert_eq!(proofs.len(), 3);
        assert_eq!(proofs[0].height, 2);
        assert_eq!(proofs[1].height, 3);
        assert_eq!(proofs[2].height, 4);
    }

    #[tokio::test]
    async fn test_finality_gadget_proof_pruning() {
        let (key, sealer, pubkey) = make_validator();
        let validators = ValidatorSet::new(vec![sealer]);

        let mut config = FinalityConfig::default();
        config.max_proofs_in_memory = 3;

        let gadget = FinalityGadget::new(config, 0);

        // Record more finalities than max
        for height in 1u64..=5 {
            let block_hash = BlockHash(hash(&height.to_le_bytes()));
            let vote = make_vote(&key, &pubkey, height, 0, block_hash);
            gadget.record_finality(height, block_hash, 0, vec![vote], &validators).await.unwrap();
        }

        // Should have pruned old proofs
        let stats = gadget.stats().await;
        assert_eq!(stats.proofs_in_memory, 3);

        // Old proofs should be gone
        assert!(gadget.get_proof(1).await.is_none());
        assert!(gadget.get_proof(2).await.is_none());

        // Recent proofs should still exist
        assert!(gadget.get_proof(3).await.is_some());
        assert!(gadget.get_proof(4).await.is_some());
        assert!(gadget.get_proof(5).await.is_some());
    }

    #[test]
    fn test_notification_from_proof() {
        let (key, _, pubkey) = make_validator();
        let block_hash = make_block_hash();
        let vote = make_vote(&key, &pubkey, 10, 2, block_hash);

        let proof = FinalityProof::new(10, block_hash, 2, vec![vote]);
        let notification = FinalityNotification::from(&proof);

        assert_eq!(notification.height, 10);
        assert_eq!(notification.round, 2);
        assert_eq!(notification.block_hash, block_hash);
        assert_eq!(notification.vote_count, 1);
    }

    #[test]
    fn test_compact_finality_proof() {
        let validators_data: Vec<_> = (0..3).map(|_| make_validator()).collect();
        let sealers: Vec<_> = validators_data.iter().map(|(_, s, _)| s.clone()).collect();
        let validators = ValidatorSet::new(sealers);

        let block_hash = make_block_hash();

        let votes: Vec<_> = validators_data
            .iter()
            .map(|(key, _, pubkey)| make_vote(key, pubkey, 1, 0, block_hash))
            .collect();

        let proof = FinalityProof::new(1, block_hash, 0, votes);
        let compact = CompactFinalityProof::from_proof(&proof, &validators);

        assert_eq!(compact.height, 1);
        assert_eq!(compact.round, 0);
        assert_eq!(compact.voter_indices.len(), 3);
    }
}
