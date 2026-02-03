//! Round-based consensus state machine.
//!
//! Implements Aura-style PoA consensus with:
//! - Round-robin leader selection
//! - Proposal, prevote, precommit phases
//! - Timeout handling for liveness

use std::time::{Duration, Instant};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};

use moloch_chain::ValidatorSet;
use moloch_core::block::{Block, BlockBuilder, BlockHash, BlockHeader, SealerId};
use moloch_core::crypto::{SecretKey, Sig};
use moloch_core::event::AuditEvent;

use crate::votes::{Vote, VoteSet, VoteType};

/// Consensus configuration.
#[derive(Debug, Clone)]
pub struct ConsensusConfig {
    /// Target block time in milliseconds.
    pub block_time_ms: u64,
    /// Timeout for proposal phase.
    pub propose_timeout: Duration,
    /// Timeout for prevote phase.
    pub prevote_timeout: Duration,
    /// Timeout for precommit phase.
    pub precommit_timeout: Duration,
    /// Minimum time between blocks.
    pub min_block_interval: Duration,
    /// Skip empty blocks.
    pub skip_empty_blocks: bool,
    /// Maximum events per block.
    pub max_events_per_block: usize,
}

impl Default for ConsensusConfig {
    fn default() -> Self {
        Self {
            block_time_ms: 1000,
            propose_timeout: Duration::from_secs(3),
            prevote_timeout: Duration::from_secs(2),
            precommit_timeout: Duration::from_secs(2),
            min_block_interval: Duration::from_millis(500),
            skip_empty_blocks: false,
            max_events_per_block: 10_000,
        }
    }
}

/// Current step within a consensus round.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RoundStep {
    /// Waiting for proposal from leader.
    Propose,
    /// Collecting prevotes.
    Prevote,
    /// Collecting precommits.
    Precommit,
    /// Round is complete, block committed.
    Commit,
}

impl std::fmt::Display for RoundStep {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RoundStep::Propose => write!(f, "propose"),
            RoundStep::Prevote => write!(f, "prevote"),
            RoundStep::Precommit => write!(f, "precommit"),
            RoundStep::Commit => write!(f, "commit"),
        }
    }
}

/// State of a consensus round.
#[derive(Debug, Clone)]
pub struct RoundState {
    /// Current height being decided.
    pub height: u64,
    /// Current round number (resets on new height).
    pub round: u32,
    /// Current step within the round.
    pub step: RoundStep,
    /// The proposed block (if any).
    pub proposal: Option<Block>,
    /// Hash of the proposed block.
    pub proposal_hash: Option<BlockHash>,
    /// When the round started.
    pub started_at: Instant,
    /// Whether we've sent our prevote.
    pub prevoted: bool,
    /// Whether we've sent our precommit.
    pub precommitted: bool,
    /// Locked block (if any).
    pub locked_block: Option<Block>,
    /// Locked round.
    pub locked_round: Option<u32>,
    /// Valid block from this round.
    pub valid_block: Option<Block>,
    /// Valid round.
    pub valid_round: Option<u32>,
}

impl RoundState {
    /// Create a new round state for a given height.
    pub fn new(height: u64, round: u32) -> Self {
        Self {
            height,
            round,
            step: RoundStep::Propose,
            proposal: None,
            proposal_hash: None,
            started_at: Instant::now(),
            prevoted: false,
            precommitted: false,
            locked_block: None,
            locked_round: None,
            valid_block: None,
            valid_round: None,
        }
    }

    /// Get timeout duration for current step.
    pub fn timeout(&self, config: &ConsensusConfig) -> Duration {
        match self.step {
            RoundStep::Propose => config.propose_timeout,
            RoundStep::Prevote => config.prevote_timeout,
            RoundStep::Precommit => config.precommit_timeout,
            RoundStep::Commit => Duration::MAX, // No timeout in commit
        }
    }

    /// Check if current step has timed out.
    pub fn is_timed_out(&self, config: &ConsensusConfig) -> bool {
        self.started_at.elapsed() > self.timeout(config)
    }

    /// Advance to next step.
    pub fn advance_step(&mut self) {
        self.step = match self.step {
            RoundStep::Propose => RoundStep::Prevote,
            RoundStep::Prevote => RoundStep::Precommit,
            RoundStep::Precommit => RoundStep::Commit,
            RoundStep::Commit => RoundStep::Commit,
        };
        debug!(
            "Advanced to step {} at height {} round {}",
            self.step, self.height, self.round
        );
    }

    /// Start a new round at the same height.
    pub fn new_round(&mut self, round: u32) {
        self.round = round;
        self.step = RoundStep::Propose;
        self.proposal = None;
        self.proposal_hash = None;
        self.started_at = Instant::now();
        self.prevoted = false;
        self.precommitted = false;
        debug!("Starting round {} at height {}", round, self.height);
    }

    /// Start a new height.
    pub fn new_height(&mut self, height: u64) {
        self.height = height;
        self.round = 0;
        self.step = RoundStep::Propose;
        self.proposal = None;
        self.proposal_hash = None;
        self.started_at = Instant::now();
        self.prevoted = false;
        self.precommitted = false;
        self.locked_block = None;
        self.locked_round = None;
        self.valid_block = None;
        self.valid_round = None;
        debug!("Starting height {}", height);
    }
}

/// Consensus engine errors.
#[derive(Debug, thiserror::Error)]
pub enum ConsensusError {
    #[error("not the leader for this round")]
    NotLeader,

    #[error("invalid proposal: {0}")]
    InvalidProposal(String),

    #[error("invalid vote: {0}")]
    InvalidVote(String),

    #[error("duplicate vote from {0}")]
    DuplicateVote(String),

    #[error("vote from unknown validator: {0}")]
    UnknownValidator(String),

    #[error("wrong height: expected {expected}, got {got}")]
    WrongHeight { expected: u64, got: u64 },

    #[error("wrong round: expected {expected}, got {got}")]
    WrongRound { expected: u32, got: u32 },

    #[error("block validation failed: {0}")]
    BlockValidation(String),

    #[error("timeout")]
    Timeout,

    #[error("no validators configured")]
    NoValidators,

    #[error("storage error: {0}")]
    Storage(#[from] moloch_core::Error),
}

/// A block proposal from the leader.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Proposal {
    /// Height of the proposed block.
    pub height: u64,
    /// Round number.
    pub round: u32,
    /// The proposed block.
    pub block: Block,
    /// Valid round (for unlocking).
    pub valid_round: Option<u32>,
    /// Proposer's signature.
    pub signature: Sig,
}

impl Proposal {
    /// Create a new proposal.
    pub fn new(
        height: u64,
        round: u32,
        block: Block,
        valid_round: Option<u32>,
        key: &SecretKey,
    ) -> Self {
        let bytes = Self::signing_bytes(height, round, &block, valid_round);
        let signature = key.sign(&bytes);
        Self {
            height,
            round,
            block,
            valid_round,
            signature,
        }
    }

    /// Get the bytes to sign.
    fn signing_bytes(height: u64, round: u32, block: &Block, valid_round: Option<u32>) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&height.to_le_bytes());
        bytes.extend_from_slice(&round.to_le_bytes());
        bytes.extend_from_slice(block.hash().as_hash().as_bytes());
        if let Some(vr) = valid_round {
            bytes.extend_from_slice(&vr.to_le_bytes());
        }
        bytes
    }

    /// Verify the proposal signature.
    pub fn verify(&self) -> Result<(), ConsensusError> {
        let bytes = Self::signing_bytes(self.height, self.round, &self.block, self.valid_round);
        self.block
            .header
            .sealer
            .as_pubkey()
            .verify(&bytes, &self.signature)
            .map_err(|_| ConsensusError::InvalidProposal("invalid signature".into()))
    }
}

/// Committed block with aggregated votes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommittedBlock {
    /// The committed block.
    pub block: Block,
    /// Precommit votes that finalized this block.
    pub votes: Vec<Vote>,
    /// When the block was committed.
    #[serde(with = "chrono::serde::ts_milliseconds")]
    pub committed_at: DateTime<Utc>,
}

/// The consensus engine.
#[derive(Debug)]
pub struct ConsensusEngine {
    /// Configuration.
    config: ConsensusConfig,
    /// Our validator key.
    validator_key: SecretKey,
    /// Our sealer ID.
    sealer_id: SealerId,
    /// Current validator set.
    validators: RwLock<ValidatorSet>,
    /// Current round state.
    state: RwLock<RoundState>,
    /// Prevotes for current height.
    prevotes: RwLock<VoteSet>,
    /// Precommits for current height.
    precommits: RwLock<VoteSet>,
    /// Last committed block time.
    last_block_time: RwLock<Option<Instant>>,
    /// Pending events for next block.
    pending_events: RwLock<Vec<AuditEvent>>,
}

impl ConsensusEngine {
    /// Create a new consensus engine.
    pub fn new(
        config: ConsensusConfig,
        validator_key: SecretKey,
        validators: ValidatorSet,
        start_height: u64,
    ) -> Self {
        let sealer_id = SealerId::new(validator_key.public_key());

        Self {
            config,
            sealer_id,
            validator_key,
            validators: RwLock::new(validators.clone()),
            state: RwLock::new(RoundState::new(start_height, 0)),
            prevotes: RwLock::new(VoteSet::new(
                start_height,
                0,
                VoteType::Prevote,
                validators.clone(),
            )),
            precommits: RwLock::new(VoteSet::new(
                start_height,
                0,
                VoteType::Precommit,
                validators,
            )),
            last_block_time: RwLock::new(None),
            pending_events: RwLock::new(Vec::new()),
        }
    }

    /// Get the current round state.
    pub async fn state(&self) -> RoundState {
        self.state.read().await.clone()
    }

    /// Get the validator set.
    pub async fn validators(&self) -> ValidatorSet {
        self.validators.read().await.clone()
    }

    /// Check if we are the leader for the current round.
    pub async fn is_leader(&self) -> bool {
        let state = self.state.read().await;
        let validators = self.validators.read().await;

        validators
            .leader_for_round(state.height + state.round as u64)
            .map(|leader| leader == &self.sealer_id)
            .unwrap_or(false)
    }

    /// Get the leader for the current round.
    pub async fn current_leader(&self) -> Option<SealerId> {
        let state = self.state.read().await;
        let validators = self.validators.read().await;
        validators
            .leader_for_round(state.height + state.round as u64)
            .cloned()
    }

    /// Add an event to the pending pool.
    pub async fn add_event(&self, event: AuditEvent) {
        let mut pending = self.pending_events.write().await;
        if pending.len() < self.config.max_events_per_block {
            pending.push(event);
        }
    }

    /// Create a block proposal if we are the leader.
    pub async fn create_proposal(
        &self,
        parent: Option<&BlockHeader>,
    ) -> Result<Proposal, ConsensusError> {
        if !self.is_leader().await {
            return Err(ConsensusError::NotLeader);
        }

        // Check minimum block interval
        let last_time = self.last_block_time.read().await;
        if let Some(last) = *last_time {
            if last.elapsed() < self.config.min_block_interval {
                return Err(ConsensusError::Timeout);
            }
        }

        let state = self.state.read().await;
        let mut pending = self.pending_events.write().await;

        // Skip empty blocks if configured
        if pending.is_empty() && self.config.skip_empty_blocks {
            return Err(ConsensusError::Timeout);
        }

        // Take events for this block
        let events: Vec<_> = pending
            .drain(..)
            .take(self.config.max_events_per_block)
            .collect();

        // Build the block
        let mut builder = BlockBuilder::new(self.sealer_id.clone()).events(events);

        if let Some(p) = parent {
            builder = builder.parent(p.clone());
        }

        let block = builder.seal(&self.validator_key);

        // Create proposal
        let valid_round = state.valid_round;
        let proposal = Proposal::new(
            state.height,
            state.round,
            block,
            valid_round,
            &self.validator_key,
        );

        info!(
            "Created proposal for height {} round {}",
            state.height, state.round
        );

        Ok(proposal)
    }

    /// Handle an incoming proposal.
    pub async fn handle_proposal(
        &self,
        proposal: Proposal,
    ) -> Result<Option<Vote>, ConsensusError> {
        let mut state = self.state.write().await;

        // Verify height and round
        if proposal.height != state.height {
            return Err(ConsensusError::WrongHeight {
                expected: state.height,
                got: proposal.height,
            });
        }

        if proposal.round != state.round {
            return Err(ConsensusError::WrongRound {
                expected: state.round,
                got: proposal.round,
            });
        }

        // Verify proposal signature
        proposal.verify()?;

        // Verify proposer is the leader
        let validators = self.validators.read().await;
        let expected_leader = validators
            .leader_for_round(state.height + state.round as u64)
            .ok_or(ConsensusError::NoValidators)?;

        if proposal.block.header.sealer != *expected_leader {
            return Err(ConsensusError::InvalidProposal("not the leader".into()));
        }

        // Validate the block
        // In a real implementation, we'd validate against chain state
        proposal
            .block
            .header
            .verify_seal()
            .map_err(|e| ConsensusError::BlockValidation(e.to_string()))?;

        // Store proposal
        state.proposal = Some(proposal.block.clone());
        state.proposal_hash = Some(proposal.block.hash());

        // Advance to prevote step
        state.advance_step();

        // Cast our prevote if we haven't already
        let should_vote = !state.prevoted;
        let block_hash = proposal.block.hash();
        let height = state.height;
        let round = state.round;

        if should_vote {
            state.prevoted = true;
        }

        // Drop state lock before creating vote to avoid deadlock
        drop(state);

        if should_vote {
            let vote = Vote::new(
                height,
                round,
                VoteType::Prevote,
                Some(block_hash),
                self.validator_key.public_key(),
                &self.validator_key,
            );
            return Ok(Some(vote));
        }

        Ok(None)
    }

    /// Handle an incoming vote.
    pub async fn handle_vote(&self, vote: Vote) -> Result<Option<Vote>, ConsensusError> {
        let state = self.state.read().await;

        // Verify height and round
        if vote.height != state.height {
            return Err(ConsensusError::WrongHeight {
                expected: state.height,
                got: vote.height,
            });
        }

        if vote.round != state.round {
            return Err(ConsensusError::WrongRound {
                expected: state.round,
                got: vote.round,
            });
        }

        // Verify voter is a validator
        let validators = self.validators.read().await;
        let voter_sealer = SealerId::new(vote.voter.clone());
        if !validators.contains(&voter_sealer) {
            return Err(ConsensusError::UnknownValidator(format!(
                "{:?}",
                vote.voter
            )));
        }
        drop(validators);

        // Verify signature
        vote.verify()
            .map_err(|_| ConsensusError::InvalidVote("invalid signature".into()))?;

        drop(state);

        // Add vote to appropriate set
        match vote.vote_type {
            VoteType::Prevote => {
                let mut prevotes = self.prevotes.write().await;
                if prevotes.add_vote(vote.clone()).is_err() {
                    return Err(ConsensusError::DuplicateVote(format!("{:?}", vote.voter)));
                }

                // Check for 2/3+ prevotes
                if let Some(block_hash) = prevotes.has_supermajority() {
                    drop(prevotes);

                    // Lock on this block
                    let mut state = self.state.write().await;
                    if let Some(proposal) = state.proposal.clone() {
                        if Some(proposal.hash()) == block_hash {
                            state.locked_block = Some(proposal.clone());
                            state.locked_round = Some(state.round);
                            state.valid_block = Some(proposal);
                            state.valid_round = Some(state.round);
                        }
                    }

                    // Advance to precommit if we're in prevote
                    if state.step == RoundStep::Prevote {
                        state.advance_step();
                    }

                    // Cast our precommit
                    let should_precommit = !state.precommitted;
                    let height = state.height;
                    let round = state.round;

                    if should_precommit {
                        state.precommitted = true;
                    }

                    // Drop state lock before creating vote to avoid deadlock
                    drop(state);

                    if should_precommit {
                        let vote = Vote::new(
                            height,
                            round,
                            VoteType::Precommit,
                            block_hash,
                            self.validator_key.public_key(),
                            &self.validator_key,
                        );
                        return Ok(Some(vote));
                    }
                }
            }
            VoteType::Precommit => {
                let mut precommits = self.precommits.write().await;
                if precommits.add_vote(vote.clone()).is_err() {
                    return Err(ConsensusError::DuplicateVote(format!("{:?}", vote.voter)));
                }

                // Check for 2/3+ precommits
                if let Some(_block_hash) = precommits.has_supermajority() {
                    drop(precommits);

                    // Commit!
                    let mut state = self.state.write().await;
                    state.step = RoundStep::Commit;

                    info!(
                        "Block committed at height {} round {}",
                        state.height, state.round
                    );
                }
            }
        }

        Ok(None)
    }

    /// Create a vote for the current round.
    async fn create_vote(&self, vote_type: VoteType, block_hash: Option<BlockHash>) -> Vote {
        let state = self.state.read().await;
        Vote::new(
            state.height,
            state.round,
            vote_type,
            block_hash,
            self.validator_key.public_key(),
            &self.validator_key,
        )
    }

    /// Get the committed block if consensus reached.
    pub async fn get_committed_block(&self) -> Option<CommittedBlock> {
        let state = self.state.read().await;

        if state.step != RoundStep::Commit {
            return None;
        }

        let block = state.proposal.clone()?;
        let precommits = self.precommits.read().await;
        let votes = precommits.votes_for(Some(block.hash()));

        Some(CommittedBlock {
            block,
            votes,
            committed_at: Utc::now(),
        })
    }

    /// Advance to the next height after committing.
    pub async fn advance_height(&self) {
        let mut state = self.state.write().await;
        let new_height = state.height + 1;

        // Reset vote sets
        let validators = self.validators.read().await;
        *self.prevotes.write().await =
            VoteSet::new(new_height, 0, VoteType::Prevote, validators.clone());
        *self.precommits.write().await =
            VoteSet::new(new_height, 0, VoteType::Precommit, validators.clone());

        // Update last block time
        *self.last_block_time.write().await = Some(Instant::now());

        // Advance state
        state.new_height(new_height);
    }

    /// Handle timeout for the current step.
    pub async fn handle_timeout(&self) -> Option<Vote> {
        let mut state = self.state.write().await;

        match state.step {
            RoundStep::Propose => {
                // Timeout waiting for proposal - prevote nil
                state.advance_step();
                if !state.prevoted {
                    state.prevoted = true;
                    drop(state);
                    let vote = self.create_vote(VoteType::Prevote, None).await;
                    return Some(vote);
                }
            }
            RoundStep::Prevote => {
                // Timeout waiting for prevotes - precommit nil
                state.advance_step();
                if !state.precommitted {
                    state.precommitted = true;
                    drop(state);
                    let vote = self.create_vote(VoteType::Precommit, None).await;
                    return Some(vote);
                }
            }
            RoundStep::Precommit => {
                // Timeout waiting for precommits - start new round
                let new_round = state.round + 1;
                state.new_round(new_round);

                // Reset vote sets for new round
                let validators = self.validators.read().await;
                *self.prevotes.write().await = VoteSet::new(
                    state.height,
                    new_round,
                    VoteType::Prevote,
                    validators.clone(),
                );
                *self.precommits.write().await = VoteSet::new(
                    state.height,
                    new_round,
                    VoteType::Precommit,
                    validators.clone(),
                );

                warn!(
                    "Timeout in precommit, advancing to round {} at height {}",
                    new_round, state.height
                );
            }
            RoundStep::Commit => {
                // Already committed, nothing to do
            }
        }

        None
    }

    /// Update the validator set.
    pub async fn update_validators(&self, validators: ValidatorSet) {
        *self.validators.write().await = validators;
    }

    /// Get consensus statistics.
    pub async fn stats(&self) -> ConsensusStats {
        let state = self.state.read().await;
        let prevotes = self.prevotes.read().await;
        let precommits = self.precommits.read().await;

        ConsensusStats {
            height: state.height,
            round: state.round,
            step: state.step,
            has_proposal: state.proposal.is_some(),
            prevote_count: prevotes.count(),
            precommit_count: precommits.count(),
            is_locked: state.locked_block.is_some(),
        }
    }
}

/// Consensus statistics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsensusStats {
    /// Current height.
    pub height: u64,
    /// Current round.
    pub round: u32,
    /// Current step.
    pub step: RoundStep,
    /// Has a proposal been received.
    pub has_proposal: bool,
    /// Number of prevotes received.
    pub prevote_count: usize,
    /// Number of precommits received.
    pub precommit_count: usize,
    /// Is the engine locked on a block.
    pub is_locked: bool,
}

#[cfg(test)]
mod tests {
    use super::*;
    use moloch_core::event::{ActorId, ActorKind, EventType, ResourceId, ResourceKind};
    use moloch_core::Hash;

    fn make_validator() -> (SecretKey, SealerId) {
        let key = SecretKey::generate();
        let sealer = SealerId::new(key.public_key());
        (key, sealer)
    }

    fn make_event(key: &SecretKey) -> AuditEvent {
        let actor = ActorId::new(key.public_key(), ActorKind::User);
        let resource = ResourceId::new(ResourceKind::Repository, "test");

        AuditEvent::builder()
            .now()
            .event_type(EventType::Push {
                force: false,
                commits: 1,
            })
            .actor(actor)
            .resource(resource)
            .sign(key)
            .unwrap()
    }

    #[test]
    fn test_round_state_new() {
        let state = RoundState::new(10, 0);
        assert_eq!(state.height, 10);
        assert_eq!(state.round, 0);
        assert_eq!(state.step, RoundStep::Propose);
        assert!(state.proposal.is_none());
    }

    #[test]
    fn test_round_state_advance() {
        let mut state = RoundState::new(0, 0);

        state.advance_step();
        assert_eq!(state.step, RoundStep::Prevote);

        state.advance_step();
        assert_eq!(state.step, RoundStep::Precommit);

        state.advance_step();
        assert_eq!(state.step, RoundStep::Commit);

        // Should stay at commit
        state.advance_step();
        assert_eq!(state.step, RoundStep::Commit);
    }

    #[test]
    fn test_round_state_new_round() {
        let mut state = RoundState::new(0, 0);
        state.step = RoundStep::Precommit;
        state.prevoted = true;

        state.new_round(1);

        assert_eq!(state.round, 1);
        assert_eq!(state.step, RoundStep::Propose);
        assert!(!state.prevoted);
    }

    #[test]
    fn test_round_state_new_height() {
        let mut state = RoundState::new(10, 5);
        state.step = RoundStep::Commit;
        state.locked_block = Some(Block {
            header: BlockHeader {
                height: 10,
                parent: moloch_core::block::BlockHash::ZERO,
                events_root: Hash::ZERO,
                events_count: 0,
                mmr_root: Hash::ZERO,
                timestamp: Utc::now(),
                sealer: make_validator().1,
                seal: Sig::empty(),
            },
            events: vec![],
        });

        state.new_height(11);

        assert_eq!(state.height, 11);
        assert_eq!(state.round, 0);
        assert_eq!(state.step, RoundStep::Propose);
        assert!(state.locked_block.is_none());
    }

    #[test]
    fn test_proposal_sign_verify() {
        let (key, sealer) = make_validator();
        let block = BlockBuilder::new(sealer).events(vec![]).seal(&key);

        let proposal = Proposal::new(1, 0, block, None, &key);
        assert!(proposal.verify().is_ok());
    }

    #[tokio::test]
    async fn test_consensus_engine_creation() {
        let (key, sealer) = make_validator();
        let validators = ValidatorSet::new(vec![sealer]);
        let config = ConsensusConfig::default();

        let engine = ConsensusEngine::new(config, key, validators, 0);

        let state = engine.state().await;
        assert_eq!(state.height, 0);
        assert_eq!(state.round, 0);
    }

    #[tokio::test]
    async fn test_consensus_engine_is_leader() {
        let (key1, sealer1) = make_validator();
        let (key2, sealer2) = make_validator();

        // Engine 1 with both validators, sealer1 is first (leader for round 0)
        let validators = ValidatorSet::new(vec![sealer1.clone(), sealer2.clone()]);
        let engine1 = ConsensusEngine::new(ConsensusConfig::default(), key1, validators.clone(), 0);

        assert!(engine1.is_leader().await);

        // Engine 2 with sealer2 as our key
        let engine2 = ConsensusEngine::new(ConsensusConfig::default(), key2, validators, 0);
        assert!(!engine2.is_leader().await);
    }

    #[tokio::test]
    async fn test_consensus_engine_create_proposal() {
        let (key, sealer) = make_validator();
        let validators = ValidatorSet::new(vec![sealer]);
        let config = ConsensusConfig {
            min_block_interval: Duration::ZERO,
            ..Default::default()
        };

        let engine = ConsensusEngine::new(config, key.clone(), validators, 0);

        // Add an event
        engine.add_event(make_event(&key)).await;

        let proposal = engine.create_proposal(None).await.unwrap();
        assert_eq!(proposal.height, 0);
        assert_eq!(proposal.round, 0);
        assert_eq!(proposal.block.events.len(), 1);
    }

    #[tokio::test]
    async fn test_consensus_engine_not_leader() {
        let (_key1, sealer1) = make_validator();
        let (key2, sealer2) = make_validator();

        let validators = ValidatorSet::new(vec![sealer1, sealer2]);
        let engine = ConsensusEngine::new(ConsensusConfig::default(), key2, validators, 0);

        let result = engine.create_proposal(None).await;
        assert!(matches!(result, Err(ConsensusError::NotLeader)));
    }

    #[tokio::test]
    async fn test_consensus_engine_handle_proposal() {
        let (key, sealer) = make_validator();
        let validators = ValidatorSet::new(vec![sealer.clone()]);
        let config = ConsensusConfig {
            min_block_interval: Duration::ZERO,
            ..Default::default()
        };

        let engine = ConsensusEngine::new(config, key.clone(), validators, 0);

        // Create and handle proposal
        let proposal = engine.create_proposal(None).await.unwrap();
        let vote = engine.handle_proposal(proposal).await.unwrap();

        // Should have cast a prevote
        assert!(vote.is_some());
        let vote = vote.unwrap();
        assert_eq!(vote.vote_type, VoteType::Prevote);

        // State should have advanced
        let state = engine.state().await;
        assert_eq!(state.step, RoundStep::Prevote);
        assert!(state.proposal.is_some());
    }

    #[tokio::test]
    async fn test_consensus_engine_stats() {
        let (key, sealer) = make_validator();
        let validators = ValidatorSet::new(vec![sealer]);

        let engine = ConsensusEngine::new(ConsensusConfig::default(), key, validators, 5);

        let stats = engine.stats().await;
        assert_eq!(stats.height, 5);
        assert_eq!(stats.round, 0);
        assert!(!stats.has_proposal);
    }

    #[test]
    fn test_round_step_display() {
        assert_eq!(format!("{}", RoundStep::Propose), "propose");
        assert_eq!(format!("{}", RoundStep::Prevote), "prevote");
        assert_eq!(format!("{}", RoundStep::Precommit), "precommit");
        assert_eq!(format!("{}", RoundStep::Commit), "commit");
    }
}
