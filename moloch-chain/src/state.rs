//! Chain state management.
//!
//! The `ChainState` tracks the current state of the audit chain including:
//! - Current head block and height
//! - Validator set
//! - MMR state for inclusion proofs

use moloch_core::{Block, BlockHash, BlockHeader, Hash, Result};
use moloch_storage::ChainStore;
use std::sync::Arc;

use crate::validators::ValidatorSet;

/// Current state of the audit chain.
#[derive(Debug)]
pub struct ChainState<S: ChainStore> {
    /// The storage backend.
    storage: Arc<S>,
    /// Current head block header.
    head: Option<BlockHeader>,
    /// Current chain height (0-indexed).
    height: Option<u64>,
    /// Current validator set.
    validators: ValidatorSet,
    /// Chain configuration.
    config: ChainConfig,
}

/// Chain configuration parameters.
#[derive(Debug, Clone)]
pub struct ChainConfig {
    /// Chain identifier (for replay protection).
    pub chain_id: String,
    /// Maximum events per block.
    pub max_events_per_block: usize,
    /// Maximum block size in bytes.
    pub max_block_size: usize,
    /// Target block time in milliseconds.
    pub block_time_ms: u64,
    /// Minimum validators required for consensus.
    pub min_validators: usize,
}

impl Default for ChainConfig {
    fn default() -> Self {
        Self {
            chain_id: "moloch-mainnet".into(),
            max_events_per_block: 10_000,
            max_block_size: 10 * 1024 * 1024, // 10MB
            block_time_ms: 1000,              // 1 second
            min_validators: 1,
        }
    }
}

/// Result of applying a block.
#[derive(Debug, Clone)]
pub struct ApplyResult {
    /// The block that was applied.
    pub block_hash: BlockHash,
    /// New chain height.
    pub height: u64,
    /// Number of events in the block.
    pub event_count: usize,
    /// MMR root after applying.
    pub mmr_root: Hash,
}

/// Errors specific to chain state operations.
#[derive(Debug, thiserror::Error)]
pub enum ChainError {
    #[error("block height mismatch: expected {expected}, got {got}")]
    HeightMismatch { expected: u64, got: u64 },

    #[error("invalid parent hash: expected {expected}, got {got}")]
    InvalidParent { expected: String, got: String },

    #[error("block sealed by unknown validator: {0}")]
    UnknownValidator(String),

    #[error("block validation failed: {0}")]
    BlockValidation(String),

    #[error("block too large: {size} bytes exceeds limit {limit}")]
    BlockTooLarge { size: usize, limit: usize },

    #[error("too many events: {count} exceeds limit {limit}")]
    TooManyEvents { count: usize, limit: usize },

    #[error("chain not initialized (no genesis block)")]
    NotInitialized,

    #[error("genesis block already exists")]
    GenesisExists,

    #[error("cannot revert genesis block")]
    CannotRevertGenesis,

    #[error("storage error: {0}")]
    Storage(#[from] moloch_core::Error),
}

impl<S: ChainStore> ChainState<S> {
    /// Create a new chain state with the given storage and validators.
    pub fn new(storage: Arc<S>, validators: ValidatorSet, config: ChainConfig) -> Result<Self> {
        // Load current state from storage
        let height = storage.latest_height()?;
        let head = if let Some(h) = height {
            storage.get_header(h)?
        } else {
            None
        };

        Ok(Self {
            storage,
            head,
            height,
            validators,
            config,
        })
    }

    /// Get the current chain height (None if no blocks).
    pub fn height(&self) -> Option<u64> {
        self.height
    }

    /// Get the current head block header.
    pub fn head(&self) -> Option<&BlockHeader> {
        self.head.as_ref()
    }

    /// Get the current head block hash.
    pub fn head_hash(&self) -> Option<BlockHash> {
        self.head.as_ref().map(|h| h.hash())
    }

    /// Get the validator set.
    pub fn validators(&self) -> &ValidatorSet {
        &self.validators
    }

    /// Get the chain configuration.
    pub fn config(&self) -> &ChainConfig {
        &self.config
    }

    /// Check if the chain has been initialized with a genesis block.
    pub fn is_initialized(&self) -> bool {
        self.height.is_some()
    }

    /// Get the expected height for the next block.
    pub fn next_height(&self) -> u64 {
        self.height.map_or(0, |h| h + 1)
    }

    /// Get the expected parent hash for the next block.
    pub fn expected_parent(&self) -> Option<BlockHash> {
        self.head_hash()
    }

    /// Initialize the chain with a genesis block.
    pub fn init_genesis(&mut self, genesis: Block) -> std::result::Result<ApplyResult, ChainError> {
        if self.is_initialized() {
            return Err(ChainError::GenesisExists);
        }

        if genesis.header.height != 0 {
            return Err(ChainError::HeightMismatch {
                expected: 0,
                got: genesis.header.height,
            });
        }

        self.apply_block_internal(genesis)
    }

    /// Apply a block to the chain.
    ///
    /// Validates the block against:
    /// - Height (must be next expected)
    /// - Parent hash (must match current head)
    /// - Sealer (must be valid validator)
    /// - Signature
    /// - Size limits
    pub fn apply_block(&mut self, block: Block) -> std::result::Result<ApplyResult, ChainError> {
        // Validate height
        let expected_height = self.next_height();
        if block.header.height != expected_height {
            return Err(ChainError::HeightMismatch {
                expected: expected_height,
                got: block.header.height,
            });
        }

        // Validate parent (skip for genesis)
        if block.header.height > 0 {
            let expected_parent = self.head_hash().ok_or(ChainError::NotInitialized)?;
            if block.header.parent != expected_parent {
                return Err(ChainError::InvalidParent {
                    expected: hex::encode(expected_parent.as_hash().as_bytes()),
                    got: hex::encode(block.header.parent.as_hash().as_bytes()),
                });
            }
        }

        // Validate sealer is a known validator
        if !self.validators.contains(&block.header.sealer) {
            return Err(ChainError::UnknownValidator(hex::encode(
                block.header.sealer.as_pubkey().as_bytes(),
            )));
        }

        // Validate block size limits
        self.validate_block_limits(&block)?;

        // Validate block signature and structure
        let parent_header = self.head.as_ref();
        block
            .validate(parent_header)
            .map_err(|e| ChainError::BlockValidation(e.to_string()))?;

        self.apply_block_internal(block)
    }

    /// Internal block application (after validation).
    fn apply_block_internal(
        &mut self,
        block: Block,
    ) -> std::result::Result<ApplyResult, ChainError> {
        let height = block.header.height;
        let event_count = block.events.len();
        let block_hash = block.hash();
        let mmr_root = block.header.mmr_root;

        // Store the block
        self.storage.put_block(&block)?;

        // Update MMR with block hash
        self.storage.put_mmr_node(height, *block_hash.as_hash())?;
        self.storage.set_mmr_meta(height + 1, height + 1)?;

        // Update state
        self.head = Some(block.header);
        self.height = Some(height);

        Ok(ApplyResult {
            block_hash,
            height,
            event_count,
            mmr_root,
        })
    }

    /// Validate block size limits.
    fn validate_block_limits(&self, block: &Block) -> std::result::Result<(), ChainError> {
        if block.events.len() > self.config.max_events_per_block {
            return Err(ChainError::TooManyEvents {
                count: block.events.len(),
                limit: self.config.max_events_per_block,
            });
        }

        let size = bincode::serialize(block).map(|b| b.len()).unwrap_or(0);
        if size > self.config.max_block_size {
            return Err(ChainError::BlockTooLarge {
                size,
                limit: self.config.max_block_size,
            });
        }

        Ok(())
    }

    /// Revert the chain to the previous block.
    ///
    /// This is primarily for handling reorgs in PoA (should be rare).
    /// Returns the reverted block.
    pub fn revert_block(&mut self) -> std::result::Result<Block, ChainError> {
        let height = self.height.ok_or(ChainError::NotInitialized)?;

        if height == 0 {
            return Err(ChainError::CannotRevertGenesis);
        }

        // Get the block we're reverting
        let block = self
            .storage
            .get_block(height)?
            .ok_or(ChainError::NotInitialized)?;

        // Load previous block header
        let prev_height = height - 1;
        let prev_header = self.storage.get_header(prev_height)?;

        // Update state (note: we don't delete from storage, just update head)
        self.head = prev_header;
        self.height = Some(prev_height);

        Ok(block)
    }

    /// Get a block by height.
    pub fn get_block(&self, height: u64) -> Result<Option<Block>> {
        self.storage.get_block(height)
    }

    /// Get a block by hash.
    pub fn get_block_by_hash(&self, hash: &BlockHash) -> Result<Option<Block>> {
        self.storage.get_block_by_hash(hash)
    }

    /// Create a snapshot of the current state.
    pub fn snapshot(&self) -> ChainSnapshot {
        ChainSnapshot {
            height: self.height,
            head_hash: self.head_hash(),
            validator_count: self.validators.len(),
            chain_id: self.config.chain_id.clone(),
        }
    }
}

/// A lightweight snapshot of chain state.
#[derive(Debug, Clone)]
pub struct ChainSnapshot {
    pub height: Option<u64>,
    pub head_hash: Option<BlockHash>,
    pub validator_count: usize,
    pub chain_id: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use moloch_core::{
        block::{BlockBuilder, SealerId},
        crypto::SecretKey,
        event::{ActorId, ActorKind, EventType, ResourceId, ResourceKind},
        AuditEvent,
    };
    use moloch_storage::RocksStorage;

    fn test_event(key: &SecretKey) -> AuditEvent {
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

    fn test_chain() -> (ChainState<RocksStorage>, SecretKey) {
        let storage = Arc::new(RocksStorage::open_temp().unwrap());
        let key = SecretKey::generate();
        let sealer = SealerId::new(key.public_key());
        let validators = ValidatorSet::new(vec![sealer]);
        let config = ChainConfig::default();

        let chain = ChainState::new(storage, validators, config).unwrap();
        (chain, key)
    }

    #[test]
    fn test_chain_state_initial() {
        let (chain, _) = test_chain();

        assert!(!chain.is_initialized());
        assert_eq!(chain.height(), None);
        assert!(chain.head().is_none());
        assert_eq!(chain.next_height(), 0);
    }

    #[test]
    fn test_genesis_block() {
        let (mut chain, key) = test_chain();
        let sealer = SealerId::new(key.public_key());

        let genesis = BlockBuilder::new(sealer)
            .events(vec![test_event(&key)])
            .seal(&key);

        let result = chain.init_genesis(genesis).unwrap();

        assert_eq!(result.height, 0);
        assert_eq!(result.event_count, 1);
        assert!(chain.is_initialized());
        assert_eq!(chain.height(), Some(0));
        assert_eq!(chain.next_height(), 1);
    }

    #[test]
    fn test_genesis_already_exists() {
        let (mut chain, key) = test_chain();
        let sealer = SealerId::new(key.public_key());

        let genesis = BlockBuilder::new(sealer.clone())
            .events(vec![test_event(&key)])
            .seal(&key);

        chain.init_genesis(genesis).unwrap();

        let genesis2 = BlockBuilder::new(sealer)
            .events(vec![test_event(&key)])
            .seal(&key);

        let err = chain.init_genesis(genesis2).unwrap_err();
        assert!(matches!(err, ChainError::GenesisExists));
    }

    #[test]
    fn test_apply_block_sequence() {
        let (mut chain, key) = test_chain();
        let sealer = SealerId::new(key.public_key());

        // Genesis
        let genesis = BlockBuilder::new(sealer.clone())
            .events(vec![test_event(&key)])
            .seal(&key);
        let genesis_header = genesis.header.clone();
        chain.init_genesis(genesis).unwrap();

        // Block 1
        let block1 = BlockBuilder::new(sealer.clone())
            .parent(genesis_header.clone())
            .events(vec![test_event(&key), test_event(&key)])
            .seal(&key);

        let result = chain.apply_block(block1.clone()).unwrap();
        assert_eq!(result.height, 1);
        assert_eq!(result.event_count, 2);

        // Block 2
        let block2 = BlockBuilder::new(sealer)
            .parent(block1.header.clone())
            .events(vec![test_event(&key)])
            .seal(&key);

        let result = chain.apply_block(block2).unwrap();
        assert_eq!(result.height, 2);
        assert_eq!(chain.height(), Some(2));
    }

    #[test]
    fn test_apply_block_wrong_height() {
        let (mut chain, key) = test_chain();
        let sealer = SealerId::new(key.public_key());

        let genesis = BlockBuilder::new(sealer.clone())
            .events(vec![test_event(&key)])
            .seal(&key);
        chain.init_genesis(genesis).unwrap();

        // Try to apply block with wrong height (creates genesis which has height 0)
        let bad_block = BlockBuilder::new(sealer)
            .events(vec![test_event(&key)])
            .seal(&key);

        let err = chain.apply_block(bad_block).unwrap_err();
        assert!(matches!(
            err,
            ChainError::HeightMismatch {
                expected: 1,
                got: 0
            }
        ));
    }

    #[test]
    fn test_apply_block_wrong_parent() {
        let (mut chain, key) = test_chain();
        let sealer = SealerId::new(key.public_key());

        let genesis = BlockBuilder::new(sealer.clone())
            .events(vec![test_event(&key)])
            .seal(&key);
        let genesis_header = genesis.header.clone();
        chain.init_genesis(genesis).unwrap();

        // Create block1 correctly
        let block1 = BlockBuilder::new(sealer.clone())
            .parent(genesis_header.clone())
            .events(vec![test_event(&key)])
            .seal(&key);
        let block1_header = block1.header.clone();
        chain.apply_block(block1).unwrap();

        // Create a fake header at height 1 with wrong hash
        let mut fake_parent = block1_header.clone();
        fake_parent.events_root = moloch_core::hash(b"fake"); // Change to make different hash

        // Try to create block2 with wrong parent hash (but correct height)
        let bad_block = BlockBuilder::new(sealer)
            .parent(fake_parent) // Has correct height but wrong hash!
            .events(vec![test_event(&key)])
            .seal(&key);

        let err = chain.apply_block(bad_block).unwrap_err();
        // Will fail validation since parent doesn't match (height is correct but hash differs)
        assert!(matches!(
            err,
            ChainError::InvalidParent { .. } | ChainError::BlockValidation(_)
        ));
    }

    #[test]
    fn test_apply_block_unknown_validator() {
        let (mut chain, key) = test_chain();
        let sealer = SealerId::new(key.public_key());

        let genesis = BlockBuilder::new(sealer)
            .events(vec![test_event(&key)])
            .seal(&key);
        let genesis_header = genesis.header.clone();
        chain.init_genesis(genesis).unwrap();

        // Create block with unknown validator
        let unknown_key = SecretKey::generate();
        let unknown_sealer = SealerId::new(unknown_key.public_key());

        let bad_block = BlockBuilder::new(unknown_sealer)
            .parent(genesis_header)
            .events(vec![test_event(&unknown_key)])
            .seal(&unknown_key);

        let err = chain.apply_block(bad_block).unwrap_err();
        assert!(matches!(err, ChainError::UnknownValidator(_)));
    }

    #[test]
    fn test_revert_block() {
        let (mut chain, key) = test_chain();
        let sealer = SealerId::new(key.public_key());

        let genesis = BlockBuilder::new(sealer.clone())
            .events(vec![test_event(&key)])
            .seal(&key);
        let genesis_header = genesis.header.clone();
        chain.init_genesis(genesis).unwrap();

        let block1 = BlockBuilder::new(sealer)
            .parent(genesis_header)
            .events(vec![test_event(&key)])
            .seal(&key);
        chain.apply_block(block1).unwrap();

        assert_eq!(chain.height(), Some(1));

        let reverted = chain.revert_block().unwrap();
        assert_eq!(reverted.header.height, 1);
        assert_eq!(chain.height(), Some(0));
    }

    #[test]
    fn test_cannot_revert_genesis() {
        let (mut chain, key) = test_chain();
        let sealer = SealerId::new(key.public_key());

        let genesis = BlockBuilder::new(sealer)
            .events(vec![test_event(&key)])
            .seal(&key);
        chain.init_genesis(genesis).unwrap();

        let err = chain.revert_block().unwrap_err();
        assert!(matches!(err, ChainError::CannotRevertGenesis));
    }

    #[test]
    fn test_snapshot() {
        let (mut chain, key) = test_chain();
        let sealer = SealerId::new(key.public_key());

        let genesis = BlockBuilder::new(sealer)
            .events(vec![test_event(&key)])
            .seal(&key);
        let hash = genesis.hash();
        chain.init_genesis(genesis).unwrap();

        let snapshot = chain.snapshot();
        assert_eq!(snapshot.height, Some(0));
        assert_eq!(snapshot.head_hash, Some(hash));
        assert_eq!(snapshot.validator_count, 1);
        assert_eq!(snapshot.chain_id, "moloch-mainnet");
    }
}
