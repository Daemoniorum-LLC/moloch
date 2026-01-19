//! Storage traits.

use moloch_core::{
    AuditEvent, Block, BlockHash, BlockHeader, EventId, Hash, Result,
};

/// Store for audit events.
pub trait EventStore {
    /// Get an event by ID.
    fn get_event(&self, id: &EventId) -> Result<Option<AuditEvent>>;

    /// Store an event.
    fn put_event(&self, event: &AuditEvent) -> Result<()>;

    /// Check if an event exists.
    fn event_exists(&self, id: &EventId) -> Result<bool>;

    /// Get events by block height.
    fn get_events_by_block(&self, height: u64) -> Result<Vec<AuditEvent>>;
}

/// Store for blocks.
pub trait BlockStore {
    /// Get a block by height.
    fn get_block(&self, height: u64) -> Result<Option<Block>>;

    /// Get a block by hash.
    fn get_block_by_hash(&self, hash: &BlockHash) -> Result<Option<Block>>;

    /// Get a block header by height.
    fn get_header(&self, height: u64) -> Result<Option<BlockHeader>>;

    /// Store a block.
    fn put_block(&self, block: &Block) -> Result<()>;

    /// Get the latest block height.
    fn latest_height(&self) -> Result<Option<u64>>;

    /// Get the latest block.
    fn latest_block(&self) -> Result<Option<Block>>;
}

/// Combined chain store with MMR support.
pub trait ChainStore: EventStore + BlockStore {
    /// Get an MMR node by position.
    fn get_mmr_node(&self, pos: u64) -> Result<Option<Hash>>;

    /// Store an MMR node.
    fn put_mmr_node(&self, pos: u64, hash: Hash) -> Result<()>;

    /// Get the MMR size.
    fn mmr_size(&self) -> Result<u64>;

    /// Get the MMR leaf count.
    fn mmr_leaf_count(&self) -> Result<u64>;

    /// Set MMR metadata.
    fn set_mmr_meta(&self, size: u64, leaf_count: u64) -> Result<()>;

    /// Flush all pending writes.
    fn flush(&self) -> Result<()>;
}
