//! Batch operations for efficient atomic writes.
//!
//! Provides APIs for:
//! - Atomic multi-write operations (events, blocks, MMR nodes)
//! - Bulk read operations
//! - Transaction-like semantics with commit/abort

use moloch_core::{AuditEvent, Block, EventId, Hash, Result};

/// An operation to include in a batch.
#[derive(Debug, Clone)]
pub enum BatchOp {
    /// Store an event.
    PutEvent(AuditEvent),
    /// Store a block (includes its events).
    PutBlock(Block),
    /// Store an MMR node.
    PutMmrNode { pos: u64, hash: Hash },
    /// Update MMR metadata.
    SetMmrMeta { size: u64, leaf_count: u64 },
}

/// A batch of operations to commit atomically.
///
/// # Example
///
/// ```ignore
/// use moloch_storage::{RocksStorage, StorageBatch};
///
/// let storage = RocksStorage::open("./data")?;
/// let mut batch = storage.batch();
///
/// batch.put_event(&event1);
/// batch.put_event(&event2);
/// batch.put_block(&block);
///
/// batch.commit()?; // Atomic write
/// ```
#[derive(Debug, Default)]
pub struct StorageBatch {
    ops: Vec<BatchOp>,
}

impl StorageBatch {
    /// Create a new empty batch.
    pub fn new() -> Self {
        Self { ops: Vec::new() }
    }

    /// Create a batch with pre-allocated capacity.
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            ops: Vec::with_capacity(capacity),
        }
    }

    /// Add an event to the batch.
    pub fn put_event(&mut self, event: AuditEvent) -> &mut Self {
        self.ops.push(BatchOp::PutEvent(event));
        self
    }

    /// Add a block to the batch.
    pub fn put_block(&mut self, block: Block) -> &mut Self {
        self.ops.push(BatchOp::PutBlock(block));
        self
    }

    /// Add an MMR node to the batch.
    pub fn put_mmr_node(&mut self, pos: u64, hash: Hash) -> &mut Self {
        self.ops.push(BatchOp::PutMmrNode { pos, hash });
        self
    }

    /// Set MMR metadata in the batch.
    pub fn set_mmr_meta(&mut self, size: u64, leaf_count: u64) -> &mut Self {
        self.ops.push(BatchOp::SetMmrMeta { size, leaf_count });
        self
    }

    /// Get the number of operations in the batch.
    pub fn len(&self) -> usize {
        self.ops.len()
    }

    /// Check if the batch is empty.
    pub fn is_empty(&self) -> bool {
        self.ops.is_empty()
    }

    /// Clear all operations from the batch.
    pub fn clear(&mut self) {
        self.ops.clear();
    }

    /// Get the operations in this batch.
    pub fn ops(&self) -> &[BatchOp] {
        &self.ops
    }

    /// Take ownership of the operations.
    pub fn into_ops(self) -> Vec<BatchOp> {
        self.ops
    }
}

/// Trait for stores that support batch writes.
pub trait BatchWriter {
    /// Create a new batch for this store.
    fn batch(&self) -> StorageBatch {
        StorageBatch::new()
    }

    /// Commit a batch of operations atomically.
    fn commit(&self, batch: StorageBatch) -> Result<()>;
}

/// Trait for stores that support bulk reads.
pub trait BulkReader {
    /// Get multiple events by ID.
    fn get_events(&self, ids: &[EventId]) -> Result<Vec<Option<AuditEvent>>>;

    /// Get a range of blocks by height.
    fn get_block_range(&self, start: u64, end: u64) -> Result<Vec<Block>>;

    /// Get multiple MMR nodes by position.
    fn get_mmr_nodes(&self, positions: &[u64]) -> Result<Vec<Option<Hash>>>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use moloch_core::hash;

    #[test]
    fn test_batch_builder() {
        let mut batch = StorageBatch::new();
        assert!(batch.is_empty());

        batch
            .put_mmr_node(0, hash(b"node0"))
            .put_mmr_node(1, hash(b"node1"))
            .set_mmr_meta(2, 2);

        assert_eq!(batch.len(), 3);
        assert!(!batch.is_empty());
    }

    #[test]
    fn test_batch_clear() {
        let mut batch = StorageBatch::with_capacity(10);
        batch.put_mmr_node(0, hash(b"test"));
        assert_eq!(batch.len(), 1);

        batch.clear();
        assert!(batch.is_empty());
    }
}
