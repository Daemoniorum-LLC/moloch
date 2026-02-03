//! Storage layer for Moloch.
//!
//! Provides persistent storage for:
//! - Audit events
//! - Blocks
//! - MMR nodes
//! - Indexes for efficient queries
//!
//! # Batch Operations
//!
//! For efficient bulk writes, use the batch API:
//!
//! ```ignore
//! use moloch_storage::{RocksStorage, StorageBatch, BatchWriter};
//!
//! let storage = RocksStorage::open("./data")?;
//! let mut batch = StorageBatch::new();
//!
//! batch.put_block(block1);
//! batch.put_block(block2);
//! batch.put_mmr_node(0, hash);
//!
//! storage.commit(batch)?; // Atomic write
//! ```
//!
//! # Iterators
//!
//! For efficient traversal, use the iterator API:
//!
//! ```ignore
//! use moloch_storage::{RocksStorage, BlockIterator, EventIterator};
//!
//! let storage = RocksStorage::open("./data")?;
//!
//! // Iterate over all blocks
//! for block in BlockIterator::all(&storage)? {
//!     println!("Block {}", block?.header.height);
//! }
//!
//! // Iterate over events in specific block range
//! for event in EventIterator::in_blocks(&storage, 0, 100) {
//!     let (height, event) = event?;
//!     println!("Event {} in block {}", event.id(), height);
//! }
//! ```

mod batch;
mod iter;
mod mmap;
mod rocks;
pub mod snapshot;
mod traits;

pub use batch::{BatchOp, BatchWriter, BulkReader, StorageBatch};
pub use iter::{BlockIterator, EventIterator, MmrNodeIterator};
pub use mmap::{MmapConfig, MmapStats, MmapStorage};
pub use rocks::RocksStorage;
pub use snapshot::{
    ImportPhase, ImportProgress, PruneConfig, PruneStats, Snapshot, SnapshotBuilder, SnapshotError,
    SnapshotHeader, SnapshotReader, SNAPSHOT_MAGIC, SNAPSHOT_VERSION,
};
pub use traits::{BlockStore, ChainStore, EventStore};
