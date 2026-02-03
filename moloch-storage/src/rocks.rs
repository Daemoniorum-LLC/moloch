//! RocksDB storage implementation.

use std::path::Path;
use std::sync::Arc;

use rocksdb::{ColumnFamilyDescriptor, Options, WriteBatch, DB};
use tracing::{debug, info};

use moloch_core::{AuditEvent, Block, BlockHash, BlockHeader, Error, EventId, Hash, Result};
use moloch_mmr::MmrStore;

use crate::traits::{BlockStore, ChainStore, EventStore};

/// Column family names.
mod cf {
    pub const DEFAULT: &str = "default";
    pub const EVENTS: &str = "events";
    pub const BLOCKS: &str = "blocks";
    pub const BLOCK_INDEX: &str = "block_index";
    pub const MMR: &str = "mmr";
    pub const META: &str = "meta";
}

/// Metadata keys.
mod meta {
    pub const LATEST_HEIGHT: &[u8] = b"latest_height";
    pub const MMR_SIZE: &[u8] = b"mmr_size";
    pub const MMR_LEAF_COUNT: &[u8] = b"mmr_leaf_count";
}

/// RocksDB-backed storage.
pub struct RocksStorage {
    db: Arc<DB>,
}

impl RocksStorage {
    /// Open or create a storage at the given path.
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        info!("Opening RocksDB at {:?}", path);

        let mut opts = Options::default();
        opts.create_if_missing(true);
        opts.create_missing_column_families(true);

        let cf_names = [
            cf::DEFAULT,
            cf::EVENTS,
            cf::BLOCKS,
            cf::BLOCK_INDEX,
            cf::MMR,
            cf::META,
        ];

        let cf_descriptors: Vec<_> = cf_names
            .iter()
            .map(|name| ColumnFamilyDescriptor::new(*name, Options::default()))
            .collect();

        let db = DB::open_cf_descriptors(&opts, path, cf_descriptors)
            .map_err(|e| Error::storage(e.to_string()))?;

        Ok(Self { db: Arc::new(db) })
    }

    /// Open with a temporary directory (for testing).
    pub fn open_temp() -> Result<Self> {
        let dir = tempfile::tempdir().map_err(|e| Error::storage(e.to_string()))?;
        let path = dir.path().to_path_buf();
        // Keep the temp dir alive by forgetting it (won't be cleaned up on drop)
        std::mem::forget(dir);
        Self::open(path)
    }

    fn get_cf(&self, cf_name: &str, key: &[u8]) -> Result<Option<Vec<u8>>> {
        let cf = self
            .db
            .cf_handle(cf_name)
            .ok_or_else(|| Error::storage(format!("missing column family: {}", cf_name)))?;
        self.db
            .get_cf(&cf, key)
            .map_err(|e| Error::storage(e.to_string()))
    }

    fn put_cf(&self, cf_name: &str, key: &[u8], value: &[u8]) -> Result<()> {
        let cf = self
            .db
            .cf_handle(cf_name)
            .ok_or_else(|| Error::storage(format!("missing column family: {}", cf_name)))?;
        self.db
            .put_cf(&cf, key, value)
            .map_err(|e| Error::storage(e.to_string()))
    }

    fn get_u64(&self, cf_name: &str, key: &[u8]) -> Result<Option<u64>> {
        match self.get_cf(cf_name, key)? {
            Some(bytes) => {
                if bytes.len() != 8 {
                    return Err(Error::storage("invalid u64 encoding"));
                }
                let arr: [u8; 8] = bytes.as_slice().try_into().unwrap();
                Ok(Some(u64::from_be_bytes(arr)))
            }
            None => Ok(None),
        }
    }
}

impl Clone for RocksStorage {
    fn clone(&self) -> Self {
        Self {
            db: Arc::clone(&self.db),
        }
    }
}

impl EventStore for RocksStorage {
    fn get_event(&self, id: &EventId) -> Result<Option<AuditEvent>> {
        match self.get_cf(cf::EVENTS, id.as_hash().as_bytes())? {
            Some(bytes) => {
                let event: AuditEvent = bincode::deserialize(&bytes)?;
                Ok(Some(event))
            }
            None => Ok(None),
        }
    }

    fn put_event(&self, event: &AuditEvent) -> Result<()> {
        let id = event.id();
        let bytes = bincode::serialize(event)?;
        self.put_cf(cf::EVENTS, id.as_hash().as_bytes(), &bytes)
    }

    fn event_exists(&self, id: &EventId) -> Result<bool> {
        Ok(self.get_cf(cf::EVENTS, id.as_hash().as_bytes())?.is_some())
    }

    fn get_events_by_block(&self, height: u64) -> Result<Vec<AuditEvent>> {
        if let Some(block) = self.get_block(height)? {
            Ok(block.events)
        } else {
            Ok(vec![])
        }
    }
}

impl BlockStore for RocksStorage {
    fn get_block(&self, height: u64) -> Result<Option<Block>> {
        match self.get_cf(cf::BLOCKS, &height.to_be_bytes())? {
            Some(bytes) => {
                let block: Block = bincode::deserialize(&bytes)?;
                Ok(Some(block))
            }
            None => Ok(None),
        }
    }

    fn get_block_by_hash(&self, hash: &BlockHash) -> Result<Option<Block>> {
        match self.get_cf(cf::BLOCK_INDEX, hash.as_hash().as_bytes())? {
            Some(bytes) => {
                if bytes.len() != 8 {
                    return Err(Error::storage("invalid height encoding"));
                }
                let height = u64::from_be_bytes(bytes.as_slice().try_into().unwrap());
                self.get_block(height)
            }
            None => Ok(None),
        }
    }

    fn get_header(&self, height: u64) -> Result<Option<BlockHeader>> {
        Ok(self.get_block(height)?.map(|b| b.header))
    }

    fn put_block(&self, block: &Block) -> Result<()> {
        let height = block.header.height;
        let hash = block.hash();

        let blocks_cf = self
            .db
            .cf_handle(cf::BLOCKS)
            .ok_or_else(|| Error::storage("missing blocks cf"))?;
        let index_cf = self
            .db
            .cf_handle(cf::BLOCK_INDEX)
            .ok_or_else(|| Error::storage("missing block_index cf"))?;
        let events_cf = self
            .db
            .cf_handle(cf::EVENTS)
            .ok_or_else(|| Error::storage("missing events cf"))?;
        let meta_cf = self
            .db
            .cf_handle(cf::META)
            .ok_or_else(|| Error::storage("missing meta cf"))?;

        let mut batch = WriteBatch::default();

        // Store block
        let block_bytes = bincode::serialize(block)?;
        batch.put_cf(&blocks_cf, height.to_be_bytes(), block_bytes);

        // Index by hash
        batch.put_cf(&index_cf, hash.as_hash().as_bytes(), height.to_be_bytes());

        // Store events
        for event in &block.events {
            let event_bytes = bincode::serialize(event)?;
            batch.put_cf(&events_cf, event.id().as_hash().as_bytes(), event_bytes);
        }

        // Update latest height
        batch.put_cf(&meta_cf, meta::LATEST_HEIGHT, height.to_be_bytes());

        self.db
            .write(batch)
            .map_err(|e| Error::storage(e.to_string()))?;

        debug!("Stored block {} with {} events", height, block.events.len());
        Ok(())
    }

    fn latest_height(&self) -> Result<Option<u64>> {
        self.get_u64(cf::META, meta::LATEST_HEIGHT)
    }

    fn latest_block(&self) -> Result<Option<Block>> {
        match self.latest_height()? {
            Some(height) => self.get_block(height),
            None => Ok(None),
        }
    }
}

impl ChainStore for RocksStorage {
    fn get_mmr_node(&self, pos: u64) -> Result<Option<Hash>> {
        match self.get_cf(cf::MMR, &pos.to_be_bytes())? {
            Some(bytes) => {
                if bytes.len() != 32 {
                    return Err(Error::storage("invalid hash encoding"));
                }
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&bytes);
                Ok(Some(Hash::from_bytes(arr)))
            }
            None => Ok(None),
        }
    }

    fn put_mmr_node(&self, pos: u64, hash: Hash) -> Result<()> {
        self.put_cf(cf::MMR, &pos.to_be_bytes(), hash.as_bytes())
    }

    fn mmr_size(&self) -> Result<u64> {
        self.get_u64(cf::META, meta::MMR_SIZE)
            .map(|o| o.unwrap_or(0))
    }

    fn mmr_leaf_count(&self) -> Result<u64> {
        self.get_u64(cf::META, meta::MMR_LEAF_COUNT)
            .map(|o| o.unwrap_or(0))
    }

    fn set_mmr_meta(&self, size: u64, leaf_count: u64) -> Result<()> {
        let cf = self
            .db
            .cf_handle(cf::META)
            .ok_or_else(|| Error::storage("missing meta cf"))?;

        let mut batch = WriteBatch::default();
        batch.put_cf(&cf, meta::MMR_SIZE, size.to_be_bytes());
        batch.put_cf(&cf, meta::MMR_LEAF_COUNT, leaf_count.to_be_bytes());

        self.db
            .write(batch)
            .map_err(|e| Error::storage(e.to_string()))
    }

    fn flush(&self) -> Result<()> {
        self.db.flush().map_err(|e| Error::storage(e.to_string()))
    }
}

impl crate::batch::BatchWriter for RocksStorage {
    fn commit(&self, batch: crate::batch::StorageBatch) -> Result<()> {
        use crate::batch::BatchOp;

        if batch.is_empty() {
            return Ok(());
        }

        let blocks_cf = self
            .db
            .cf_handle(cf::BLOCKS)
            .ok_or_else(|| Error::storage("missing blocks cf"))?;
        let index_cf = self
            .db
            .cf_handle(cf::BLOCK_INDEX)
            .ok_or_else(|| Error::storage("missing block_index cf"))?;
        let events_cf = self
            .db
            .cf_handle(cf::EVENTS)
            .ok_or_else(|| Error::storage("missing events cf"))?;
        let meta_cf = self
            .db
            .cf_handle(cf::META)
            .ok_or_else(|| Error::storage("missing meta cf"))?;
        let mmr_cf = self
            .db
            .cf_handle(cf::MMR)
            .ok_or_else(|| Error::storage("missing mmr cf"))?;

        let mut wb = WriteBatch::default();
        let mut max_height: Option<u64> = None;

        for op in batch.into_ops() {
            match op {
                BatchOp::PutEvent(event) => {
                    let bytes = bincode::serialize(&event)?;
                    wb.put_cf(&events_cf, event.id().as_hash().as_bytes(), bytes);
                }
                BatchOp::PutBlock(block) => {
                    let height = block.header.height;
                    let hash = block.hash();
                    let block_bytes = bincode::serialize(&block)?;

                    wb.put_cf(&blocks_cf, height.to_be_bytes(), block_bytes);
                    wb.put_cf(&index_cf, hash.as_hash().as_bytes(), height.to_be_bytes());

                    // Store events from block
                    for event in &block.events {
                        let event_bytes = bincode::serialize(event)?;
                        wb.put_cf(&events_cf, event.id().as_hash().as_bytes(), event_bytes);
                    }

                    // Track max height for updating latest
                    max_height = Some(max_height.map_or(height, |h| h.max(height)));
                }
                BatchOp::PutMmrNode { pos, hash } => {
                    wb.put_cf(&mmr_cf, pos.to_be_bytes(), hash.as_bytes());
                }
                BatchOp::SetMmrMeta { size, leaf_count } => {
                    wb.put_cf(&meta_cf, meta::MMR_SIZE, size.to_be_bytes());
                    wb.put_cf(&meta_cf, meta::MMR_LEAF_COUNT, leaf_count.to_be_bytes());
                }
            }
        }

        // Update latest height if blocks were added
        if let Some(height) = max_height {
            wb.put_cf(&meta_cf, meta::LATEST_HEIGHT, height.to_be_bytes());
        }

        self.db
            .write(wb)
            .map_err(|e| Error::storage(e.to_string()))?;

        debug!("Committed batch with max_height={:?}", max_height);
        Ok(())
    }
}

impl crate::batch::BulkReader for RocksStorage {
    fn get_events(&self, ids: &[EventId]) -> Result<Vec<Option<AuditEvent>>> {
        ids.iter().map(|id| self.get_event(id)).collect()
    }

    fn get_block_range(&self, start: u64, end: u64) -> Result<Vec<Block>> {
        let mut blocks = Vec::with_capacity((end - start) as usize);
        for height in start..end {
            if let Some(block) = self.get_block(height)? {
                blocks.push(block);
            }
        }
        Ok(blocks)
    }

    fn get_mmr_nodes(&self, positions: &[u64]) -> Result<Vec<Option<Hash>>> {
        positions
            .iter()
            .map(|pos| self.get_mmr_node(*pos))
            .collect()
    }
}

/// Adapter to use RocksStorage as an MmrStore.
/// Note: This is designed for use by the consensus layer but not yet in use.
#[allow(dead_code)]
#[derive(Clone)]
pub struct RocksMmrStore {
    storage: RocksStorage,
    size: u64,
}

#[allow(dead_code)]
impl RocksMmrStore {
    /// Create from existing storage.
    pub fn new(storage: RocksStorage) -> Result<Self> {
        let size = storage.mmr_size()?;
        Ok(Self { storage, size })
    }
}

impl MmrStore for RocksMmrStore {
    fn get(&self, pos: u64) -> Result<Option<Hash>> {
        self.storage.get_mmr_node(pos)
    }

    fn insert(&mut self, pos: u64, hash: Hash) -> Result<()> {
        self.storage.put_mmr_node(pos, hash)?;
        if pos >= self.size {
            self.size = pos + 1;
        }
        Ok(())
    }

    fn size(&self) -> u64 {
        self.size
    }

    fn set_size(&mut self, size: u64) {
        self.size = size;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use moloch_core::{
        block::{BlockBuilder, SealerId},
        crypto::SecretKey,
        event::{ActorId, ActorKind, EventType, ResourceId, ResourceKind},
    };

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

    #[test]
    fn test_event_storage() {
        let storage = RocksStorage::open_temp().unwrap();
        let key = SecretKey::generate();
        let event = test_event(&key);
        let id = event.id();

        assert!(!storage.event_exists(&id).unwrap());

        storage.put_event(&event).unwrap();
        assert!(storage.event_exists(&id).unwrap());

        let retrieved = storage.get_event(&id).unwrap().unwrap();
        assert_eq!(retrieved.id(), id);
    }

    #[test]
    fn test_block_storage() {
        let storage = RocksStorage::open_temp().unwrap();
        let key = SecretKey::generate();
        let sealer = SealerId::new(key.public_key());

        let event = test_event(&key);
        let block = BlockBuilder::new(sealer).events(vec![event]).seal(&key);

        storage.put_block(&block).unwrap();

        let by_height = storage.get_block(0).unwrap().unwrap();
        assert_eq!(by_height.hash(), block.hash());

        let by_hash = storage.get_block_by_hash(&block.hash()).unwrap().unwrap();
        assert_eq!(by_hash.header.height, 0);

        assert_eq!(storage.latest_height().unwrap(), Some(0));
    }

    #[test]
    fn test_mmr_storage() {
        let storage = RocksStorage::open_temp().unwrap();

        let h1 = moloch_core::hash(b"node1");
        let h2 = moloch_core::hash(b"node2");

        storage.put_mmr_node(0, h1).unwrap();
        storage.put_mmr_node(1, h2).unwrap();
        storage.set_mmr_meta(2, 2).unwrap();

        assert_eq!(storage.get_mmr_node(0).unwrap(), Some(h1));
        assert_eq!(storage.get_mmr_node(1).unwrap(), Some(h2));
        assert_eq!(storage.mmr_size().unwrap(), 2);
        assert_eq!(storage.mmr_leaf_count().unwrap(), 2);
    }

    #[test]
    fn test_block_chain() {
        let storage = RocksStorage::open_temp().unwrap();
        let key = SecretKey::generate();
        let sealer = SealerId::new(key.public_key());

        let genesis = BlockBuilder::new(sealer.clone())
            .events(vec![test_event(&key)])
            .seal(&key);
        storage.put_block(&genesis).unwrap();

        let block1 = BlockBuilder::new(sealer.clone())
            .parent(genesis.header.clone())
            .events(vec![test_event(&key)])
            .seal(&key);
        storage.put_block(&block1).unwrap();

        let block2 = BlockBuilder::new(sealer)
            .parent(block1.header.clone())
            .events(vec![test_event(&key)])
            .seal(&key);
        storage.put_block(&block2).unwrap();

        assert_eq!(storage.latest_height().unwrap(), Some(2));

        assert!(storage.get_block(0).unwrap().is_some());
        assert!(storage.get_block(1).unwrap().is_some());
        assert!(storage.get_block(2).unwrap().is_some());
        assert!(storage.get_block(3).unwrap().is_none());
    }

    #[test]
    fn test_batch_commit() {
        use crate::batch::{BatchWriter, StorageBatch};

        let storage = RocksStorage::open_temp().unwrap();
        let key = SecretKey::generate();
        let sealer = SealerId::new(key.public_key());

        let event1 = test_event(&key);
        let event2 = test_event(&key);
        let block = BlockBuilder::new(sealer)
            .events(vec![test_event(&key)])
            .seal(&key);

        let id1 = event1.id();
        let id2 = event2.id();

        let mut batch = StorageBatch::new();
        batch
            .put_event(event1)
            .put_event(event2)
            .put_block(block.clone())
            .put_mmr_node(0, moloch_core::hash(b"node0"))
            .set_mmr_meta(1, 1);

        // Nothing stored yet
        assert!(!storage.event_exists(&id1).unwrap());
        assert!(!storage.event_exists(&id2).unwrap());
        assert!(storage.get_block(0).unwrap().is_none());

        // Commit atomically
        storage.commit(batch).unwrap();

        // Now everything is stored
        assert!(storage.event_exists(&id1).unwrap());
        assert!(storage.event_exists(&id2).unwrap());
        assert!(storage.get_block(0).unwrap().is_some());
        assert_eq!(storage.mmr_size().unwrap(), 1);
        assert_eq!(storage.mmr_leaf_count().unwrap(), 1);
    }

    #[test]
    fn test_bulk_read() {
        use crate::batch::BulkReader;
        use moloch_core::EventId;

        let storage = RocksStorage::open_temp().unwrap();
        let key = SecretKey::generate();
        let sealer = SealerId::new(key.public_key());

        // Store some events
        let event1 = test_event(&key);
        let event2 = test_event(&key);
        let id1 = event1.id();
        let id2 = event2.id();
        // Create a fake ID that definitely doesn't exist
        let missing_id = EventId(moloch_core::hash(b"nonexistent_event"));

        storage.put_event(&event1).unwrap();
        storage.put_event(&event2).unwrap();

        // Bulk read
        let results = storage.get_events(&[id1, id2, missing_id]).unwrap();
        assert_eq!(results.len(), 3);
        assert!(results[0].is_some());
        assert!(results[1].is_some());
        assert!(results[2].is_none());

        // Store some blocks
        let genesis = BlockBuilder::new(sealer.clone())
            .events(vec![test_event(&key)])
            .seal(&key);
        storage.put_block(&genesis).unwrap();

        let block1 = BlockBuilder::new(sealer.clone())
            .parent(genesis.header.clone())
            .events(vec![test_event(&key)])
            .seal(&key);
        storage.put_block(&block1).unwrap();

        let block2 = BlockBuilder::new(sealer)
            .parent(block1.header.clone())
            .events(vec![test_event(&key)])
            .seal(&key);
        storage.put_block(&block2).unwrap();

        // Read block range
        let blocks = storage.get_block_range(0, 3).unwrap();
        assert_eq!(blocks.len(), 3);
        assert_eq!(blocks[0].header.height, 0);
        assert_eq!(blocks[1].header.height, 1);
        assert_eq!(blocks[2].header.height, 2);

        // Partial range
        let blocks = storage.get_block_range(1, 2).unwrap();
        assert_eq!(blocks.len(), 1);
        assert_eq!(blocks[0].header.height, 1);

        // MMR nodes
        storage.put_mmr_node(0, moloch_core::hash(b"n0")).unwrap();
        storage.put_mmr_node(2, moloch_core::hash(b"n2")).unwrap();

        let nodes = storage.get_mmr_nodes(&[0, 1, 2]).unwrap();
        assert!(nodes[0].is_some());
        assert!(nodes[1].is_none());
        assert!(nodes[2].is_some());
    }

    #[test]
    fn test_empty_batch() {
        use crate::batch::{BatchWriter, StorageBatch};

        let storage = RocksStorage::open_temp().unwrap();
        let batch = StorageBatch::new();

        // Empty batch should succeed
        storage.commit(batch).unwrap();
    }
}
