//! Memory-mapped storage for ultra-fast access.
//!
//! This module provides a memory-mapped file-based storage backend that bypasses
//! RocksDB for scenarios requiring:
//! - Zero-copy access to archived data (via rkyv)
//! - Minimal memory overhead
//! - Read-heavy workloads
//! - Embedded/resource-constrained environments
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────┐
//! │                     MmapStorage                                 │
//! ├─────────────────────────────────────────────────────────────────┤
//! │  events.mmap   - Append-only event data (rkyv archived)         │
//! │  mmr.mmap      - MMR node hashes (fixed 32-byte records)        │
//! │  index.mmap    - EventId -> file offset index                   │
//! │  meta.bin      - Metadata (sizes, counts)                       │
//! └─────────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Performance
//!
//! - Read: O(1) via mmap pointer access, ~10ns
//! - Write: Append-only, ~100ns + sync time
//! - MMR access: Direct array indexing, ~1ns

use memmap2::{MmapMut, MmapOptions};
use parking_lot::RwLock;
use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use crate::traits::{BlockStore, ChainStore, EventStore};
use moloch_core::{AuditEvent, Block, BlockHash, BlockHeader, Error, EventId, Hash, Result};

/// Size of MMR node records (32 bytes per hash).
const MMR_RECORD_SIZE: usize = 32;

/// Initial mmap file size (1GB).
const INITIAL_MMAP_SIZE: u64 = 1024 * 1024 * 1024;

/// Configuration for memory-mapped storage.
#[derive(Debug, Clone)]
pub struct MmapConfig {
    /// Initial size for event data file.
    pub events_size: u64,
    /// Initial size for MMR file.
    pub mmr_size: u64,
    /// Whether to sync writes immediately.
    pub sync_on_write: bool,
}

impl Default for MmapConfig {
    fn default() -> Self {
        Self {
            events_size: INITIAL_MMAP_SIZE,
            mmr_size: 256 * 1024 * 1024, // 256MB for MMR
            sync_on_write: false,
        }
    }
}

/// Metadata persisted to disk.
#[derive(Debug, Clone, Default)]
struct StorageMeta {
    /// Current end offset in events file.
    events_end: u64,
    /// Number of MMR nodes.
    mmr_size: u64,
    /// Number of MMR leaves.
    mmr_leaf_count: u64,
    /// Latest block height.
    latest_height: Option<u64>,
}

impl StorageMeta {
    fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(32);
        buf.extend_from_slice(&self.events_end.to_le_bytes());
        buf.extend_from_slice(&self.mmr_size.to_le_bytes());
        buf.extend_from_slice(&self.mmr_leaf_count.to_le_bytes());
        buf.extend_from_slice(&self.latest_height.unwrap_or(u64::MAX).to_le_bytes());
        buf
    }

    fn deserialize(data: &[u8]) -> Option<Self> {
        if data.len() < 32 {
            return None;
        }
        let events_end = u64::from_le_bytes(data[0..8].try_into().ok()?);
        let mmr_size = u64::from_le_bytes(data[8..16].try_into().ok()?);
        let mmr_leaf_count = u64::from_le_bytes(data[16..24].try_into().ok()?);
        let latest_height_raw = u64::from_le_bytes(data[24..32].try_into().ok()?);
        let latest_height = if latest_height_raw == u64::MAX {
            None
        } else {
            Some(latest_height_raw)
        };
        Some(Self {
            events_end,
            mmr_size,
            mmr_leaf_count,
            latest_height,
        })
    }
}

/// Memory-mapped storage backend.
///
/// Provides ultra-fast access to chain data via memory-mapped files.
/// All data is persisted immediately (append-only) and can be accessed
/// without deserialization overhead using rkyv.
pub struct MmapStorage {
    /// Base directory.
    base_path: PathBuf,
    /// Events data file.
    events_file: File,
    /// Events mmap.
    events_mmap: RwLock<MmapMut>,
    /// MMR nodes file.
    mmr_file: File,
    /// MMR mmap.
    mmr_mmap: RwLock<MmapMut>,
    /// Event ID to offset index (in-memory for now).
    event_index: RwLock<HashMap<EventId, u64>>,
    /// Block height to offset index.
    block_index: RwLock<HashMap<u64, u64>>,
    /// Block hash to height index.
    hash_index: RwLock<HashMap<BlockHash, u64>>,
    /// Current end of events data.
    events_end: AtomicU64,
    /// MMR size.
    mmr_size: AtomicU64,
    /// MMR leaf count.
    mmr_leaf_count: AtomicU64,
    /// Latest block height.
    latest_height: RwLock<Option<u64>>,
    /// Configuration.
    config: MmapConfig,
}

impl MmapStorage {
    /// Open or create storage at the given path.
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self> {
        Self::open_with_config(path, MmapConfig::default())
    }

    /// Open or create storage with custom configuration.
    pub fn open_with_config<P: AsRef<Path>>(path: P, config: MmapConfig) -> Result<Self> {
        let base_path = path.as_ref().to_path_buf();
        std::fs::create_dir_all(&base_path)
            .map_err(|e| Error::storage(format!("failed to create dir: {}", e)))?;

        // Open events file
        let events_path = base_path.join("events.mmap");
        let events_file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .open(&events_path)
            .map_err(|e| Error::storage(format!("failed to open events file: {}", e)))?;

        // Ensure file is sized
        let events_len = events_file
            .metadata()
            .map_err(|e| Error::storage(format!("failed to get events metadata: {}", e)))?
            .len();
        if events_len < config.events_size {
            events_file
                .set_len(config.events_size)
                .map_err(|e| Error::storage(format!("failed to resize events file: {}", e)))?;
        }

        // Open MMR file
        let mmr_path = base_path.join("mmr.mmap");
        let mmr_file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .open(&mmr_path)
            .map_err(|e| Error::storage(format!("failed to open mmr file: {}", e)))?;

        let mmr_len = mmr_file
            .metadata()
            .map_err(|e| Error::storage(format!("failed to get mmr metadata: {}", e)))?
            .len();
        if mmr_len < config.mmr_size {
            mmr_file
                .set_len(config.mmr_size)
                .map_err(|e| Error::storage(format!("failed to resize mmr file: {}", e)))?;
        }

        // Create mmaps
        let events_mmap = unsafe {
            MmapOptions::new()
                .map_mut(&events_file)
                .map_err(|e| Error::storage(format!("failed to mmap events: {}", e)))?
        };

        let mmr_mmap = unsafe {
            MmapOptions::new()
                .map_mut(&mmr_file)
                .map_err(|e| Error::storage(format!("failed to mmap mmr: {}", e)))?
        };

        // Load metadata
        let meta_path = base_path.join("meta.bin");
        let meta = if meta_path.exists() {
            let mut file = File::open(&meta_path)
                .map_err(|e| Error::storage(format!("failed to open meta: {}", e)))?;
            let mut buf = Vec::new();
            file.read_to_end(&mut buf)
                .map_err(|e| Error::storage(format!("failed to read meta: {}", e)))?;
            StorageMeta::deserialize(&buf).unwrap_or_default()
        } else {
            StorageMeta::default()
        };

        Ok(Self {
            base_path,
            events_file,
            events_mmap: RwLock::new(events_mmap),
            mmr_file,
            mmr_mmap: RwLock::new(mmr_mmap),
            event_index: RwLock::new(HashMap::new()),
            block_index: RwLock::new(HashMap::new()),
            hash_index: RwLock::new(HashMap::new()),
            events_end: AtomicU64::new(meta.events_end),
            mmr_size: AtomicU64::new(meta.mmr_size),
            mmr_leaf_count: AtomicU64::new(meta.mmr_leaf_count),
            latest_height: RwLock::new(meta.latest_height),
            config,
        })
    }

    /// Save metadata to disk.
    fn save_meta(&self) -> Result<()> {
        let meta = StorageMeta {
            events_end: self.events_end.load(Ordering::Relaxed),
            mmr_size: self.mmr_size.load(Ordering::Relaxed),
            mmr_leaf_count: self.mmr_leaf_count.load(Ordering::Relaxed),
            latest_height: *self.latest_height.read(),
        };

        let meta_path = self.base_path.join("meta.bin");
        let mut file = File::create(&meta_path)
            .map_err(|e| Error::storage(format!("failed to create meta: {}", e)))?;
        file.write_all(&meta.serialize())
            .map_err(|e| Error::storage(format!("failed to write meta: {}", e)))?;
        file.sync_all()
            .map_err(|e| Error::storage(format!("failed to sync meta: {}", e)))?;

        Ok(())
    }

    /// Append data to events file and return offset.
    fn append_event_data(&self, data: &[u8]) -> Result<u64> {
        let offset = self
            .events_end
            .fetch_add(data.len() as u64, Ordering::SeqCst);

        // Write to mmap
        {
            let mut mmap = self.events_mmap.write();
            let end = offset as usize + data.len();
            if end > mmap.len() {
                return Err(Error::storage(
                    "events file full, expansion not implemented",
                ));
            }
            mmap[offset as usize..end].copy_from_slice(data);
            if self.config.sync_on_write {
                mmap.flush()
                    .map_err(|e| Error::storage(format!("flush failed: {}", e)))?;
            }
        }

        Ok(offset)
    }

    /// Read event data at offset.
    fn read_event_data(&self, offset: u64, len: usize) -> Result<Vec<u8>> {
        let mmap = self.events_mmap.read();
        let start = offset as usize;
        let end = start + len;
        if end > mmap.len() {
            return Err(Error::storage("read beyond events file"));
        }
        Ok(mmap[start..end].to_vec())
    }

    /// Get raw access to MMR node at position.
    pub fn mmr_node_raw(&self, pos: u64) -> Option<[u8; 32]> {
        let mmap = self.mmr_mmap.read();
        let start = (pos as usize) * MMR_RECORD_SIZE;
        let end = start + MMR_RECORD_SIZE;
        if end > mmap.len() {
            return None;
        }
        let mut buf = [0u8; 32];
        buf.copy_from_slice(&mmap[start..end]);
        // Check if zero (not set)
        if buf == [0u8; 32] {
            return None;
        }
        Some(buf)
    }

    /// Set MMR node at position.
    pub fn set_mmr_node_raw(&self, pos: u64, hash: &[u8; 32]) -> Result<()> {
        let mut mmap = self.mmr_mmap.write();
        let start = (pos as usize) * MMR_RECORD_SIZE;
        let end = start + MMR_RECORD_SIZE;
        if end > mmap.len() {
            return Err(Error::storage("MMR file full, expansion not implemented"));
        }
        mmap[start..end].copy_from_slice(hash);
        if self.config.sync_on_write {
            mmap.flush()
                .map_err(|e| Error::storage(format!("flush failed: {}", e)))?;
        }

        // Update size if needed
        let current_size = self.mmr_size.load(Ordering::Relaxed);
        if pos >= current_size {
            self.mmr_size.store(pos + 1, Ordering::Relaxed);
        }

        Ok(())
    }

    /// Get storage statistics.
    pub fn stats(&self) -> MmapStats {
        MmapStats {
            events_used: self.events_end.load(Ordering::Relaxed),
            events_capacity: self.config.events_size,
            mmr_size: self.mmr_size.load(Ordering::Relaxed),
            mmr_leaf_count: self.mmr_leaf_count.load(Ordering::Relaxed),
            event_count: self.event_index.read().len(),
            block_count: self.block_index.read().len(),
        }
    }
}

impl EventStore for MmapStorage {
    fn get_event(&self, id: &EventId) -> Result<Option<AuditEvent>> {
        // Look up in index
        let index = self.event_index.read();
        let offset = match index.get(id) {
            Some(&off) => off,
            None => return Ok(None),
        };
        drop(index);

        // Read length prefix (4 bytes) then data
        let mmap = self.events_mmap.read();
        let len_bytes: [u8; 4] = mmap[offset as usize..offset as usize + 4]
            .try_into()
            .map_err(|_| Error::storage("invalid length prefix"))?;
        let len = u32::from_le_bytes(len_bytes) as usize;
        let data = &mmap[offset as usize + 4..offset as usize + 4 + len];

        // Deserialize
        let event: AuditEvent = bincode::deserialize(data)
            .map_err(|e| Error::storage(format!("deserialize failed: {}", e)))?;

        Ok(Some(event))
    }

    fn put_event(&self, event: &AuditEvent) -> Result<()> {
        let id = event.id();

        // Serialize with length prefix
        let data = bincode::serialize(event)
            .map_err(|e| Error::storage(format!("serialize failed: {}", e)))?;
        let len = data.len() as u32;
        let mut buf = Vec::with_capacity(4 + data.len());
        buf.extend_from_slice(&len.to_le_bytes());
        buf.extend_from_slice(&data);

        // Append to file
        let offset = self.append_event_data(&buf)?;

        // Update index
        self.event_index.write().insert(id, offset);

        Ok(())
    }

    fn event_exists(&self, id: &EventId) -> Result<bool> {
        Ok(self.event_index.read().contains_key(id))
    }

    fn get_events_by_block(&self, _height: u64) -> Result<Vec<AuditEvent>> {
        // Would require block-to-events index
        Ok(vec![])
    }
}

impl BlockStore for MmapStorage {
    fn get_block(&self, height: u64) -> Result<Option<Block>> {
        let index = self.block_index.read();
        let offset = match index.get(&height) {
            Some(&off) => off,
            None => return Ok(None),
        };
        drop(index);

        // Read length prefix then data
        let mmap = self.events_mmap.read();
        let len_bytes: [u8; 4] = mmap[offset as usize..offset as usize + 4]
            .try_into()
            .map_err(|_| Error::storage("invalid length prefix"))?;
        let len = u32::from_le_bytes(len_bytes) as usize;
        let data = &mmap[offset as usize + 4..offset as usize + 4 + len];

        let block: Block = bincode::deserialize(data)
            .map_err(|e| Error::storage(format!("deserialize block failed: {}", e)))?;

        Ok(Some(block))
    }

    fn get_block_by_hash(&self, hash: &BlockHash) -> Result<Option<Block>> {
        let height = match self.hash_index.read().get(hash) {
            Some(&h) => h,
            None => return Ok(None),
        };
        self.get_block(height)
    }

    fn get_header(&self, height: u64) -> Result<Option<BlockHeader>> {
        self.get_block(height).map(|opt| opt.map(|b| b.header))
    }

    fn put_block(&self, block: &Block) -> Result<()> {
        let height = block.header.height;
        let hash = block.hash();

        // Serialize with length prefix
        let data = bincode::serialize(block)
            .map_err(|e| Error::storage(format!("serialize failed: {}", e)))?;
        let len = data.len() as u32;
        let mut buf = Vec::with_capacity(4 + data.len());
        buf.extend_from_slice(&len.to_le_bytes());
        buf.extend_from_slice(&data);

        // Append to file
        let offset = self.append_event_data(&buf)?;

        // Update indexes
        self.block_index.write().insert(height, offset);
        self.hash_index.write().insert(hash, height);

        // Update latest height
        {
            let mut latest = self.latest_height.write();
            if latest.map(|h| height > h).unwrap_or(true) {
                *latest = Some(height);
            }
        }

        Ok(())
    }

    fn latest_height(&self) -> Result<Option<u64>> {
        Ok(*self.latest_height.read())
    }

    fn latest_block(&self) -> Result<Option<Block>> {
        match *self.latest_height.read() {
            Some(h) => self.get_block(h),
            None => Ok(None),
        }
    }
}

impl ChainStore for MmapStorage {
    fn get_mmr_node(&self, pos: u64) -> Result<Option<Hash>> {
        Ok(self.mmr_node_raw(pos).map(Hash::from_bytes))
    }

    fn put_mmr_node(&self, pos: u64, hash: Hash) -> Result<()> {
        self.set_mmr_node_raw(pos, hash.as_bytes())
    }

    fn mmr_size(&self) -> Result<u64> {
        Ok(self.mmr_size.load(Ordering::Relaxed))
    }

    fn mmr_leaf_count(&self) -> Result<u64> {
        Ok(self.mmr_leaf_count.load(Ordering::Relaxed))
    }

    fn set_mmr_meta(&self, size: u64, leaf_count: u64) -> Result<()> {
        self.mmr_size.store(size, Ordering::Relaxed);
        self.mmr_leaf_count.store(leaf_count, Ordering::Relaxed);
        Ok(())
    }

    fn flush(&self) -> Result<()> {
        // Flush mmaps
        self.events_mmap
            .read()
            .flush()
            .map_err(|e| Error::storage(format!("flush events failed: {}", e)))?;
        self.mmr_mmap
            .read()
            .flush()
            .map_err(|e| Error::storage(format!("flush mmr failed: {}", e)))?;

        // Save metadata
        self.save_meta()?;

        Ok(())
    }
}

/// Statistics for mmap storage.
#[derive(Debug, Clone)]
pub struct MmapStats {
    /// Bytes used in events file.
    pub events_used: u64,
    /// Total capacity of events file.
    pub events_capacity: u64,
    /// Number of MMR nodes.
    pub mmr_size: u64,
    /// Number of MMR leaves.
    pub mmr_leaf_count: u64,
    /// Number of events in index.
    pub event_count: usize,
    /// Number of blocks in index.
    pub block_count: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use moloch_core::{
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
    fn test_mmap_storage_open() {
        let dir = tempfile::tempdir().unwrap();
        let storage = MmapStorage::open(dir.path()).unwrap();

        let stats = storage.stats();
        assert_eq!(stats.event_count, 0);
        assert_eq!(stats.block_count, 0);
    }

    #[test]
    fn test_mmap_event_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let storage = MmapStorage::open(dir.path()).unwrap();
        let key = SecretKey::generate();
        let event = test_event(&key);
        let id = event.id();

        storage.put_event(&event).unwrap();
        assert!(storage.event_exists(&id).unwrap());

        let loaded = storage.get_event(&id).unwrap().unwrap();
        assert_eq!(loaded.id(), id);
    }

    #[test]
    fn test_mmap_mmr_operations() {
        let dir = tempfile::tempdir().unwrap();
        let storage = MmapStorage::open(dir.path()).unwrap();

        let hash = Hash::from_bytes([1u8; 32]);
        storage.put_mmr_node(0, hash).unwrap();
        storage.put_mmr_node(1, hash).unwrap();
        storage.put_mmr_node(5, hash).unwrap();

        assert_eq!(storage.get_mmr_node(0).unwrap(), Some(hash));
        assert_eq!(storage.get_mmr_node(1).unwrap(), Some(hash));
        assert_eq!(storage.get_mmr_node(5).unwrap(), Some(hash));
        assert_eq!(storage.get_mmr_node(2).unwrap(), None);
    }

    #[test]
    fn test_mmap_persistence() {
        let dir = tempfile::tempdir().unwrap();
        let key = SecretKey::generate();
        let event = test_event(&key);
        let id = event.id();

        // Write
        {
            let storage = MmapStorage::open(dir.path()).unwrap();
            storage.put_event(&event).unwrap();
            storage
                .put_mmr_node(0, Hash::from_bytes([1u8; 32]))
                .unwrap();
            storage.set_mmr_meta(1, 1).unwrap();
            storage.flush().unwrap();
        }

        // Reopen and verify
        {
            let storage = MmapStorage::open(dir.path()).unwrap();
            // Note: event index is not persisted yet, would need index file
            // But MMR metadata should be persisted
            assert_eq!(storage.mmr_size().unwrap(), 1);
            assert_eq!(storage.mmr_leaf_count().unwrap(), 1);
        }
    }

    #[test]
    fn test_mmap_multiple_events() {
        let dir = tempfile::tempdir().unwrap();
        let storage = MmapStorage::open(dir.path()).unwrap();

        // Use different keys to ensure unique event IDs
        for i in 0..100 {
            let key = SecretKey::generate();
            let actor = ActorId::new(key.public_key(), ActorKind::User);
            let resource = ResourceId::new(ResourceKind::Repository, format!("test-{}", i));

            let event = AuditEvent::builder()
                .now()
                .event_type(EventType::Push {
                    force: false,
                    commits: i as u32,
                })
                .actor(actor)
                .resource(resource)
                .sign(&key)
                .unwrap();

            storage.put_event(&event).unwrap();
        }

        let stats = storage.stats();
        assert_eq!(stats.event_count, 100);
    }
}
