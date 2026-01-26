//! Snapshot creation and import for fast sync.
//!
//! Snapshots allow new nodes to bootstrap quickly by downloading
//! a complete state dump rather than replaying all blocks.
//!
//! # Format
//!
//! Snapshots are stored as compressed archives containing:
//! - Header: metadata and verification hashes
//! - Blocks: serialized block data
//! - MMR: merkle mountain range nodes
//! - Indexes: secondary indexes (optional)
//!
//! # Example
//!
//! ```ignore
//! use moloch_storage::{RocksStorage, SnapshotBuilder, SnapshotImporter};
//!
//! // Create a snapshot
//! let storage = RocksStorage::open("./data")?;
//! let snapshot = SnapshotBuilder::new(&storage)
//!     .at_height(1000000)
//!     .with_indexes(true)
//!     .build()?;
//!
//! snapshot.write_to_file("snapshot-1000000.msnap")?;
//!
//! // Import a snapshot
//! let importer = SnapshotImporter::new("snapshot-1000000.msnap")?;
//! importer.import_into(&mut new_storage)?;
//! ```

use std::fs::File;
use std::io::{BufReader, BufWriter, Read, Write};
use std::path::Path;

use moloch_core::{BlockHash, Hash};
use serde::{Deserialize, Serialize};

/// Snapshot format version.
pub const SNAPSHOT_VERSION: u32 = 1;

/// Magic bytes for snapshot files.
pub const SNAPSHOT_MAGIC: &[u8; 8] = b"MSNAP001";

/// Snapshot metadata header.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotHeader {
    /// Format version.
    pub version: u32,
    /// Chain ID.
    pub chain_id: String,
    /// Block height at snapshot.
    pub height: u64,
    /// Block hash at snapshot.
    pub block_hash: BlockHash,
    /// MMR root at snapshot.
    pub mmr_root: Hash,
    /// Total number of events.
    pub total_events: u64,
    /// Total number of blocks.
    pub total_blocks: u64,
    /// Whether indexes are included.
    pub includes_indexes: bool,
    /// Uncompressed data size.
    pub uncompressed_size: u64,
    /// Hash of all data (for integrity check).
    pub data_hash: Hash,
    /// Timestamp of snapshot creation.
    pub created_at: i64,
}

impl SnapshotHeader {
    /// Verify the header is valid.
    pub fn validate(&self) -> Result<()> {
        if self.version != SNAPSHOT_VERSION {
            return Err(SnapshotError::UnsupportedVersion(self.version));
        }
        if self.height == 0 && self.total_blocks > 0 {
            return Err(SnapshotError::InvalidHeader(
                "height is 0 but blocks exist".to_string(),
            ));
        }
        Ok(())
    }
}

/// Errors during snapshot operations.
#[derive(Debug, thiserror::Error)]
pub enum SnapshotError {
    /// IO error.
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    /// Serialization error.
    #[error("serialization error: {0}")]
    Serialization(String),

    /// Invalid snapshot format.
    #[error("invalid snapshot: {0}")]
    InvalidFormat(String),

    /// Unsupported version.
    #[error("unsupported snapshot version: {0}")]
    UnsupportedVersion(u32),

    /// Invalid header.
    #[error("invalid header: {0}")]
    InvalidHeader(String),

    /// Data integrity check failed.
    #[error("data integrity check failed: expected {expected}, got {actual}")]
    IntegrityError {
        /// Expected hash.
        expected: Hash,
        /// Actual hash.
        actual: Hash,
    },

    /// Storage error.
    #[error("storage error: {0}")]
    Storage(String),
}

/// Result type for snapshot operations.
pub type Result<T> = std::result::Result<T, SnapshotError>;

/// Snapshot builder for creating snapshots from storage.
pub struct SnapshotBuilder<'a, S> {
    storage: &'a S,
    height: Option<u64>,
    include_indexes: bool,
    chain_id: String,
}

impl<'a, S> SnapshotBuilder<'a, S> {
    /// Create a new snapshot builder.
    pub fn new(storage: &'a S) -> Self {
        Self {
            storage,
            height: None,
            include_indexes: false,
            chain_id: "moloch-mainnet".to_string(),
        }
    }

    /// Set the snapshot height.
    pub fn at_height(mut self, height: u64) -> Self {
        self.height = Some(height);
        self
    }

    /// Include indexes in the snapshot.
    pub fn with_indexes(mut self, include: bool) -> Self {
        self.include_indexes = include;
        self
    }

    /// Set the chain ID.
    pub fn chain_id(mut self, id: impl Into<String>) -> Self {
        self.chain_id = id.into();
        self
    }
}

/// A complete snapshot ready for writing.
pub struct Snapshot {
    /// Snapshot header.
    pub header: SnapshotHeader,
    /// Serialized blocks data.
    blocks_data: Vec<u8>,
    /// Serialized MMR data.
    mmr_data: Vec<u8>,
    /// Serialized index data (optional).
    index_data: Option<Vec<u8>>,
}

impl Snapshot {
    /// Create a new snapshot with the given data.
    pub fn new(
        header: SnapshotHeader,
        blocks_data: Vec<u8>,
        mmr_data: Vec<u8>,
        index_data: Option<Vec<u8>>,
    ) -> Self {
        Self {
            header,
            blocks_data,
            mmr_data,
            index_data,
        }
    }

    /// Write snapshot to a file.
    pub fn write_to_file(&self, path: impl AsRef<Path>) -> Result<()> {
        let file = File::create(path)?;
        let mut writer = BufWriter::new(file);
        self.write(&mut writer)
    }

    /// Write snapshot to a writer.
    pub fn write<W: Write>(&self, writer: &mut W) -> Result<()> {
        // Write magic bytes
        writer.write_all(SNAPSHOT_MAGIC)?;

        // Write header
        let header_bytes = bincode::serialize(&self.header)
            .map_err(|e| SnapshotError::Serialization(e.to_string()))?;
        let header_len = header_bytes.len() as u32;
        writer.write_all(&header_len.to_le_bytes())?;
        writer.write_all(&header_bytes)?;

        // Write blocks data
        let blocks_len = self.blocks_data.len() as u64;
        writer.write_all(&blocks_len.to_le_bytes())?;
        writer.write_all(&self.blocks_data)?;

        // Write MMR data
        let mmr_len = self.mmr_data.len() as u64;
        writer.write_all(&mmr_len.to_le_bytes())?;
        writer.write_all(&self.mmr_data)?;

        // Write index data if present
        if let Some(ref index_data) = self.index_data {
            let index_len = index_data.len() as u64;
            writer.write_all(&index_len.to_le_bytes())?;
            writer.write_all(index_data)?;
        } else {
            writer.write_all(&0u64.to_le_bytes())?;
        }

        writer.flush()?;
        Ok(())
    }

    /// Total size of the snapshot in bytes.
    pub fn size(&self) -> usize {
        SNAPSHOT_MAGIC.len()
            + 4 // header length
            + bincode::serialized_size(&self.header).unwrap_or(0) as usize
            + 8 + self.blocks_data.len()
            + 8 + self.mmr_data.len()
            + 8 + self.index_data.as_ref().map(|d| d.len()).unwrap_or(0)
    }
}

/// Snapshot reader for importing snapshots.
pub struct SnapshotReader {
    /// Snapshot header.
    pub header: SnapshotHeader,
    /// Blocks data.
    blocks_data: Vec<u8>,
    /// MMR data.
    mmr_data: Vec<u8>,
    /// Index data.
    index_data: Option<Vec<u8>>,
}

impl SnapshotReader {
    /// Open a snapshot file for reading.
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let file = File::open(path)?;
        let mut reader = BufReader::new(file);
        Self::read(&mut reader)
    }

    /// Read a snapshot from a reader.
    pub fn read<R: Read>(reader: &mut R) -> Result<Self> {
        // Read and verify magic bytes
        let mut magic = [0u8; 8];
        reader.read_exact(&mut magic)?;
        if &magic != SNAPSHOT_MAGIC {
            return Err(SnapshotError::InvalidFormat(
                "invalid magic bytes".to_string(),
            ));
        }

        // Read header
        let mut header_len_bytes = [0u8; 4];
        reader.read_exact(&mut header_len_bytes)?;
        let header_len = u32::from_le_bytes(header_len_bytes) as usize;

        let mut header_bytes = vec![0u8; header_len];
        reader.read_exact(&mut header_bytes)?;
        let header: SnapshotHeader = bincode::deserialize(&header_bytes)
            .map_err(|e| SnapshotError::Serialization(e.to_string()))?;
        header.validate()?;

        // Read blocks data
        let mut blocks_len_bytes = [0u8; 8];
        reader.read_exact(&mut blocks_len_bytes)?;
        let blocks_len = u64::from_le_bytes(blocks_len_bytes) as usize;

        let mut blocks_data = vec![0u8; blocks_len];
        reader.read_exact(&mut blocks_data)?;

        // Read MMR data
        let mut mmr_len_bytes = [0u8; 8];
        reader.read_exact(&mut mmr_len_bytes)?;
        let mmr_len = u64::from_le_bytes(mmr_len_bytes) as usize;

        let mut mmr_data = vec![0u8; mmr_len];
        reader.read_exact(&mut mmr_data)?;

        // Read index data
        let mut index_len_bytes = [0u8; 8];
        reader.read_exact(&mut index_len_bytes)?;
        let index_len = u64::from_le_bytes(index_len_bytes) as usize;

        let index_data = if index_len > 0 {
            let mut data = vec![0u8; index_len];
            reader.read_exact(&mut data)?;
            Some(data)
        } else {
            None
        };

        Ok(Self {
            header,
            blocks_data,
            mmr_data,
            index_data,
        })
    }

    /// Verify data integrity.
    pub fn verify(&self) -> Result<()> {
        // Compute hash of all data
        let mut hasher_data = Vec::new();
        hasher_data.extend(&self.blocks_data);
        hasher_data.extend(&self.mmr_data);
        if let Some(ref index_data) = self.index_data {
            hasher_data.extend(index_data);
        }

        let actual_hash = moloch_core::hash(&hasher_data);
        if actual_hash != self.header.data_hash {
            return Err(SnapshotError::IntegrityError {
                expected: self.header.data_hash,
                actual: actual_hash,
            });
        }

        Ok(())
    }

    /// Get the snapshot height.
    pub fn height(&self) -> u64 {
        self.header.height
    }

    /// Get the blocks data.
    pub fn blocks_data(&self) -> &[u8] {
        &self.blocks_data
    }

    /// Get the MMR data.
    pub fn mmr_data(&self) -> &[u8] {
        &self.mmr_data
    }

    /// Get the index data.
    pub fn index_data(&self) -> Option<&[u8]> {
        self.index_data.as_deref()
    }
}

/// Progress callback for import operations.
pub type ProgressCallback = Box<dyn Fn(ImportProgress) + Send>;

/// Import progress information.
#[derive(Debug, Clone)]
pub struct ImportProgress {
    /// Current phase.
    pub phase: ImportPhase,
    /// Items processed.
    pub processed: u64,
    /// Total items.
    pub total: u64,
    /// Bytes processed.
    pub bytes_processed: u64,
    /// Total bytes.
    pub bytes_total: u64,
}

impl ImportProgress {
    /// Get progress as percentage.
    pub fn percent(&self) -> f64 {
        if self.total == 0 {
            100.0
        } else {
            (self.processed as f64 / self.total as f64) * 100.0
        }
    }
}

/// Phases of snapshot import.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImportPhase {
    /// Verifying snapshot integrity.
    Verifying,
    /// Importing blocks.
    ImportingBlocks,
    /// Importing MMR nodes.
    ImportingMmr,
    /// Importing indexes.
    ImportingIndexes,
    /// Finalizing import.
    Finalizing,
    /// Import complete.
    Complete,
}

/// Configuration for state pruning.
#[derive(Debug, Clone)]
pub struct PruneConfig {
    /// Keep blocks from this height onwards.
    pub keep_from_height: u64,
    /// Keep at least this many recent blocks.
    pub keep_recent_blocks: u64,
    /// Prune MMR nodes for old blocks.
    pub prune_mmr: bool,
    /// Prune indexes for old events.
    pub prune_indexes: bool,
}

impl Default for PruneConfig {
    fn default() -> Self {
        Self {
            keep_from_height: 0,
            keep_recent_blocks: 10000,
            prune_mmr: false,
            prune_indexes: true,
        }
    }
}

/// Statistics from a pruning operation.
#[derive(Debug, Clone, Default)]
pub struct PruneStats {
    /// Blocks pruned.
    pub blocks_pruned: u64,
    /// Events pruned.
    pub events_pruned: u64,
    /// MMR nodes pruned.
    pub mmr_nodes_pruned: u64,
    /// Index entries pruned.
    pub index_entries_pruned: u64,
    /// Bytes freed.
    pub bytes_freed: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_snapshot_header_validation() {
        let header = SnapshotHeader {
            version: SNAPSHOT_VERSION,
            chain_id: "test".to_string(),
            height: 1000,
            block_hash: BlockHash(Hash::ZERO),
            mmr_root: Hash::ZERO,
            total_events: 50000,
            total_blocks: 1000,
            includes_indexes: false,
            uncompressed_size: 1024 * 1024,
            data_hash: Hash::ZERO,
            created_at: 0,
        };

        assert!(header.validate().is_ok());
    }

    #[test]
    fn test_snapshot_header_invalid_version() {
        let header = SnapshotHeader {
            version: 999,
            chain_id: "test".to_string(),
            height: 0,
            block_hash: BlockHash(Hash::ZERO),
            mmr_root: Hash::ZERO,
            total_events: 0,
            total_blocks: 0,
            includes_indexes: false,
            uncompressed_size: 0,
            data_hash: Hash::ZERO,
            created_at: 0,
        };

        assert!(matches!(
            header.validate(),
            Err(SnapshotError::UnsupportedVersion(999))
        ));
    }

    #[test]
    fn test_snapshot_roundtrip() {
        let header = SnapshotHeader {
            version: SNAPSHOT_VERSION,
            chain_id: "test".to_string(),
            height: 100,
            block_hash: BlockHash(Hash::ZERO),
            mmr_root: Hash::ZERO,
            total_events: 1000,
            total_blocks: 100,
            includes_indexes: false,
            uncompressed_size: 1024,
            data_hash: Hash::ZERO,
            created_at: 0,
        };

        let snapshot = Snapshot::new(header, vec![1, 2, 3, 4], vec![5, 6, 7, 8], None);

        let mut buffer = Vec::new();
        snapshot.write(&mut buffer).unwrap();

        let mut cursor = std::io::Cursor::new(buffer);
        let reader = SnapshotReader::read(&mut cursor).unwrap();

        assert_eq!(reader.header.height, 100);
        assert_eq!(reader.blocks_data(), &[1, 2, 3, 4]);
        assert_eq!(reader.mmr_data(), &[5, 6, 7, 8]);
    }

    #[test]
    fn test_prune_config_default() {
        let config = PruneConfig::default();
        assert_eq!(config.keep_recent_blocks, 10000);
        assert!(!config.prune_mmr);
    }
}
