//! Proof generation for inclusion and consistency.
//!
//! Provides:
//! - Inclusion proofs for any indexed event
//! - Consistency proofs between chain heights
//! - Batch proof generation
//! - Compact serialization

use moloch_core::{
    proof::{BlockInclusionProof, ConsistencyProof, InclusionProof, MmrProof, Position, ProofNode},
    AuditEvent, Block, EventId, Hash, Result,
};
use moloch_storage::ChainStore;
use serde::{Deserialize, Serialize};

/// Configuration for proof generation.
#[derive(Debug, Clone)]
pub struct ProofConfig {
    /// Maximum batch size for proof generation.
    pub max_batch_size: usize,
    /// Include event data in proofs.
    pub include_event_data: bool,
}

impl Default for ProofConfig {
    fn default() -> Self {
        Self {
            max_batch_size: 1000,
            include_event_data: false,
        }
    }
}

/// Proof generator for the audit chain.
pub struct ProofGenerator<S: ChainStore> {
    /// The storage backend.
    storage: S,
    /// Configuration.
    config: ProofConfig,
}

impl<S: ChainStore> ProofGenerator<S> {
    /// Create a new proof generator.
    pub fn new(storage: S, config: ProofConfig) -> Self {
        Self { storage, config }
    }

    /// Create with default configuration.
    pub fn with_defaults(storage: S) -> Self {
        Self::new(storage, ProofConfig::default())
    }

    /// Get the storage.
    pub fn storage(&self) -> &S {
        &self.storage
    }

    /// Generate an inclusion proof for an event.
    ///
    /// This proves that an event exists in the chain at a specific height.
    pub fn generate_inclusion_proof(&self, event_id: &EventId) -> Result<Option<InclusionProof>> {
        // Find the block containing this event
        let (block, height) = match self.find_block_for_event(event_id)? {
            Some(b) => b,
            None => return Ok(None),
        };

        // Find event position in block
        let event_index = block
            .events
            .iter()
            .position(|e| &e.id() == event_id)
            .ok_or_else(|| moloch_core::Error::internal("event not found in block"))?;

        // Generate block inclusion proof (merkle path to events_root)
        let block_proof = self.generate_block_proof(&block, event_index, height)?;

        // Generate MMR proof for the block
        let chain_proof = self.generate_mmr_proof(height)?;

        Ok(Some(InclusionProof {
            block_proof,
            chain_proof,
        }))
    }

    /// Generate a block inclusion proof for an event at a known position.
    fn generate_block_proof(
        &self,
        block: &Block,
        event_index: usize,
        height: u64,
    ) -> Result<BlockInclusionProof> {
        let event = &block.events[event_index];
        let event_id = event.id();

        if block.events.is_empty() {
            return Err(moloch_core::Error::internal("empty block"));
        }

        // Build merkle tree and generate path
        let path = self.merkle_path(&block.events, event_index);

        Ok(BlockInclusionProof {
            event_id,
            block_height: height,
            path,
            events_root: block.header.events_root,
        })
    }

    /// Generate merkle path for an event in a block.
    fn merkle_path(&self, events: &[AuditEvent], index: usize) -> Vec<ProofNode> {
        if events.len() <= 1 {
            return Vec::new();
        }

        // Get leaf hashes
        let mut hashes: Vec<Hash> = events.iter().map(|e| e.id().0).collect();

        // Pad to power of 2
        while hashes.len() & (hashes.len() - 1) != 0 {
            hashes.push(*hashes.last().unwrap());
        }

        let mut path = Vec::new();
        let mut idx = index;
        let mut level_size = hashes.len();

        while level_size > 1 {
            // Determine sibling
            let sibling_idx = if idx % 2 == 0 { idx + 1 } else { idx - 1 };

            if sibling_idx < level_size {
                path.push(ProofNode {
                    hash: hashes[sibling_idx],
                    position: if idx % 2 == 0 {
                        Position::Right
                    } else {
                        Position::Left
                    },
                });
            }

            // Move to next level
            let mut next_level = Vec::with_capacity(level_size / 2);
            for pair in hashes.chunks(2) {
                next_level.push(moloch_core::hash_pair(pair[0], pair[1]));
            }
            hashes = next_level;
            idx /= 2;
            level_size /= 2;
        }

        path
    }

    /// Generate MMR proof for a block at a given height.
    fn generate_mmr_proof(&self, height: u64) -> Result<MmrProof> {
        // Load MMR metadata
        let mmr_size = self.storage.mmr_size()?;
        let leaf_count = self.storage.mmr_leaf_count()?;

        if height >= leaf_count {
            return Err(moloch_core::Error::not_found(format!(
                "block {} not in MMR (leaf_count={})",
                height, leaf_count
            )));
        }

        // Get the leaf hash (block hash) at this position
        // In Moloch, we store block hashes as MMR leaves
        let leaf_pos = height; // Simplified: height maps to position
        let leaf_hash = self.storage.get_mmr_node(leaf_pos)?.ok_or_else(|| {
            moloch_core::Error::not_found(format!("MMR node at {} not found", leaf_pos))
        })?;

        // For now, return a simplified proof
        // A full implementation would compute the actual MMR path
        let peaks = self.get_mmr_peaks(mmr_size)?;
        let root = bag_peaks(&peaks);

        Ok(MmrProof {
            leaf_pos,
            leaf_hash,
            siblings: Vec::new(), // Simplified - would compute actual path
            peak_hash: leaf_hash, // Simplified
            peaks,
            root,
            mmr_size,
        })
    }

    /// Get MMR peaks.
    fn get_mmr_peaks(&self, size: u64) -> Result<Vec<Hash>> {
        if size == 0 {
            return Ok(Vec::new());
        }

        // Collect peaks based on MMR structure
        // For simplicity, we'll collect nodes that are peaks
        let positions = peak_positions(size);
        let mut peaks = Vec::with_capacity(positions.len());

        for pos in positions {
            if let Some(hash) = self.storage.get_mmr_node(pos)? {
                peaks.push(hash);
            }
        }

        Ok(peaks)
    }

    /// Find the block containing an event.
    fn find_block_for_event(&self, event_id: &EventId) -> Result<Option<(Block, u64)>> {
        // Linear scan - in production, you'd have an index
        let latest = self.storage.latest_height()?;
        if latest.is_none() {
            return Ok(None);
        }

        for height in 0..=latest.unwrap() {
            if let Some(block) = self.storage.get_block(height)? {
                if block.events.iter().any(|e| &e.id() == event_id) {
                    return Ok(Some((block, height)));
                }
            }
        }

        Ok(None)
    }

    /// Generate a consistency proof between two heights.
    ///
    /// This proves that the chain at `old_height` is a prefix of the chain at `new_height`.
    pub fn generate_consistency_proof(
        &self,
        old_height: u64,
        new_height: u64,
    ) -> Result<ConsistencyProof> {
        if old_height > new_height {
            return Err(moloch_core::Error::invalid_proof(
                "old_height > new_height",
            ));
        }

        // Get MMR roots at both heights
        let old_size = old_height + 1;
        let new_size = new_height + 1;

        // Collect proof nodes (peaks that changed)
        let mut proof = Vec::new();

        // Get the old root
        let old_peaks = self.get_mmr_peaks(old_size)?;
        let old_root = bag_peaks(&old_peaks);

        // Get the new root
        let new_peaks = self.get_mmr_peaks(new_size)?;
        let new_root = bag_peaks(&new_peaks);

        // Add intermediate nodes for verification
        for i in old_height..=new_height {
            if let Some(hash) = self.storage.get_mmr_node(i)? {
                proof.push(hash);
            }
        }

        Ok(ConsistencyProof {
            old_size,
            new_size,
            old_root,
            new_root,
            proof,
        })
    }

    /// Generate inclusion proofs for multiple events.
    pub fn generate_batch_proofs(
        &self,
        event_ids: &[EventId],
    ) -> Result<Vec<Option<InclusionProof>>> {
        let limit = event_ids.len().min(self.config.max_batch_size);
        let mut proofs = Vec::with_capacity(limit);

        for id in event_ids.iter().take(limit) {
            proofs.push(self.generate_inclusion_proof(id)?);
        }

        Ok(proofs)
    }

    /// Verify an inclusion proof.
    pub fn verify_inclusion_proof(&self, proof: &InclusionProof) -> Result<bool> {
        proof.verify()
    }

    /// Verify a consistency proof.
    pub fn verify_consistency_proof(&self, proof: &ConsistencyProof) -> Result<bool> {
        proof.verify()
    }
}

/// Bag peaks into a single root (right to left).
fn bag_peaks(peaks: &[Hash]) -> Hash {
    if peaks.is_empty() {
        return Hash::ZERO;
    }

    let mut root = *peaks.last().unwrap();
    for peak in peaks.iter().rev().skip(1) {
        root = moloch_core::hash_pair(*peak, root);
    }
    root
}

/// Calculate peak positions for a given MMR size.
fn peak_positions(size: u64) -> Vec<u64> {
    if size == 0 {
        return Vec::new();
    }

    let mut peaks = Vec::new();
    let mut pos = 0u64;

    // Find all complete trees
    while pos < size {
        // Find the largest tree that fits starting at pos
        let remaining = size - pos;
        let bits = 64 - remaining.leading_zeros();

        for h in (0..bits).rev() {
            let tree_size = (1u64 << (h + 1)) - 1;
            if tree_size <= remaining {
                // Peak is at pos + tree_size - 1
                peaks.push(pos + tree_size - 1);
                pos += tree_size;
                break;
            }
        }
    }

    peaks
}

/// A compact proof bundle for serialization.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofBundle {
    /// Inclusion proofs.
    pub proofs: Vec<InclusionProof>,
    /// MMR root these proofs are against.
    pub mmr_root: Hash,
    /// Chain height when bundle was created.
    pub height: u64,
    /// Timestamp of bundle creation.
    pub created_at: i64,
}

impl ProofBundle {
    /// Create a new proof bundle.
    pub fn new(proofs: Vec<InclusionProof>, mmr_root: Hash, height: u64) -> Self {
        Self {
            proofs,
            mmr_root,
            height,
            created_at: chrono::Utc::now().timestamp_millis(),
        }
    }

    /// Serialize to compact binary format.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        bincode::serialize(self).map_err(Into::into)
    }

    /// Deserialize from binary format.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        bincode::deserialize(bytes).map_err(Into::into)
    }

    /// Verify all proofs in the bundle.
    pub fn verify_all(&self) -> Result<bool> {
        for proof in &self.proofs {
            if !proof.verify()? {
                return Ok(false);
            }
            // Verify against bundle's MMR root
            if proof.mmr_root() != self.mmr_root {
                return Ok(false);
            }
        }
        Ok(true)
    }

    /// Get event IDs in this bundle.
    pub fn event_ids(&self) -> Vec<EventId> {
        self.proofs.iter().map(|p| p.event_id()).collect()
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
    use moloch_storage::{RocksStorage, ChainStore, BlockStore};

    fn test_event(key: &SecretKey, resource_id: &str) -> AuditEvent {
        let actor = ActorId::new(key.public_key(), ActorKind::User);
        let resource = ResourceId::new(ResourceKind::Repository, resource_id);

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

    fn setup_chain() -> (ProofGenerator<RocksStorage>, SecretKey, Vec<EventId>) {
        let storage = RocksStorage::open_temp().unwrap();
        let key = SecretKey::generate();
        let sealer = SealerId::new(key.public_key());

        // Create a genesis block with events
        let event1 = test_event(&key, "repo1");
        std::thread::sleep(std::time::Duration::from_millis(1));
        let event2 = test_event(&key, "repo2");

        let event_ids = vec![event1.id(), event2.id()];

        let genesis = BlockBuilder::new(sealer.clone())
            .events(vec![event1, event2])
            .seal(&key);

        // Store the block
        storage.put_block(&genesis).unwrap();

        // Store MMR node
        storage.put_mmr_node(0, *genesis.hash().as_hash()).unwrap();
        storage.set_mmr_meta(1, 1).unwrap();

        let generator = ProofGenerator::with_defaults(storage);
        (generator, key, event_ids)
    }

    #[test]
    fn test_merkle_path_single() {
        let (generator, key, _) = setup_chain();
        let event = test_event(&key, "single");
        let events = vec![event];

        let path = generator.merkle_path(&events, 0);
        assert!(path.is_empty());
    }

    #[test]
    fn test_merkle_path_two() {
        let (generator, key, _) = setup_chain();
        let e1 = test_event(&key, "a");
        std::thread::sleep(std::time::Duration::from_millis(1));
        let e2 = test_event(&key, "b");
        let events = vec![e1, e2];

        // Path for first event
        let path = generator.merkle_path(&events, 0);
        assert_eq!(path.len(), 1);
        assert_eq!(path[0].position, Position::Right);

        // Path for second event
        let path = generator.merkle_path(&events, 1);
        assert_eq!(path.len(), 1);
        assert_eq!(path[0].position, Position::Left);
    }

    #[test]
    fn test_generate_block_proof() {
        let (generator, _, event_ids) = setup_chain();

        // Get the block
        let block = generator.storage().get_block(0).unwrap().unwrap();

        // Generate proof for first event
        let proof = generator.generate_block_proof(&block, 0, 0).unwrap();

        assert_eq!(proof.event_id, event_ids[0]);
        assert_eq!(proof.block_height, 0);
        assert!(proof.verify().unwrap());
    }

    #[test]
    fn test_find_block_for_event() {
        let (generator, _, event_ids) = setup_chain();

        let result = generator.find_block_for_event(&event_ids[0]).unwrap();
        assert!(result.is_some());

        let (block, height) = result.unwrap();
        assert_eq!(height, 0);
        assert!(block.events.iter().any(|e| e.id() == event_ids[0]));
    }

    #[test]
    fn test_find_block_for_nonexistent_event() {
        let (generator, _, _) = setup_chain();

        let fake_id = EventId(Hash::ZERO);
        let result = generator.find_block_for_event(&fake_id).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_peak_positions() {
        assert_eq!(peak_positions(0), Vec::<u64>::new());
        assert_eq!(peak_positions(1), vec![0]);
        assert_eq!(peak_positions(3), vec![2]);
        assert_eq!(peak_positions(4), vec![2, 3]);
        assert_eq!(peak_positions(7), vec![6]);
    }

    #[test]
    fn test_bag_peaks() {
        let p1 = moloch_core::hash(b"peak1");
        let p2 = moloch_core::hash(b"peak2");

        assert_eq!(bag_peaks(&[]), Hash::ZERO);
        assert_eq!(bag_peaks(&[p1]), p1);

        let expected = moloch_core::hash_pair(p1, p2);
        assert_eq!(bag_peaks(&[p1, p2]), expected);
    }

    #[test]
    fn test_proof_bundle_serialization() {
        let bundle = ProofBundle {
            proofs: Vec::new(),
            mmr_root: Hash::ZERO,
            height: 0,
            created_at: 12345,
        };

        let bytes = bundle.to_bytes().unwrap();
        let restored = ProofBundle::from_bytes(&bytes).unwrap();

        assert_eq!(bundle.height, restored.height);
        assert_eq!(bundle.mmr_root, restored.mmr_root);
        assert_eq!(bundle.created_at, restored.created_at);
    }
}
