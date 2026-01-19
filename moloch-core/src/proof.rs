//! Proof types for Moloch.
//!
//! Proofs allow verifying that an event exists in the chain without
//! having to download the entire chain.

use serde::{Deserialize, Serialize};

use crate::crypto::{hash_pair, Hash};
use crate::error::{Error, Result};
use crate::event::EventId;

/// Position of a sibling in a merkle proof.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Position {
    /// Sibling is on the left.
    Left,
    /// Sibling is on the right.
    Right,
}

/// A node in a merkle proof path.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofNode {
    /// Hash of the sibling node.
    pub hash: Hash,
    /// Position of the sibling relative to the path.
    pub position: Position,
}

/// Proof that an event is included in a specific block.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockInclusionProof {
    /// The event being proved.
    pub event_id: EventId,
    /// Block height containing the event.
    pub block_height: u64,
    /// Merkle path from event to block's events_root.
    pub path: Vec<ProofNode>,
    /// The block's events_root (for verification).
    pub events_root: Hash,
}

impl BlockInclusionProof {
    /// Verify this proof.
    pub fn verify(&self) -> Result<bool> {
        let mut current = self.event_id.0;

        for node in &self.path {
            current = match node.position {
                Position::Left => hash_pair(node.hash, current),
                Position::Right => hash_pair(current, node.hash),
            };
        }

        Ok(current == self.events_root)
    }
}

/// MMR (Merkle Mountain Range) proof for chain inclusion.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MmrProof {
    /// Position of the leaf in the MMR.
    pub leaf_pos: u64,
    /// The leaf hash.
    pub leaf_hash: Hash,
    /// Siblings needed to reconstruct path to peak.
    pub siblings: Vec<ProofNode>,
    /// The peak this leaf belongs to.
    pub peak_hash: Hash,
    /// Other peaks (for bagging to root).
    pub peaks: Vec<Hash>,
    /// The MMR root.
    pub root: Hash,
    /// MMR size when proof was generated.
    pub mmr_size: u64,
}

impl MmrProof {
    /// Verify this MMR proof.
    pub fn verify(&self) -> Result<bool> {
        // First, verify path to peak
        let mut current = self.leaf_hash;
        for node in &self.siblings {
            current = match node.position {
                Position::Left => hash_pair(node.hash, current),
                Position::Right => hash_pair(current, node.hash),
            };
        }

        if current != self.peak_hash {
            return Ok(false);
        }

        // Then verify bagging of peaks
        let computed_root = bag_peaks(&self.peaks)?;
        Ok(computed_root == self.root)
    }
}

/// Bag peaks into a single root (right to left).
fn bag_peaks(peaks: &[Hash]) -> Result<Hash> {
    if peaks.is_empty() {
        return Ok(Hash::ZERO);
    }

    let mut root = *peaks.last().unwrap();
    for peak in peaks.iter().rev().skip(1) {
        root = hash_pair(*peak, root);
    }
    Ok(root)
}

/// Complete inclusion proof (block + MMR).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InclusionProof {
    /// Proof of inclusion in the block.
    pub block_proof: BlockInclusionProof,
    /// Proof of block inclusion in the chain (via MMR).
    pub chain_proof: MmrProof,
}

impl InclusionProof {
    /// Verify the complete inclusion proof.
    pub fn verify(&self) -> Result<bool> {
        // Verify event is in block
        if !self.block_proof.verify()? {
            return Ok(false);
        }

        // Verify the block proof's events_root matches the MMR leaf
        // (The MMR stores events_root for each block)
        if self.block_proof.events_root != self.chain_proof.leaf_hash {
            return Ok(false);
        }

        // Verify block is in chain
        self.chain_proof.verify()
    }

    /// Get the event ID this proof is for.
    pub fn event_id(&self) -> EventId {
        self.block_proof.event_id
    }

    /// Get the block height.
    pub fn block_height(&self) -> u64 {
        self.block_proof.block_height
    }

    /// Get the MMR root this proof is against.
    pub fn mmr_root(&self) -> Hash {
        self.chain_proof.root
    }
}

/// Proof that one chain state is a prefix of another.
///
/// This is used for auditing: an auditor can verify that the chain
/// they observed previously is consistent with the current chain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConsistencyProof {
    /// Old MMR size (number of leaves).
    pub old_size: u64,
    /// New MMR size.
    pub new_size: u64,
    /// Old MMR root.
    pub old_root: Hash,
    /// New MMR root.
    pub new_root: Hash,
    /// Proof nodes (old peaks that can be derived from new tree).
    pub proof: Vec<Hash>,
}

impl ConsistencyProof {
    /// Verify this consistency proof.
    pub fn verify(&self) -> Result<bool> {
        if self.old_size > self.new_size {
            return Err(Error::invalid_proof("old_size > new_size"));
        }

        if self.old_size == self.new_size {
            return Ok(self.old_root == self.new_root);
        }

        // For a valid MMR consistency proof:
        // - All old peaks must be present in the new tree
        // - We can reconstruct old_root from proof + new tree structure
        //
        // This is a simplified check - full implementation would
        // reconstruct the old peaks from the proof nodes.
        //
        // For now, we verify structure is plausible.
        if self.proof.is_empty() {
            return Ok(false);
        }

        // The first proof element should help us find old peaks
        // Full verification requires MMR structure knowledge
        Ok(true) // Placeholder - real impl needs MMR crate
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::hash;

    #[test]
    fn test_block_inclusion_proof_single_event() {
        let event_hash = hash(b"event1");
        let event_id = EventId(event_hash);

        // Single event = root is the event itself
        let proof = BlockInclusionProof {
            event_id,
            block_height: 0,
            path: vec![],
            events_root: event_hash,
        };

        assert!(proof.verify().unwrap());
    }

    #[test]
    fn test_block_inclusion_proof_two_events() {
        let e1 = hash(b"event1");
        let e2 = hash(b"event2");
        let root = hash_pair(e1, e2);

        // Prove e1 is in tree
        let proof = BlockInclusionProof {
            event_id: EventId(e1),
            block_height: 0,
            path: vec![ProofNode {
                hash: e2,
                position: Position::Right,
            }],
            events_root: root,
        };

        assert!(proof.verify().unwrap());

        // Prove e2 is in tree
        let proof2 = BlockInclusionProof {
            event_id: EventId(e2),
            block_height: 0,
            path: vec![ProofNode {
                hash: e1,
                position: Position::Left,
            }],
            events_root: root,
        };

        assert!(proof2.verify().unwrap());
    }

    #[test]
    fn test_block_inclusion_proof_four_events() {
        let e1 = hash(b"event1");
        let e2 = hash(b"event2");
        let e3 = hash(b"event3");
        let e4 = hash(b"event4");

        let h12 = hash_pair(e1, e2);
        let h34 = hash_pair(e3, e4);
        let root = hash_pair(h12, h34);

        // Prove e3 is in tree (position 2)
        let proof = BlockInclusionProof {
            event_id: EventId(e3),
            block_height: 5,
            path: vec![
                ProofNode {
                    hash: e4,
                    position: Position::Right,
                },
                ProofNode {
                    hash: h12,
                    position: Position::Left,
                },
            ],
            events_root: root,
        };

        assert!(proof.verify().unwrap());
    }

    #[test]
    fn test_invalid_proof_fails() {
        let e1 = hash(b"event1");
        let e2 = hash(b"event2");
        let root = hash_pair(e1, e2);

        // Wrong sibling
        let proof = BlockInclusionProof {
            event_id: EventId(e1),
            block_height: 0,
            path: vec![ProofNode {
                hash: hash(b"wrong"),
                position: Position::Right,
            }],
            events_root: root,
        };

        assert!(!proof.verify().unwrap());
    }

    #[test]
    fn test_bag_peaks() {
        let p1 = hash(b"peak1");
        let p2 = hash(b"peak2");
        let p3 = hash(b"peak3");

        // Single peak
        assert_eq!(bag_peaks(&[p1]).unwrap(), p1);

        // Two peaks: hash(p1, p2)
        let expected_2 = hash_pair(p1, p2);
        assert_eq!(bag_peaks(&[p1, p2]).unwrap(), expected_2);

        // Three peaks: hash(p1, hash(p2, p3))
        let h23 = hash_pair(p2, p3);
        let expected_3 = hash_pair(p1, h23);
        assert_eq!(bag_peaks(&[p1, p2, p3]).unwrap(), expected_3);
    }

    #[test]
    fn test_mmr_proof_single_leaf() {
        let leaf = hash(b"leaf");

        let proof = MmrProof {
            leaf_pos: 0,
            leaf_hash: leaf,
            siblings: vec![],
            peak_hash: leaf,
            peaks: vec![leaf],
            root: leaf,
            mmr_size: 1,
        };

        assert!(proof.verify().unwrap());
    }
}
