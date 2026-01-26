//! Compact proofs for bandwidth-efficient verification.
//!
//! Light clients request proofs on-demand rather than downloading
//! full blocks. This module provides compact proof formats optimized
//! for mobile and browser clients.

use moloch_core::{BlockHash, EventId, Hash, PublicKey, Sig};
use serde::{Deserialize, Serialize};

use crate::errors::{LightClientError, Result};

/// A compact proof that an event exists in the chain.
///
/// This proof is much smaller than a full block and can be verified
/// against a trusted header chain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompactProof {
    /// The event ID being proven.
    pub event_id: EventId,
    /// Block height containing the event.
    pub block_height: u64,
    /// Block hash (for cross-checking).
    pub block_hash: BlockHash,
    /// Merkle proof from event to block's events_root.
    pub merkle_proof: Vec<Hash>,
    /// Index of event in block (for merkle verification).
    pub event_index: usize,
    /// MMR proof from block to current MMR root (optional).
    pub mmr_proof: Option<MmrCompactProof>,
}

impl CompactProof {
    /// Verify this proof against a trusted events root.
    pub fn verify_against_root(&self, events_root: Hash) -> Result<()> {
        // Reconstruct root from proof
        let computed_root = self.compute_events_root()?;

        if computed_root == events_root {
            Ok(())
        } else {
            Err(LightClientError::InvalidProof(
                "events root mismatch".to_string(),
            ))
        }
    }

    /// Compute the events root from this proof.
    fn compute_events_root(&self) -> Result<Hash> {
        let mut current = self.event_id.0;
        let mut index = self.event_index;

        for sibling in &self.merkle_proof {
            current = if index % 2 == 0 {
                moloch_core::hash_pair(current, *sibling)
            } else {
                moloch_core::hash_pair(*sibling, current)
            };
            index /= 2;
        }

        Ok(current)
    }

    /// Encoded size in bytes.
    pub fn encoded_size(&self) -> usize {
        // event_id: 32, block_height: 8, block_hash: 32
        // merkle_proof: 32 * len, event_index: 8
        // mmr_proof: variable
        let base = 32 + 8 + 32 + (32 * self.merkle_proof.len()) + 8;
        let mmr = self
            .mmr_proof
            .as_ref()
            .map(|p| p.encoded_size())
            .unwrap_or(0);
        base + mmr
    }
}

/// Compact MMR proof for proving block inclusion.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MmrCompactProof {
    /// MMR position of the block.
    pub position: u64,
    /// MMR size at proof generation.
    pub mmr_size: u64,
    /// Sibling hashes for the proof path.
    pub siblings: Vec<Hash>,
    /// Peak hashes for bagging.
    pub peaks: Vec<Hash>,
}

impl MmrCompactProof {
    /// Verify this proof against a trusted MMR root.
    pub fn verify(&self, leaf: Hash, expected_root: Hash) -> Result<()> {
        // Reconstruct root from proof
        let computed_root = self.compute_root(leaf)?;

        if computed_root == expected_root {
            Ok(())
        } else {
            Err(LightClientError::InvalidProof(
                "MMR root mismatch".to_string(),
            ))
        }
    }

    fn compute_root(&self, leaf: Hash) -> Result<Hash> {
        // Walk up the tree using siblings
        let mut current = leaf;
        let mut pos = self.position;
        let mut height = 0u32;

        for sibling in &self.siblings {
            let left_pos = pos - (1 << height);
            let is_left = pos == left_pos + (1 << height);

            current = if is_left {
                moloch_core::hash_pair(current, *sibling)
            } else {
                moloch_core::hash_pair(*sibling, current)
            };

            // Move to parent position
            pos = if is_left {
                pos + 1
            } else {
                pos + (1 << (height + 1))
            };
            height += 1;
        }

        // Bag peaks right to left
        let mut root = current;
        for peak in self.peaks.iter().rev() {
            root = moloch_core::hash_pair(*peak, root);
        }

        Ok(root)
    }

    /// Encoded size in bytes.
    pub fn encoded_size(&self) -> usize {
        // position: 8, mmr_size: 8
        // siblings: 32 * len, peaks: 32 * len
        8 + 8 + (32 * self.siblings.len()) + (32 * self.peaks.len())
    }
}

/// Request for a proof from a full node.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ProofRequest {
    /// Request proof for a specific event.
    Event {
        /// Event ID to prove.
        event_id: EventId,
    },
    /// Request proof for an event at a block height and index.
    EventAtIndex {
        /// Block height.
        height: u64,
        /// Event index in block.
        index: usize,
    },
    /// Request proof for multiple events.
    Batch {
        /// Event IDs to prove.
        event_ids: Vec<EventId>,
    },
    /// Request consistency proof between two heights.
    Consistency {
        /// Earlier height.
        from_height: u64,
        /// Later height.
        to_height: u64,
    },
}

/// Response containing requested proofs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ProofResponse {
    /// Single event proof.
    Event(CompactProof),
    /// Multiple event proofs.
    Batch(Vec<CompactProof>),
    /// Consistency proof.
    Consistency(ConsistencyCompactProof),
    /// Event not found.
    NotFound,
    /// Error generating proof.
    Error(String),
}

/// Compact consistency proof between two chain states.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsistencyCompactProof {
    /// Earlier MMR size.
    pub from_size: u64,
    /// Later MMR size.
    pub to_size: u64,
    /// Proof that from_root is a prefix of to_root.
    pub proof: Vec<Hash>,
}

impl ConsistencyCompactProof {
    /// Verify consistency between two MMR roots.
    pub fn verify(&self, from_root: Hash, to_root: Hash) -> Result<()> {
        // Verify the earlier tree is a prefix of the later tree
        // This proves no tampering occurred
        let computed = self.compute_to_root(from_root)?;

        if computed == to_root {
            Ok(())
        } else {
            Err(LightClientError::InvalidProof(
                "consistency proof failed".to_string(),
            ))
        }
    }

    fn compute_to_root(&self, from_root: Hash) -> Result<Hash> {
        let mut current = from_root;
        for hash in &self.proof {
            current = moloch_core::hash_pair(current, *hash);
        }
        Ok(current)
    }
}

/// Proof verifier that checks proofs against a trusted header chain.
pub struct ProofVerifier<'a> {
    /// Trusted header store.
    headers: &'a crate::header::HeaderStore,
}

impl<'a> ProofVerifier<'a> {
    /// Create a new proof verifier.
    pub fn new(headers: &'a crate::header::HeaderStore) -> Self {
        Self { headers }
    }

    /// Verify an event inclusion proof.
    pub fn verify_event(&self, proof: &CompactProof) -> Result<()> {
        // Get the trusted header for this block
        let header = self
            .headers
            .get(proof.block_height)
            .ok_or_else(|| LightClientError::MissingHeader(proof.block_height))?;

        // Verify block hash matches
        if header.hash() != proof.block_hash {
            return Err(LightClientError::InvalidProof(
                "block hash mismatch".to_string(),
            ));
        }

        // Verify merkle proof against events root
        proof.verify_against_root(header.events_root())?;

        // If MMR proof is present, verify that too
        if let Some(ref mmr_proof) = proof.mmr_proof {
            let tip = self
                .headers
                .tip()
                .ok_or_else(|| LightClientError::MissingHeader(self.headers.finalized_height()))?;
            mmr_proof.verify(header.hash().0, tip.mmr_root)?;
        }

        Ok(())
    }

    /// Verify a batch of proofs.
    pub fn verify_batch(&self, proofs: &[CompactProof]) -> Result<()> {
        for proof in proofs {
            self.verify_event(proof)?;
        }
        Ok(())
    }

    /// Verify a consistency proof.
    pub fn verify_consistency(
        &self,
        proof: &ConsistencyCompactProof,
        from_height: u64,
        to_height: u64,
    ) -> Result<()> {
        let from_header = self
            .headers
            .get(from_height)
            .ok_or_else(|| LightClientError::MissingHeader(from_height))?;

        let to_header = self
            .headers
            .get(to_height)
            .ok_or_else(|| LightClientError::MissingHeader(to_height))?;

        proof.verify(from_header.mmr_root, to_header.mmr_root)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compact_proof_size() {
        let proof = CompactProof {
            event_id: EventId(Hash::ZERO),
            block_height: 1000,
            block_hash: BlockHash(Hash::ZERO),
            merkle_proof: vec![Hash::ZERO; 10], // ~10 levels for 1000 events
            event_index: 500,
            mmr_proof: None,
        };

        // Should be under 500 bytes for a typical proof
        let size = proof.encoded_size();
        assert!(size < 500, "proof size {} should be < 500", size);
    }

    #[test]
    fn test_mmr_compact_proof_size() {
        let proof = MmrCompactProof {
            position: 1000000,
            mmr_size: 2000000,
            siblings: vec![Hash::ZERO; 20], // ~20 levels for 1M elements
            peaks: vec![Hash::ZERO; 5],     // ~5 peaks
        };

        // Should be under 1KB for large chains
        let size = proof.encoded_size();
        assert!(size < 1024, "MMR proof size {} should be < 1024", size);
    }
}
