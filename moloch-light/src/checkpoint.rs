//! Checkpoint support for fast light client bootstrapping.
//!
//! Checkpoints are trusted (height, hash) pairs that allow light clients
//! to skip validating the entire chain history.

use std::collections::BTreeMap;

use moloch_core::{BlockHash, Hash, PublicKey};
use serde::{Deserialize, Serialize};

use crate::errors::{LightClientError, Result};
use crate::header::TrustedHeader;

/// A trusted checkpoint for fast sync.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Checkpoint {
    /// Block height.
    pub height: u64,
    /// Block hash.
    pub hash: BlockHash,
    /// MMR root at this height.
    pub mmr_root: Hash,
    /// Validator set hash at this height.
    pub validators_hash: Hash,
    /// Number of events up to this height.
    pub total_events: u64,
}

impl Checkpoint {
    /// Create a new checkpoint.
    pub fn new(
        height: u64,
        hash: BlockHash,
        mmr_root: Hash,
        validators_hash: Hash,
        total_events: u64,
    ) -> Self {
        Self {
            height,
            hash,
            mmr_root,
            validators_hash,
            total_events,
        }
    }

    /// Verify a header matches this checkpoint.
    pub fn verify_header(&self, header: &TrustedHeader) -> Result<()> {
        if header.height() != self.height {
            return Err(LightClientError::InvalidCheckpoint(format!(
                "height mismatch: expected {}, got {}",
                self.height,
                header.height()
            )));
        }

        if header.hash() != self.hash {
            return Err(LightClientError::InvalidCheckpoint(
                "hash mismatch".to_string(),
            ));
        }

        if header.mmr_root != self.mmr_root {
            return Err(LightClientError::InvalidCheckpoint(
                "MMR root mismatch".to_string(),
            ));
        }

        Ok(())
    }
}

/// A trusted checkpoint with embedded header.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustedCheckpoint {
    /// The checkpoint metadata.
    pub checkpoint: Checkpoint,
    /// The full trusted header at this checkpoint.
    pub header: TrustedHeader,
    /// Validator public keys at this checkpoint.
    pub validators: Vec<PublicKey>,
}

impl TrustedCheckpoint {
    /// Create a new trusted checkpoint.
    pub fn new(
        checkpoint: Checkpoint,
        header: TrustedHeader,
        validators: Vec<PublicKey>,
    ) -> Result<Self> {
        // Verify header matches checkpoint
        checkpoint.verify_header(&header)?;

        Ok(Self {
            checkpoint,
            header,
            validators,
        })
    }

    /// Get the checkpoint height.
    pub fn height(&self) -> u64 {
        self.checkpoint.height
    }

    /// Get the checkpoint hash.
    pub fn hash(&self) -> BlockHash {
        self.checkpoint.hash
    }
}

/// Registry of known checkpoints.
#[derive(Debug, Clone, Default)]
pub struct CheckpointRegistry {
    /// Checkpoints indexed by height.
    checkpoints: BTreeMap<u64, Checkpoint>,
}

impl CheckpointRegistry {
    /// Create an empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a registry with hardcoded checkpoints.
    pub fn with_checkpoints(checkpoints: Vec<Checkpoint>) -> Self {
        let map = checkpoints.into_iter().map(|c| (c.height, c)).collect();
        Self { checkpoints: map }
    }

    /// Add a checkpoint.
    pub fn add(&mut self, checkpoint: Checkpoint) {
        self.checkpoints.insert(checkpoint.height, checkpoint);
    }

    /// Get the latest checkpoint at or below a given height.
    pub fn get_latest(&self, max_height: u64) -> Option<&Checkpoint> {
        self.checkpoints
            .range(..=max_height)
            .next_back()
            .map(|(_, c)| c)
    }

    /// Get checkpoint at exact height.
    pub fn get(&self, height: u64) -> Option<&Checkpoint> {
        self.checkpoints.get(&height)
    }

    /// Get the highest checkpoint.
    pub fn highest(&self) -> Option<&Checkpoint> {
        self.checkpoints.values().next_back()
    }

    /// Get all checkpoints.
    pub fn all(&self) -> impl Iterator<Item = &Checkpoint> {
        self.checkpoints.values()
    }
}

/// Well-known checkpoints for mainnet.
pub mod mainnet {
    use super::*;

    /// Get mainnet checkpoint registry.
    ///
    /// In production, these would be hardcoded trusted checkpoints.
    pub fn checkpoints() -> CheckpointRegistry {
        // TODO: Add real mainnet checkpoints
        CheckpointRegistry::new()
    }
}

/// Well-known checkpoints for testnet.
pub mod testnet {
    use super::*;

    /// Get testnet checkpoint registry.
    pub fn checkpoints() -> CheckpointRegistry {
        // TODO: Add real testnet checkpoints
        CheckpointRegistry::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    

    #[test]
    fn test_checkpoint_registry() {
        let mut registry = CheckpointRegistry::new();

        let cp1 = Checkpoint::new(1000, BlockHash(Hash::ZERO), Hash::ZERO, Hash::ZERO, 50000);
        let cp2 = Checkpoint::new(2000, BlockHash(Hash::ZERO), Hash::ZERO, Hash::ZERO, 100000);

        registry.add(cp1);
        registry.add(cp2);

        assert_eq!(registry.get_latest(500), None);
        assert_eq!(registry.get_latest(1500).unwrap().height, 1000);
        assert_eq!(registry.get_latest(2500).unwrap().height, 2000);
    }
}
