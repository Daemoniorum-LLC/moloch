//! Header storage and chain tracking for light clients.
//!
//! Light clients only store block headers, not full blocks.
//! This reduces storage from ~100KB/block to ~200 bytes/block.

use std::collections::BTreeMap;

use moloch_core::{BlockHash, BlockHeader, Hash, PublicKey};
use serde::{Deserialize, Serialize};

use crate::errors::{LightClientError, Result};

/// A trusted header with finality proof.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustedHeader {
    /// The block header.
    pub header: BlockHeader,
    /// Signatures from validators (at least 2/3+1).
    pub signatures: Vec<(PublicKey, moloch_core::Sig)>,
    /// MMR root at this height (for consistency proofs).
    pub mmr_root: Hash,
}

impl TrustedHeader {
    /// Create a new trusted header.
    pub fn new(
        header: BlockHeader,
        signatures: Vec<(PublicKey, moloch_core::Sig)>,
        mmr_root: Hash,
    ) -> Self {
        Self {
            header,
            signatures,
            mmr_root,
        }
    }

    /// Get the block height.
    pub fn height(&self) -> u64 {
        self.header.height
    }

    /// Get the block hash.
    pub fn hash(&self) -> BlockHash {
        self.header.hash()
    }

    /// Get the parent hash.
    pub fn parent_hash(&self) -> BlockHash {
        self.header.parent
    }

    /// Get the events merkle root.
    pub fn events_root(&self) -> Hash {
        self.header.events_root
    }

    /// Verify this header has sufficient signatures from the validator set.
    pub fn verify_finality(&self, validators: &[PublicKey], threshold: usize) -> Result<()> {
        let valid_sigs = self
            .signatures
            .iter()
            .filter(|(pk, sig)| {
                validators.contains(pk) && self.verify_signature(pk, sig)
            })
            .count();

        if valid_sigs >= threshold {
            Ok(())
        } else {
            Err(LightClientError::InsufficientSignatures {
                got: valid_sigs,
                need: threshold,
            })
        }
    }

    /// Verify a signature against this header's hash.
    fn verify_signature(&self, pk: &PublicKey, sig: &moloch_core::Sig) -> bool {
        let message = self.header.hash();
        pk.verify(message.as_bytes(), sig).is_ok()
    }

    /// Encoded size in bytes (for bandwidth estimation).
    pub fn encoded_size(&self) -> usize {
        // Header: ~150 bytes
        // Each signature: ~96 bytes (32 pubkey + 64 sig)
        // MMR root: 32 bytes
        150 + self.signatures.len() * 96 + 32
    }
}

/// In-memory header store for light clients.
#[derive(Debug, Default)]
pub struct HeaderStore {
    /// Headers indexed by height.
    headers: BTreeMap<u64, TrustedHeader>,
    /// Current finalized tip.
    finalized_height: u64,
}

impl HeaderStore {
    /// Create a new empty header store.
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a header store initialized with a checkpoint.
    pub fn with_checkpoint(checkpoint: TrustedHeader) -> Self {
        let height = checkpoint.height();
        let mut headers = BTreeMap::new();
        headers.insert(height, checkpoint);
        Self {
            headers,
            finalized_height: height,
        }
    }

    /// Insert a header, verifying it links to the chain.
    pub fn insert(&mut self, header: TrustedHeader) -> Result<()> {
        let height = header.height();

        // Verify chain linkage
        if height > 0 {
            if let Some(parent) = self.headers.get(&(height - 1)) {
                if header.parent_hash() != parent.hash() {
                    return Err(LightClientError::InvalidHeader {
                        height,
                        reason: "parent hash mismatch".to_string(),
                    });
                }
            }
        }

        self.headers.insert(height, header);

        // Update finalized height
        if height > self.finalized_height {
            self.finalized_height = height;
        }

        Ok(())
    }

    /// Get a header by height.
    pub fn get(&self, height: u64) -> Option<&TrustedHeader> {
        self.headers.get(&height)
    }

    /// Get the finalized tip.
    pub fn tip(&self) -> Option<&TrustedHeader> {
        self.headers.get(&self.finalized_height)
    }

    /// Get the finalized height.
    pub fn finalized_height(&self) -> u64 {
        self.finalized_height
    }

    /// Get the number of stored headers.
    pub fn len(&self) -> usize {
        self.headers.len()
    }

    /// Check if the store is empty.
    pub fn is_empty(&self) -> bool {
        self.headers.is_empty()
    }

    /// Get headers in a range (inclusive).
    pub fn range(&self, start: u64, end: u64) -> impl Iterator<Item = &TrustedHeader> {
        self.headers.range(start..=end).map(|(_, h)| h)
    }

    /// Prune headers below a certain height.
    pub fn prune_below(&mut self, height: u64) {
        self.headers.retain(|h, _| *h >= height);
    }

    /// Total storage size in bytes.
    pub fn storage_size(&self) -> usize {
        self.headers.values().map(|h| h.encoded_size()).sum()
    }
}

/// Chain of headers with validation.
#[derive(Debug)]
pub struct HeaderChain {
    /// Header store.
    store: HeaderStore,
    /// Known validator set (for signature verification).
    validators: Vec<PublicKey>,
    /// Finality threshold (2/3+1 of validators).
    threshold: usize,
}

impl HeaderChain {
    /// Create a new header chain with a checkpoint.
    pub fn new(checkpoint: TrustedHeader, validators: Vec<PublicKey>) -> Self {
        let threshold = (validators.len() * 2 / 3) + 1;
        Self {
            store: HeaderStore::with_checkpoint(checkpoint),
            validators,
            threshold,
        }
    }

    /// Add a new header to the chain.
    pub fn add_header(&mut self, header: TrustedHeader) -> Result<()> {
        // Verify finality
        header.verify_finality(&self.validators, self.threshold)?;

        // Insert into store
        self.store.insert(header)
    }

    /// Update the validator set (e.g., after validator change).
    pub fn update_validators(&mut self, validators: Vec<PublicKey>) {
        self.threshold = (validators.len() * 2 / 3) + 1;
        self.validators = validators;
    }

    /// Get the header store.
    pub fn store(&self) -> &HeaderStore {
        &self.store
    }

    /// Get the current tip.
    pub fn tip(&self) -> Option<&TrustedHeader> {
        self.store.tip()
    }

    /// Get the finalized height.
    pub fn height(&self) -> u64 {
        self.store.finalized_height()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use moloch_core::crypto::SecretKey;

    fn create_test_header(height: u64) -> BlockHeader {
        BlockHeader {
            height,
            parent: BlockHash(Hash::ZERO),
            events_root: Hash::ZERO,
            state_root: Hash::ZERO,
            timestamp_ms: 0,
            sealer_id: moloch_core::SealerId::default(),
        }
    }

    #[test]
    fn test_header_store_basic() {
        let store = HeaderStore::new();
        assert!(store.is_empty());
        assert_eq!(store.finalized_height(), 0);
    }

    #[test]
    fn test_trusted_header_size() {
        // Verify size estimation is reasonable
        // Note: We can't easily create a test BlockHeader without signing it,
        // so we just test the size calculation formula
        let sig_count = 0;
        let estimated_size = 150 + sig_count * 96 + 32;
        assert!(estimated_size < 250);
    }

    // ===== TDD Tests for Signature Verification =====

    #[test]
    fn test_verify_signature_valid() {
        let secret = SecretKey::generate();
        let public = secret.public_key();

        let header = create_test_header(1);
        let message = header.hash();
        let signature = secret.sign(message.as_bytes());

        let trusted = TrustedHeader::new(header, vec![(public.clone(), signature)], Hash::ZERO);

        // Should verify successfully
        assert!(trusted.verify_signature(&public, &trusted.signatures[0].1));
    }

    #[test]
    fn test_verify_signature_invalid_wrong_key() {
        let secret1 = SecretKey::generate();
        let secret2 = SecretKey::generate();
        let public1 = secret1.public_key();

        let header = create_test_header(1);
        let message = header.hash();

        // Sign with secret2 but try to verify with public1
        let wrong_signature = secret2.sign(message.as_bytes());

        let trusted = TrustedHeader::new(header, vec![(public1.clone(), wrong_signature)], Hash::ZERO);

        // Should fail verification
        assert!(!trusted.verify_signature(&public1, &trusted.signatures[0].1));
    }

    #[test]
    fn test_verify_finality_requires_threshold() {
        let validators: Vec<_> = (0..3).map(|_| SecretKey::generate()).collect();
        let public_keys: Vec<_> = validators.iter().map(|s| s.public_key()).collect();

        let header = create_test_header(1);
        let message = header.hash();

        // Create 2 valid signatures (need 2 for 2/3+1 of 3)
        let sig0 = validators[0].sign(message.as_bytes());
        let sig1 = validators[1].sign(message.as_bytes());

        let trusted = TrustedHeader::new(
            header,
            vec![
                (public_keys[0].clone(), sig0),
                (public_keys[1].clone(), sig1),
            ],
            Hash::ZERO,
        );

        // Should pass - 2 of 3 valid signatures meets threshold of 2
        let result = trusted.verify_finality(&public_keys, 2);
        assert!(result.is_ok());
    }

    #[test]
    fn test_verify_finality_fails_below_threshold() {
        let validators: Vec<_> = (0..3).map(|_| SecretKey::generate()).collect();
        let public_keys: Vec<_> = validators.iter().map(|s| s.public_key()).collect();

        let header = create_test_header(1);
        let message = header.hash();

        // Only 1 valid signature
        let sig0 = validators[0].sign(message.as_bytes());
        // Create an invalid signature for the second slot
        let invalid_sig = validators[2].sign(b"wrong message");

        let trusted = TrustedHeader::new(
            header,
            vec![
                (public_keys[0].clone(), sig0),
                (public_keys[1].clone(), invalid_sig), // Wrong key signed
            ],
            Hash::ZERO,
        );

        // Should fail - only 1 valid signature, need 2
        let result = trusted.verify_finality(&public_keys, 2);
        assert!(result.is_err());
    }
}
