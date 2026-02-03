//! Anchor proofs and verification.
//!
//! Proofs demonstrate that a commitment was anchored to an external chain.

use moloch_core::Hash;
use serde::{Deserialize, Serialize};

use crate::commitment::Commitment;
use crate::provider::TxId;

/// Status of an anchor.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AnchorStatus {
    /// Pending confirmation.
    Pending,
    /// Confirmed with N confirmations.
    Confirmed(u64),
    /// Finalized (cannot be reverted).
    Finalized,
    /// Failed or reverted.
    Failed,
}

impl AnchorStatus {
    /// Check if the anchor is at least confirmed.
    pub fn is_confirmed(&self) -> bool {
        matches!(self, Self::Confirmed(_) | Self::Finalized)
    }

    /// Check if the anchor is finalized.
    pub fn is_finalized(&self) -> bool {
        matches!(self, Self::Finalized)
    }

    /// Get confirmation count (0 if not confirmed).
    pub fn confirmations(&self) -> u64 {
        match self {
            Self::Confirmed(n) => *n,
            Self::Finalized => u64::MAX,
            _ => 0,
        }
    }
}

/// Proof that a commitment was anchored.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnchorProof {
    /// The commitment that was anchored.
    pub commitment: Commitment,
    /// Provider that created this anchor.
    pub provider: String,
    /// Chain identifier.
    pub chain_id: String,
    /// Transaction ID on the external chain.
    pub tx_id: TxId,
    /// Block height containing the anchor.
    pub block_height: u64,
    /// Block hash containing the anchor.
    pub block_hash: String,
    /// Current status.
    pub status: AnchorStatus,
    /// SPV/Merkle proof (provider-specific format).
    pub spv_proof: Option<SpvProof>,
    /// Timestamp when proof was created.
    pub created_at: i64,
}

impl AnchorProof {
    /// Create a new anchor proof.
    pub fn new(
        commitment: Commitment,
        provider: impl Into<String>,
        chain_id: impl Into<String>,
        tx_id: TxId,
        block_height: u64,
        block_hash: impl Into<String>,
    ) -> Self {
        Self {
            commitment,
            provider: provider.into(),
            chain_id: chain_id.into(),
            tx_id,
            block_height,
            block_hash: block_hash.into(),
            status: AnchorStatus::Pending,
            spv_proof: None,
            created_at: chrono::Utc::now().timestamp(),
        }
    }

    /// Set anchor status.
    pub fn with_status(mut self, status: AnchorStatus) -> Self {
        self.status = status;
        self
    }

    /// Set SPV proof.
    pub fn with_spv_proof(mut self, proof: SpvProof) -> Self {
        self.spv_proof = Some(proof);
        self
    }

    /// Unique identifier for this anchor.
    pub fn anchor_id(&self) -> Hash {
        let mut data = Vec::new();
        data.extend(self.provider.as_bytes());
        data.extend(self.chain_id.as_bytes());
        data.extend(self.tx_id.0.as_bytes());
        data.extend(self.commitment.hash().as_bytes());
        moloch_core::hash(&data)
    }

    /// Check if anchor is usable (confirmed or finalized).
    pub fn is_usable(&self) -> bool {
        self.status.is_confirmed()
    }
}

/// SPV (Simplified Payment Verification) proof.
///
/// This is a generic format; providers convert to/from their native format.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpvProof {
    /// Merkle proof path.
    pub merkle_path: Vec<Hash>,
    /// Index in the block.
    pub tx_index: u32,
    /// Block header (provider-specific format).
    pub block_header: Vec<u8>,
    /// Additional headers for proof of work chains.
    pub header_chain: Vec<Vec<u8>>,
}

impl SpvProof {
    /// Create a new SPV proof.
    pub fn new(merkle_path: Vec<Hash>, tx_index: u32, block_header: Vec<u8>) -> Self {
        Self {
            merkle_path,
            tx_index,
            block_header,
            header_chain: Vec::new(),
        }
    }

    /// Add additional headers.
    pub fn with_header_chain(mut self, headers: Vec<Vec<u8>>) -> Self {
        self.header_chain = headers;
        self
    }

    /// Encoded size in bytes.
    pub fn encoded_size(&self) -> usize {
        (self.merkle_path.len() * 32)
            + 4
            + self.block_header.len()
            + self.header_chain.iter().map(|h| h.len()).sum::<usize>()
    }
}

/// Bundle of proofs from multiple providers.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofBundle {
    /// The commitment being proven.
    pub commitment: Commitment,
    /// Proofs from different providers.
    pub proofs: Vec<AnchorProof>,
    /// Timestamp of bundle creation.
    pub created_at: i64,
}

impl ProofBundle {
    /// Create a new proof bundle.
    pub fn new(commitment: Commitment) -> Self {
        Self {
            commitment,
            proofs: Vec::new(),
            created_at: chrono::Utc::now().timestamp(),
        }
    }

    /// Add a proof to the bundle.
    pub fn add_proof(&mut self, proof: AnchorProof) {
        self.proofs.push(proof);
    }

    /// Get number of providers.
    pub fn provider_count(&self) -> usize {
        self.proofs.len()
    }

    /// Get number of confirmed proofs.
    pub fn confirmed_count(&self) -> usize {
        self.proofs
            .iter()
            .filter(|p| p.status.is_confirmed())
            .count()
    }

    /// Get number of finalized proofs.
    pub fn finalized_count(&self) -> usize {
        self.proofs
            .iter()
            .filter(|p| p.status.is_finalized())
            .count()
    }

    /// Check if bundle has at least N confirmations across providers.
    pub fn has_quorum(&self, required: usize) -> bool {
        self.confirmed_count() >= required
    }
}

/// Result of verifying an anchor.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Verification {
    /// Is the anchor valid?
    pub valid: bool,
    /// Provider that was verified.
    pub provider: String,
    /// Chain that was verified.
    pub chain_id: String,
    /// Current confirmations.
    pub confirmations: u64,
    /// Verification timestamp.
    pub verified_at: i64,
    /// Error message if invalid.
    pub error: Option<String>,
}

impl Verification {
    /// Create a successful verification.
    pub fn success(
        provider: impl Into<String>,
        chain_id: impl Into<String>,
        confirmations: u64,
    ) -> Self {
        Self {
            valid: true,
            provider: provider.into(),
            chain_id: chain_id.into(),
            confirmations,
            verified_at: chrono::Utc::now().timestamp(),
            error: None,
        }
    }

    /// Create a failed verification.
    pub fn failure(
        provider: impl Into<String>,
        chain_id: impl Into<String>,
        error: impl Into<String>,
    ) -> Self {
        Self {
            valid: false,
            provider: provider.into(),
            chain_id: chain_id.into(),
            confirmations: 0,
            verified_at: chrono::Utc::now().timestamp(),
            error: Some(error.into()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::provider::TxId;

    #[test]
    fn test_anchor_status() {
        assert!(!AnchorStatus::Pending.is_confirmed());
        assert!(AnchorStatus::Confirmed(6).is_confirmed());
        assert!(AnchorStatus::Finalized.is_finalized());
        assert_eq!(AnchorStatus::Confirmed(10).confirmations(), 10);
    }

    #[test]
    fn test_proof_bundle() {
        let commitment = Commitment::new("test", Hash::ZERO, 100);
        let mut bundle = ProofBundle::new(commitment.clone());

        let proof1 = AnchorProof::new(
            commitment.clone(),
            "bitcoin",
            "mainnet",
            TxId::new("tx1"),
            1000,
            "block1",
        )
        .with_status(AnchorStatus::Confirmed(6));

        let proof2 = AnchorProof::new(
            commitment,
            "ethereum",
            "mainnet",
            TxId::new("tx2"),
            2000,
            "block2",
        )
        .with_status(AnchorStatus::Pending);

        bundle.add_proof(proof1);
        bundle.add_proof(proof2);

        assert_eq!(bundle.provider_count(), 2);
        assert_eq!(bundle.confirmed_count(), 1);
        assert!(bundle.has_quorum(1));
        assert!(!bundle.has_quorum(2));
    }
}
