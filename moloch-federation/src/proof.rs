//! Cross-chain proofs for federation.

use moloch_core::{BlockHash, EventId, Hash};
use moloch_light::CompactProof;
use serde::{Deserialize, Serialize};

use crate::errors::{FederationError, Result};

/// A reference to an event on another chain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrossChainReference {
    /// Source chain ID.
    pub source_chain: String,
    /// Event ID on source chain.
    pub event_id: EventId,
    /// Block height containing the event.
    pub block_height: u64,
    /// Block hash for verification.
    pub block_hash: BlockHash,
    /// Timestamp of reference creation.
    pub created_at: i64,
    /// Proof bundle (optional, can be fetched later).
    pub proof: Option<ProofBundle>,
}

impl CrossChainReference {
    /// Create a new cross-chain reference.
    pub fn new(
        source_chain: String,
        event_id: EventId,
        block_height: u64,
        block_hash: BlockHash,
    ) -> Self {
        Self {
            source_chain,
            event_id,
            block_height,
            block_hash,
            created_at: chrono::Utc::now().timestamp(),
            proof: None,
        }
    }

    /// Attach a proof to this reference.
    pub fn with_proof(mut self, proof: ProofBundle) -> Self {
        self.proof = Some(proof);
        self
    }

    /// Check if proof is attached.
    pub fn has_proof(&self) -> bool {
        self.proof.is_some()
    }

    /// Compute reference ID (hash of reference data).
    pub fn reference_id(&self) -> Hash {
        let mut data = Vec::new();
        data.extend(self.source_chain.as_bytes());
        data.extend(self.event_id.0.as_bytes());
        data.extend(&self.block_height.to_le_bytes());
        data.extend(self.block_hash.0.as_bytes());
        moloch_core::hash(&data)
    }
}

/// Bundle of proofs for cross-chain verification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofBundle {
    /// Event inclusion proof.
    pub event_proof: CompactProof,
    /// Finality proof (signatures from validators).
    pub finality_proof: FinalityProof,
    /// Chain state proof (for consistency).
    pub state_proof: Option<ChainStateProof>,
}

impl ProofBundle {
    /// Create a new proof bundle.
    pub fn new(event_proof: CompactProof, finality_proof: FinalityProof) -> Self {
        Self {
            event_proof,
            finality_proof,
            state_proof: None,
        }
    }

    /// Add chain state proof.
    pub fn with_state_proof(mut self, proof: ChainStateProof) -> Self {
        self.state_proof = Some(proof);
        self
    }

    /// Encoded size in bytes.
    pub fn encoded_size(&self) -> usize {
        self.event_proof.encoded_size()
            + self.finality_proof.encoded_size()
            + self
                .state_proof
                .as_ref()
                .map(|p| p.encoded_size())
                .unwrap_or(0)
    }
}

/// Proof of finality for a block.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FinalityProof {
    /// Block hash.
    pub block_hash: BlockHash,
    /// Block height.
    pub height: u64,
    /// Signatures from validators.
    pub signatures: Vec<(moloch_core::PublicKey, moloch_core::Sig)>,
    /// Validator set hash.
    pub validators_hash: Hash,
}

impl FinalityProof {
    /// Verify finality against a known validator set.
    pub fn verify(&self, validators: &[moloch_core::PublicKey], threshold: usize) -> Result<()> {
        let valid_count = self
            .signatures
            .iter()
            .filter(|(pk, _sig)| validators.contains(pk))
            .count();

        if valid_count >= threshold {
            Ok(())
        } else {
            Err(FederationError::ProofVerificationFailed(format!(
                "insufficient signatures: {} < {}",
                valid_count, threshold
            )))
        }
    }

    /// Encoded size in bytes.
    pub fn encoded_size(&self) -> usize {
        32 + 8 + (self.signatures.len() * 96) + 32
    }
}

/// Proof of chain state at a point in time.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainStateProof {
    /// MMR root at this state.
    pub mmr_root: Hash,
    /// Total events at this state.
    pub total_events: u64,
    /// State hash.
    pub state_hash: Hash,
    /// Height of this state.
    pub height: u64,
}

impl ChainStateProof {
    /// Encoded size in bytes.
    pub fn encoded_size(&self) -> usize {
        32 + 8 + 32 + 8
    }
}

/// A complete cross-chain proof for verification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrossChainProof {
    /// The reference being proven.
    pub reference: CrossChainReference,
    /// Source chain genesis for context.
    pub source_genesis: BlockHash,
    /// Current source chain state.
    pub source_state: ChainStateProof,
    /// Target chain height at proof creation.
    pub target_height: u64,
}

impl CrossChainProof {
    /// Create a new cross-chain proof.
    pub fn new(
        reference: CrossChainReference,
        source_genesis: BlockHash,
        source_state: ChainStateProof,
        target_height: u64,
    ) -> Self {
        Self {
            reference,
            source_genesis,
            source_state,
            target_height,
        }
    }

    /// Verify the proof is complete.
    pub fn is_complete(&self) -> bool {
        self.reference.has_proof()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cross_chain_reference() {
        let reference = CrossChainReference::new(
            "source-chain".to_string(),
            EventId(Hash::ZERO),
            100,
            BlockHash(Hash::ZERO),
        );

        assert_eq!(reference.source_chain, "source-chain");
        assert!(!reference.has_proof());

        let ref_id = reference.reference_id();
        assert_ne!(ref_id, Hash::ZERO);
    }

    #[test]
    fn test_proof_bundle_size() {
        let finality = FinalityProof {
            block_hash: BlockHash(Hash::ZERO),
            height: 100,
            signatures: vec![],
            validators_hash: Hash::ZERO,
        };

        // Empty signatures = minimal size
        assert_eq!(finality.encoded_size(), (32 + 8) + 32);
    }
}
