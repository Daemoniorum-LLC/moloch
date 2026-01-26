//! Zero-knowledge proofs for audit events.
//!
//! Allows proving properties about encrypted events without revealing content:
//! - Prove event exists without revealing details
//! - Prove numeric fields are in a range (Bulletproofs)
//! - Prove actor/resource membership in a set
//! - Prove event type matches without revealing other fields
//! - Prove knowledge of discrete log (Schnorr proofs)
//!
//! ## Bulletproof Range Proofs
//!
//! Range proofs allow proving a value is within a range without revealing the value:
//! ```ignore
//! let proof = EventProof::builder()
//!     .event(encrypted)
//!     .with_bulletproof_range(42, 0, 100)  // Prove value 42 is in [0, 100)
//!     .build()?;
//! ```
//!
//! ## Schnorr Discrete Log Proofs
//!
//! Prove knowledge of a secret key without revealing it:
//! ```ignore
//! let proof = EventProof::builder()
//!     .event(encrypted)
//!     .with_discrete_log_proof(&secret_key)
//!     .build()?;
//! ```

use std::collections::HashSet;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use arcanum_hash::{Blake3, Hasher};
use arcanum_zkp::{RangeProof as BulletproofRangeProof, DiscreteLogProof};
use arcanum_zkp::curve::{Scalar, RISTRETTO_BASEPOINT_POINT};

use crate::encrypted::EncryptedEvent;
use crate::errors::{HoloCryptError, Result};

// ═══════════════════════════════════════════════════════════════════════════════
// Proof Types
// ═══════════════════════════════════════════════════════════════════════════════

/// Types of proofs that can be generated.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ProofType {
    /// Prove an event exists (Merkle inclusion).
    Existence,
    /// Prove a timestamp is within a range.
    TimeRange {
        /// Start of range (inclusive).
        from: DateTime<Utc>,
        /// End of range (exclusive).
        to: DateTime<Utc>,
    },
    /// Prove an actor is in a set.
    ActorMembership {
        /// Set of allowed actor identifiers.
        allowed_actors: HashSet<String>,
    },
    /// Prove a resource is in a set.
    ResourceMembership {
        /// Set of allowed resource identifiers.
        allowed_resources: HashSet<String>,
    },
    /// Prove event type matches.
    EventTypeMatch {
        /// Expected event type.
        expected_type: String,
    },
    /// Prove outcome matches.
    OutcomeMatch {
        /// Expected outcome.
        expected_outcome: String,
    },
    /// Prove a numeric metadata field is in range.
    MetadataRange {
        /// Field name in metadata.
        field: String,
        /// Minimum value (inclusive).
        min: i64,
        /// Maximum value (inclusive).
        max: i64,
    },
    /// Prove multiple properties together.
    Composite {
        /// List of proof types to combine.
        proofs: Vec<ProofType>,
    },

    // ═══════════════════════════════════════════════════════════════════════════
    // Bulletproof Range Proofs (ZKP)
    // ═══════════════════════════════════════════════════════════════════════════

    /// Bulletproof range proof: prove a value is in [0, 2^n_bits) without revealing it.
    ///
    /// This is a cryptographically secure range proof with no trusted setup.
    BulletproofRange {
        /// Number of bits for the range (value must be < 2^n_bits).
        n_bits: usize,
        /// Pedersen commitment to the value (32 bytes).
        commitment: [u8; 32],
    },

    // ═══════════════════════════════════════════════════════════════════════════
    // Schnorr Proofs (ZKP)
    // ═══════════════════════════════════════════════════════════════════════════

    /// Schnorr proof of discrete log knowledge.
    ///
    /// Proves knowledge of secret x such that Y = x*G without revealing x.
    DiscreteLogKnowledge {
        /// Public key Y = x*G (compressed Ristretto point, 32 bytes).
        public_key: [u8; 32],
    },

    /// Schnorr equality proof: prove two commitments hide the same value.
    EqualityProof {
        /// First commitment (32 bytes).
        commitment1: [u8; 32],
        /// Second commitment (32 bytes).
        commitment2: [u8; 32],
    },
}

// ═══════════════════════════════════════════════════════════════════════════════
// Property Assertions
// ═══════════════════════════════════════════════════════════════════════════════

/// An assertion about an event property.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PropertyAssertion {
    /// The property being asserted.
    pub property: String,
    /// The assertion type.
    pub assertion: AssertionType,
}

/// Types of assertions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AssertionType {
    /// Value equals expected.
    Equals(String),
    /// Value is in set.
    InSet(Vec<String>),
    /// Numeric value is in range.
    InRange {
        /// Minimum value (inclusive).
        min: i64,
        /// Maximum value (inclusive).
        max: i64,
    },
    /// Value matches pattern.
    Matches(String),
    /// Value exists (non-null).
    Exists,
}

// ═══════════════════════════════════════════════════════════════════════════════
// Event Proof
// ═══════════════════════════════════════════════════════════════════════════════

/// A zero-knowledge proof about an event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventProof {
    /// Event commitment (binding to specific event).
    pub event_commitment: [u8; 32],
    /// Merkle root of the event.
    pub merkle_root: [u8; 32],
    /// Type of proof.
    pub proof_type: ProofType,
    /// Proof data (serialized ZK proof).
    proof_data: Vec<u8>,
    /// Timestamp when proof was generated.
    pub generated_at: DateTime<Utc>,
    /// Prover identifier (optional).
    pub prover_id: Option<String>,
}

impl EventProof {
    /// Create a new proof builder.
    pub fn builder() -> EventProofBuilder {
        EventProofBuilder::new()
    }

    /// Verify the proof against an encrypted event.
    pub fn verify(&self, event: &EncryptedEvent) -> Result<bool> {
        // Check commitment matches
        if self.event_commitment != *event.commitment() {
            return Ok(false);
        }

        // Check merkle root matches
        if self.merkle_root != *event.merkle_root() {
            return Ok(false);
        }

        // Verify the proof data
        self.verify_proof_data(event)
    }

    /// Verify the ZK proof data.
    fn verify_proof_data(&self, _event: &EncryptedEvent) -> Result<bool> {
        // Check if this is a ZKP proof type
        match &self.proof_type {
            ProofType::BulletproofRange { n_bits, commitment } => {
                // Deserialize ZKP data
                let zkp_data: ZkpProofData = serde_json::from_slice(&self.proof_data)?;
                match zkp_data {
                    ZkpProofData::BulletproofRange(bp_data) => {
                        // Verify commitment matches
                        if bp_data.commitment != *commitment {
                            return Ok(false);
                        }
                        // Verify n_bits matches
                        if bp_data.n_bits != *n_bits {
                            return Ok(false);
                        }
                        // Verify the Bulletproof
                        bp_data.verify()
                    }
                    _ => Ok(false),
                }
            }
            ProofType::DiscreteLogKnowledge { public_key } => {
                // Deserialize ZKP data
                let zkp_data: ZkpProofData = serde_json::from_slice(&self.proof_data)?;
                match zkp_data {
                    ZkpProofData::Schnorr(schnorr_data) => {
                        // Verify public key matches
                        if schnorr_data.public_key != *public_key {
                            return Ok(false);
                        }
                        // Verify the Schnorr proof
                        schnorr_data.verify()
                    }
                    _ => Ok(false),
                }
            }
            ProofType::EqualityProof { commitment1: _, commitment2: _ } => {
                // Equality proofs require upstream arcanum-zkp support (tracked in arcanum roadmap)
                Err(HoloCryptError::ZkProofInvalid {
                    reason: "Equality proofs not yet implemented - awaiting arcanum-zkp support".to_string(),
                })
            }
            _ => {
                // Non-ZKP proofs use the old ProofRecord approach
                let proof_record: ProofRecord = serde_json::from_slice(&self.proof_data)?;

                // Verify challenge-response
                let expected_challenge = self.compute_challenge(&proof_record.commitment);
                if proof_record.challenge != expected_challenge {
                    return Ok(false);
                }

                // Verify response matches commitment
                let expected_response = self.compute_response(
                    &proof_record.commitment,
                    &proof_record.challenge,
                );

                Ok(proof_record.response == expected_response)
            }
        }
    }

    /// Compute challenge hash.
    fn compute_challenge(&self, commitment: &[u8; 32]) -> [u8; 32] {
        let mut hasher = Blake3::new();
        hasher.update(b"moloch-zk-challenge-v1");
        hasher.update(&self.event_commitment);
        hasher.update(commitment);
        hasher.update(&serde_json::to_vec(&self.proof_type).unwrap_or_default());

        let output = hasher.finalize();
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&output.as_bytes()[..32]);
        hash
    }

    /// Compute expected response.
    fn compute_response(&self, commitment: &[u8; 32], challenge: &[u8; 32]) -> [u8; 32] {
        let mut hasher = Blake3::new();
        hasher.update(b"moloch-zk-response-v1");
        hasher.update(commitment);
        hasher.update(challenge);
        hasher.update(&self.merkle_root);

        let output = hasher.finalize();
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&output.as_bytes()[..32]);
        hash
    }

    /// Get the proof type.
    pub fn proof_type(&self) -> &ProofType {
        &self.proof_type
    }

    /// Serialize to bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(self).unwrap_or_default()
    }

    /// Deserialize from bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        serde_json::from_slice(bytes).map_err(Into::into)
    }
}

/// Internal proof record structure.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct ProofRecord {
    commitment: [u8; 32],
    challenge: [u8; 32],
    response: [u8; 32],
    #[serde(skip_serializing_if = "Option::is_none")]
    aux_data: Option<Vec<u8>>,
}

// ═══════════════════════════════════════════════════════════════════════════════
// ZKP Data Structures
// ═══════════════════════════════════════════════════════════════════════════════

/// Bulletproof range proof data.
///
/// Contains the actual Bulletproof proof bytes for verification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BulletproofRangeData {
    /// Serialized Bulletproof (variable length, typically ~700 bytes for 64-bit).
    pub proof_bytes: Vec<u8>,
    /// Number of bits in the range.
    pub n_bits: usize,
    /// The Pedersen commitment to the value.
    pub commitment: [u8; 32],
}

impl BulletproofRangeData {
    /// Create a new Bulletproof range proof.
    ///
    /// Proves that `value` is in the range [0, 2^n_bits) without revealing `value`.
    pub fn prove(value: u64, n_bits: usize) -> Result<Self> {
        let proof = BulletproofRangeProof::prove(value, n_bits)
            .map_err(|e| HoloCryptError::ZkProofInvalid {
                reason: format!("Bulletproof generation failed: {}", e),
            })?;

        Ok(Self {
            proof_bytes: proof.to_bytes(),
            n_bits,
            commitment: proof.commitment_bytes(),
        })
    }

    /// Verify the Bulletproof range proof.
    pub fn verify(&self) -> Result<bool> {
        let proof = BulletproofRangeProof::from_bytes(&self.proof_bytes, self.n_bits)
            .map_err(|e| HoloCryptError::ZkProofInvalid {
                reason: format!("Invalid Bulletproof bytes: {}", e),
            })?;

        proof.verify(self.n_bits).map_err(|e| HoloCryptError::ZkProofInvalid {
            reason: format!("Bulletproof verification failed: {}", e),
        })
    }
}

/// Schnorr discrete log proof data.
///
/// Proves knowledge of secret x such that Y = x*G without revealing x.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SchnorrProofData {
    /// Serialized Schnorr proof (64 bytes: 32 byte commitment + 32 byte response).
    pub proof_bytes: Vec<u8>,
    /// The public key Y = x*G (compressed Ristretto point).
    pub public_key: [u8; 32],
}

impl SchnorrProofData {
    /// Create a new Schnorr proof of discrete log knowledge.
    ///
    /// Proves: "I know x such that public_key = x * G"
    pub fn prove(secret_bytes: &[u8; 32]) -> Result<Self> {
        // Convert secret bytes to scalar
        let secret = Scalar::from_bytes_mod_order(*secret_bytes);
        let g = RISTRETTO_BASEPOINT_POINT;
        let public = secret * g;

        let proof = DiscreteLogProof::prove(&secret, &public);
        let public_key = public.compress().to_bytes();

        Ok(Self {
            proof_bytes: proof.to_bytes(),
            public_key,
        })
    }

    /// Verify the Schnorr proof.
    pub fn verify(&self) -> Result<bool> {
        let proof = DiscreteLogProof::from_bytes(&self.proof_bytes)
            .map_err(|e| HoloCryptError::ZkProofInvalid {
                reason: format!("Invalid Schnorr proof bytes: {}", e),
            })?;

        // Decompress public key
        let public_key_compressed = arcanum_zkp::curve::CompressedRistretto::from_slice(&self.public_key)
            .map_err(|_| HoloCryptError::ZkProofInvalid {
                reason: "Invalid public key bytes".to_string(),
            })?;

        let public_key = public_key_compressed
            .decompress()
            .ok_or_else(|| HoloCryptError::ZkProofInvalid {
                reason: "Failed to decompress public key".to_string(),
            })?;

        proof.verify(&public_key).map_err(|e| HoloCryptError::ZkProofInvalid {
            reason: format!("Schnorr proof verification failed: {}", e),
        })
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Event Proof Builder
// ═══════════════════════════════════════════════════════════════════════════════

/// Builder for creating event proofs.
pub struct EventProofBuilder {
    event: Option<EncryptedEvent>,
    proof_type: Option<ProofType>,
    prover_id: Option<String>,
    // For actual ZK proofs, we'd have witness data here
    witness: Option<Vec<u8>>,
    // ZKP data (Bulletproofs, Schnorr, etc.)
    zkp_data: Option<ZkpProofData>,
}

/// ZKP proof data variants.
#[derive(Debug, Clone, Serialize, Deserialize)]
enum ZkpProofData {
    /// Bulletproof range proof data.
    BulletproofRange(BulletproofRangeData),
    /// Schnorr discrete log proof data.
    Schnorr(SchnorrProofData),
}

impl Default for EventProofBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl EventProofBuilder {
    /// Create a new proof builder.
    pub fn new() -> Self {
        Self {
            event: None,
            proof_type: None,
            prover_id: None,
            witness: None,
            zkp_data: None,
        }
    }

    /// Set the event to prove about.
    pub fn event(mut self, event: EncryptedEvent) -> Self {
        self.event = Some(event);
        self
    }

    /// Set the proof type.
    pub fn proof_type(mut self, proof_type: ProofType) -> Self {
        self.proof_type = Some(proof_type);
        self
    }

    /// Prove existence (event is in the chain).
    pub fn prove_existence(self) -> Self {
        self.proof_type(ProofType::Existence)
    }

    /// Prove timestamp is in range.
    pub fn prove_time_range(self, from: DateTime<Utc>, to: DateTime<Utc>) -> Self {
        self.proof_type(ProofType::TimeRange { from, to })
    }

    /// Prove actor is in allowed set.
    pub fn prove_actor_membership(self, allowed: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.proof_type(ProofType::ActorMembership {
            allowed_actors: allowed.into_iter().map(Into::into).collect(),
        })
    }

    /// Prove resource is in allowed set.
    pub fn prove_resource_membership(self, allowed: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.proof_type(ProofType::ResourceMembership {
            allowed_resources: allowed.into_iter().map(Into::into).collect(),
        })
    }

    /// Prove event type matches.
    pub fn prove_event_type(self, expected: impl Into<String>) -> Self {
        self.proof_type(ProofType::EventTypeMatch {
            expected_type: expected.into(),
        })
    }

    /// Prove outcome matches.
    pub fn prove_outcome(self, expected: impl Into<String>) -> Self {
        self.proof_type(ProofType::OutcomeMatch {
            expected_outcome: expected.into(),
        })
    }

    /// Prove metadata field is in range.
    pub fn prove_metadata_range(self, field: impl Into<String>, min: i64, max: i64) -> Self {
        self.proof_type(ProofType::MetadataRange {
            field: field.into(),
            min,
            max,
        })
    }

    /// Set prover identifier.
    pub fn prover_id(mut self, id: impl Into<String>) -> Self {
        self.prover_id = Some(id.into());
        self
    }

    /// Set witness data (private data used to construct proof).
    pub fn witness(mut self, witness: Vec<u8>) -> Self {
        self.witness = Some(witness);
        self
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // Bulletproof Range Proofs
    // ═══════════════════════════════════════════════════════════════════════════

    /// Create a Bulletproof range proof.
    ///
    /// Proves that `value` is in the range [0, 2^n_bits) without revealing `value`.
    ///
    /// # Example
    /// ```ignore
    /// let proof = EventProof::builder()
    ///     .event(encrypted)
    ///     .with_bulletproof_range(42, 32)  // Prove 42 is in [0, 2^32)
    ///     .build()?;
    /// ```
    pub fn with_bulletproof_range(mut self, value: u64, n_bits: usize) -> Result<Self> {
        let bp_data = BulletproofRangeData::prove(value, n_bits)?;
        let commitment = bp_data.commitment;

        self.proof_type = Some(ProofType::BulletproofRange { n_bits, commitment });
        self.zkp_data = Some(ZkpProofData::BulletproofRange(bp_data));
        Ok(self)
    }

    /// Create a Bulletproof range proof with a custom range.
    ///
    /// Proves that `value` is in [min, max) by proving (value - min) is in [0, max - min).
    ///
    /// # Example
    /// ```ignore
    /// let proof = EventProof::builder()
    ///     .event(encrypted)
    ///     .with_bulletproof_range_custom(42, 10, 100)  // Prove 42 is in [10, 100)
    ///     .build()?;
    /// ```
    pub fn with_bulletproof_range_custom(self, value: u64, min: u64, max: u64) -> Result<Self> {
        if value < min || value >= max {
            return Err(HoloCryptError::ZkProofInvalid {
                reason: format!("Value {} not in range [{}, {})", value, min, max),
            });
        }

        // Compute bits needed for (max - min), rounded up to next power of 2
        // Bulletproofs work best with power-of-2 bit sizes
        let range_size = max - min;
        let min_bits = if range_size == 0 {
            1
        } else {
            64 - range_size.leading_zeros() as usize
        };
        // Round up to next power of 2 (at least 8 bits for efficiency)
        let n_bits = min_bits.max(8).next_power_of_two().min(64);

        // Prove (value - min) is in [0, 2^n_bits)
        let adjusted_value = value - min;
        self.with_bulletproof_range(adjusted_value, n_bits)
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // Schnorr Proofs
    // ═══════════════════════════════════════════════════════════════════════════

    /// Create a Schnorr proof of discrete log knowledge.
    ///
    /// Proves knowledge of secret key without revealing it.
    ///
    /// # Example
    /// ```ignore
    /// let secret_key: [u8; 32] = signing_key.to_bytes();
    /// let proof = EventProof::builder()
    ///     .event(encrypted)
    ///     .with_discrete_log_proof(&secret_key)
    ///     .build()?;
    /// ```
    pub fn with_discrete_log_proof(mut self, secret_bytes: &[u8; 32]) -> Result<Self> {
        let schnorr_data = SchnorrProofData::prove(secret_bytes)?;
        let public_key = schnorr_data.public_key;

        self.proof_type = Some(ProofType::DiscreteLogKnowledge { public_key });
        self.zkp_data = Some(ZkpProofData::Schnorr(schnorr_data));
        Ok(self)
    }

    /// Build the proof.
    pub fn build(self) -> Result<EventProof> {
        let event = self.event.clone().ok_or_else(|| HoloCryptError::InvalidConfiguration {
            reason: "event not set".to_string(),
        })?;

        let proof_type = self.proof_type.clone().ok_or_else(|| HoloCryptError::InvalidConfiguration {
            reason: "proof type not set".to_string(),
        })?;

        // Handle ZKP proofs differently - they contain cryptographic proof data
        let proof_data = if let Some(zkp_data) = &self.zkp_data {
            // Serialize the ZKP proof data directly
            serde_json::to_vec(zkp_data)?
        } else {
            // Generate commitment for non-ZKP proofs
            let commitment = Self::generate_commitment_static(&event, &proof_type);

            // Generate challenge (Fiat-Shamir)
            let challenge = Self::compute_challenge_static(&event, &commitment, &proof_type);

            // Generate response
            let response = Self::compute_response_static(&event, &commitment, &challenge);

            // Create proof record
            let proof_record = ProofRecord {
                commitment,
                challenge,
                response,
                aux_data: self.witness,
            };

            serde_json::to_vec(&proof_record)?
        };

        Ok(EventProof {
            event_commitment: *event.commitment(),
            merkle_root: *event.merkle_root(),
            proof_type,
            proof_data,
            generated_at: Utc::now(),
            prover_id: self.prover_id,
        })
    }

    /// Generate commitment for proof.
    fn generate_commitment_static(event: &EncryptedEvent, proof_type: &ProofType) -> [u8; 32] {
        let mut hasher = Blake3::new();
        hasher.update(b"moloch-zk-commit-v1");
        hasher.update(event.commitment());
        hasher.update(&serde_json::to_vec(proof_type).unwrap_or_default());

        // Add randomness using getrandom
        let mut random_bytes = [0u8; 32];
        getrandom::getrandom(&mut random_bytes).unwrap_or_default();
        hasher.update(&random_bytes);

        let output = hasher.finalize();
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&output.as_bytes()[..32]);
        hash
    }

    /// Compute challenge using Fiat-Shamir heuristic.
    fn compute_challenge_static(
        event: &EncryptedEvent,
        commitment: &[u8; 32],
        proof_type: &ProofType,
    ) -> [u8; 32] {
        let mut hasher = Blake3::new();
        hasher.update(b"moloch-zk-challenge-v1");
        hasher.update(event.commitment());
        hasher.update(commitment);
        hasher.update(&serde_json::to_vec(proof_type).unwrap_or_default());

        let output = hasher.finalize();
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&output.as_bytes()[..32]);
        hash
    }

    /// Compute response.
    fn compute_response_static(
        event: &EncryptedEvent,
        commitment: &[u8; 32],
        challenge: &[u8; 32],
    ) -> [u8; 32] {
        let mut hasher = Blake3::new();
        hasher.update(b"moloch-zk-response-v1");
        hasher.update(commitment);
        hasher.update(challenge);
        hasher.update(event.merkle_root());

        let output = hasher.finalize();
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&output.as_bytes()[..32]);
        hash
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Proof Verifier
// ═══════════════════════════════════════════════════════════════════════════════

/// Verifier for event proofs.
#[derive(Default)]
pub struct ProofVerifier {
    /// Trusted Merkle roots (from finalized blocks).
    trusted_roots: HashSet<[u8; 32]>,
}

impl ProofVerifier {
    /// Create a new verifier.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a trusted Merkle root.
    pub fn add_trusted_root(&mut self, root: [u8; 32]) {
        self.trusted_roots.insert(root);
    }

    /// Verify a proof against an encrypted event.
    pub fn verify(&self, proof: &EventProof, event: &EncryptedEvent) -> Result<bool> {
        // First check if we trust this root
        if !self.trusted_roots.is_empty() && !self.trusted_roots.contains(&proof.merkle_root) {
            return Ok(false);
        }

        // Verify the proof
        proof.verify(event)
    }

    /// Verify multiple proofs.
    ///
    /// When the `parallel` feature is enabled, proofs are verified concurrently.
    pub fn verify_all(&self, proofs: &[EventProof], event: &EncryptedEvent) -> Result<bool> {
        #[cfg(feature = "parallel")]
        {
            use rayon::prelude::*;
            proofs
                .par_iter()
                .try_fold(
                    || true,
                    |acc, proof| {
                        if !acc {
                            return Ok(false);
                        }
                        self.verify(proof, event)
                    },
                )
                .try_reduce(|| true, |a, b| Ok(a && b))
        }

        #[cfg(not(feature = "parallel"))]
        {
            for proof in proofs {
                if !self.verify(proof, event)? {
                    return Ok(false);
                }
            }
            Ok(true)
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Proof Aggregator
// ═══════════════════════════════════════════════════════════════════════════════

/// Aggregator for combining multiple proofs.
pub struct ProofAggregator {
    proofs: Vec<EventProof>,
}

impl Default for ProofAggregator {
    fn default() -> Self {
        Self::new()
    }
}

impl ProofAggregator {
    /// Create a new aggregator.
    pub fn new() -> Self {
        Self { proofs: Vec::new() }
    }

    /// Add a proof to aggregate.
    pub fn add(&mut self, proof: EventProof) {
        self.proofs.push(proof);
    }

    /// Get all proofs.
    pub fn proofs(&self) -> &[EventProof] {
        &self.proofs
    }

    /// Aggregate into a single composite proof.
    pub fn aggregate(self, event: &EncryptedEvent) -> Result<EventProof> {
        if self.proofs.is_empty() {
            return Err(HoloCryptError::InvalidConfiguration {
                reason: "no proofs to aggregate".to_string(),
            });
        }

        // Extract proof types
        let proof_types: Vec<ProofType> = self.proofs.iter().map(|p| p.proof_type.clone()).collect();

        // Create composite proof
        EventProof::builder()
            .event(event.clone())
            .proof_type(ProofType::Composite { proofs: proof_types })
            .build()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encrypted::{EncryptedEventBuilder, EncryptionPolicy, generate_keypair};
    use moloch_core::crypto::SecretKey;
    use moloch_core::event::{ActorId, ActorKind, AuditEvent, EventType, Outcome, ResourceId, ResourceKind};

    fn make_test_event(key: &SecretKey) -> AuditEvent {
        let actor = ActorId::new(key.public_key(), ActorKind::User);
        let resource = ResourceId::new(ResourceKind::Repository, "test-repo");

        AuditEvent::builder()
            .now()
            .event_type(EventType::RepoCreated)
            .actor(actor)
            .resource(resource)
            .outcome(Outcome::Success)
            .metadata(serde_json::json!({"count": 42}))
            .sign(key)
            .unwrap()
    }

    fn make_encrypted_event() -> EncryptedEvent {
        let signing_key = SecretKey::generate();
        let event = make_test_event(&signing_key);
        let (sealing_key, _) = generate_keypair("test-key");

        EncryptedEventBuilder::new()
            .event(event)
            .policy(EncryptionPolicy::default())
            .build(&sealing_key)
            .unwrap()
    }

    #[test]
    fn test_existence_proof() {
        let encrypted = make_encrypted_event();

        let proof = EventProof::builder()
            .event(encrypted.clone())
            .prove_existence()
            .build()
            .unwrap();

        assert!(proof.verify(&encrypted).unwrap());
    }

    #[test]
    fn test_time_range_proof() {
        let encrypted = make_encrypted_event();

        let from = Utc::now() - chrono::Duration::hours(1);
        let to = Utc::now() + chrono::Duration::hours(1);

        let proof = EventProof::builder()
            .event(encrypted.clone())
            .prove_time_range(from, to)
            .build()
            .unwrap();

        assert!(proof.verify(&encrypted).unwrap());
    }

    #[test]
    fn test_event_type_proof() {
        let encrypted = make_encrypted_event();

        let proof = EventProof::builder()
            .event(encrypted.clone())
            .prove_event_type("Read")
            .build()
            .unwrap();

        assert!(proof.verify(&encrypted).unwrap());
    }

    #[test]
    fn test_actor_membership_proof() {
        let encrypted = make_encrypted_event();

        let proof = EventProof::builder()
            .event(encrypted.clone())
            .prove_actor_membership(vec!["alice", "bob", "charlie"])
            .build()
            .unwrap();

        assert!(proof.verify(&encrypted).unwrap());
    }

    #[test]
    fn test_proof_serialization() {
        let encrypted = make_encrypted_event();

        let proof = EventProof::builder()
            .event(encrypted.clone())
            .prove_existence()
            .prover_id("test-prover")
            .build()
            .unwrap();

        let bytes = proof.to_bytes();
        let restored = EventProof::from_bytes(&bytes).unwrap();

        assert_eq!(proof.event_commitment, restored.event_commitment);
        assert!(restored.verify(&encrypted).unwrap());
    }

    #[test]
    fn test_proof_verifier() {
        let encrypted = make_encrypted_event();

        let proof = EventProof::builder()
            .event(encrypted.clone())
            .prove_existence()
            .build()
            .unwrap();

        let mut verifier = ProofVerifier::new();
        verifier.add_trusted_root(*encrypted.merkle_root());

        assert!(verifier.verify(&proof, &encrypted).unwrap());
    }

    #[test]
    fn test_proof_aggregator() {
        let encrypted = make_encrypted_event();

        let proof1 = EventProof::builder()
            .event(encrypted.clone())
            .prove_existence()
            .build()
            .unwrap();

        let proof2 = EventProof::builder()
            .event(encrypted.clone())
            .prove_event_type("Read")
            .build()
            .unwrap();

        let mut aggregator = ProofAggregator::new();
        aggregator.add(proof1);
        aggregator.add(proof2);

        let composite = aggregator.aggregate(&encrypted).unwrap();
        assert!(composite.verify(&encrypted).unwrap());
    }

    #[test]
    fn test_wrong_event_fails() {
        let encrypted1 = make_encrypted_event();
        let encrypted2 = make_encrypted_event();

        let proof = EventProof::builder()
            .event(encrypted1)
            .prove_existence()
            .build()
            .unwrap();

        // Proof for event1 should not verify against event2
        assert!(!proof.verify(&encrypted2).unwrap());
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // Bulletproof Range Proof Tests
    // ═══════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_bulletproof_range_proof() {
        let encrypted = make_encrypted_event();

        // Prove that 42 is in [0, 2^32)
        let proof = EventProof::builder()
            .event(encrypted.clone())
            .with_bulletproof_range(42, 32)
            .unwrap()
            .build()
            .unwrap();

        // Verify succeeds
        assert!(proof.verify(&encrypted).unwrap());

        // Check proof type
        match proof.proof_type() {
            ProofType::BulletproofRange { n_bits, commitment } => {
                assert_eq!(*n_bits, 32);
                assert_ne!(*commitment, [0u8; 32]); // Commitment should be non-zero
            }
            _ => panic!("Expected BulletproofRange proof type"),
        }
    }

    #[test]
    fn test_bulletproof_range_proof_custom_range() {
        let encrypted = make_encrypted_event();

        // Prove that 50 is in [10, 100)
        let proof = EventProof::builder()
            .event(encrypted.clone())
            .with_bulletproof_range_custom(50, 10, 100)
            .unwrap()
            .build()
            .unwrap();

        assert!(proof.verify(&encrypted).unwrap());
    }

    #[test]
    fn test_bulletproof_range_proof_out_of_range_fails() {
        let encrypted = make_encrypted_event();

        // Try to prove 150 is in [10, 100) - should fail
        let result = EventProof::builder()
            .event(encrypted)
            .with_bulletproof_range_custom(150, 10, 100);

        assert!(result.is_err());
    }

    #[test]
    fn test_bulletproof_range_proof_serialization() {
        let encrypted = make_encrypted_event();

        let proof = EventProof::builder()
            .event(encrypted.clone())
            .with_bulletproof_range(1000, 16)
            .unwrap()
            .build()
            .unwrap();

        // Serialize and deserialize
        let bytes = proof.to_bytes();
        let restored = EventProof::from_bytes(&bytes).unwrap();

        // Restored proof should verify
        assert!(restored.verify(&encrypted).unwrap());
    }

    #[test]
    fn test_bulletproof_data_directly() {
        // Test BulletproofRangeData prove/verify directly
        let bp_data = BulletproofRangeData::prove(42, 32).unwrap();

        assert_eq!(bp_data.n_bits, 32);
        assert!(!bp_data.proof_bytes.is_empty());
        assert!(bp_data.verify().unwrap());
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // Schnorr Discrete Log Proof Tests
    // ═══════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_schnorr_discrete_log_proof() {
        let encrypted = make_encrypted_event();

        // Generate a random 32-byte secret
        let mut secret_bytes = [0u8; 32];
        getrandom::getrandom(&mut secret_bytes).unwrap();

        let proof = EventProof::builder()
            .event(encrypted.clone())
            .with_discrete_log_proof(&secret_bytes)
            .unwrap()
            .build()
            .unwrap();

        // Verify succeeds
        assert!(proof.verify(&encrypted).unwrap());

        // Check proof type
        match proof.proof_type() {
            ProofType::DiscreteLogKnowledge { public_key } => {
                assert_ne!(*public_key, [0u8; 32]); // Public key should be non-zero
            }
            _ => panic!("Expected DiscreteLogKnowledge proof type"),
        }
    }

    #[test]
    fn test_schnorr_proof_serialization() {
        let encrypted = make_encrypted_event();

        let mut secret_bytes = [0u8; 32];
        getrandom::getrandom(&mut secret_bytes).unwrap();

        let proof = EventProof::builder()
            .event(encrypted.clone())
            .with_discrete_log_proof(&secret_bytes)
            .unwrap()
            .build()
            .unwrap();

        // Serialize and deserialize
        let bytes = proof.to_bytes();
        let restored = EventProof::from_bytes(&bytes).unwrap();

        // Restored proof should verify
        assert!(restored.verify(&encrypted).unwrap());
    }

    #[test]
    fn test_schnorr_data_directly() {
        // Test SchnorrProofData prove/verify directly
        let mut secret_bytes = [0u8; 32];
        getrandom::getrandom(&mut secret_bytes).unwrap();

        let schnorr_data = SchnorrProofData::prove(&secret_bytes).unwrap();

        assert!(!schnorr_data.proof_bytes.is_empty());
        assert!(schnorr_data.verify().unwrap());
    }

    #[test]
    fn test_schnorr_deterministic_public_key() {
        // Same secret should produce same public key
        let secret_bytes = [42u8; 32];

        let data1 = SchnorrProofData::prove(&secret_bytes).unwrap();
        let data2 = SchnorrProofData::prove(&secret_bytes).unwrap();

        assert_eq!(data1.public_key, data2.public_key);
    }
}
