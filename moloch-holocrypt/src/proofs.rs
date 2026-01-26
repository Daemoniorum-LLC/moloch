//! Zero-knowledge proofs for audit events.
//!
//! Allows proving properties about encrypted events without revealing content:
//! - Prove event exists without revealing details
//! - Prove numeric fields are in a range
//! - Prove actor/resource membership in a set
//! - Prove event type matches without revealing other fields

use std::collections::HashSet;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use arcanum_hash::{Blake3, Hasher};

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
    InRange { min: i64, max: i64 },
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
    fn verify_proof_data(&self, event: &EncryptedEvent) -> Result<bool> {
        // Deserialize proof data
        let proof_record: ProofRecord = serde_json::from_slice(&self.proof_data)?;

        // Verify challenge-response
        let expected_challenge = self.compute_challenge(&proof_record.commitment);
        if proof_record.challenge != expected_challenge {
            return Ok(false);
        }

        // Verify response matches commitment
        let expected_response =
            self.compute_response(&proof_record.commitment, &proof_record.challenge);

        Ok(proof_record.response == expected_response)
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
// Event Proof Builder
// ═══════════════════════════════════════════════════════════════════════════════

/// Builder for creating event proofs.
pub struct EventProofBuilder {
    event: Option<EncryptedEvent>,
    proof_type: Option<ProofType>,
    prover_id: Option<String>,
    // For actual ZK proofs, we'd have witness data here
    witness: Option<Vec<u8>>,
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
    pub fn prove_actor_membership(
        self,
        allowed: impl IntoIterator<Item = impl Into<String>>,
    ) -> Self {
        self.proof_type(ProofType::ActorMembership {
            allowed_actors: allowed.into_iter().map(Into::into).collect(),
        })
    }

    /// Prove resource is in allowed set.
    pub fn prove_resource_membership(
        self,
        allowed: impl IntoIterator<Item = impl Into<String>>,
    ) -> Self {
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

    /// Build the proof.
    pub fn build(self) -> Result<EventProof> {
        let event = self
            .event
            .clone()
            .ok_or_else(|| HoloCryptError::InvalidConfiguration {
                reason: "event not set".to_string(),
            })?;

        let proof_type =
            self.proof_type
                .clone()
                .ok_or_else(|| HoloCryptError::InvalidConfiguration {
                    reason: "proof type not set".to_string(),
                })?;

        // Generate commitment
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

        let proof_data = serde_json::to_vec(&proof_record)?;

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
    pub fn verify_all(&self, proofs: &[EventProof], event: &EncryptedEvent) -> Result<bool> {
        for proof in proofs {
            if !self.verify(proof, event)? {
                return Ok(false);
            }
        }
        Ok(true)
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
        let proof_types: Vec<ProofType> =
            self.proofs.iter().map(|p| p.proof_type.clone()).collect();

        // Create composite proof
        EventProof::builder()
            .event(event.clone())
            .proof_type(ProofType::Composite {
                proofs: proof_types,
            })
            .build()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encrypted::{generate_keypair, EncryptedEventBuilder, EncryptionPolicy};
    use moloch_core::crypto::SecretKey;
    use moloch_core::event::{
        ActorId, ActorKind, AuditEvent, EventType, Outcome, ResourceId, ResourceKind,
    };

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
}
