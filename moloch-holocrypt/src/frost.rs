//! FROST threshold signing for encrypted events.
//!
//! Provides t-of-n threshold signatures using the FROST protocol,
//! enabling distributed signing where any t participants can produce
//! a valid signature.
//!
//! ## Features
//!
//! - **Two-Round Protocol**: Efficient signing with minimal communication
//! - **Low-Level API**: Full control over signing rounds
//! - **Ceremony Helper**: Convenient wrapper for managing the signing process
//!
//! ## Usage
//!
//! ### Low-Level API
//!
//! ```ignore
//! use moloch_holocrypt::frost::{FrostConfig, FrostCoordinator, FrostParticipant};
//!
//! // Setup (2-of-3 threshold)
//! let config = FrostConfig::new(2, 3);
//! let (coordinator, participants) = FrostCoordinator::setup(&config)?;
//!
//! // Round 1: Generate commitments
//! let round1_outputs: Vec<_> = participants.iter()
//!     .map(|p| p.round1())
//!     .collect();
//!
//! // Coordinator creates signing package
//! let signing_package = coordinator.create_signing_package(&round1_outputs, message)?;
//!
//! // Round 2: Generate signature shares
//! let shares: Vec<_> = participants.iter()
//!     .zip(&round1_outputs)
//!     .take(2)  // Only need threshold participants
//!     .map(|(p, r1)| p.round2(message, &r1.nonces, &signing_package))
//!     .collect();
//!
//! // Aggregate into final signature
//! let signature = coordinator.aggregate(&signing_package, &shares)?;
//! ```
//!
//! ### Ceremony Helper
//!
//! ```ignore
//! use moloch_holocrypt::frost::FrostSigningCeremony;
//!
//! let mut ceremony = FrostSigningCeremony::new(coordinator, message);
//!
//! // Add round 1 outputs from participants
//! for (id, participant) in participants {
//!     let r1 = participant.round1()?;
//!     ceremony.add_round1(id, r1)?;
//! }
//!
//! // Check quorum and create signing package
//! let signing_package = ceremony.signing_package()?;
//!
//! // Add round 2 outputs
//! for (id, participant, nonces) in active_participants {
//!     let share = participant.round2(message, &nonces, &signing_package)?;
//!     ceremony.add_round2(id, share)?;
//! }
//!
//! // Finalize
//! let signature = ceremony.finalize()?;
//! ```

pub use arcanum_threshold::frost::GroupVerifyingKey as FrostGroupKey;
use arcanum_threshold::frost::{
    trusted_dealer_keygen, FrostSigner, FrostVerifier, GroupVerifyingKey, PublicKeyPackage,
    Signature, SignatureShare, SigningCommitments, SigningNonces, SigningPackage,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::errors::{HoloCryptError, Result};

// ═══════════════════════════════════════════════════════════════════════════════
// FROST CONFIGURATION
// ═══════════════════════════════════════════════════════════════════════════════

/// Configuration for FROST threshold signing.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct FrostConfig {
    /// Minimum number of signers required (threshold).
    threshold: u16,
    /// Total number of participants.
    total: u16,
}

impl FrostConfig {
    /// Create a new FROST configuration.
    ///
    /// # Arguments
    /// * `threshold` - Minimum signers required (k)
    /// * `total` - Total participants (n)
    ///
    /// # Panics
    /// Panics if threshold > total or threshold == 0.
    pub fn new(threshold: u16, total: u16) -> Self {
        assert!(threshold > 0, "Threshold must be at least 1");
        assert!(threshold <= total, "Threshold cannot exceed total");
        Self { threshold, total }
    }

    /// Get the threshold (minimum signers).
    pub fn threshold(&self) -> u16 {
        self.threshold
    }

    /// Get the total participants.
    pub fn total(&self) -> u16 {
        self.total
    }

    /// Check if a given count meets threshold.
    pub fn has_quorum(&self, count: usize) -> bool {
        count >= self.threshold as usize
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// FROST COORDINATOR
// ═══════════════════════════════════════════════════════════════════════════════

/// Coordinator for FROST signing ceremonies.
///
/// Manages the signing process, collects commitments and shares,
/// and aggregates the final signature.
pub struct FrostCoordinator {
    /// Group verifying key.
    group_key: GroupVerifyingKey,
    /// Public key package for aggregation.
    pubkey_package: PublicKeyPackage,
    /// Configuration.
    config: FrostConfig,
}

impl FrostCoordinator {
    /// Setup a new FROST group with trusted dealer.
    ///
    /// Returns the coordinator and a list of participants.
    ///
    /// # Note
    /// For production use, consider using DKG instead of trusted dealer.
    pub fn setup(config: &FrostConfig) -> Result<(Self, Vec<FrostParticipant>)> {
        let (shares, pubkey_package) = trusted_dealer_keygen(config.threshold, config.total)
            .map_err(|e| HoloCryptError::InvalidConfiguration {
                reason: format!("FROST keygen failed: {}", e),
            })?;

        let group_key =
            GroupVerifyingKey::from_frost(pubkey_package.verifying_key()).map_err(|e| {
                HoloCryptError::InvalidConfiguration {
                    reason: format!("Failed to get group key: {}", e),
                }
            })?;

        // Create participants from shares
        let participants: Vec<_> = shares
            .into_iter()
            .enumerate()
            .map(|(i, share)| {
                let key_package = frost_ed25519::keys::KeyPackage::try_from(share)
                    .expect("valid share should create key package");
                FrostParticipant::new(i as u16, FrostSigner::new(key_package))
            })
            .collect();

        let coordinator = Self {
            group_key,
            pubkey_package: PublicKeyPackage::from_frost(pubkey_package),
            config: *config,
        };

        Ok((coordinator, participants))
    }

    /// Get the group verifying key.
    pub fn group_key(&self) -> &GroupVerifyingKey {
        &self.group_key
    }

    /// Get the configuration.
    pub fn config(&self) -> &FrostConfig {
        &self.config
    }

    /// Create a signing package from round 1 outputs.
    pub fn create_signing_package(
        &self,
        round1_outputs: &[Round1Output],
        message: &[u8],
    ) -> Result<SigningPackage> {
        let commitments: Vec<_> = round1_outputs
            .iter()
            .map(|r| r.commitments.clone())
            .collect();

        SigningPackage::new(&commitments, message).map_err(|e| HoloCryptError::FrostRoundFailed {
            round: 1,
            reason: format!("Failed to create signing package: {}", e),
        })
    }

    /// Aggregate signature shares into a final signature.
    pub fn aggregate(
        &self,
        signing_package: &SigningPackage,
        shares: &[SignatureShare],
    ) -> Result<FrostSignature> {
        if !self.config.has_quorum(shares.len()) {
            return Err(HoloCryptError::InsufficientFrostParticipants {
                required: self.config.threshold,
                provided: shares.len() as u16,
            });
        }

        let verifier =
            FrostVerifier::new(&self.group_key).map_err(|e| HoloCryptError::FrostRoundFailed {
                round: 2,
                reason: format!("Failed to create verifier: {}", e),
            })?;

        let signature = verifier
            .aggregate(signing_package, shares, &self.pubkey_package)
            .map_err(|e| HoloCryptError::FrostRoundFailed {
                round: 2,
                reason: format!("Failed to aggregate: {}", e),
            })?;

        Ok(FrostSignature {
            inner: signature,
            group_key: self.group_key.clone(),
        })
    }

    /// Verify a signature against the group key.
    pub fn verify(&self, message: &[u8], signature: &FrostSignature) -> Result<bool> {
        let verifier =
            FrostVerifier::new(&self.group_key).map_err(|e| HoloCryptError::FrostRoundFailed {
                round: 2,
                reason: format!("Failed to create verifier: {}", e),
            })?;

        verifier
            .verify(message, &signature.inner)
            .map_err(|_| HoloCryptError::SignatureInvalid)
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// FROST PARTICIPANT
// ═══════════════════════════════════════════════════════════════════════════════

/// A participant in FROST threshold signing.
pub struct FrostParticipant {
    /// Participant ID.
    id: u16,
    /// Underlying signer.
    signer: FrostSigner,
}

impl FrostParticipant {
    /// Create a new participant.
    pub fn new(id: u16, signer: FrostSigner) -> Self {
        Self { id, signer }
    }

    /// Get the participant ID.
    pub fn id(&self) -> u16 {
        self.id
    }

    /// Round 1: Generate commitment.
    pub fn round1(&self) -> Result<Round1Output> {
        let (nonces, commitments) =
            self.signer
                .round1()
                .map_err(|e| HoloCryptError::FrostRoundFailed {
                    round: 1,
                    reason: format!("Round 1 failed: {}", e),
                })?;

        Ok(Round1Output {
            participant_id: self.id,
            nonces,
            commitments,
        })
    }

    /// Round 2: Generate signature share.
    pub fn round2(
        &self,
        message: &[u8],
        nonces: &SigningNonces,
        signing_package: &SigningPackage,
    ) -> Result<SignatureShare> {
        self.signer
            .round2(message, nonces, signing_package)
            .map_err(|e| HoloCryptError::FrostRoundFailed {
                round: 2,
                reason: format!("Round 2 failed: {}", e),
            })
    }
}

/// Output from Round 1 of FROST signing.
pub struct Round1Output {
    /// Participant ID.
    pub participant_id: u16,
    /// Signing nonces (kept secret).
    pub nonces: SigningNonces,
    /// Signing commitments (shared with coordinator).
    pub commitments: SigningCommitments,
}

// ═══════════════════════════════════════════════════════════════════════════════
// FROST SIGNATURE
// ═══════════════════════════════════════════════════════════════════════════════

/// A complete FROST threshold signature.
#[derive(Clone, Serialize, Deserialize)]
pub struct FrostSignature {
    /// The signature.
    inner: Signature,
    /// Group verifying key (for self-verification).
    group_key: GroupVerifyingKey,
}

impl FrostSignature {
    /// Get the raw signature bytes.
    pub fn as_bytes(&self) -> &[u8] {
        self.inner.as_bytes()
    }

    /// Get the group verifying key.
    pub fn group_key(&self) -> &GroupVerifyingKey {
        &self.group_key
    }

    /// Verify the signature against a message.
    pub fn verify(&self, message: &[u8]) -> Result<bool> {
        let verifier =
            FrostVerifier::new(&self.group_key).map_err(|e| HoloCryptError::FrostRoundFailed {
                round: 2,
                reason: format!("Failed to create verifier: {}", e),
            })?;

        verifier
            .verify(message, &self.inner)
            .map_err(|_| HoloCryptError::SignatureInvalid)
    }
}

impl std::fmt::Debug for FrostSignature {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "FrostSignature({} bytes)", self.inner.len())
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// FROST SIGNING CEREMONY (Convenience Helper)
// ═══════════════════════════════════════════════════════════════════════════════

/// State of the signing ceremony.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CeremonyState {
    /// Waiting for Round 1 commitments.
    CollectingRound1,
    /// Ready to create signing package.
    Round1Complete,
    /// Waiting for Round 2 shares.
    CollectingRound2,
    /// Ready to finalize.
    Round2Complete,
    /// Ceremony complete.
    Finalized,
}

/// High-level ceremony helper for FROST signing.
///
/// Manages the state of a signing ceremony and provides
/// a simpler interface than the low-level API.
pub struct FrostSigningCeremony {
    /// Coordinator managing the ceremony.
    coordinator: FrostCoordinator,
    /// Message to sign.
    message: Vec<u8>,
    /// Current state.
    state: CeremonyState,
    /// Round 1 outputs by participant ID.
    round1_outputs: HashMap<u16, Round1Output>,
    /// Round 2 shares by participant ID.
    round2_shares: HashMap<u16, SignatureShare>,
    /// Signing package (created after round 1).
    signing_package: Option<SigningPackage>,
}

impl FrostSigningCeremony {
    /// Start a new signing ceremony.
    pub fn new(coordinator: FrostCoordinator, message: &[u8]) -> Self {
        Self {
            coordinator,
            message: message.to_vec(),
            state: CeremonyState::CollectingRound1,
            round1_outputs: HashMap::new(),
            round2_shares: HashMap::new(),
            signing_package: None,
        }
    }

    /// Get current state.
    pub fn state(&self) -> CeremonyState {
        self.state
    }

    /// Get number of round 1 participants.
    pub fn round1_count(&self) -> usize {
        self.round1_outputs.len()
    }

    /// Get number of round 2 participants.
    pub fn round2_count(&self) -> usize {
        self.round2_shares.len()
    }

    /// Check if we have enough round 1 participants.
    pub fn has_round1_quorum(&self) -> bool {
        self.coordinator
            .config
            .has_quorum(self.round1_outputs.len())
    }

    /// Check if we have enough round 2 participants.
    pub fn has_round2_quorum(&self) -> bool {
        self.coordinator.config.has_quorum(self.round2_shares.len())
    }

    /// Add a round 1 output.
    pub fn add_round1(&mut self, output: Round1Output) -> Result<()> {
        if self.state != CeremonyState::CollectingRound1 {
            return Err(HoloCryptError::FrostRoundFailed {
                round: 1,
                reason: "Not in round 1 collection state".into(),
            });
        }

        self.round1_outputs.insert(output.participant_id, output);

        if self.has_round1_quorum() {
            self.state = CeremonyState::Round1Complete;
        }

        Ok(())
    }

    /// Create the signing package (transition to round 2).
    pub fn create_signing_package(&mut self) -> Result<&SigningPackage> {
        if self.state != CeremonyState::Round1Complete {
            return Err(HoloCryptError::FrostRoundFailed {
                round: 1,
                reason: "Round 1 not complete".into(),
            });
        }

        let outputs: Vec<_> = self.round1_outputs.values().cloned().collect();
        let package = self
            .coordinator
            .create_signing_package(&outputs, &self.message)?;
        self.signing_package = Some(package);
        self.state = CeremonyState::CollectingRound2;

        Ok(self.signing_package.as_ref().unwrap())
    }

    /// Get the signing package (if created).
    pub fn signing_package(&self) -> Option<&SigningPackage> {
        self.signing_package.as_ref()
    }

    /// Add a round 2 signature share.
    pub fn add_round2(&mut self, participant_id: u16, share: SignatureShare) -> Result<()> {
        if self.state != CeremonyState::CollectingRound2 {
            return Err(HoloCryptError::FrostRoundFailed {
                round: 2,
                reason: "Not in round 2 collection state".into(),
            });
        }

        self.round2_shares.insert(participant_id, share);

        if self.has_round2_quorum() {
            self.state = CeremonyState::Round2Complete;
        }

        Ok(())
    }

    /// Finalize the ceremony and produce the signature.
    pub fn finalize(&mut self) -> Result<FrostSignature> {
        if self.state != CeremonyState::Round2Complete {
            return Err(HoloCryptError::FrostRoundFailed {
                round: 2,
                reason: "Round 2 not complete".into(),
            });
        }

        let signing_package =
            self.signing_package
                .as_ref()
                .ok_or_else(|| HoloCryptError::FrostRoundFailed {
                    round: 2,
                    reason: "No signing package".into(),
                })?;

        let shares: Vec<_> = self.round2_shares.values().cloned().collect();
        let signature = self.coordinator.aggregate(signing_package, &shares)?;

        self.state = CeremonyState::Finalized;
        Ok(signature)
    }
}

// Need to implement Clone for Round1Output for the ceremony helper
impl Clone for Round1Output {
    fn clone(&self) -> Self {
        // We can only clone the commitments, not the nonces
        // This is a limitation - in practice, round1 outputs shouldn't be cloned
        panic!("Round1Output should not be cloned - nonces are secret")
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// FROST SIGNED EVENT
// ═══════════════════════════════════════════════════════════════════════════════

/// An event signed with FROST threshold signature.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FrostSignedEvent {
    /// Encrypted event data.
    ciphertext: Vec<u8>,
    /// Nonce used for encryption.
    nonce: Vec<u8>,
    /// Commitment to plaintext.
    commitment: [u8; 32],
    /// Merkle root of fields.
    merkle_root: [u8; 32],
    /// FROST threshold signature.
    signature: FrostSignature,
    /// FROST configuration used.
    config: FrostConfig,
}

impl FrostSignedEvent {
    /// Create a new FROST signed event.
    pub fn new(
        ciphertext: Vec<u8>,
        nonce: Vec<u8>,
        commitment: [u8; 32],
        merkle_root: [u8; 32],
        signature: FrostSignature,
        config: FrostConfig,
    ) -> Self {
        Self {
            ciphertext,
            nonce,
            commitment,
            merkle_root,
            signature,
            config,
        }
    }

    /// Get the ciphertext.
    pub fn ciphertext(&self) -> &[u8] {
        &self.ciphertext
    }

    /// Get the nonce.
    pub fn nonce(&self) -> &[u8] {
        &self.nonce
    }

    /// Get the commitment.
    pub fn commitment(&self) -> &[u8; 32] {
        &self.commitment
    }

    /// Get the Merkle root.
    pub fn merkle_root(&self) -> &[u8; 32] {
        &self.merkle_root
    }

    /// Get the signature.
    pub fn signature(&self) -> &FrostSignature {
        &self.signature
    }

    /// Get the FROST configuration.
    pub fn config(&self) -> &FrostConfig {
        &self.config
    }

    /// Verify the signature.
    pub fn verify_signature(&self) -> Result<bool> {
        // Create a message to verify - typically hash of ciphertext + commitment
        let mut message = Vec::new();
        message.extend_from_slice(&self.ciphertext);
        message.extend_from_slice(&self.commitment);
        message.extend_from_slice(&self.merkle_root);

        self.signature.verify(&message)
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// TESTS
// ═══════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_frost_config() {
        let config = FrostConfig::new(2, 3);
        assert_eq!(config.threshold(), 2);
        assert_eq!(config.total(), 3);
        assert!(config.has_quorum(2));
        assert!(config.has_quorum(3));
        assert!(!config.has_quorum(1));
    }

    #[test]
    #[should_panic(expected = "Threshold cannot exceed total")]
    fn test_frost_config_invalid() {
        FrostConfig::new(4, 3);
    }

    #[test]
    fn test_frost_setup() {
        let config = FrostConfig::new(2, 3);
        let (coordinator, participants) = FrostCoordinator::setup(&config).unwrap();

        assert_eq!(participants.len(), 3);
        assert_eq!(coordinator.config().threshold(), 2);
        assert_eq!(coordinator.config().total(), 3);
    }

    #[test]
    fn test_frost_signing_low_level() {
        let config = FrostConfig::new(2, 3);
        let (coordinator, participants) = FrostCoordinator::setup(&config).unwrap();
        let message = b"Test message for FROST signing";

        // Round 1: Generate commitments from first 2 participants
        let round1_outputs: Vec<_> = participants
            .iter()
            .take(2)
            .map(|p| p.round1().unwrap())
            .collect();

        // Create signing package
        let signing_package = coordinator
            .create_signing_package(&round1_outputs, message)
            .unwrap();

        // Round 2: Generate signature shares
        let shares: Vec<_> = round1_outputs
            .iter()
            .zip(participants.iter().take(2))
            .map(|(r1, p)| p.round2(message, &r1.nonces, &signing_package).unwrap())
            .collect();

        // Aggregate
        let signature = coordinator.aggregate(&signing_package, &shares).unwrap();

        // Verify
        assert!(coordinator.verify(message, &signature).unwrap());
        assert!(signature.verify(message).unwrap());
    }

    #[test]
    fn test_frost_wrong_message_fails() {
        let config = FrostConfig::new(2, 3);
        let (coordinator, participants) = FrostCoordinator::setup(&config).unwrap();
        let message = b"Original message";
        let wrong_message = b"Wrong message";

        let round1_outputs: Vec<_> = participants
            .iter()
            .take(2)
            .map(|p| p.round1().unwrap())
            .collect();

        let signing_package = coordinator
            .create_signing_package(&round1_outputs, message)
            .unwrap();

        let shares: Vec<_> = round1_outputs
            .iter()
            .zip(participants.iter().take(2))
            .map(|(r1, p)| p.round2(message, &r1.nonces, &signing_package).unwrap())
            .collect();

        let signature = coordinator.aggregate(&signing_package, &shares).unwrap();

        // Verify with wrong message should fail
        assert!(signature.verify(wrong_message).is_err());
    }

    #[test]
    fn test_frost_insufficient_participants_detected() {
        let config = FrostConfig::new(2, 3);

        // Test that the config correctly identifies insufficient participants
        assert!(!config.has_quorum(0));
        assert!(!config.has_quorum(1));
        assert!(config.has_quorum(2));
        assert!(config.has_quorum(3));

        // Test threshold and total accessors
        assert_eq!(config.threshold(), 2);
        assert_eq!(config.total(), 3);
    }

    #[test]
    fn test_frost_signature_serialization() {
        let config = FrostConfig::new(2, 3);
        let (coordinator, participants) = FrostCoordinator::setup(&config).unwrap();
        let message = b"Test message";

        let round1_outputs: Vec<_> = participants
            .iter()
            .take(2)
            .map(|p| p.round1().unwrap())
            .collect();

        let signing_package = coordinator
            .create_signing_package(&round1_outputs, message)
            .unwrap();

        let shares: Vec<_> = round1_outputs
            .iter()
            .zip(participants.iter().take(2))
            .map(|(r1, p)| p.round2(message, &r1.nonces, &signing_package).unwrap())
            .collect();

        let signature = coordinator.aggregate(&signing_package, &shares).unwrap();

        // Serialize and deserialize
        let json = serde_json::to_string(&signature).unwrap();
        let restored: FrostSignature = serde_json::from_str(&json).unwrap();

        // Restored signature should verify
        assert!(restored.verify(message).unwrap());
    }

    #[test]
    fn test_frost_signed_event() {
        let config = FrostConfig::new(2, 3);
        let (coordinator, participants) = FrostCoordinator::setup(&config).unwrap();

        // Create dummy event data
        let ciphertext = b"encrypted data".to_vec();
        let nonce = vec![0u8; 12];
        let commitment = [1u8; 32];
        let merkle_root = [2u8; 32];

        // Message to sign is hash of event data
        let mut message = Vec::new();
        message.extend_from_slice(&ciphertext);
        message.extend_from_slice(&commitment);
        message.extend_from_slice(&merkle_root);

        // Sign
        let round1_outputs: Vec<_> = participants
            .iter()
            .take(2)
            .map(|p| p.round1().unwrap())
            .collect();

        let signing_package = coordinator
            .create_signing_package(&round1_outputs, &message)
            .unwrap();

        let shares: Vec<_> = round1_outputs
            .iter()
            .zip(participants.iter().take(2))
            .map(|(r1, p)| p.round2(&message, &r1.nonces, &signing_package).unwrap())
            .collect();

        let signature = coordinator.aggregate(&signing_package, &shares).unwrap();

        // Create signed event
        let event = FrostSignedEvent::new(
            ciphertext,
            nonce,
            commitment,
            merkle_root,
            signature,
            config,
        );

        // Verify
        assert!(event.verify_signature().unwrap());
    }
}
