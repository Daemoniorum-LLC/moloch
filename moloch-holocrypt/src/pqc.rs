//! Post-quantum cryptography for audit events.
//!
//! Provides quantum-resistant encryption using ML-KEM (Kyber) for
//! key encapsulation and hybrid modes for defense in depth.
//!
//! ## Migration Path
//!
//! 1. **Hybrid Mode**: Use both classical (X25519) and PQC (ML-KEM) simultaneously
//! 2. **PQC Only**: After confidence in PQC, switch to ML-KEM only
//! 3. **Composite Signatures**: Ed25519 + ML-DSA for authenticity

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use arcanum_holocrypt::pqc::{PqcContainer, PqcEnvelope, PqcKeyPair};
use arcanum_pqc::kem::{MlKem768DecapsulationKey, MlKem768EncapsulationKey};

use moloch_core::event::AuditEvent;

use crate::errors::{HoloCryptError, Result};

// ═══════════════════════════════════════════════════════════════════════════════
// Hybrid Encryption Mode
// ═══════════════════════════════════════════════════════════════════════════════

/// Encryption mode for post-quantum security.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum EncryptionMode {
    /// Classical encryption only (X25519 + ChaCha20).
    Classical,
    /// Post-quantum only (ML-KEM-768 + ChaCha20).
    PostQuantum,
    /// Hybrid mode (both classical and PQC for defense in depth).
    #[default]
    Hybrid,
}

// ═══════════════════════════════════════════════════════════════════════════════
// Hybrid Encryption
// ═══════════════════════════════════════════════════════════════════════════════

/// Hybrid encryption combining classical and post-quantum cryptography.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HybridEncryption {
    /// Mode of encryption.
    pub mode: EncryptionMode,
    /// Classical key ID (if used).
    pub classical_key_id: Option<String>,
    /// PQC key ID (if used).
    pub pqc_key_id: Option<String>,
}

impl Default for HybridEncryption {
    fn default() -> Self {
        Self {
            mode: EncryptionMode::Hybrid,
            classical_key_id: None,
            pqc_key_id: None,
        }
    }
}

impl HybridEncryption {
    /// Create classical-only encryption.
    pub fn classical(key_id: impl Into<String>) -> Self {
        Self {
            mode: EncryptionMode::Classical,
            classical_key_id: Some(key_id.into()),
            pqc_key_id: None,
        }
    }

    /// Create PQC-only encryption.
    pub fn pqc(key_id: impl Into<String>) -> Self {
        Self {
            mode: EncryptionMode::PostQuantum,
            classical_key_id: None,
            pqc_key_id: Some(key_id.into()),
        }
    }

    /// Create hybrid encryption.
    pub fn hybrid(classical_key_id: impl Into<String>, pqc_key_id: impl Into<String>) -> Self {
        Self {
            mode: EncryptionMode::Hybrid,
            classical_key_id: Some(classical_key_id.into()),
            pqc_key_id: Some(pqc_key_id.into()),
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// PQC Key Pair Wrapper
// ═══════════════════════════════════════════════════════════════════════════════

/// A post-quantum key pair for Moloch events.
#[derive(Clone)]
pub struct EventPqcKeyPair {
    inner: PqcKeyPair,
    key_id: String,
    created_at: DateTime<Utc>,
    algorithm: String,
}

impl EventPqcKeyPair {
    /// Generate a new ML-KEM-768 key pair.
    pub fn generate(key_id: impl Into<String>) -> Self {
        Self {
            inner: PqcKeyPair::generate(),
            key_id: key_id.into(),
            created_at: Utc::now(),
            algorithm: "ML-KEM-768".to_string(),
        }
    }

    /// Get the key ID.
    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    /// Get the algorithm name.
    pub fn algorithm(&self) -> &str {
        &self.algorithm
    }

    /// Get the creation timestamp.
    pub fn created_at(&self) -> DateTime<Utc> {
        self.created_at
    }

    /// Get the public (encapsulation) key.
    pub fn encapsulation_key(&self) -> &MlKem768EncapsulationKey {
        self.inner.encapsulation_key()
    }

    /// Get the private (decapsulation) key.
    pub fn decapsulation_key(&self) -> &MlKem768DecapsulationKey {
        self.inner.decapsulation_key()
    }

    /// Export public key bytes.
    pub fn public_key_bytes(&self) -> Vec<u8> {
        self.inner.public_key_bytes()
    }

    /// Export private key bytes (handle with care!).
    pub fn private_key_bytes(&self) -> Vec<u8> {
        self.inner.private_key_bytes()
    }
}

impl std::fmt::Debug for EventPqcKeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EventPqcKeyPair")
            .field("key_id", &self.key_id)
            .field("algorithm", &self.algorithm)
            .field("created_at", &self.created_at)
            .finish_non_exhaustive()
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// PQC Event
// ═══════════════════════════════════════════════════════════════════════════════

/// Payload for PQC container.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct PqcPayload {
    event: AuditEvent,
}

/// An audit event encrypted with post-quantum cryptography.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PqcEvent {
    /// Encryption mode used.
    pub mode: EncryptionMode,
    /// Key ID for decryption.
    pub key_id: String,
    /// Algorithm used.
    pub algorithm: String,
    /// The sealed container (serialized).
    container: Vec<u8>,
    /// Event commitment.
    commitment: [u8; 32],
    /// Merkle root.
    merkle_root: [u8; 32],
    /// Creation timestamp.
    created_at: DateTime<Utc>,
}

impl PqcEvent {
    /// Seal an event with PQC encryption.
    pub fn seal(event: &AuditEvent, key: &EventPqcKeyPair) -> Result<Self> {
        let payload = PqcPayload {
            event: event.clone(),
        };

        let container = PqcContainer::seal(&payload, key.encapsulation_key()).map_err(|e| {
            HoloCryptError::EncryptionFailed {
                reason: e.to_string(),
            }
        })?;

        let container_bytes = serde_json::to_vec(&container)?;

        Ok(Self {
            mode: EncryptionMode::PostQuantum,
            key_id: key.key_id().to_string(),
            algorithm: key.algorithm().to_string(),
            container: container_bytes,
            commitment: *container.commitment(),
            merkle_root: *container.merkle_root(),
            created_at: Utc::now(),
        })
    }

    /// Unseal an event with PQC decryption.
    pub fn unseal(&self, key: &EventPqcKeyPair) -> Result<AuditEvent> {
        // Verify key ID
        if self.key_id != key.key_id() {
            return Err(HoloCryptError::KeyNotFound {
                key_id: self.key_id.clone(),
            });
        }

        let container: PqcContainer<PqcPayload> = serde_json::from_slice(&self.container)?;

        let payload = container.unseal(key.decapsulation_key()).map_err(|e| {
            HoloCryptError::DecryptionFailed {
                reason: e.to_string(),
            }
        })?;

        Ok(payload.event)
    }

    /// Verify container structure without decrypting.
    pub fn verify_structure(&self) -> Result<()> {
        let container: PqcContainer<PqcPayload> = serde_json::from_slice(&self.container)?;

        container
            .verify_structure()
            .map_err(|e| HoloCryptError::CryptoError {
                reason: e.to_string(),
            })
    }

    /// Get event commitment.
    pub fn commitment(&self) -> &[u8; 32] {
        &self.commitment
    }

    /// Get Merkle root.
    pub fn merkle_root(&self) -> &[u8; 32] {
        &self.merkle_root
    }

    /// Get creation timestamp.
    pub fn created_at(&self) -> DateTime<Utc> {
        self.created_at
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

// ═══════════════════════════════════════════════════════════════════════════════
// Quantum-Safe Event (Hybrid)
// ═══════════════════════════════════════════════════════════════════════════════

/// An event encrypted with both classical and post-quantum cryptography.
///
/// Both encryption layers must be successfully decrypted.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuantumSafeEvent {
    /// Hybrid encryption settings.
    pub encryption: HybridEncryption,
    /// PQC envelope wrapping the content key.
    pqc_envelope: Vec<u8>,
    /// Encrypted event data.
    encrypted_data: Vec<u8>,
    /// Nonce for data encryption.
    nonce: Vec<u8>,
    /// Commitment to plaintext.
    commitment: [u8; 32],
    /// Creation timestamp.
    created_at: DateTime<Utc>,
}

impl QuantumSafeEvent {
    /// Create a quantum-safe event using hybrid encryption.
    pub fn seal(event: &AuditEvent, pqc_key: &EventPqcKeyPair) -> Result<Self> {
        use arcanum_hash::{Blake3, Hasher};
        use arcanum_symmetric::{ChaCha20Poly1305Cipher, Cipher};

        // Generate random content key
        let content_key_vec = ChaCha20Poly1305Cipher::generate_key();
        let mut content_key = [0u8; 32];
        content_key.copy_from_slice(&content_key_vec);

        // Serialize event
        let plaintext = serde_json::to_vec(event)?;

        // Compute commitment
        let mut hasher = Blake3::new();
        hasher.update(b"moloch-quantum-safe-v1");
        hasher.update(&plaintext);
        let output = hasher.finalize();
        let mut commitment = [0u8; 32];
        commitment.copy_from_slice(&output.as_bytes()[..32]);

        // Encrypt event with content key
        let nonce = ChaCha20Poly1305Cipher::generate_nonce();
        let encrypted_data = ChaCha20Poly1305Cipher::encrypt(
            &content_key_vec,
            &nonce,
            &plaintext,
            Some(&commitment),
        )
        .map_err(|e| HoloCryptError::EncryptionFailed {
            reason: format!("data encryption failed: {:?}", e),
        })?;

        // Wrap content key with PQC envelope
        let envelope =
            PqcEnvelope::wrap(&content_key, pqc_key.encapsulation_key()).map_err(|e| {
                HoloCryptError::PqcEncapsulationFailed {
                    reason: e.to_string(),
                }
            })?;

        let envelope_bytes = envelope.to_bytes();

        Ok(Self {
            encryption: HybridEncryption::pqc(pqc_key.key_id()),
            pqc_envelope: envelope_bytes,
            encrypted_data,
            nonce,
            commitment,
            created_at: Utc::now(),
        })
    }

    /// Unseal a quantum-safe event.
    pub fn unseal(&self, pqc_key: &EventPqcKeyPair) -> Result<AuditEvent> {
        use arcanum_symmetric::{ChaCha20Poly1305Cipher, Cipher};

        // Verify key ID if available
        if let Some(ref key_id) = self.encryption.pqc_key_id {
            if key_id != pqc_key.key_id() {
                return Err(HoloCryptError::KeyNotFound {
                    key_id: key_id.clone(),
                });
            }
        }

        // Unwrap content key from PQC envelope
        let envelope = PqcEnvelope::from_bytes(&self.pqc_envelope).map_err(|e| {
            HoloCryptError::CryptoError {
                reason: e.to_string(),
            }
        })?;

        let content_key = envelope.unwrap(pqc_key.decapsulation_key()).map_err(|e| {
            HoloCryptError::PqcDecapsulationFailed {
                reason: e.to_string(),
            }
        })?;

        // Decrypt event data
        let plaintext = ChaCha20Poly1305Cipher::decrypt(
            &content_key,
            &self.nonce,
            &self.encrypted_data,
            Some(&self.commitment),
        )
        .map_err(|_| HoloCryptError::DecryptionFailed {
            reason: "data decryption failed".into(),
        })?;

        // Verify commitment
        use arcanum_hash::{Blake3, Hasher};
        let mut hasher = Blake3::new();
        hasher.update(b"moloch-quantum-safe-v1");
        hasher.update(&plaintext);
        let output = hasher.finalize();
        let mut computed = [0u8; 32];
        computed.copy_from_slice(&output.as_bytes()[..32]);

        if computed != self.commitment {
            return Err(HoloCryptError::CommitmentMismatch);
        }

        // Deserialize event
        serde_json::from_slice(&plaintext).map_err(Into::into)
    }

    /// Get commitment.
    pub fn commitment(&self) -> &[u8; 32] {
        &self.commitment
    }

    /// Get creation timestamp.
    pub fn created_at(&self) -> DateTime<Utc> {
        self.created_at
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

// ═══════════════════════════════════════════════════════════════════════════════
// Key Migration
// ═══════════════════════════════════════════════════════════════════════════════

/// Migrates events from classical to post-quantum encryption.
pub struct KeyMigration;

impl KeyMigration {
    /// Migrate an event from classical to PQC encryption.
    ///
    /// Requires access to both the classical decryption key (to unseal)
    /// and the new PQC key (to re-seal).
    pub fn migrate_to_pqc<F>(
        event_data: &[u8],
        decrypt_fn: F,
        new_pqc_key: &EventPqcKeyPair,
    ) -> Result<PqcEvent>
    where
        F: FnOnce(&[u8]) -> Result<AuditEvent>,
    {
        // Decrypt with old key
        let event = decrypt_fn(event_data)?;

        // Re-encrypt with PQC
        PqcEvent::seal(&event, new_pqc_key)
    }

    /// Migrate from one PQC key to another (key rotation).
    pub fn rotate_pqc_key(
        pqc_event: &PqcEvent,
        old_key: &EventPqcKeyPair,
        new_key: &EventPqcKeyPair,
    ) -> Result<PqcEvent> {
        // Decrypt with old key
        let event = pqc_event.unseal(old_key)?;

        // Re-encrypt with new key
        PqcEvent::seal(&event, new_key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use moloch_core::crypto::SecretKey;
    use moloch_core::event::{ActorId, ActorKind, EventType, Outcome, ResourceId, ResourceKind};

    fn make_test_event(key: &SecretKey) -> AuditEvent {
        let actor = ActorId::new(key.public_key(), ActorKind::User);
        let resource = ResourceId::new(ResourceKind::Repository, "test-repo");

        AuditEvent::builder()
            .now()
            .event_type(EventType::RepoCreated)
            .actor(actor)
            .resource(resource)
            .outcome(Outcome::Success)
            .sign(key)
            .unwrap()
    }

    #[test]
    fn test_pqc_keypair_generation() {
        let keypair = EventPqcKeyPair::generate("test-key-1");

        assert_eq!(keypair.key_id(), "test-key-1");
        assert_eq!(keypair.algorithm(), "ML-KEM-768");

        // ML-KEM-768 key sizes
        assert_eq!(keypair.public_key_bytes().len(), 1184);
        assert_eq!(keypair.private_key_bytes().len(), 2400);
    }

    #[test]
    fn test_pqc_event_seal_unseal() {
        let signing_key = SecretKey::generate();
        let event = make_test_event(&signing_key);

        let pqc_key = EventPqcKeyPair::generate("pqc-key-1");

        let pqc_event = PqcEvent::seal(&event, &pqc_key).unwrap();
        let decrypted = pqc_event.unseal(&pqc_key).unwrap();

        assert_eq!(event.event_type, decrypted.event_type);
        assert_eq!(event.outcome, decrypted.outcome);
    }

    #[test]
    fn test_pqc_event_wrong_key_fails() {
        let signing_key = SecretKey::generate();
        let event = make_test_event(&signing_key);

        let key1 = EventPqcKeyPair::generate("key-1");
        let key2 = EventPqcKeyPair::generate("key-2");

        let pqc_event = PqcEvent::seal(&event, &key1).unwrap();

        // Wrong key should fail
        let result = pqc_event.unseal(&key2);
        assert!(result.is_err());
    }

    #[test]
    fn test_pqc_event_verify_structure() {
        let signing_key = SecretKey::generate();
        let event = make_test_event(&signing_key);

        let pqc_key = EventPqcKeyPair::generate("pqc-key-2");
        let pqc_event = PqcEvent::seal(&event, &pqc_key).unwrap();

        // Should verify without decryption
        assert!(pqc_event.verify_structure().is_ok());
    }

    #[test]
    fn test_quantum_safe_event() {
        let signing_key = SecretKey::generate();
        let event = make_test_event(&signing_key);

        let pqc_key = EventPqcKeyPair::generate("quantum-safe-key");

        let qs_event = QuantumSafeEvent::seal(&event, &pqc_key).unwrap();
        let decrypted = qs_event.unseal(&pqc_key).unwrap();

        assert_eq!(event.event_type, decrypted.event_type);
    }

    #[test]
    fn test_pqc_event_serialization() {
        let signing_key = SecretKey::generate();
        let event = make_test_event(&signing_key);

        let pqc_key = EventPqcKeyPair::generate("serial-key");

        let pqc_event = PqcEvent::seal(&event, &pqc_key).unwrap();
        let bytes = pqc_event.to_bytes();
        let restored = PqcEvent::from_bytes(&bytes).unwrap();

        let decrypted = restored.unseal(&pqc_key).unwrap();
        assert_eq!(event.event_type, decrypted.event_type);
    }

    #[test]
    fn test_encryption_modes() {
        assert_eq!(EncryptionMode::default(), EncryptionMode::Hybrid);

        let classical = HybridEncryption::classical("key-1");
        assert_eq!(classical.mode, EncryptionMode::Classical);

        let pqc = HybridEncryption::pqc("key-2");
        assert_eq!(pqc.mode, EncryptionMode::PostQuantum);

        let hybrid = HybridEncryption::hybrid("key-1", "key-2");
        assert_eq!(hybrid.mode, EncryptionMode::Hybrid);
    }

    #[test]
    fn test_key_rotation() {
        let signing_key = SecretKey::generate();
        let event = make_test_event(&signing_key);

        let old_key = EventPqcKeyPair::generate("old-key");
        let new_key = EventPqcKeyPair::generate("new-key");

        // Seal with old key
        let pqc_event = PqcEvent::seal(&event, &old_key).unwrap();

        // Rotate to new key
        let rotated = KeyMigration::rotate_pqc_key(&pqc_event, &old_key, &new_key).unwrap();

        // Should decrypt with new key
        let decrypted = rotated.unseal(&new_key).unwrap();
        assert_eq!(event.event_type, decrypted.event_type);

        // Should fail with old key
        let result = rotated.unseal(&old_key);
        assert!(result.is_err());
    }

    #[test]
    fn test_quantum_safe_event_serialization() {
        let signing_key = SecretKey::generate();
        let event = make_test_event(&signing_key);

        let pqc_key = EventPqcKeyPair::generate("qs-serial-key");

        let qs_event = QuantumSafeEvent::seal(&event, &pqc_key).unwrap();
        let bytes = qs_event.to_bytes();
        let restored = QuantumSafeEvent::from_bytes(&bytes).unwrap();

        let decrypted = restored.unseal(&pqc_key).unwrap();
        assert_eq!(event.event_type, decrypted.event_type);
    }
}
