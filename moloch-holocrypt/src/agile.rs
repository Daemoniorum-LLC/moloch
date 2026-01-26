//! Cryptographic agility for encrypted audit events.
//!
//! Provides algorithm-agnostic encryption with version management,
//! policy enforcement, and migration support.
//!
//! ## Features
//!
//! - **Algorithm Versioning**: Self-describing containers identify encryption algorithm
//! - **Policy Enforcement**: Restrict algorithms based on compliance requirements
//! - **Migration Support**: Tools for re-encrypting with newer algorithms
//! - **Presets**: Pre-configured settings for common use cases
//!
//! ## Presets
//!
//! - `AgileConfig::default()` - ChaCha20-Poly1305 + Ed25519 + Blake3
//! - `AgileConfig::fips_140_3()` - AES-256-GCM + ECDSA-P256 + SHA-256
//! - `AgileConfig::post_quantum()` - AES-256-GCM + CompositeSignature + Blake3
//!
//! ## Usage
//!
//! ```ignore
//! use moloch_holocrypt::agile::{AgileConfig, AgileEncryptedEvent};
//!
//! // Create with default configuration
//! let config = AgileConfig::default();
//!
//! // Encrypt an event
//! let agile_event = AgileEncryptedEvent::seal(&event, &key, &config)?;
//!
//! // Check algorithm used
//! println!("Encrypted with: {:?}", agile_event.algorithm());
//!
//! // Check policy compliance
//! let policy = Policy::fips_140_3();
//! if !policy.allows(agile_event.algorithm()) {
//!     println!("Needs migration to FIPS-compliant algorithm");
//! }
//! ```

use arcanum_agile::AgileCiphertext;
pub use arcanum_agile::{AlgorithmId, ComplianceProfile, Policy, SecurityLevel};
use arcanum_hash::{Blake3, Hasher};
use serde::{Deserialize, Serialize};

use crate::errors::{HoloCryptError, Result};

// ═══════════════════════════════════════════════════════════════════════════════
// AGILE CONFIGURATION
// ═══════════════════════════════════════════════════════════════════════════════

/// Configuration for agile encryption.
///
/// Specifies which algorithms to use for symmetric encryption, signatures,
/// and hashing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgileConfig {
    /// Symmetric encryption algorithm (AEAD)
    symmetric_algorithm: AlgorithmId,
    /// Signature algorithm identifier
    signature_algorithm: SignatureAlgorithm,
    /// Hash algorithm identifier
    hash_algorithm: HashAlgorithm,
    /// Policy for algorithm restrictions
    policy: Option<Policy>,
}

/// Signature algorithm choices.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SignatureAlgorithm {
    /// Ed25519 - fast and widely used
    Ed25519,
    /// ECDSA with P-256 curve (FIPS)
    EcdsaP256,
    /// Composite Ed25519 + ML-DSA-65 (post-quantum hybrid)
    Composite,
}

/// Hash algorithm choices.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum HashAlgorithm {
    /// Blake3 - fast, secure, parallelizable
    Blake3,
    /// SHA-256 (FIPS)
    Sha256,
    /// SHA-512 (FIPS)
    Sha512,
}

impl Default for AgileConfig {
    fn default() -> Self {
        Self {
            symmetric_algorithm: AlgorithmId::ChaCha20Poly1305,
            signature_algorithm: SignatureAlgorithm::Ed25519,
            hash_algorithm: HashAlgorithm::Blake3,
            policy: None,
        }
    }
}

impl AgileConfig {
    /// Create a new agile configuration.
    pub fn new(symmetric: AlgorithmId, signature: SignatureAlgorithm, hash: HashAlgorithm) -> Self {
        Self {
            symmetric_algorithm: symmetric,
            signature_algorithm: signature,
            hash_algorithm: hash,
            policy: None,
        }
    }

    /// Create a FIPS 140-3 compliant configuration.
    ///
    /// Uses AES-256-GCM, ECDSA-P256, and SHA-256.
    pub fn fips_140_3() -> Self {
        Self {
            symmetric_algorithm: AlgorithmId::Aes256Gcm,
            signature_algorithm: SignatureAlgorithm::EcdsaP256,
            hash_algorithm: HashAlgorithm::Sha256,
            policy: Some(Policy::fips_140_3()),
        }
    }

    /// Create a post-quantum hybrid configuration.
    ///
    /// Uses AES-256-GCM, Composite signature (Ed25519 + ML-DSA-65), and Blake3.
    pub fn post_quantum() -> Self {
        Self {
            symmetric_algorithm: AlgorithmId::Aes256Gcm,
            signature_algorithm: SignatureAlgorithm::Composite,
            hash_algorithm: HashAlgorithm::Blake3,
            policy: None,
        }
    }

    /// Create a high-security configuration.
    ///
    /// Uses XChaCha20-Poly1305 (larger nonce), composite signatures, and Blake3.
    pub fn high_security() -> Self {
        Self {
            symmetric_algorithm: AlgorithmId::XChaCha20Poly1305,
            signature_algorithm: SignatureAlgorithm::Composite,
            hash_algorithm: HashAlgorithm::Blake3,
            policy: None,
        }
    }

    /// Get the symmetric algorithm.
    pub fn symmetric_algorithm(&self) -> AlgorithmId {
        self.symmetric_algorithm
    }

    /// Get the signature algorithm.
    pub fn signature_algorithm(&self) -> SignatureAlgorithm {
        self.signature_algorithm
    }

    /// Get the hash algorithm.
    pub fn hash_algorithm(&self) -> HashAlgorithm {
        self.hash_algorithm
    }

    /// Get the policy if set.
    pub fn policy(&self) -> Option<&Policy> {
        self.policy.as_ref()
    }

    /// Set the policy.
    pub fn with_policy(mut self, policy: Policy) -> Self {
        self.policy = Some(policy);
        self
    }

    /// Validate configuration against policy.
    pub fn validate(&self) -> Result<()> {
        if let Some(policy) = &self.policy {
            if !policy.allows(self.symmetric_algorithm) {
                return Err(HoloCryptError::UnsupportedPolicy {
                    policy: format!(
                        "Symmetric algorithm {:?} not allowed by policy",
                        self.symmetric_algorithm
                    ),
                });
            }
        }
        Ok(())
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// AGILE ENCRYPTED EVENT
// ═══════════════════════════════════════════════════════════════════════════════

/// An encrypted event with algorithm agility.
///
/// Self-describing container that includes algorithm metadata,
/// enabling future migration and policy enforcement.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgileEncryptedEvent {
    /// Configuration used for this event
    config: AgileConfig,
    /// The agile ciphertext container
    #[serde(with = "agile_ciphertext_serde")]
    container: AgileCiphertext,
    /// Commitment to the plaintext
    commitment: [u8; 32],
    /// Merkle root of the event fields
    merkle_root: [u8; 32],
}

mod agile_ciphertext_serde {
    use super::*;
    use serde::{Deserializer, Serializer};

    pub fn serialize<S>(ct: &AgileCiphertext, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let bytes = ct.to_bytes();
        if serializer.is_human_readable() {
            serializer.serialize_str(&hex::encode(&bytes))
        } else {
            serializer.serialize_bytes(&bytes)
        }
    }

    pub fn deserialize<'de, D>(deserializer: D) -> std::result::Result<AgileCiphertext, D::Error>
    where
        D: Deserializer<'de>,
    {
        if deserializer.is_human_readable() {
            let s = String::deserialize(deserializer)?;
            let bytes = hex::decode(&s).map_err(serde::de::Error::custom)?;
            AgileCiphertext::parse(&bytes).map_err(serde::de::Error::custom)
        } else {
            let bytes = <Vec<u8>>::deserialize(deserializer)?;
            AgileCiphertext::parse(&bytes).map_err(serde::de::Error::custom)
        }
    }
}

impl AgileEncryptedEvent {
    /// Create a new agile encrypted event.
    ///
    /// # Arguments
    /// * `plaintext` - Data to encrypt
    /// * `key` - Encryption key (must match algorithm's key size)
    /// * `config` - Agile configuration specifying algorithms
    pub fn seal(plaintext: &[u8], key: &[u8], config: &AgileConfig) -> Result<Self> {
        // Validate configuration
        config.validate()?;

        // Compute commitment
        let commitment = compute_commitment(plaintext);

        // Compute merkle root (simplified - just hash of commitment for now)
        let merkle_root = compute_merkle_root(&commitment);

        // Encrypt with specified algorithm
        let container = AgileCiphertext::encrypt(config.symmetric_algorithm(), key, plaintext)
            .map_err(|e| HoloCryptError::EncryptionFailed {
                reason: format!("Agile encryption failed: {}", e),
            })?;

        Ok(Self {
            config: config.clone(),
            container,
            commitment,
            merkle_root,
        })
    }

    /// Decrypt and return the plaintext.
    pub fn unseal(&self, key: &[u8]) -> Result<Vec<u8>> {
        let plaintext =
            self.container
                .decrypt(key)
                .map_err(|e| HoloCryptError::DecryptionFailed {
                    reason: format!("Agile decryption failed: {}", e),
                })?;

        // Verify commitment
        let expected_commitment = compute_commitment(&plaintext);
        if expected_commitment != self.commitment {
            return Err(HoloCryptError::CommitmentMismatch);
        }

        Ok(plaintext)
    }

    /// Get the algorithm used for encryption.
    pub fn algorithm(&self) -> AlgorithmId {
        self.container.algorithm()
    }

    /// Get the configuration.
    pub fn config(&self) -> &AgileConfig {
        &self.config
    }

    /// Get the commitment.
    pub fn commitment(&self) -> &[u8; 32] {
        &self.commitment
    }

    /// Get the Merkle root.
    pub fn merkle_root(&self) -> &[u8; 32] {
        &self.merkle_root
    }

    /// Check if migration is recommended.
    pub fn needs_migration(&self) -> bool {
        self.container.migration_recommendation().is_some()
    }

    /// Get migration recommendation if the algorithm is deprecated.
    pub fn migration_recommendation(&self) -> Option<MigrationInfo> {
        self.container
            .migration_recommendation()
            .map(|r| MigrationInfo {
                source: r.source,
                target: r.target,
                reason: r.reason,
            })
    }

    /// Migrate to a new algorithm.
    ///
    /// Decrypts with old key and re-encrypts with new algorithm.
    pub fn migrate(
        &self,
        old_key: &[u8],
        new_key: &[u8],
        new_config: &AgileConfig,
    ) -> Result<Self> {
        let plaintext = self.unseal(old_key)?;
        Self::seal(&plaintext, new_key, new_config)
    }

    /// Check if this event complies with a policy.
    pub fn complies_with(&self, policy: &Policy) -> bool {
        policy.allows(self.algorithm())
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

/// Information about a recommended migration.
#[derive(Debug, Clone)]
pub struct MigrationInfo {
    /// Current algorithm
    pub source: AlgorithmId,
    /// Recommended target algorithm
    pub target: AlgorithmId,
    /// Reason for migration
    pub reason: String,
}

// ═══════════════════════════════════════════════════════════════════════════════
// HELPER FUNCTIONS
// ═══════════════════════════════════════════════════════════════════════════════

fn compute_commitment(data: &[u8]) -> [u8; 32] {
    let mut hasher = Blake3::new();
    hasher.update(b"moloch-agile-commitment-v1");
    hasher.update(data);
    let output = hasher.finalize();
    let mut commitment = [0u8; 32];
    commitment.copy_from_slice(&output.as_bytes()[..32]);
    commitment
}

fn compute_merkle_root(commitment: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Blake3::new();
    hasher.update(b"moloch-agile-merkle-v1");
    hasher.update(commitment);
    let output = hasher.finalize();
    let mut root = [0u8; 32];
    root.copy_from_slice(&output.as_bytes()[..32]);
    root
}

// ═══════════════════════════════════════════════════════════════════════════════
// TESTS
// ═══════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = AgileConfig::default();
        assert_eq!(config.symmetric_algorithm(), AlgorithmId::ChaCha20Poly1305);
        assert_eq!(config.signature_algorithm(), SignatureAlgorithm::Ed25519);
        assert_eq!(config.hash_algorithm(), HashAlgorithm::Blake3);
    }

    #[test]
    fn test_fips_config() {
        let config = AgileConfig::fips_140_3();
        assert_eq!(config.symmetric_algorithm(), AlgorithmId::Aes256Gcm);
        assert_eq!(config.signature_algorithm(), SignatureAlgorithm::EcdsaP256);
        assert_eq!(config.hash_algorithm(), HashAlgorithm::Sha256);
        assert!(config.policy().is_some());
    }

    #[test]
    fn test_post_quantum_config() {
        let config = AgileConfig::post_quantum();
        assert_eq!(config.symmetric_algorithm(), AlgorithmId::Aes256Gcm);
        assert_eq!(config.signature_algorithm(), SignatureAlgorithm::Composite);
        assert_eq!(config.hash_algorithm(), HashAlgorithm::Blake3);
    }

    #[test]
    fn test_seal_unseal_chacha20() {
        let config = AgileConfig::default();
        let key = [0u8; 32];
        let plaintext = b"Hello, agile encryption!";

        let event = AgileEncryptedEvent::seal(plaintext, &key, &config).unwrap();
        assert_eq!(event.algorithm(), AlgorithmId::ChaCha20Poly1305);

        let decrypted = event.unseal(&key).unwrap();
        assert_eq!(&decrypted, plaintext);
    }

    #[test]
    fn test_seal_unseal_aes256gcm() {
        let config = AgileConfig::fips_140_3();
        let key = [0u8; 32];
        let plaintext = b"FIPS compliant data!";

        let event = AgileEncryptedEvent::seal(plaintext, &key, &config).unwrap();
        assert_eq!(event.algorithm(), AlgorithmId::Aes256Gcm);

        let decrypted = event.unseal(&key).unwrap();
        assert_eq!(&decrypted, plaintext);
    }

    #[test]
    fn test_wrong_key_fails() {
        let config = AgileConfig::default();
        let key = [0u8; 32];
        let wrong_key = [1u8; 32];
        let plaintext = b"Secret data";

        let event = AgileEncryptedEvent::seal(plaintext, &key, &config).unwrap();
        assert!(event.unseal(&wrong_key).is_err());
    }

    #[test]
    fn test_migration() {
        let old_config = AgileConfig::default();
        let new_config = AgileConfig::fips_140_3();
        let old_key = [0u8; 32];
        let new_key = [1u8; 32];
        let plaintext = b"Data to migrate";

        let old_event = AgileEncryptedEvent::seal(plaintext, &old_key, &old_config).unwrap();
        let new_event = old_event.migrate(&old_key, &new_key, &new_config).unwrap();

        assert_eq!(old_event.algorithm(), AlgorithmId::ChaCha20Poly1305);
        assert_eq!(new_event.algorithm(), AlgorithmId::Aes256Gcm);

        let decrypted = new_event.unseal(&new_key).unwrap();
        assert_eq!(&decrypted, plaintext);
    }

    #[test]
    fn test_policy_compliance() {
        let config = AgileConfig::default();
        let key = [0u8; 32];
        let plaintext = b"Test data";

        let event = AgileEncryptedEvent::seal(plaintext, &key, &config).unwrap();

        let fips_policy = Policy::fips_140_3();
        assert!(!event.complies_with(&fips_policy)); // ChaCha20 not FIPS

        let default_policy = Policy::default();
        assert!(event.complies_with(&default_policy)); // ChaCha20 OK by default
    }

    #[test]
    fn test_serialization() {
        let config = AgileConfig::default();
        let key = [0u8; 32];
        let plaintext = b"Serialize me";

        let event = AgileEncryptedEvent::seal(plaintext, &key, &config).unwrap();
        let bytes = event.to_bytes();
        let restored = AgileEncryptedEvent::from_bytes(&bytes).unwrap();

        let decrypted = restored.unseal(&key).unwrap();
        assert_eq!(&decrypted, plaintext);
    }

    #[test]
    fn test_commitment_verification() {
        let config = AgileConfig::default();
        let key = [0u8; 32];
        let plaintext = b"Integrity check";

        let event = AgileEncryptedEvent::seal(plaintext, &key, &config).unwrap();

        // Commitment should be non-zero
        assert_ne!(event.commitment(), &[0u8; 32]);

        // Merkle root should be non-zero
        assert_ne!(event.merkle_root(), &[0u8; 32]);
    }
}
