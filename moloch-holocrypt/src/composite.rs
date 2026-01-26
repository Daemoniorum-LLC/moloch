//! Composite post-quantum signatures (Ed25519 + ML-DSA-65).
//!
//! Provides hybrid signatures that are secure against both classical and
//! quantum attacks. Both component signatures must verify for the composite
//! to be considered valid.
//!
//! ## Security Rationale
//!
//! - Ed25519 provides battle-tested classical security
//! - ML-DSA-65 provides post-quantum security (NIST Level 3)
//! - If either algorithm is broken, the other provides protection
//!
//! ## Size Characteristics
//!
//! - Signing key: 32 + 4032 = 4064 bytes
//! - Verifying key: 32 + 1952 = 1984 bytes
//! - Signature: 64 + 3309 = 3373 bytes
//!
//! ## Usage
//!
//! ```ignore
//! use moloch_holocrypt::composite::{CompositeSigningKey, CompositeVerifyingKey};
//!
//! // Generate keys
//! let signing_key = CompositeSigningKey::generate();
//! let verifying_key = signing_key.verifying_key();
//!
//! // Sign a message
//! let signature = signing_key.sign(b"Hello, post-quantum world!");
//!
//! // Verify - both Ed25519 and ML-DSA-65 must pass
//! assert!(verifying_key.verify(b"Hello, post-quantum world!", &signature).is_ok());
//! ```

use arcanum_signatures::ed25519::{
    Ed25519SigningKey, Ed25519VerifyingKey, Ed25519Signature,
};
use arcanum_signatures::{
    SigningKey as SigningKeyTrait, VerifyingKey as VerifyingKeyTrait, Signature as SignatureTrait,
};
use arcanum_pqc::dsa::{MlDsa65, MlDsa65SigningKey, MlDsa65VerifyingKey, MlDsa65Signature};
use arcanum_pqc::PostQuantumSignature;
use serde::{Deserialize, Serialize};

use crate::errors::{HoloCryptError, Result};

// ═══════════════════════════════════════════════════════════════════════════════
// COMPOSITE SIGNING KEY
// ═══════════════════════════════════════════════════════════════════════════════

/// Composite signing key combining Ed25519 and ML-DSA-65.
///
/// This key can sign messages with both algorithms simultaneously,
/// providing hybrid classical/post-quantum security.
///
/// Note: This struct stores both the signing key and verifying key for ML-DSA
/// because the arcanum-pqc crate doesn't expose public key derivation from
/// just the signing key.
#[derive(Clone)]
pub struct CompositeSigningKey {
    /// Ed25519 signing key (32 bytes).
    ed25519_sk: Ed25519SigningKey,
    /// Ed25519 verifying key (32 bytes).
    ed25519_vk: Ed25519VerifyingKey,
    /// ML-DSA-65 signing key (4032 bytes).
    ml_dsa_sk: MlDsa65SigningKey,
    /// ML-DSA-65 verifying key (1952 bytes).
    ml_dsa_vk: MlDsa65VerifyingKey,
}

impl CompositeSigningKey {
    /// Signing key serialized size: Ed25519 SK (32) + ML-DSA-65 SK (4032) + ML-DSA-65 VK (1952) = 6016 bytes.
    /// We also store the Ed25519 VK can be derived, so we store: 32 + 4032 + 1952 = 6016 bytes.
    pub const SIZE: usize = 32 + 4032 + 1952;

    /// Generate a new composite signing key.
    pub fn generate() -> Self {
        let ed25519_sk: Ed25519SigningKey = SigningKeyTrait::generate();
        let ed25519_vk = SigningKeyTrait::verifying_key(&ed25519_sk);
        let (ml_dsa_sk, ml_dsa_vk) = MlDsa65::generate_keypair();

        Self {
            ed25519_sk,
            ed25519_vk,
            ml_dsa_sk,
            ml_dsa_vk,
        }
    }

    /// Create from component keys.
    pub fn from_components(
        ed25519_sk: Ed25519SigningKey,
        ml_dsa_sk: MlDsa65SigningKey,
        ml_dsa_vk: MlDsa65VerifyingKey,
    ) -> Self {
        let ed25519_vk = SigningKeyTrait::verifying_key(&ed25519_sk);
        Self {
            ed25519_sk,
            ed25519_vk,
            ml_dsa_sk,
            ml_dsa_vk,
        }
    }

    /// Create from serialized bytes.
    ///
    /// Format: [ed25519_sk: 32 bytes][ml_dsa_sk: 4032 bytes][ml_dsa_vk: 1952 bytes]
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != Self::SIZE {
            return Err(HoloCryptError::InvalidConfiguration {
                reason: format!(
                    "Invalid composite signing key size: expected {}, got {}",
                    Self::SIZE,
                    bytes.len()
                ),
            });
        }

        let ed25519_sk: Ed25519SigningKey = SigningKeyTrait::from_bytes(&bytes[..32])
            .map_err(|e| HoloCryptError::InvalidConfiguration {
                reason: format!("Invalid Ed25519 signing key: {}", e),
            })?;
        let ed25519_vk = SigningKeyTrait::verifying_key(&ed25519_sk);

        let ml_dsa_sk = MlDsa65SigningKey::from_bytes(&bytes[32..32 + 4032])
            .map_err(|e| HoloCryptError::InvalidConfiguration {
                reason: format!("Invalid ML-DSA-65 signing key: {}", e),
            })?;

        let ml_dsa_vk = MlDsa65VerifyingKey::from_bytes(&bytes[32 + 4032..])
            .map_err(|e| HoloCryptError::InvalidConfiguration {
                reason: format!("Invalid ML-DSA-65 verifying key: {}", e),
            })?;

        Ok(Self {
            ed25519_sk,
            ed25519_vk,
            ml_dsa_sk,
            ml_dsa_vk,
        })
    }

    /// Serialize to bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(Self::SIZE);
        bytes.extend_from_slice(&SigningKeyTrait::to_bytes(&self.ed25519_sk));
        bytes.extend_from_slice(&self.ml_dsa_sk.to_bytes());
        bytes.extend_from_slice(&self.ml_dsa_vk.to_bytes());
        bytes
    }

    /// Get the corresponding verifying key.
    pub fn verifying_key(&self) -> CompositeVerifyingKey {
        CompositeVerifyingKey {
            ed25519: self.ed25519_vk.clone(),
            ml_dsa: self.ml_dsa_vk.clone(),
        }
    }

    /// Sign a message with both algorithms.
    ///
    /// Returns a composite signature containing both Ed25519 and ML-DSA-65 signatures.
    pub fn sign(&self, message: &[u8]) -> CompositeSignature {
        let ed25519_sig = SigningKeyTrait::sign(&self.ed25519_sk, message);
        let ml_dsa_sig = MlDsa65::sign(&self.ml_dsa_sk, message);

        CompositeSignature {
            ed25519: ed25519_sig,
            ml_dsa: ml_dsa_sig,
        }
    }

    /// Get the Ed25519 component signing key.
    pub fn ed25519_key(&self) -> &Ed25519SigningKey {
        &self.ed25519_sk
    }

    /// Get the ML-DSA-65 component signing key.
    pub fn ml_dsa_key(&self) -> &MlDsa65SigningKey {
        &self.ml_dsa_sk
    }
}

impl std::fmt::Debug for CompositeSigningKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "CompositeSigningKey([REDACTED])")
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// COMPOSITE VERIFYING KEY
// ═══════════════════════════════════════════════════════════════════════════════

/// Composite verifying key combining Ed25519 and ML-DSA-65.
///
/// Used to verify composite signatures. Both component signatures must
/// verify for the composite verification to succeed.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompositeVerifyingKey {
    /// Ed25519 verifying key (32 bytes).
    ed25519: Ed25519VerifyingKey,
    /// ML-DSA-65 verifying key (1952 bytes).
    ml_dsa: MlDsa65VerifyingKey,
}

impl CompositeVerifyingKey {
    /// Total verifying key size: Ed25519 (32) + ML-DSA-65 (1952) = 1984 bytes.
    pub const SIZE: usize = 32 + 1952;

    /// Create from component keys.
    pub fn from_components(ed25519: Ed25519VerifyingKey, ml_dsa: MlDsa65VerifyingKey) -> Self {
        Self { ed25519, ml_dsa }
    }

    /// Create from serialized bytes.
    ///
    /// Format: [ed25519: 32 bytes][ml_dsa: 1952 bytes]
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != Self::SIZE {
            return Err(HoloCryptError::InvalidConfiguration {
                reason: format!(
                    "Invalid composite verifying key size: expected {}, got {}",
                    Self::SIZE,
                    bytes.len()
                ),
            });
        }

        let ed25519: Ed25519VerifyingKey = VerifyingKeyTrait::from_bytes(&bytes[..32])
            .map_err(|e| HoloCryptError::InvalidConfiguration {
                reason: format!("Invalid Ed25519 verifying key: {}", e),
            })?;

        let ml_dsa = MlDsa65VerifyingKey::from_bytes(&bytes[32..])
            .map_err(|e| HoloCryptError::InvalidConfiguration {
                reason: format!("Invalid ML-DSA-65 verifying key: {}", e),
            })?;

        Ok(Self { ed25519, ml_dsa })
    }

    /// Serialize to bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(Self::SIZE);
        bytes.extend_from_slice(&VerifyingKeyTrait::to_bytes(&self.ed25519));
        bytes.extend_from_slice(&self.ml_dsa.to_bytes());
        bytes
    }

    /// Encode as hex string.
    pub fn to_hex(&self) -> String {
        hex::encode(self.to_bytes())
    }

    /// Decode from hex string.
    pub fn from_hex(hex_str: &str) -> Result<Self> {
        let bytes = hex::decode(hex_str).map_err(|e| HoloCryptError::InvalidConfiguration {
            reason: format!("Invalid hex: {}", e),
        })?;
        Self::from_bytes(&bytes)
    }

    /// Verify a composite signature.
    ///
    /// Both Ed25519 and ML-DSA-65 signatures must verify for this to succeed.
    pub fn verify(&self, message: &[u8], signature: &CompositeSignature) -> Result<()> {
        // Verify Ed25519 signature
        VerifyingKeyTrait::verify(&self.ed25519, message, &signature.ed25519)
            .map_err(|_| HoloCryptError::CompositeSignatureInvalid {
                component: "Ed25519".to_string(),
            })?;

        // Verify ML-DSA-65 signature
        MlDsa65::verify(&self.ml_dsa, message, &signature.ml_dsa)
            .map_err(|_| HoloCryptError::CompositeSignatureInvalid {
                component: "ML-DSA-65".to_string(),
            })?;

        Ok(())
    }

    /// Get the Ed25519 component key.
    pub fn ed25519_key(&self) -> &Ed25519VerifyingKey {
        &self.ed25519
    }

    /// Get the ML-DSA-65 component key.
    pub fn ml_dsa_key(&self) -> &MlDsa65VerifyingKey {
        &self.ml_dsa
    }
}

impl std::fmt::Debug for CompositeVerifyingKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "CompositeVerifyingKey(ed25519={:?}, ml_dsa={:?})",
            self.ed25519, self.ml_dsa
        )
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// COMPOSITE SIGNATURE
// ═══════════════════════════════════════════════════════════════════════════════

/// Composite signature combining Ed25519 and ML-DSA-65.
///
/// Contains both component signatures. Both must verify for the
/// composite signature to be considered valid.
#[derive(Clone, Serialize, Deserialize)]
pub struct CompositeSignature {
    /// Ed25519 signature (64 bytes).
    ed25519: Ed25519Signature,
    /// ML-DSA-65 signature (3309 bytes).
    ml_dsa: MlDsa65Signature,
}

impl PartialEq for CompositeSignature {
    fn eq(&self, other: &Self) -> bool {
        SignatureTrait::to_bytes(&self.ed25519) == SignatureTrait::to_bytes(&other.ed25519)
            && self.ml_dsa.to_bytes() == other.ml_dsa.to_bytes()
    }
}

impl Eq for CompositeSignature {}

impl CompositeSignature {
    /// Total signature size: Ed25519 (64) + ML-DSA-65 (3309) = 3373 bytes.
    pub const SIZE: usize = 64 + 3309;

    /// Create from component signatures.
    pub fn from_components(ed25519: Ed25519Signature, ml_dsa: MlDsa65Signature) -> Self {
        Self { ed25519, ml_dsa }
    }

    /// Create from serialized bytes.
    ///
    /// Format: [ed25519: 64 bytes][ml_dsa: 3309 bytes]
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != Self::SIZE {
            return Err(HoloCryptError::InvalidConfiguration {
                reason: format!(
                    "Invalid composite signature size: expected {}, got {}",
                    Self::SIZE,
                    bytes.len()
                ),
            });
        }

        let ed25519 = SignatureTrait::from_bytes(&bytes[..64])
            .map_err(|_| HoloCryptError::CompositeSignatureInvalid {
                component: "Ed25519 signature bytes".to_string(),
            })?;

        let ml_dsa = MlDsa65Signature::from_bytes(&bytes[64..])
            .map_err(|_| HoloCryptError::CompositeSignatureInvalid {
                component: "ML-DSA-65 signature bytes".to_string(),
            })?;

        Ok(Self { ed25519, ml_dsa })
    }

    /// Serialize to bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(Self::SIZE);
        bytes.extend_from_slice(&SignatureTrait::to_bytes(&self.ed25519));
        bytes.extend_from_slice(&self.ml_dsa.to_bytes());
        bytes
    }

    /// Encode as hex string.
    pub fn to_hex(&self) -> String {
        hex::encode(self.to_bytes())
    }

    /// Get the Ed25519 component signature.
    pub fn ed25519_signature(&self) -> &Ed25519Signature {
        &self.ed25519
    }

    /// Get the ML-DSA-65 component signature.
    pub fn ml_dsa_signature(&self) -> &MlDsa65Signature {
        &self.ml_dsa
    }
}

impl std::fmt::Debug for CompositeSignature {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "CompositeSignature({} bytes)", Self::SIZE)
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// CONVENIENCE FUNCTIONS
// ═══════════════════════════════════════════════════════════════════════════════

/// Generate a new composite key pair.
pub fn generate_keypair() -> (CompositeSigningKey, CompositeVerifyingKey) {
    let signing_key = CompositeSigningKey::generate();
    let verifying_key = signing_key.verifying_key();
    (signing_key, verifying_key)
}

/// Sign a message with a composite key.
pub fn sign(signing_key: &CompositeSigningKey, message: &[u8]) -> CompositeSignature {
    signing_key.sign(message)
}

/// Verify a composite signature.
pub fn verify(
    verifying_key: &CompositeVerifyingKey,
    message: &[u8],
    signature: &CompositeSignature,
) -> Result<()> {
    verifying_key.verify(message, signature)
}

// ═══════════════════════════════════════════════════════════════════════════════
// TESTS
// ═══════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_composite_sign_verify() {
        let (sk, vk) = generate_keypair();
        let message = b"Hello, post-quantum world!";

        let signature = sk.sign(message);
        assert!(vk.verify(message, &signature).is_ok());
    }

    #[test]
    fn test_composite_wrong_message_fails() {
        let (sk, vk) = generate_keypair();
        let message = b"Hello!";
        let wrong_message = b"Wrong!";

        let signature = sk.sign(message);
        assert!(vk.verify(wrong_message, &signature).is_err());
    }

    #[test]
    fn test_composite_wrong_key_fails() {
        let (sk1, _vk1) = generate_keypair();
        let (_sk2, vk2) = generate_keypair();
        let message = b"Hello!";

        let signature = sk1.sign(message);
        assert!(vk2.verify(message, &signature).is_err());
    }

    #[test]
    fn test_composite_signature_size() {
        let (sk, _vk) = generate_keypair();
        let signature = sk.sign(b"test");

        assert_eq!(signature.to_bytes().len(), CompositeSignature::SIZE);
    }

    #[test]
    fn test_composite_key_sizes() {
        let (sk, vk) = generate_keypair();

        assert_eq!(sk.to_bytes().len(), CompositeSigningKey::SIZE);
        assert_eq!(vk.to_bytes().len(), CompositeVerifyingKey::SIZE);
    }

    #[test]
    fn test_composite_key_serialization() {
        let (sk, vk) = generate_keypair();

        // Test verifying key serialization
        let vk_bytes = vk.to_bytes();
        let vk_restored = CompositeVerifyingKey::from_bytes(&vk_bytes).unwrap();
        assert_eq!(vk, vk_restored);

        // Test signing key serialization
        let sk_bytes = sk.to_bytes();
        let sk_restored = CompositeSigningKey::from_bytes(&sk_bytes).unwrap();

        // Verify the restored key works
        let message = b"Test message";
        let sig = sk_restored.sign(message);
        assert!(vk.verify(message, &sig).is_ok());
    }

    #[test]
    fn test_composite_signature_serialization() {
        let (sk, vk) = generate_keypair();
        let message = b"Test message";

        let signature = sk.sign(message);
        let sig_bytes = signature.to_bytes();
        let sig_restored = CompositeSignature::from_bytes(&sig_bytes).unwrap();

        assert!(vk.verify(message, &sig_restored).is_ok());
    }

    #[test]
    fn test_composite_hex_roundtrip() {
        let (_sk, vk) = generate_keypair();

        let hex = vk.to_hex();
        let restored = CompositeVerifyingKey::from_hex(&hex).unwrap();

        assert_eq!(vk, restored);
    }

    #[test]
    fn test_composite_json_serialization() {
        let (sk, vk) = generate_keypair();
        let message = b"Test";
        let signature = sk.sign(message);

        // Test verifying key JSON
        let vk_json = serde_json::to_string(&vk).unwrap();
        let vk_restored: CompositeVerifyingKey = serde_json::from_str(&vk_json).unwrap();
        assert_eq!(vk, vk_restored);

        // Test signature JSON
        let sig_json = serde_json::to_string(&signature).unwrap();
        let sig_restored: CompositeSignature = serde_json::from_str(&sig_json).unwrap();
        assert!(vk.verify(message, &sig_restored).is_ok());
    }

    #[test]
    fn test_component_access() {
        let (sk, vk) = generate_keypair();

        // Access individual components
        let _ed25519_sk = sk.ed25519_key();
        let _ml_dsa_sk = sk.ml_dsa_key();
        let _ed25519_vk = vk.ed25519_key();
        let _ml_dsa_vk = vk.ml_dsa_key();
    }

    #[test]
    fn test_individual_signature_verification() {
        let (sk, vk) = generate_keypair();
        let message = b"Test message";
        let signature = sk.sign(message);

        // Verify Ed25519 component separately
        assert!(VerifyingKeyTrait::verify(
            vk.ed25519_key(),
            message,
            signature.ed25519_signature()
        )
        .is_ok());

        // Verify ML-DSA-65 component separately
        assert!(MlDsa65::verify(
            vk.ml_dsa_key(),
            message,
            signature.ml_dsa_signature()
        )
        .is_ok());
    }
}
