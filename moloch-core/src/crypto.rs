//! Cryptographic primitives for Moloch, powered by Arcanum.
//!
//! We use Arcanum's optimized implementations:
//! - BLAKE3 for content hashing (SIMD-accelerated, fast, secure)
//! - Ed25519 for signatures (fast verification, small signatures)
//! - Batch verification for 3-8x faster block validation

use std::fmt;

use arcanum_hash::prelude::{Blake3, Hasher as ArcanumHasher};
use arcanum_signatures::prelude::{
    Ed25519SigningKey, Ed25519Signature, Ed25519VerifyingKey,
    SigningKey as ArcanumSigningKey, Signature as ArcanumSignature, VerifyingKey as ArcanumVerifyingKey,
};
use arcanum_signatures::ed25519::Ed25519BatchVerifier;
use arcanum_signatures::BatchVerifier;
use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

/// A 32-byte hash value.
#[derive(Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Hash([u8; 32]);

impl Hash {
    /// The zero hash (used as a sentinel).
    pub const ZERO: Self = Self([0u8; 32]);

    /// Create a hash from raw bytes.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Get the raw bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Create from hex string.
    pub fn from_hex(s: &str) -> Result<Self> {
        let bytes = hex::decode(s)?;
        if bytes.len() != 32 {
            return Err(Error::invalid_hash(format!(
                "expected 32 bytes, got {}",
                bytes.len()
            )));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(Self(arr))
    }

    /// Convert to hex string.
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    /// Check if this is the zero hash.
    pub fn is_zero(&self) -> bool {
        self == &Self::ZERO
    }
}

impl fmt::Debug for Hash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Hash({})", &self.to_hex()[..16])
    }
}

impl fmt::Display for Hash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

impl AsRef<[u8]> for Hash {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// Hash arbitrary data using Arcanum BLAKE3 (SIMD-accelerated).
pub fn hash(data: &[u8]) -> Hash {
    let output = Blake3::hash(data);
    let bytes: [u8; 32] = output.to_array().expect("BLAKE3 always outputs 32 bytes");
    Hash(bytes)
}

/// Hash two child hashes to produce a parent hash.
/// Used in merkle tree construction.
pub fn hash_pair(left: Hash, right: Hash) -> Hash {
    let mut hasher = Blake3::new();
    hasher.update(left.as_bytes());
    hasher.update(right.as_bytes());
    let output = hasher.finalize();
    let bytes: [u8; 32] = output.to_array().expect("BLAKE3 always outputs 32 bytes");
    Hash(bytes)
}

/// Hash multiple items by concatenating their hashes.
pub fn hash_all<T: AsRef<[u8]>>(items: &[T]) -> Hash {
    let mut hasher = Blake3::new();
    for item in items {
        hasher.update(item.as_ref());
    }
    let output = hasher.finalize();
    let bytes: [u8; 32] = output.to_array().expect("BLAKE3 always outputs 32 bytes");
    Hash(bytes)
}

/// A public key for verifying signatures.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicKey(#[serde(with = "public_key_serde")] Ed25519VerifyingKey);

mod public_key_serde {
    use super::*;
    use serde::{Deserializer, Serializer};

    pub fn serialize<S: Serializer>(key: &Ed25519VerifyingKey, s: S) -> std::result::Result<S::Ok, S::Error> {
        // Serialize as fixed-size array for bincode compatibility
        let bytes = ArcanumVerifyingKey::to_bytes(key);
        let arr: [u8; 32] = bytes.try_into().map_err(|_| serde::ser::Error::custom("invalid key length"))?;
        arr.serialize(s)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> std::result::Result<Ed25519VerifyingKey, D::Error> {
        let bytes: [u8; 32] = Deserialize::deserialize(d)?;
        Ed25519VerifyingKey::from_bytes(&bytes).map_err(serde::de::Error::custom)
    }
}

impl PublicKey {
    /// Create from raw bytes.
    pub fn from_bytes(bytes: &[u8; 32]) -> Result<Self> {
        let key = Ed25519VerifyingKey::from_bytes(bytes).map_err(|e| Error::invalid_key(e.to_string()))?;
        Ok(Self(key))
    }

    /// Get the raw bytes.
    pub fn as_bytes(&self) -> [u8; 32] {
        let bytes = ArcanumVerifyingKey::to_bytes(&self.0);
        bytes.try_into().expect("Ed25519 public key is always 32 bytes")
    }

    /// Derive a unique identifier from this key.
    pub fn id(&self) -> Hash {
        hash(&self.as_bytes())
    }

    /// Verify a signature.
    pub fn verify(&self, message: &[u8], signature: &Sig) -> Result<()> {
        ArcanumVerifyingKey::verify(&self.0, message, &signature.0)
            .map_err(|_| Error::invalid_signature())
    }

    /// Get the inner Ed25519 verifying key for batch operations.
    pub(crate) fn inner(&self) -> &Ed25519VerifyingKey {
        &self.0
    }
}

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PublicKey({})", &hex::encode(&self.as_bytes()[..8]))
    }
}

impl std::hash::Hash for PublicKey {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.as_bytes().hash(state);
    }
}

/// A secret key for signing.
#[derive(Clone)]
pub struct SecretKey(Ed25519SigningKey);

impl SecretKey {
    /// Generate a new random key pair.
    pub fn generate() -> Self {
        Self(Ed25519SigningKey::generate())
    }

    /// Create from raw bytes.
    pub fn from_bytes(bytes: &[u8; 32]) -> Result<Self> {
        let key = Ed25519SigningKey::from_bytes(bytes).map_err(|e| Error::invalid_key(e.to_string()))?;
        Ok(Self(key))
    }

    /// Get the raw bytes.
    pub fn as_bytes(&self) -> [u8; 32] {
        let bytes = ArcanumSigningKey::to_bytes(&self.0);
        bytes.try_into().expect("Ed25519 secret key is always 32 bytes")
    }

    /// Get the corresponding public key.
    pub fn public_key(&self) -> PublicKey {
        PublicKey(ArcanumSigningKey::verifying_key(&self.0))
    }

    /// Sign a message.
    pub fn sign(&self, message: &[u8]) -> Sig {
        Sig(ArcanumSigningKey::sign(&self.0, message))
    }
}

impl fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecretKey([redacted])")
    }
}

/// A digital signature.
#[derive(Clone, Serialize, Deserialize)]
pub struct Sig(#[serde(with = "sig_serde")] Ed25519Signature);

impl PartialEq for Sig {
    fn eq(&self, other: &Self) -> bool {
        self.to_bytes() == other.to_bytes()
    }
}

impl Eq for Sig {}

mod sig_serde {
    use super::*;
    use serde::{Deserializer, Serializer};

    pub fn serialize<S: Serializer>(sig: &Ed25519Signature, s: S) -> std::result::Result<S::Ok, S::Error> {
        // Serialize as two 32-byte arrays for bincode compatibility
        // (serde only implements for arrays up to 32 elements)
        let bytes = ArcanumSignature::to_bytes(sig);
        let (first, second) = bytes.split_at(32);
        let first: [u8; 32] = first.try_into().map_err(|_| serde::ser::Error::custom("invalid signature length"))?;
        let second: [u8; 32] = second.try_into().map_err(|_| serde::ser::Error::custom("invalid signature length"))?;
        (first, second).serialize(s)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> std::result::Result<Ed25519Signature, D::Error> {
        let (first, second): ([u8; 32], [u8; 32]) = Deserialize::deserialize(d)?;
        let mut bytes = [0u8; 64];
        bytes[..32].copy_from_slice(&first);
        bytes[32..].copy_from_slice(&second);
        Ed25519Signature::from_bytes(&bytes).map_err(serde::de::Error::custom)
    }
}

impl Sig {
    /// Create an empty/placeholder signature.
    pub fn empty() -> Self {
        Self(Ed25519Signature::from_bytes(&[0u8; 64]).expect("zero bytes is valid"))
    }

    /// Create from raw bytes.
    pub fn from_bytes(bytes: &[u8; 64]) -> Result<Self> {
        Ok(Self(Ed25519Signature::from_bytes(bytes).map_err(|_| Error::invalid_signature())?))
    }

    /// Get the raw bytes.
    pub fn to_bytes(&self) -> [u8; 64] {
        ArcanumSignature::to_bytes(&self.0).try_into().expect("Ed25519 signature is always 64 bytes")
    }

    /// Check if this is an empty signature.
    pub fn is_empty(&self) -> bool {
        self.to_bytes() == [0u8; 64]
    }

    /// Get the inner Ed25519 signature for batch operations.
    pub(crate) fn inner(&self) -> &Ed25519Signature {
        &self.0
    }
}

/// Batch-verify multiple signatures at once.
///
/// This is 3-8x faster than verifying signatures individually for large batches.
/// Uses Arcanum's optimized Ed25519 batch verifier with Straus' multi-scalar
/// multiplication algorithm.
///
/// # Arguments
/// * `items` - Slice of (public_key, message, signature) tuples to verify
///
/// # Returns
/// * `Ok(())` if all signatures are valid
/// * `Err` if any signature is invalid (does not identify which one)
///
/// # Example
/// ```ignore
/// let items = events.iter()
///     .map(|e| (e.attester(), e.canonical_bytes(), e.signature()))
///     .collect::<Vec<_>>();
/// batch_verify(&items)?;
/// ```
pub fn batch_verify(items: &[(&PublicKey, &[u8], &Sig)]) -> Result<()> {
    if items.is_empty() {
        return Ok(());
    }

    // Convert to Arcanum's expected format
    let arcanum_items: Vec<(&Ed25519VerifyingKey, &[u8], &Ed25519Signature)> = items
        .iter()
        .map(|(pk, msg, sig)| (pk.inner(), *msg, sig.inner()))
        .collect();

    Ed25519BatchVerifier::verify_batch(&arcanum_items)
        .map_err(|_| Error::invalid_signature())
}

/// Result of batch verification with identification of invalid signatures.
#[derive(Debug, Clone)]
pub struct BatchVerifyResult {
    /// Indices of items that failed verification.
    pub invalid_indices: Vec<usize>,
}

impl BatchVerifyResult {
    /// Check if all signatures were valid.
    pub fn all_valid(&self) -> bool {
        self.invalid_indices.is_empty()
    }
}

/// Batch-verify with fallback to identify invalid signatures.
///
/// If batch verification fails, falls back to individual verification
/// to identify which signatures are invalid.
///
/// # Performance
/// - Fast path (all valid): O(n) with batch optimization
/// - Slow path (some invalid): O(n) sequential verification
pub fn batch_verify_with_fallback(items: &[(&PublicKey, &[u8], &Sig)]) -> BatchVerifyResult {
    // Try batch first
    if batch_verify(items).is_ok() {
        return BatchVerifyResult {
            invalid_indices: Vec::new(),
        };
    }

    // Fallback: identify which ones are invalid
    let invalid_indices = items
        .iter()
        .enumerate()
        .filter_map(|(i, (pk, msg, sig))| {
            if pk.verify(msg, sig).is_err() {
                Some(i)
            } else {
                None
            }
        })
        .collect();

    BatchVerifyResult { invalid_indices }
}

impl fmt::Debug for Sig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Sig({})", &hex::encode(&self.to_bytes()[..8]))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sig_bincode_roundtrip() {
        let key = SecretKey::generate();
        let sig = key.sign(b"test message");

        // Serialize
        let bytes = bincode::serialize(&sig).expect("serialize should work");
        println!("Serialized sig size: {} bytes", bytes.len());

        // Deserialize
        let restored: Sig = bincode::deserialize(&bytes).expect("deserialize should work");

        assert_eq!(sig.to_bytes(), restored.to_bytes());
    }

    #[test]
    fn test_pubkey_bincode_roundtrip() {
        let key = SecretKey::generate();
        let pk = key.public_key();

        // Serialize
        let bytes = bincode::serialize(&pk).expect("serialize should work");
        println!("Serialized pubkey size: {} bytes", bytes.len());

        // Deserialize
        let restored: PublicKey = bincode::deserialize(&bytes).expect("deserialize should work");

        assert_eq!(pk.as_bytes(), restored.as_bytes());
    }

    #[test]
    fn test_hash_basic() {
        let h1 = hash(b"hello");
        let h2 = hash(b"hello");
        let h3 = hash(b"world");

        assert_eq!(h1, h2);
        assert_ne!(h1, h3);
        assert!(!h1.is_zero());
        assert!(Hash::ZERO.is_zero());
    }

    #[test]
    fn test_hash_matches_blake3() {
        // Verify we get the same output as direct blake3
        let h = hash(b"hello");
        // BLAKE3 hash of "hello" is known
        assert_eq!(
            h.to_hex(),
            "ea8f163db38682925e4491c5e58d4bb3506ef8c14eb78a86e908c5624a67200f"
        );
    }

    #[test]
    fn test_hash_hex_roundtrip() {
        let h = hash(b"test data");
        let hex_str = h.to_hex();
        let h2 = Hash::from_hex(&hex_str).unwrap();
        assert_eq!(h, h2);
    }

    #[test]
    fn test_hash_pair_order_matters() {
        let a = hash(b"a");
        let b = hash(b"b");

        let ab = hash_pair(a, b);
        let ba = hash_pair(b, a);

        assert_ne!(ab, ba);
    }

    #[test]
    fn test_sign_verify() {
        let sk = SecretKey::generate();
        let pk = sk.public_key();

        let message = b"audit event data";
        let sig = sk.sign(message);

        assert!(pk.verify(message, &sig).is_ok());
        assert!(pk.verify(b"wrong message", &sig).is_err());
    }

    #[test]
    fn test_key_id_deterministic() {
        let sk = SecretKey::generate();
        let pk = sk.public_key();

        let id1 = pk.id();
        let id2 = pk.id();

        assert_eq!(id1, id2);
    }

    #[test]
    fn test_secret_key_roundtrip() {
        let sk = SecretKey::generate();
        let bytes = sk.as_bytes();
        let restored = SecretKey::from_bytes(&bytes).unwrap();

        // Verify they produce same public key
        assert_eq!(sk.public_key().as_bytes(), restored.public_key().as_bytes());
    }
}
