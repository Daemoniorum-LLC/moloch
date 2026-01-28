//! Attestation registry for managing and verifying agent attestations.
//!
//! The registry tracks valid attestations, trusted authorities, and revocations.

use std::collections::{HashMap, HashSet};

use crate::crypto::{Hash, PublicKey};

use super::attestation::{AgentAttestation, AttestationError};

/// Registry of valid attestations.
///
/// The registry maintains:
/// - Active attestations indexed by agent ID
/// - Set of trusted attestation authorities
/// - Set of revoked attestation hashes
pub struct AttestationRegistry {
    /// Active attestations by agent ID (using byte array as key for efficiency).
    attestations: HashMap<[u8; 32], AgentAttestation>,

    /// Trusted attestation authorities.
    authorities: HashSet<[u8; 32]>,

    /// Revoked attestation hashes.
    revocations: HashSet<Hash>,

    /// Revocation reasons (for auditing).
    revocation_reasons: HashMap<Hash, String>,
}

impl AttestationRegistry {
    /// Create a new empty registry.
    pub fn new() -> Self {
        Self {
            attestations: HashMap::new(),
            authorities: HashSet::new(),
            revocations: HashSet::new(),
            revocation_reasons: HashMap::new(),
        }
    }

    /// Add a trusted attestation authority.
    pub fn add_authority(&mut self, authority: &PublicKey) {
        self.authorities.insert(authority.as_bytes());
    }

    /// Remove an attestation authority.
    pub fn remove_authority(&mut self, authority: &PublicKey) {
        self.authorities.remove(&authority.as_bytes());
    }

    /// Check if an authority is trusted.
    pub fn is_trusted_authority(&self, authority: &PublicKey) -> bool {
        self.authorities.contains(&authority.as_bytes())
    }

    /// Get the number of trusted authorities.
    pub fn authority_count(&self) -> usize {
        self.authorities.len()
    }

    /// Register a new attestation.
    ///
    /// # Arguments
    /// * `attestation` - The attestation to register
    ///
    /// # Errors
    /// Returns error if:
    /// - Attestation signature is invalid
    /// - Authority is not trusted
    /// - Attestation is already expired
    pub fn register(&mut self, attestation: AgentAttestation) -> Result<(), AttestationError> {
        // Verify signature
        attestation
            .verify_signature()
            .map_err(|_| AttestationError::InvalidSignature)?;

        // Check authority is trusted
        if !self.is_trusted_authority(attestation.authority()) {
            return Err(AttestationError::UntrustedAuthority);
        }

        // Check not already expired
        let now = chrono::Utc::now().timestamp_millis();
        if !attestation.is_valid_at(now) {
            return Err(AttestationError::Expired);
        }

        // Store attestation
        let key = attestation.agent_id().as_bytes();
        self.attestations.insert(key, attestation);

        Ok(())
    }

    /// Verify an agent has a valid attestation at a given time.
    ///
    /// # Arguments
    /// * `agent_id` - The agent's public key
    /// * `action_time` - When the action occurred (Unix timestamp ms)
    ///
    /// # Errors
    /// Returns error if:
    /// - No attestation registered for agent
    /// - Attestation expired at action_time
    /// - Attestation has been revoked
    pub fn verify(
        &self,
        agent_id: &PublicKey,
        action_time: i64,
    ) -> Result<&AgentAttestation, AttestationError> {
        // Find attestation
        let key = agent_id.as_bytes();
        let attestation = self
            .attestations
            .get(&key)
            .ok_or(AttestationError::NotFound)?;

        // Check not revoked
        let attestation_hash = attestation.hash();
        if self.revocations.contains(&attestation_hash) {
            return Err(AttestationError::Revoked);
        }

        // Check validity at action time
        if !attestation.is_valid_at(action_time) {
            return Err(AttestationError::Expired);
        }

        Ok(attestation)
    }

    /// Revoke an attestation.
    ///
    /// Revocation is permanent and cannot be undone. The attestation hash
    /// is added to the revocations set.
    ///
    /// # Arguments
    /// * `attestation_hash` - Hash of the attestation to revoke
    /// * `reason` - Reason for revocation
    pub fn revoke(&mut self, attestation_hash: Hash, reason: String) {
        self.revocations.insert(attestation_hash);
        self.revocation_reasons.insert(attestation_hash, reason);
    }

    /// Check if an attestation has been revoked.
    pub fn is_revoked(&self, attestation_hash: &Hash) -> bool {
        self.revocations.contains(attestation_hash)
    }

    /// Get the revocation reason if available.
    pub fn revocation_reason(&self, attestation_hash: &Hash) -> Option<&String> {
        self.revocation_reasons.get(attestation_hash)
    }

    /// Get an attestation by agent ID (without validation).
    pub fn get(&self, agent_id: &PublicKey) -> Option<&AgentAttestation> {
        let key = agent_id.as_bytes();
        self.attestations.get(&key)
    }

    /// Remove an attestation (for cleanup, not revocation).
    pub fn remove(&mut self, agent_id: &PublicKey) -> Option<AgentAttestation> {
        let key = agent_id.as_bytes();
        self.attestations.remove(&key)
    }

    /// Get the number of registered attestations.
    pub fn attestation_count(&self) -> usize {
        self.attestations.len()
    }

    /// Get the number of revoked attestations.
    pub fn revocation_count(&self) -> usize {
        self.revocations.len()
    }
}

impl Default for AttestationRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{hash, SecretKey};
    use std::time::Duration;

    use super::super::attestation::{AgentAttestation, RuntimeAttestation};

    fn create_attestation(
        agent: &SecretKey,
        authority: &SecretKey,
        attested_at: i64,
        validity_secs: u64,
    ) -> AgentAttestation {
        AgentAttestation::builder()
            .agent_id(agent.public_key())
            .code_hash(hash(b"code"))
            .config_hash(hash(b"config"))
            .prompt_hash(hash(b"prompt"))
            .runtime(RuntimeAttestation::new("test-v1", hash(b"runtime")))
            .attested_at(attested_at)
            .validity_period(Duration::from_secs(validity_secs))
            .sign(authority)
            .unwrap()
    }

    // === Registration Tests ===

    #[test]
    fn register_stores_attestation() {
        let authority = SecretKey::generate();
        let agent = SecretKey::generate();

        let mut registry = AttestationRegistry::new();
        registry.add_authority(&authority.public_key());

        let now = chrono::Utc::now().timestamp_millis();
        let attestation = create_attestation(&agent, &authority, now, 3600);

        registry.register(attestation).unwrap();

        assert!(registry.get(&agent.public_key()).is_some());
        assert_eq!(registry.attestation_count(), 1);
    }

    #[test]
    fn register_rejects_untrusted_authority() {
        let authority = SecretKey::generate();
        let agent = SecretKey::generate();

        let mut registry = AttestationRegistry::new();
        // Don't add authority to trusted set

        let now = chrono::Utc::now().timestamp_millis();
        let attestation = create_attestation(&agent, &authority, now, 3600);

        let result = registry.register(attestation);
        assert!(matches!(result, Err(AttestationError::UntrustedAuthority)));
    }

    #[test]
    fn register_rejects_expired_attestation() {
        let authority = SecretKey::generate();
        let agent = SecretKey::generate();

        let mut registry = AttestationRegistry::new();
        registry.add_authority(&authority.public_key());

        // Create already-expired attestation
        let past = chrono::Utc::now().timestamp_millis() - 10000;
        let attestation = create_attestation(&agent, &authority, past, 1); // 1 second validity

        let result = registry.register(attestation);
        assert!(matches!(result, Err(AttestationError::Expired)));
    }

    // === Verification Tests ===

    #[test]
    fn verify_returns_attestation_if_valid() {
        let authority = SecretKey::generate();
        let agent = SecretKey::generate();

        let mut registry = AttestationRegistry::new();
        registry.add_authority(&authority.public_key());

        let now = chrono::Utc::now().timestamp_millis();
        let attestation = create_attestation(&agent, &authority, now, 3600);

        registry.register(attestation).unwrap();

        let result = registry.verify(&agent.public_key(), now + 1000);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().agent_id(), &agent.public_key());
    }

    #[test]
    fn verify_fails_if_not_registered() {
        let authority = SecretKey::generate();
        let agent = SecretKey::generate();

        let mut registry = AttestationRegistry::new();
        registry.add_authority(&authority.public_key());

        let now = chrono::Utc::now().timestamp_millis();
        let result = registry.verify(&agent.public_key(), now);

        assert!(matches!(result, Err(AttestationError::NotFound)));
    }

    #[test]
    fn verify_fails_if_expired_at_action_time() {
        let authority = SecretKey::generate();
        let agent = SecretKey::generate();

        let mut registry = AttestationRegistry::new();
        registry.add_authority(&authority.public_key());

        let now = chrono::Utc::now().timestamp_millis();
        let attestation = create_attestation(&agent, &authority, now, 60); // 60 seconds

        registry.register(attestation).unwrap();

        // Verify at time after expiry
        let result = registry.verify(&agent.public_key(), now + 70 * 1000);
        assert!(matches!(result, Err(AttestationError::Expired)));
    }

    #[test]
    fn verify_fails_if_revoked() {
        let authority = SecretKey::generate();
        let agent = SecretKey::generate();

        let mut registry = AttestationRegistry::new();
        registry.add_authority(&authority.public_key());

        let now = chrono::Utc::now().timestamp_millis();
        let attestation = create_attestation(&agent, &authority, now, 3600);
        let attestation_hash = attestation.hash();

        registry.register(attestation).unwrap();
        registry.revoke(attestation_hash, "Security incident".to_string());

        let result = registry.verify(&agent.public_key(), now + 1000);
        assert!(matches!(result, Err(AttestationError::Revoked)));
    }

    // === Revocation Tests ===

    #[test]
    fn revoke_adds_to_revocation_list() {
        let mut registry = AttestationRegistry::new();
        let hash = hash(b"attestation-data");

        registry.revoke(hash, "Test revocation".to_string());

        assert!(registry.is_revoked(&hash));
        assert_eq!(registry.revocation_count(), 1);
    }

    #[test]
    fn revoke_makes_verify_fail() {
        let authority = SecretKey::generate();
        let agent = SecretKey::generate();

        let mut registry = AttestationRegistry::new();
        registry.add_authority(&authority.public_key());

        let now = chrono::Utc::now().timestamp_millis();
        let attestation = create_attestation(&agent, &authority, now, 3600);
        let attestation_hash = attestation.hash();

        registry.register(attestation).unwrap();

        // Verify works before revocation
        assert!(registry.verify(&agent.public_key(), now + 1000).is_ok());

        // Revoke
        registry.revoke(attestation_hash, "Compromised".to_string());

        // Verify fails after revocation
        let result = registry.verify(&agent.public_key(), now + 2000);
        assert!(matches!(result, Err(AttestationError::Revoked)));
    }

    #[test]
    fn revoke_is_permanent() {
        let mut registry = AttestationRegistry::new();
        let hash = hash(b"attestation-data");

        registry.revoke(hash, "First revocation".to_string());

        // Cannot un-revoke (revoke again has no effect)
        assert!(registry.is_revoked(&hash));

        // Hash remains in revocation list
        assert!(registry.is_revoked(&hash));
    }

    #[test]
    fn revocation_reason_recorded() {
        let mut registry = AttestationRegistry::new();
        let hash = hash(b"attestation-data");
        let reason = "Security vulnerability discovered".to_string();

        registry.revoke(hash, reason.clone());

        assert_eq!(registry.revocation_reason(&hash), Some(&reason));
    }

    // === Authority Management Tests ===

    #[test]
    fn add_and_remove_authority() {
        let authority = SecretKey::generate();
        let mut registry = AttestationRegistry::new();

        assert!(!registry.is_trusted_authority(&authority.public_key()));
        assert_eq!(registry.authority_count(), 0);

        registry.add_authority(&authority.public_key());
        assert!(registry.is_trusted_authority(&authority.public_key()));
        assert_eq!(registry.authority_count(), 1);

        registry.remove_authority(&authority.public_key());
        assert!(!registry.is_trusted_authority(&authority.public_key()));
        assert_eq!(registry.authority_count(), 0);
    }

    #[test]
    fn remove_attestation() {
        let authority = SecretKey::generate();
        let agent = SecretKey::generate();

        let mut registry = AttestationRegistry::new();
        registry.add_authority(&authority.public_key());

        let now = chrono::Utc::now().timestamp_millis();
        let attestation = create_attestation(&agent, &authority, now, 3600);

        registry.register(attestation).unwrap();
        assert_eq!(registry.attestation_count(), 1);

        let removed = registry.remove(&agent.public_key());
        assert!(removed.is_some());
        assert_eq!(registry.attestation_count(), 0);
    }
}
