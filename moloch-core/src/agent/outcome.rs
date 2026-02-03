//! Outcome verification for agent actions.
//!
//! Outcome verification confirms that recorded actions actually occurred as described.
//! It answers: "Did this action actually happen?"

use serde::{Deserialize, Serialize};

use crate::crypto::{hash, Hash, PublicKey, SecretKey, Sig};
use crate::error::{Error, Result};
use crate::event::{EventId, ResourceId};

use super::hitl::Severity;
use super::principal::PrincipalId;

/// Attestation that an action outcome occurred.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutcomeAttestation {
    /// The action event being attested.
    action_event_id: EventId,
    /// What outcome occurred.
    outcome: ActionOutcome,
    /// Evidence supporting the outcome.
    evidence: Vec<Evidence>,
    /// Who is attesting to this outcome.
    attestor: Attestor,
    /// When the outcome was observed (Unix timestamp ms).
    observed_at: i64,
    /// Signature from attestor.
    signature: Sig,
}

impl OutcomeAttestation {
    /// Create a new outcome attestation builder.
    pub fn builder() -> OutcomeAttestationBuilder {
        OutcomeAttestationBuilder::new()
    }

    /// Get the action event ID.
    pub fn action_event_id(&self) -> EventId {
        self.action_event_id
    }

    /// Get the outcome.
    pub fn outcome(&self) -> &ActionOutcome {
        &self.outcome
    }

    /// Get the evidence.
    pub fn evidence(&self) -> &[Evidence] {
        &self.evidence
    }

    /// Get the attestor.
    pub fn attestor(&self) -> &Attestor {
        &self.attestor
    }

    /// Get the observation timestamp.
    pub fn observed_at(&self) -> i64 {
        self.observed_at
    }

    /// Get the signature.
    pub fn signature(&self) -> &Sig {
        &self.signature
    }

    /// Compute canonical bytes for signing/verification.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(self.action_event_id.0.as_bytes());

        let outcome_json = serde_json::to_vec(&self.outcome).unwrap_or_default();
        data.extend_from_slice(&outcome_json);

        for evidence in &self.evidence {
            let evidence_json = serde_json::to_vec(evidence).unwrap_or_default();
            data.extend_from_slice(&evidence_json);
        }

        let attestor_json = serde_json::to_vec(&self.attestor).unwrap_or_default();
        data.extend_from_slice(&attestor_json);

        data.extend_from_slice(&self.observed_at.to_le_bytes());

        data
    }

    /// Verify the signature against an arbitrary public key.
    ///
    /// **Warning**: This does not check that `public_key` matches the embedded
    /// [`Attestor`]. Prefer [`verify_against_attestor`](Self::verify_against_attestor)
    /// which enforces signature-attestor binding.
    pub fn verify_signature(&self, public_key: &PublicKey) -> Result<()> {
        let message = self.canonical_bytes();
        public_key.verify(&message, &self.signature)
    }

    /// Verify the signature against the attestor's embedded public key.
    ///
    /// Unlike [`verify_signature`](Self::verify_signature) which accepts an arbitrary key,
    /// this method extracts the expected key from the [`Attestor`] and verifies against it,
    /// ensuring the signature is cryptographically bound to the claimed attestor identity.
    ///
    /// Returns an error if:
    /// - The attestor type does not carry a public key (e.g., `HumanObserver`, `CryptographicProof`)
    /// - The signature does not verify against the attestor's key
    pub fn verify_against_attestor(&self) -> Result<()> {
        let public_key = self.attestor.public_key().ok_or_else(|| {
            Error::invalid_input(
                "attestor type does not carry a public key; \
                 use external verification for HumanObserver/CryptographicProof",
            )
        })?;
        self.verify_signature(public_key)
    }

    /// Check if evidence is sufficient for the given severity per rule 8.3.3.
    pub fn is_evidence_sufficient(&self, severity: Severity) -> bool {
        match severity {
            Severity::Low => {
                // Self-attestation is sufficient
                true
            }
            Severity::Medium => {
                // At least one piece of external evidence required
                self.evidence.iter().any(|e| e.is_external())
            }
            Severity::High => {
                // Multiple independent evidence sources
                let external_count = self.evidence.iter().filter(|e| e.is_external()).count();
                external_count >= 2
            }
            Severity::Critical => {
                // Cryptographic proof or human verification required
                self.evidence.iter().any(|e| {
                    matches!(
                        e,
                        Evidence::ThirdPartyAttestation { .. } | Evidence::Receipt { .. }
                    )
                }) || matches!(self.attestor, Attestor::HumanObserver { .. })
            }
        }
    }

    /// Check if this is a self-attestation.
    pub fn is_self_attestation(&self) -> bool {
        matches!(self.attestor, Attestor::SelfAttestation { .. })
    }
}

/// Builder for OutcomeAttestation.
#[derive(Debug, Default)]
pub struct OutcomeAttestationBuilder {
    action_event_id: Option<EventId>,
    outcome: Option<ActionOutcome>,
    evidence: Vec<Evidence>,
    attestor: Option<Attestor>,
    observed_at: Option<i64>,
}

impl OutcomeAttestationBuilder {
    /// Create a new builder.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the action event ID.
    pub fn action_event_id(mut self, id: EventId) -> Self {
        self.action_event_id = Some(id);
        self
    }

    /// Set the outcome.
    pub fn outcome(mut self, outcome: ActionOutcome) -> Self {
        self.outcome = Some(outcome);
        self
    }

    /// Add evidence.
    pub fn evidence(mut self, evidence: Evidence) -> Self {
        self.evidence.push(evidence);
        self
    }

    /// Add multiple pieces of evidence.
    pub fn evidence_list(mut self, evidence: Vec<Evidence>) -> Self {
        self.evidence = evidence;
        self
    }

    /// Set the attestor.
    pub fn attestor(mut self, attestor: Attestor) -> Self {
        self.attestor = Some(attestor);
        self
    }

    /// Set the observation timestamp.
    pub fn observed_at(mut self, timestamp: i64) -> Self {
        self.observed_at = Some(timestamp);
        self
    }

    /// Set observation to now.
    pub fn observed_now(mut self) -> Self {
        self.observed_at = Some(chrono::Utc::now().timestamp_millis());
        self
    }

    /// Sign and build the attestation.
    pub fn sign(self, key: &SecretKey) -> Result<OutcomeAttestation> {
        let action_event_id = self
            .action_event_id
            .ok_or_else(|| Error::invalid_input("action_event_id is required"))?;

        let outcome = self
            .outcome
            .ok_or_else(|| Error::invalid_input("outcome is required"))?;

        let attestor = self
            .attestor
            .ok_or_else(|| Error::invalid_input("attestor is required"))?;

        let observed_at = self
            .observed_at
            .unwrap_or_else(|| chrono::Utc::now().timestamp_millis());

        // Create unsigned attestation for signing
        let mut attestation = OutcomeAttestation {
            action_event_id,
            outcome,
            evidence: self.evidence,
            attestor,
            observed_at,
            signature: Sig::empty(), // Placeholder
        };

        // Sign
        let message = attestation.canonical_bytes();
        attestation.signature = key.sign(&message);

        Ok(attestation)
    }
}

/// Detailed outcome of an action (for attestation purposes).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum ActionOutcome {
    /// Action succeeded as expected.
    Success {
        /// Result data.
        result: serde_json::Value,
        /// Hash of the result for verification.
        result_hash: Hash,
    },
    /// Action partially succeeded.
    PartialSuccess {
        /// What was completed.
        completed: Vec<String>,
        /// What failed.
        failed: Vec<String>,
        /// Partial result.
        result: serde_json::Value,
    },
    /// Action failed.
    Failure {
        /// Error message.
        error: String,
        /// Error code if available.
        error_code: Option<String>,
        /// Whether the failure is recoverable.
        recoverable: bool,
    },
    /// Outcome unknown or pending.
    Pending {
        /// Expected completion time (Unix timestamp ms).
        expected_completion: Option<i64>,
    },
    /// Action was rolled back.
    RolledBack {
        /// Reason for rollback.
        rollback_reason: String,
        /// Event ID of the rollback action.
        rollback_event_id: EventId,
    },
}

impl ActionOutcome {
    /// Create a success outcome.
    pub fn success(result: serde_json::Value) -> Self {
        let result_hash = hash(result.to_string().as_bytes());
        Self::Success {
            result,
            result_hash,
        }
    }

    /// Create a success outcome with explicit hash.
    pub fn success_with_hash(result: serde_json::Value, result_hash: Hash) -> Self {
        Self::Success {
            result,
            result_hash,
        }
    }

    /// Create a partial success outcome.
    pub fn partial_success(
        completed: Vec<String>,
        failed: Vec<String>,
        result: serde_json::Value,
    ) -> Self {
        Self::PartialSuccess {
            completed,
            failed,
            result,
        }
    }

    /// Create a failure outcome.
    pub fn failure(error: impl Into<String>, recoverable: bool) -> Self {
        Self::Failure {
            error: error.into(),
            error_code: None,
            recoverable,
        }
    }

    /// Create a failure outcome with error code.
    pub fn failure_with_code(
        error: impl Into<String>,
        error_code: impl Into<String>,
        recoverable: bool,
    ) -> Self {
        Self::Failure {
            error: error.into(),
            error_code: Some(error_code.into()),
            recoverable,
        }
    }

    /// Create a pending outcome.
    pub fn pending(expected_completion: Option<i64>) -> Self {
        Self::Pending {
            expected_completion,
        }
    }

    /// Create a rolled back outcome.
    pub fn rolled_back(reason: impl Into<String>, rollback_event_id: EventId) -> Self {
        Self::RolledBack {
            rollback_reason: reason.into(),
            rollback_event_id,
        }
    }

    /// Check if this is a successful outcome.
    pub fn is_success(&self) -> bool {
        matches!(self, ActionOutcome::Success { .. })
    }

    /// Check if this is a failure.
    pub fn is_failure(&self) -> bool {
        matches!(self, ActionOutcome::Failure { .. })
    }

    /// Check if this is pending.
    pub fn is_pending(&self) -> bool {
        matches!(self, ActionOutcome::Pending { .. })
    }

    /// Check if this outcome is final (not pending).
    pub fn is_final(&self) -> bool {
        !matches!(self, ActionOutcome::Pending { .. })
    }

    /// Check if a failed outcome is recoverable.
    pub fn is_recoverable(&self) -> bool {
        match self {
            ActionOutcome::Failure { recoverable, .. } => *recoverable,
            _ => false,
        }
    }
}

/// Evidence supporting an outcome attestation.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Evidence {
    /// Hash of data that was written.
    DataHash {
        /// Resource that was modified.
        resource: ResourceId,
        /// Hash of the data.
        hash: Hash,
        /// Size of the data in bytes.
        size: u64,
    },
    /// External system confirmation.
    ExternalConfirmation {
        /// System that confirmed.
        system: String,
        /// Confirmation identifier.
        confirmation_id: String,
        /// When confirmed (Unix timestamp ms).
        timestamp: i64,
    },
    /// Cryptographic receipt.
    Receipt {
        /// Who issued the receipt.
        issuer: String,
        /// Receipt data.
        receipt: Vec<u8>,
    },
    /// Screenshot or visual evidence.
    Visual {
        /// Hash of the visual evidence.
        hash: Hash,
        /// Description of what the visual shows.
        description: String,
    },
    /// Log entries.
    LogEntries {
        /// Source of the logs.
        source: String,
        /// Relevant log entries.
        entries: Vec<String>,
        /// Hash of the entries for integrity.
        hash: Hash,
    },
    /// Third-party attestation.
    ThirdPartyAttestation {
        /// Public key of the attestor.
        attestor: PublicKey,
        /// Raw attestation data.
        attestation: Vec<u8>,
    },
}

impl Evidence {
    /// Create data hash evidence.
    pub fn data_hash(resource: ResourceId, hash: Hash, size: u64) -> Self {
        Self::DataHash {
            resource,
            hash,
            size,
        }
    }

    /// Create external confirmation evidence.
    pub fn external_confirmation(
        system: impl Into<String>,
        confirmation_id: impl Into<String>,
        timestamp: i64,
    ) -> Self {
        Self::ExternalConfirmation {
            system: system.into(),
            confirmation_id: confirmation_id.into(),
            timestamp,
        }
    }

    /// Create receipt evidence.
    pub fn receipt(issuer: impl Into<String>, receipt: Vec<u8>) -> Self {
        Self::Receipt {
            issuer: issuer.into(),
            receipt,
        }
    }

    /// Create visual evidence.
    pub fn visual(hash: Hash, description: impl Into<String>) -> Self {
        Self::Visual {
            hash,
            description: description.into(),
        }
    }

    /// Create log entries evidence.
    pub fn log_entries(source: impl Into<String>, entries: Vec<String>) -> Self {
        let entries_json = serde_json::to_string(&entries).unwrap_or_default();
        let hash = hash(entries_json.as_bytes());
        Self::LogEntries {
            source: source.into(),
            entries,
            hash,
        }
    }

    /// Create third-party attestation evidence.
    pub fn third_party_attestation(attestor: PublicKey, attestation: Vec<u8>) -> Self {
        Self::ThirdPartyAttestation {
            attestor,
            attestation,
        }
    }

    /// Check if this evidence is external (not self-generated).
    pub fn is_external(&self) -> bool {
        matches!(
            self,
            Evidence::ExternalConfirmation { .. }
                | Evidence::Receipt { .. }
                | Evidence::ThirdPartyAttestation { .. }
        )
    }
}

/// Who is attesting to the outcome.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Attestor {
    /// The agent that performed the action.
    SelfAttestation {
        /// Agent's public key.
        agent: PublicKey,
    },
    /// The system that executed the action.
    ExecutionSystem {
        /// System identifier.
        system_id: String,
        /// System's public key.
        system_key: PublicKey,
    },
    /// A monitoring system.
    Monitor {
        /// Monitor identifier.
        monitor_id: String,
        /// Monitor's public key.
        monitor_key: PublicKey,
    },
    /// A human observer.
    HumanObserver {
        /// Principal ID of the human.
        principal: PrincipalId,
    },
    /// Cryptographic proof (e.g., blockchain confirmation).
    CryptographicProof {
        /// Type of proof.
        proof_type: String,
    },
}

impl Attestor {
    /// Create a self-attestation.
    pub fn self_attestation(agent: PublicKey) -> Self {
        Self::SelfAttestation { agent }
    }

    /// Create an execution system attestor.
    pub fn execution_system(system_id: impl Into<String>, system_key: PublicKey) -> Self {
        Self::ExecutionSystem {
            system_id: system_id.into(),
            system_key,
        }
    }

    /// Create a monitor attestor.
    pub fn monitor(monitor_id: impl Into<String>, monitor_key: PublicKey) -> Self {
        Self::Monitor {
            monitor_id: monitor_id.into(),
            monitor_key,
        }
    }

    /// Create a human observer attestor.
    pub fn human_observer(principal: PrincipalId) -> Self {
        Self::HumanObserver { principal }
    }

    /// Create a cryptographic proof attestor.
    pub fn cryptographic_proof(proof_type: impl Into<String>) -> Self {
        Self::CryptographicProof {
            proof_type: proof_type.into(),
        }
    }

    /// Get the public key of the attestor if available.
    pub fn public_key(&self) -> Option<&PublicKey> {
        match self {
            Attestor::SelfAttestation { agent } => Some(agent),
            Attestor::ExecutionSystem { system_key, .. } => Some(system_key),
            Attestor::Monitor { monitor_key, .. } => Some(monitor_key),
            Attestor::HumanObserver { .. } => None,
            Attestor::CryptographicProof { .. } => None,
        }
    }
}

/// Unique idempotency key for actions.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct IdempotencyKey {
    /// Agent that performed the action.
    agent: PublicKey,
    /// Action type.
    action_type: String,
    /// Unique client-provided key.
    client_key: String,
}

impl IdempotencyKey {
    /// Create a new idempotency key.
    pub fn new(
        agent: PublicKey,
        action_type: impl Into<String>,
        client_key: impl Into<String>,
    ) -> Self {
        Self {
            agent,
            action_type: action_type.into(),
            client_key: client_key.into(),
        }
    }

    /// Get the agent.
    pub fn agent(&self) -> &PublicKey {
        &self.agent
    }

    /// Get the action type.
    pub fn action_type(&self) -> &str {
        &self.action_type
    }

    /// Get the client key.
    pub fn client_key(&self) -> &str {
        &self.client_key
    }

    /// Compute a hash of this key for storage.
    pub fn hash(&self) -> Hash {
        let mut data = Vec::new();
        data.extend_from_slice(&self.agent.as_bytes());
        data.extend_from_slice(self.action_type.as_bytes());
        data.extend_from_slice(self.client_key.as_bytes());
        hash(&data)
    }
}

impl std::fmt::Display for IdempotencyKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}:{}:{}",
            hex::encode(self.agent.as_bytes()),
            self.action_type,
            self.client_key
        )
    }
}

/// Record for ensuring action idempotency.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdempotencyRecord {
    /// Unique idempotency key.
    key: IdempotencyKey,
    /// The original action event.
    original_event_id: EventId,
    /// Original outcome.
    outcome: ActionOutcome,
    /// When this record was created (Unix timestamp ms).
    created_at: i64,
    /// When this record expires (Unix timestamp ms).
    expires_at: i64,
}

impl IdempotencyRecord {
    /// Create a new idempotency record.
    pub fn new(
        key: IdempotencyKey,
        original_event_id: EventId,
        outcome: ActionOutcome,
        ttl_ms: i64,
    ) -> Self {
        let now = chrono::Utc::now().timestamp_millis();
        Self {
            key,
            original_event_id,
            outcome,
            created_at: now,
            expires_at: now + ttl_ms,
        }
    }

    /// Get the key.
    pub fn key(&self) -> &IdempotencyKey {
        &self.key
    }

    /// Get the original event ID.
    pub fn original_event_id(&self) -> EventId {
        self.original_event_id
    }

    /// Get the outcome.
    pub fn outcome(&self) -> &ActionOutcome {
        &self.outcome
    }

    /// Get the creation timestamp.
    pub fn created_at(&self) -> i64 {
        self.created_at
    }

    /// Get the expiration timestamp.
    pub fn expires_at(&self) -> i64 {
        self.expires_at
    }

    /// Check if this record is expired.
    pub fn is_expired(&self) -> bool {
        chrono::Utc::now().timestamp_millis() > self.expires_at
    }

    /// Check if this record is still valid.
    pub fn is_valid(&self) -> bool {
        !self.is_expired()
    }
}

/// Outcome dispute record per rule 8.3.5.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutcomeDispute {
    /// The attestation being disputed.
    disputed_attestation_event_id: EventId,
    /// Who is disputing.
    disputant: Attestor,
    /// Reason for the dispute.
    reason: String,
    /// Counter-evidence.
    counter_evidence: Vec<Evidence>,
    /// When the dispute was filed (Unix timestamp ms).
    filed_at: i64,
    /// Current status of the dispute.
    status: DisputeStatus,
}

impl OutcomeDispute {
    /// Create a new dispute.
    pub fn new(
        disputed_attestation_event_id: EventId,
        disputant: Attestor,
        reason: impl Into<String>,
    ) -> Self {
        Self {
            disputed_attestation_event_id,
            disputant,
            reason: reason.into(),
            counter_evidence: Vec::new(),
            filed_at: chrono::Utc::now().timestamp_millis(),
            status: DisputeStatus::Pending,
        }
    }

    /// Add counter-evidence.
    pub fn with_evidence(mut self, evidence: Evidence) -> Self {
        self.counter_evidence.push(evidence);
        self
    }

    /// Get the disputed attestation event ID.
    pub fn disputed_attestation_event_id(&self) -> EventId {
        self.disputed_attestation_event_id
    }

    /// Get the disputant.
    pub fn disputant(&self) -> &Attestor {
        &self.disputant
    }

    /// Get the reason.
    pub fn reason(&self) -> &str {
        &self.reason
    }

    /// Get the counter-evidence.
    pub fn counter_evidence(&self) -> &[Evidence] {
        &self.counter_evidence
    }

    /// Get when filed.
    pub fn filed_at(&self) -> i64 {
        self.filed_at
    }

    /// Get the status.
    pub fn status(&self) -> &DisputeStatus {
        &self.status
    }

    /// Update the status.
    pub fn set_status(&mut self, status: DisputeStatus) {
        self.status = status;
    }
}

/// Status of an outcome dispute.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum DisputeStatus {
    /// Dispute is pending review.
    Pending,
    /// Under human review.
    UnderReview {
        /// Who is reviewing.
        reviewer: PrincipalId,
        /// When review started.
        started_at: i64,
    },
    /// Dispute resolved in favor of original attestation.
    RejectedOriginalStands {
        /// Resolution reason.
        reason: String,
        /// Resolution event ID.
        resolution_event_id: EventId,
    },
    /// Dispute upheld - original attestation invalidated.
    UpheldOriginalInvalidated {
        /// Resolution reason.
        reason: String,
        /// Corrected outcome if any.
        corrected_outcome: Option<Box<ActionOutcome>>,
        /// Resolution event ID.
        resolution_event_id: EventId,
    },
}

impl DisputeStatus {
    /// Check if the dispute is still pending.
    pub fn is_pending(&self) -> bool {
        matches!(
            self,
            DisputeStatus::Pending | DisputeStatus::UnderReview { .. }
        )
    }

    /// Check if the dispute is resolved.
    pub fn is_resolved(&self) -> bool {
        !self.is_pending()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::ResourceKind;

    fn test_event_id() -> EventId {
        EventId(hash(b"test-event"))
    }

    fn test_key() -> SecretKey {
        SecretKey::generate()
    }

    fn test_resource_id() -> ResourceId {
        ResourceId::new(ResourceKind::File, "/tmp/test.txt")
    }

    // === ActionOutcome Tests ===

    #[test]
    fn outcome_success() {
        let outcome = ActionOutcome::success(serde_json::json!({"result": "ok"}));
        assert!(outcome.is_success());
        assert!(!outcome.is_failure());
        assert!(outcome.is_final());
    }

    #[test]
    fn outcome_failure() {
        let outcome = ActionOutcome::failure("Something went wrong", true);
        assert!(outcome.is_failure());
        assert!(outcome.is_recoverable());

        let non_recoverable = ActionOutcome::failure("Fatal error", false);
        assert!(!non_recoverable.is_recoverable());
    }

    #[test]
    fn outcome_partial_success() {
        let outcome = ActionOutcome::partial_success(
            vec!["step1".to_string(), "step2".to_string()],
            vec!["step3".to_string()],
            serde_json::json!({}),
        );
        assert!(!outcome.is_success());
        assert!(!outcome.is_failure());
    }

    #[test]
    fn outcome_pending() {
        let outcome = ActionOutcome::pending(Some(chrono::Utc::now().timestamp_millis() + 60000));
        assert!(outcome.is_pending());
        assert!(!outcome.is_final());
    }

    #[test]
    fn outcome_rolled_back() {
        let outcome = ActionOutcome::rolled_back("User cancelled", test_event_id());
        assert!(outcome.is_final());
    }

    // === Evidence Tests ===

    #[test]
    fn evidence_data_hash() {
        let evidence = Evidence::data_hash(test_resource_id(), hash(b"data"), 1024);
        assert!(!evidence.is_external());
    }

    #[test]
    fn evidence_external_confirmation() {
        let evidence = Evidence::external_confirmation("github", "pr-123", 1000);
        assert!(evidence.is_external());
    }

    #[test]
    fn evidence_receipt() {
        let evidence = Evidence::receipt("blockchain", vec![1, 2, 3, 4]);
        assert!(evidence.is_external());
    }

    #[test]
    fn evidence_visual() {
        let evidence = Evidence::visual(hash(b"screenshot"), "Shows successful deployment");
        assert!(!evidence.is_external());
    }

    #[test]
    fn evidence_log_entries() {
        let evidence = Evidence::log_entries("server.log", vec!["INFO: Started".to_string()]);
        assert!(!evidence.is_external());
    }

    #[test]
    fn evidence_third_party() {
        let key = test_key();
        let evidence = Evidence::third_party_attestation(key.public_key(), vec![1, 2, 3]);
        assert!(evidence.is_external());
    }

    // === Attestor Tests ===

    #[test]
    fn attestor_self() {
        let key = test_key();
        let attestor = Attestor::self_attestation(key.public_key());
        assert!(attestor.public_key().is_some());
    }

    #[test]
    fn attestor_execution_system() {
        let key = test_key();
        let attestor = Attestor::execution_system("docker-runtime", key.public_key());
        assert!(attestor.public_key().is_some());
    }

    #[test]
    fn attestor_human() {
        let principal = PrincipalId::user("user@example.com").unwrap();
        let attestor = Attestor::human_observer(principal);
        assert!(attestor.public_key().is_none());
    }

    // === OutcomeAttestation Tests ===

    #[test]
    fn attestation_build_and_sign() {
        let key = test_key();
        let attestation = OutcomeAttestation::builder()
            .action_event_id(test_event_id())
            .outcome(ActionOutcome::success(serde_json::json!({})))
            .attestor(Attestor::self_attestation(key.public_key()))
            .observed_now()
            .sign(&key)
            .unwrap();

        assert!(attestation.verify_signature(&key.public_key()).is_ok());
    }

    #[test]
    fn attestation_requires_action_event_id() {
        let key = test_key();
        let result = OutcomeAttestation::builder()
            .outcome(ActionOutcome::success(serde_json::json!({})))
            .attestor(Attestor::self_attestation(key.public_key()))
            .sign(&key);
        assert!(result.is_err());
    }

    #[test]
    fn attestation_requires_outcome() {
        let key = test_key();
        let result = OutcomeAttestation::builder()
            .action_event_id(test_event_id())
            .attestor(Attestor::self_attestation(key.public_key()))
            .sign(&key);
        assert!(result.is_err());
    }

    #[test]
    fn attestation_requires_attestor() {
        let key = test_key();
        let result = OutcomeAttestation::builder()
            .action_event_id(test_event_id())
            .outcome(ActionOutcome::success(serde_json::json!({})))
            .sign(&key);
        assert!(result.is_err());
    }

    // === Evidence Sufficiency Tests ===

    #[test]
    fn evidence_sufficiency_low() {
        let key = test_key();
        let attestation = OutcomeAttestation::builder()
            .action_event_id(test_event_id())
            .outcome(ActionOutcome::success(serde_json::json!({})))
            .attestor(Attestor::self_attestation(key.public_key()))
            .sign(&key)
            .unwrap();

        // Low severity: self-attestation is sufficient
        assert!(attestation.is_evidence_sufficient(Severity::Low));
    }

    #[test]
    fn evidence_sufficiency_medium() {
        let key = test_key();

        // Without external evidence
        let attestation = OutcomeAttestation::builder()
            .action_event_id(test_event_id())
            .outcome(ActionOutcome::success(serde_json::json!({})))
            .attestor(Attestor::self_attestation(key.public_key()))
            .sign(&key)
            .unwrap();
        assert!(!attestation.is_evidence_sufficient(Severity::Medium));

        // With external evidence
        let attestation = OutcomeAttestation::builder()
            .action_event_id(test_event_id())
            .outcome(ActionOutcome::success(serde_json::json!({})))
            .attestor(Attestor::self_attestation(key.public_key()))
            .evidence(Evidence::external_confirmation("ci", "build-123", 1000))
            .sign(&key)
            .unwrap();
        assert!(attestation.is_evidence_sufficient(Severity::Medium));
    }

    #[test]
    fn evidence_sufficiency_high() {
        let key = test_key();

        // With only one external evidence
        let attestation = OutcomeAttestation::builder()
            .action_event_id(test_event_id())
            .outcome(ActionOutcome::success(serde_json::json!({})))
            .attestor(Attestor::self_attestation(key.public_key()))
            .evidence(Evidence::external_confirmation("ci", "build-123", 1000))
            .sign(&key)
            .unwrap();
        assert!(!attestation.is_evidence_sufficient(Severity::High));

        // With two external evidence sources
        let attestation = OutcomeAttestation::builder()
            .action_event_id(test_event_id())
            .outcome(ActionOutcome::success(serde_json::json!({})))
            .attestor(Attestor::self_attestation(key.public_key()))
            .evidence(Evidence::external_confirmation("ci", "build-123", 1000))
            .evidence(Evidence::receipt("notary", vec![1, 2, 3]))
            .sign(&key)
            .unwrap();
        assert!(attestation.is_evidence_sufficient(Severity::High));
    }

    #[test]
    fn evidence_sufficiency_critical() {
        let key = test_key();

        // Without cryptographic proof or human verification
        let attestation = OutcomeAttestation::builder()
            .action_event_id(test_event_id())
            .outcome(ActionOutcome::success(serde_json::json!({})))
            .attestor(Attestor::self_attestation(key.public_key()))
            .evidence(Evidence::external_confirmation("ci", "build-123", 1000))
            .sign(&key)
            .unwrap();
        assert!(!attestation.is_evidence_sufficient(Severity::Critical));

        // With third-party attestation
        let attestation = OutcomeAttestation::builder()
            .action_event_id(test_event_id())
            .outcome(ActionOutcome::success(serde_json::json!({})))
            .attestor(Attestor::self_attestation(key.public_key()))
            .evidence(Evidence::third_party_attestation(
                key.public_key(),
                vec![1, 2, 3],
            ))
            .sign(&key)
            .unwrap();
        assert!(attestation.is_evidence_sufficient(Severity::Critical));

        // With human observer
        let principal = PrincipalId::user("admin@example.com").unwrap();
        let attestation = OutcomeAttestation::builder()
            .action_event_id(test_event_id())
            .outcome(ActionOutcome::success(serde_json::json!({})))
            .attestor(Attestor::human_observer(principal))
            .sign(&key)
            .unwrap();
        assert!(attestation.is_evidence_sufficient(Severity::Critical));
    }

    // === verify_against_attestor Tests (Phase 1, Finding 1.1) ===

    #[test]
    fn verify_against_attestor_rejects_key_mismatch() {
        // OutcomeAttestation signed by real_key but claiming attestor with fake_key
        // must fail verify_against_attestor()
        let real_key = test_key();
        let fake_key = test_key();

        let attestation = OutcomeAttestation::builder()
            .action_event_id(test_event_id())
            .outcome(ActionOutcome::success(serde_json::json!({})))
            .attestor(Attestor::self_attestation(fake_key.public_key())) // Claims fake
            .observed_now()
            .sign(&real_key) // Signed by real
            .unwrap();

        // Raw verify with real_key passes — this is the vulnerability
        assert!(attestation.verify_signature(&real_key.public_key()).is_ok());

        // verify_against_attestor must reject: attestor says fake_key, sig is real_key
        assert!(attestation.verify_against_attestor().is_err());
    }

    #[test]
    fn verify_against_attestor_accepts_matching_key() {
        let key = test_key();

        let attestation = OutcomeAttestation::builder()
            .action_event_id(test_event_id())
            .outcome(ActionOutcome::success(serde_json::json!({})))
            .attestor(Attestor::self_attestation(key.public_key()))
            .observed_now()
            .sign(&key)
            .unwrap();

        assert!(attestation.verify_against_attestor().is_ok());
    }

    #[test]
    fn verify_against_attestor_for_human_observer_returns_error() {
        // HumanObserver has no public key, so attestor-based verify
        // must return an appropriate error (not silently pass)
        let key = test_key();
        let principal = PrincipalId::user("admin@example.com").unwrap();

        let attestation = OutcomeAttestation::builder()
            .action_event_id(test_event_id())
            .outcome(ActionOutcome::success(serde_json::json!({})))
            .attestor(Attestor::human_observer(principal))
            .observed_now()
            .sign(&key)
            .unwrap();

        let result = attestation.verify_against_attestor();
        assert!(result.is_err());
    }

    #[test]
    fn verify_against_attestor_for_execution_system() {
        let system_key = test_key();

        let attestation = OutcomeAttestation::builder()
            .action_event_id(test_event_id())
            .outcome(ActionOutcome::success(serde_json::json!({})))
            .attestor(Attestor::execution_system(
                "docker",
                system_key.public_key(),
            ))
            .observed_now()
            .sign(&system_key)
            .unwrap();

        assert!(attestation.verify_against_attestor().is_ok());
    }

    #[test]
    fn verify_against_attestor_for_monitor() {
        let monitor_key = test_key();

        let attestation = OutcomeAttestation::builder()
            .action_event_id(test_event_id())
            .outcome(ActionOutcome::success(serde_json::json!({})))
            .attestor(Attestor::monitor("prometheus", monitor_key.public_key()))
            .observed_now()
            .sign(&monitor_key)
            .unwrap();

        assert!(attestation.verify_against_attestor().is_ok());
    }

    #[test]
    fn verify_against_attestor_for_cryptographic_proof_returns_error() {
        // CryptographicProof has no public key, similar to HumanObserver
        let key = test_key();

        let attestation = OutcomeAttestation::builder()
            .action_event_id(test_event_id())
            .outcome(ActionOutcome::success(serde_json::json!({})))
            .attestor(Attestor::cryptographic_proof("blockchain-anchor"))
            .observed_now()
            .sign(&key)
            .unwrap();

        assert!(attestation.verify_against_attestor().is_err());
    }

    // === IdempotencyKey Tests ===

    #[test]
    fn idempotency_key_hash() {
        let key = test_key();
        let idem_key1 = IdempotencyKey::new(key.public_key(), "file_write", "request-123");
        let idem_key2 = IdempotencyKey::new(key.public_key(), "file_write", "request-123");
        assert_eq!(idem_key1.hash(), idem_key2.hash());

        let idem_key3 = IdempotencyKey::new(key.public_key(), "file_write", "request-456");
        assert_ne!(idem_key1.hash(), idem_key3.hash());
    }

    #[test]
    fn idempotency_key_display() {
        let key = test_key();
        let idem_key = IdempotencyKey::new(key.public_key(), "file_write", "request-123");
        let display = format!("{}", idem_key);
        assert!(display.contains("file_write"));
        assert!(display.contains("request-123"));
    }

    // === IdempotencyRecord Tests ===

    #[test]
    fn idempotency_record_valid() {
        let key = test_key();
        let idem_key = IdempotencyKey::new(key.public_key(), "file_write", "request-123");
        let record = IdempotencyRecord::new(
            idem_key,
            test_event_id(),
            ActionOutcome::success(serde_json::json!({})),
            60000, // 1 minute TTL
        );

        assert!(record.is_valid());
        assert!(!record.is_expired());
    }

    #[test]
    fn idempotency_record_expired() {
        let key = test_key();
        let idem_key = IdempotencyKey::new(key.public_key(), "file_write", "request-123");
        let record = IdempotencyRecord::new(
            idem_key,
            test_event_id(),
            ActionOutcome::success(serde_json::json!({})),
            -1, // Already expired
        );

        assert!(!record.is_valid());
        assert!(record.is_expired());
    }

    // === OutcomeDispute Tests ===

    #[test]
    fn dispute_creation() {
        let key = test_key();
        let dispute = OutcomeDispute::new(
            test_event_id(),
            Attestor::self_attestation(key.public_key()),
            "Outcome was not as described",
        );

        assert!(dispute.status().is_pending());
        assert!(!dispute.status().is_resolved());
    }

    #[test]
    fn dispute_with_evidence() {
        let key = test_key();
        let dispute = OutcomeDispute::new(
            test_event_id(),
            Attestor::self_attestation(key.public_key()),
            "Incorrect outcome",
        )
        .with_evidence(Evidence::log_entries(
            "server.log",
            vec!["ERROR: Failed".to_string()],
        ));

        assert_eq!(dispute.counter_evidence().len(), 1);
    }

    #[test]
    fn dispute_status_transitions() {
        let principal = PrincipalId::user("reviewer@example.com").unwrap();

        let pending = DisputeStatus::Pending;
        assert!(pending.is_pending());

        let under_review = DisputeStatus::UnderReview {
            reviewer: principal.clone(),
            started_at: chrono::Utc::now().timestamp_millis(),
        };
        assert!(under_review.is_pending());

        let rejected = DisputeStatus::RejectedOriginalStands {
            reason: "Evidence insufficient".to_string(),
            resolution_event_id: test_event_id(),
        };
        assert!(rejected.is_resolved());

        let upheld = DisputeStatus::UpheldOriginalInvalidated {
            reason: "Clear evidence of error".to_string(),
            corrected_outcome: Some(Box::new(ActionOutcome::failure("Actual failure", false))),
            resolution_event_id: test_event_id(),
        };
        assert!(upheld.is_resolved());
    }
}
