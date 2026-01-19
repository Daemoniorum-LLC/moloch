//! Audit event types.
//!
//! An audit event is the atomic unit of the Moloch chain. Unlike financial
//! transactions, events are immutable records of something that happened.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::crypto::{hash, Hash, PublicKey, Sig};
use crate::error::{Error, Result};

/// Unique identifier for an event (content-addressed).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct EventId(pub Hash);

impl EventId {
    /// Get the underlying hash.
    pub fn as_hash(&self) -> &Hash {
        &self.0
    }
}

impl std::fmt::Display for EventId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Identifies the actor (who did something).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActorId {
    /// The actor's public key (cryptographic identity).
    pub key: PublicKey,
    /// Human-readable name (not authenticated).
    pub name: Option<String>,
    /// Actor type.
    pub kind: ActorKind,
}

impl ActorId {
    /// Create a new actor ID.
    pub fn new(key: PublicKey, kind: ActorKind) -> Self {
        Self {
            key,
            name: None,
            kind,
        }
    }

    /// Add a display name.
    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }

    /// Get the unique hash ID for this actor.
    pub fn id(&self) -> Hash {
        self.key.id()
    }
}

/// Type of actor.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActorKind {
    /// A human user.
    User,
    /// An automated system/service.
    System,
    /// An AI agent.
    Agent,
    /// External service integration.
    Integration,
}

/// Identifies what was affected.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourceId {
    /// Resource type.
    pub kind: ResourceKind,
    /// Unique identifier within the resource type.
    pub id: String,
    /// Optional parent resource (for hierarchical resources).
    pub parent: Option<Box<ResourceId>>,
}

impl ResourceId {
    /// Create a new resource ID.
    pub fn new(kind: ResourceKind, id: impl Into<String>) -> Self {
        Self {
            kind,
            id: id.into(),
            parent: None,
        }
    }

    /// Add a parent resource.
    pub fn with_parent(mut self, parent: ResourceId) -> Self {
        self.parent = Some(Box::new(parent));
        self
    }
}

/// Type of resource.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResourceKind {
    /// Git repository.
    Repository,
    /// Git commit.
    Commit,
    /// Git branch.
    Branch,
    /// Git tag.
    Tag,
    /// Pull/merge request.
    PullRequest,
    /// Issue.
    Issue,
    /// File.
    File,
    /// User account.
    User,
    /// Organization.
    Organization,
    /// API key or token.
    Credential,
    /// Configuration.
    Config,
    /// Generic document.
    Document,
    /// Other resource type.
    Other,
}

/// What happened.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventType {
    // === Repository Events ===
    /// Repository was created.
    RepoCreated,
    /// Repository was deleted.
    RepoDeleted,
    /// Repository ownership transferred.
    RepoTransferred,
    /// Repository visibility changed.
    RepoVisibilityChanged,

    // === Git Events ===
    /// Commits pushed to a branch.
    Push { force: bool, commits: u32 },
    /// Branch created.
    BranchCreated,
    /// Branch deleted.
    BranchDeleted,
    /// Branch protection rules changed.
    BranchProtectionChanged,
    /// Tag created.
    TagCreated,
    /// Tag deleted.
    TagDeleted,

    // === Collaboration Events ===
    /// Pull request opened.
    PullRequestOpened,
    /// Pull request merged.
    PullRequestMerged,
    /// Pull request closed (not merged).
    PullRequestClosed,
    /// Code review submitted.
    ReviewSubmitted { verdict: ReviewVerdict },
    /// Issue opened.
    IssueOpened,
    /// Issue closed.
    IssueClosed,

    // === Access Events ===
    /// Access granted to resource.
    AccessGranted { permission: String },
    /// Access revoked from resource.
    AccessRevoked,
    /// User logged in.
    Login { method: String },
    /// User logged out.
    Logout,
    /// Login attempt failed.
    LoginFailed { reason: String },
    /// MFA configured.
    MfaConfigured,

    // === Agent Events ===
    /// AI agent performed an action.
    AgentAction {
        action: String,
        reasoning: Option<String>,
    },
    /// Agent authorization granted.
    AgentAuthorized { scope: Vec<String> },
    /// Agent authorization revoked.
    AgentRevoked,

    // === Compliance Events ===
    /// Data export requested (GDPR).
    DataExportRequested,
    /// Data export completed.
    DataExportCompleted,
    /// Data deletion requested.
    DataDeletionRequested,
    /// Data deletion completed.
    DataDeletionCompleted,
    /// Consent given.
    ConsentGiven { purpose: String },
    /// Consent revoked.
    ConsentRevoked { purpose: String },

    // === System Events ===
    /// Configuration changed.
    ConfigChanged { key: String },
    /// Release published.
    ReleasePublished { version: String },
    /// Backup created.
    BackupCreated,
    /// Security scan completed.
    SecurityScan { findings: u32 },

    // === Generic ===
    /// Custom event type.
    Custom { name: String },
}

/// Code review verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReviewVerdict {
    Approved,
    ChangesRequested,
    Commented,
}

/// Result of an action.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    /// Action succeeded.
    Success,
    /// Action failed.
    Failure { reason: String },
    /// Action was denied (authorization).
    Denied { reason: String },
    /// Action is pending.
    Pending,
}

/// Attestation from the submitting system.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Attestation {
    /// Public key of the attesting system.
    pub attester: PublicKey,
    /// Signature over the event's canonical form.
    pub signature: Sig,
    /// Optional chain of attestations (for forwarded events).
    pub chain: Vec<AttestationLink>,
}

/// A link in an attestation chain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttestationLink {
    pub attester: PublicKey,
    pub signature: Sig,
    #[serde(with = "chrono::serde::ts_milliseconds")]
    pub timestamp: DateTime<Utc>,
}

impl Attestation {
    /// Create a new attestation.
    pub fn new(attester: PublicKey, signature: Sig) -> Self {
        Self {
            attester,
            signature,
            chain: Vec::new(),
        }
    }

    /// Verify this attestation against an event's canonical bytes.
    pub fn verify(&self, canonical_bytes: &[u8]) -> Result<()> {
        self.attester.verify(canonical_bytes, &self.signature)?;

        // Verify chain if present
        // Each link attests to the previous signature
        let mut prev_sig_bytes = self.signature.to_bytes().to_vec();
        for link in &self.chain {
            link.attester.verify(&prev_sig_bytes, &link.signature)?;
            prev_sig_bytes = link.signature.to_bytes().to_vec();
        }

        Ok(())
    }
}

/// An audit event.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditEvent {
    /// When the event occurred (claimed by submitter), as Unix timestamp in millis.
    #[serde(with = "chrono::serde::ts_milliseconds")]
    pub event_time: DateTime<Utc>,

    /// What happened.
    pub event_type: EventType,

    /// Who did it.
    pub actor: ActorId,

    /// What was affected.
    pub resource: ResourceId,

    /// Result of the action.
    pub outcome: Outcome,

    /// Additional structured data (JSON serialized to bytes).
    pub metadata: Vec<u8>,

    /// Attestation from submitting system.
    pub attestation: Attestation,
}

impl AuditEvent {
    /// Create a new event builder.
    pub fn builder() -> AuditEventBuilder {
        AuditEventBuilder::default()
    }

    /// Compute the canonical bytes for this event (for hashing/signing).
    pub fn canonical_bytes(&self) -> Vec<u8> {
        // We serialize without the attestation for signing
        let signable = SignableEvent {
            event_time: self.event_time,
            event_type: &self.event_type,
            actor: &self.actor,
            resource: &self.resource,
            outcome: &self.outcome,
            metadata: &self.metadata,
        };
        // Use bincode for deterministic serialization
        bincode::serialize(&signable).expect("serialization should not fail")
    }

    /// Get metadata as JSON value (if parseable).
    pub fn metadata_json(&self) -> Option<serde_json::Value> {
        if self.metadata.is_empty() {
            return None;
        }
        serde_json::from_slice(&self.metadata).ok()
    }

    /// Check if metadata is present.
    pub fn has_metadata(&self) -> bool {
        !self.metadata.is_empty()
    }

    /// Compute the content-addressed ID for this event.
    pub fn id(&self) -> EventId {
        EventId(hash(&self.canonical_bytes()))
    }

    /// Get the attester's public key.
    pub fn attester(&self) -> &PublicKey {
        &self.attestation.attester
    }

    /// Get the attestation signature.
    pub fn signature(&self) -> &Sig {
        &self.attestation.signature
    }

    /// Get verification components for batch verification.
    ///
    /// Returns (public_key, canonical_bytes, signature) tuple suitable for
    /// passing to `batch_verify()`.
    pub fn verification_tuple(&self) -> (&PublicKey, Vec<u8>, &Sig) {
        (self.attester(), self.canonical_bytes(), self.signature())
    }

    /// Validate this event.
    pub fn validate(&self) -> Result<()> {
        // Verify attestation
        self.attestation.verify(&self.canonical_bytes())?;

        // Event time should be reasonable (not too far in future)
        let now = Utc::now();
        if self.event_time > now + chrono::Duration::minutes(5) {
            return Err(Error::invalid_event("event_time is in the future"));
        }

        Ok(())
    }
}

/// Helper struct for canonical serialization (excludes attestation).
#[derive(Serialize)]
struct SignableEvent<'a> {
    #[serde(with = "chrono::serde::ts_milliseconds")]
    event_time: DateTime<Utc>,
    event_type: &'a EventType,
    actor: &'a ActorId,
    resource: &'a ResourceId,
    outcome: &'a Outcome,
    metadata: &'a [u8],
}

/// Builder for creating audit events.
#[derive(Default)]
pub struct AuditEventBuilder {
    event_time: Option<DateTime<Utc>>,
    event_type: Option<EventType>,
    actor: Option<ActorId>,
    resource: Option<ResourceId>,
    outcome: Option<Outcome>,
    metadata: Vec<u8>,
}

impl AuditEventBuilder {
    /// Set the event time.
    pub fn event_time(mut self, time: DateTime<Utc>) -> Self {
        self.event_time = Some(time);
        self
    }

    /// Use current time as event time.
    pub fn now(mut self) -> Self {
        self.event_time = Some(Utc::now());
        self
    }

    /// Set the event type.
    pub fn event_type(mut self, event_type: EventType) -> Self {
        self.event_type = Some(event_type);
        self
    }

    /// Set the actor.
    pub fn actor(mut self, actor: ActorId) -> Self {
        self.actor = Some(actor);
        self
    }

    /// Set the resource.
    pub fn resource(mut self, resource: ResourceId) -> Self {
        self.resource = Some(resource);
        self
    }

    /// Set the outcome.
    pub fn outcome(mut self, outcome: Outcome) -> Self {
        self.outcome = Some(outcome);
        self
    }

    /// Set metadata from JSON value (serialized to bytes).
    pub fn metadata(mut self, metadata: serde_json::Value) -> Self {
        self.metadata = serde_json::to_vec(&metadata).unwrap_or_default();
        self
    }

    /// Set metadata from raw bytes.
    pub fn metadata_bytes(mut self, bytes: Vec<u8>) -> Self {
        self.metadata = bytes;
        self
    }

    /// Build and sign the event.
    pub fn sign(self, key: &crate::crypto::SecretKey) -> Result<AuditEvent> {
        let event_time = self.event_time.ok_or_else(|| Error::invalid_event("missing event_time"))?;
        let event_type = self.event_type.ok_or_else(|| Error::invalid_event("missing event_type"))?;
        let actor = self.actor.ok_or_else(|| Error::invalid_event("missing actor"))?;
        let resource = self.resource.ok_or_else(|| Error::invalid_event("missing resource"))?;
        let outcome = self.outcome.unwrap_or(Outcome::Success);

        // Create event without attestation first to get canonical bytes
        let signable = SignableEvent {
            event_time,
            event_type: &event_type,
            actor: &actor,
            resource: &resource,
            outcome: &outcome,
            metadata: &self.metadata,
        };
        let canonical = bincode::serialize(&signable)?;
        let signature = key.sign(&canonical);

        Ok(AuditEvent {
            event_time,
            event_type,
            actor,
            resource,
            outcome,
            metadata: self.metadata,
            attestation: Attestation::new(key.public_key(), signature),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::SecretKey;

    fn test_key() -> SecretKey {
        SecretKey::generate()
    }

    #[test]
    fn test_event_creation_and_validation() {
        let key = test_key();
        let actor = ActorId::new(key.public_key(), ActorKind::User).with_name("alice");
        let resource = ResourceId::new(ResourceKind::Repository, "myrepo");

        let event = AuditEvent::builder()
            .now()
            .event_type(EventType::Push {
                force: false,
                commits: 3,
            })
            .actor(actor)
            .resource(resource)
            .outcome(Outcome::Success)
            .sign(&key)
            .unwrap();

        assert!(event.validate().is_ok());
    }

    #[test]
    fn test_event_id_is_deterministic() {
        let key = test_key();
        let time = Utc::now();
        let actor = ActorId::new(key.public_key(), ActorKind::System);
        let resource = ResourceId::new(ResourceKind::Config, "settings");

        let event1 = AuditEvent::builder()
            .event_time(time)
            .event_type(EventType::ConfigChanged {
                key: "theme".into(),
            })
            .actor(actor.clone())
            .resource(resource.clone())
            .sign(&key)
            .unwrap();

        let event2 = AuditEvent::builder()
            .event_time(time)
            .event_type(EventType::ConfigChanged {
                key: "theme".into(),
            })
            .actor(actor)
            .resource(resource)
            .sign(&key)
            .unwrap();

        assert_eq!(event1.id(), event2.id());
    }

    #[test]
    fn test_tampered_event_fails_validation() {
        let key = test_key();
        let actor = ActorId::new(key.public_key(), ActorKind::User);
        let resource = ResourceId::new(ResourceKind::Repository, "myrepo");

        let mut event = AuditEvent::builder()
            .now()
            .event_type(EventType::RepoDeleted)
            .actor(actor)
            .resource(resource)
            .sign(&key)
            .unwrap();

        // Tamper with the event
        event.outcome = Outcome::Failure {
            reason: "tampered".into(),
        };

        // Validation should fail
        assert!(event.validate().is_err());
    }

    #[test]
    fn test_bincode_roundtrip() {
        let key = test_key();
        let actor = ActorId::new(key.public_key(), ActorKind::User);
        let resource = ResourceId::new(ResourceKind::Repository, "myrepo");

        let event = AuditEvent::builder()
            .now()
            .event_type(EventType::Push {
                force: false,
                commits: 1,
            })
            .actor(actor)
            .resource(resource)
            .sign(&key)
            .unwrap();

        // Serialize
        let bytes = bincode::serialize(&event).expect("serialize should work");
        println!("Serialized event size: {} bytes", bytes.len());

        // Deserialize
        let restored: AuditEvent = bincode::deserialize(&bytes).expect("deserialize should work");

        assert_eq!(event.id(), restored.id());
        assert!(restored.validate().is_ok());
    }

    #[test]
    fn test_datetime_bincode() {
        use chrono::{DateTime, Utc};
        use serde::{Deserialize, Serialize};

        #[derive(Serialize, Deserialize, Debug)]
        struct TestTime {
            #[serde(with = "chrono::serde::ts_milliseconds")]
            time: DateTime<Utc>,
        }

        let t = TestTime { time: Utc::now() };
        let bytes = bincode::serialize(&t).expect("serialize");
        let restored: TestTime = bincode::deserialize(&bytes).expect("deserialize");
        // Note: ts_milliseconds loses sub-millisecond precision, so we check
        // that the times are within 1ms of each other
        let diff = (t.time - restored.time).num_milliseconds().abs();
        assert!(diff <= 1, "times should be within 1ms");
    }

    #[test]
    fn test_actor_bincode() {
        let key = test_key();
        let actor = ActorId::new(key.public_key(), ActorKind::User).with_name("alice");

        let bytes = bincode::serialize(&actor).expect("serialize");
        println!("ActorId size: {} bytes", bytes.len());
        let restored: ActorId = bincode::deserialize(&bytes).expect("deserialize");
        assert_eq!(actor.id(), restored.id());
    }

    #[test]
    fn test_attestation_bincode() {
        let key = test_key();
        let sig = key.sign(b"test");
        let att = Attestation::new(key.public_key(), sig);

        let bytes = bincode::serialize(&att).expect("serialize");
        println!("Attestation size: {} bytes", bytes.len());
        let restored: Attestation = bincode::deserialize(&bytes).expect("deserialize");
        assert_eq!(att.attester.as_bytes(), restored.attester.as_bytes());
    }

    #[test]
    fn test_event_type_bincode() {
        let et = EventType::Push { force: true, commits: 5 };
        let bytes = bincode::serialize(&et).expect("serialize");
        println!("EventType size: {} bytes", bytes.len());
        let restored: EventType = bincode::deserialize(&bytes).expect("deserialize");
        assert_eq!(et, restored);
    }

    #[test]
    fn test_resource_bincode() {
        let r = ResourceId::new(ResourceKind::Repository, "myrepo");
        let bytes = bincode::serialize(&r).expect("serialize");
        println!("ResourceId size: {} bytes", bytes.len());
        let restored: ResourceId = bincode::deserialize(&bytes).expect("deserialize");
        assert_eq!(r.id, restored.id);
    }

    #[test]
    fn test_outcome_bincode() {
        let o = Outcome::Success;
        let bytes = bincode::serialize(&o).expect("serialize");
        println!("Outcome size: {} bytes", bytes.len());
        let restored: Outcome = bincode::deserialize(&bytes).expect("deserialize");
        assert_eq!(o, restored);
    }

    #[test]
    fn test_minimal_struct_bincode() {
        use serde::{Deserialize, Serialize};
        use crate::crypto::Sig;

        // Test struct with Sig inside
        #[derive(Serialize, Deserialize, Debug)]
        struct TestWithSig {
            data: u64,
            sig: Sig,
        }

        let key = test_key();
        let sig = key.sign(b"test");
        let t = TestWithSig { data: 42, sig };

        let bytes = bincode::serialize(&t).expect("serialize");
        println!("TestWithSig size: {} bytes", bytes.len());
        let _restored: TestWithSig = bincode::deserialize(&bytes).expect("deserialize");
    }

    #[test]
    fn test_vec_attestation_link_bincode() {
        let chain: Vec<AttestationLink> = vec![];
        let bytes = bincode::serialize(&chain).expect("serialize");
        println!("Empty chain size: {} bytes", bytes.len());
        let restored: Vec<AttestationLink> = bincode::deserialize(&bytes).expect("deserialize");
        assert_eq!(chain.len(), restored.len());
    }

    #[test]
    fn test_full_struct_bincode() {
        use chrono::{DateTime, Utc};
        use serde::{Deserialize, Serialize};

        // Mirror AuditEvent exactly
        #[derive(Serialize, Deserialize, Debug)]
        struct TestEvent {
            #[serde(with = "chrono::serde::ts_milliseconds")]
            event_time: DateTime<Utc>,
            event_type: EventType,
            actor: ActorId,
            resource: ResourceId,
            outcome: Outcome,
            metadata: Vec<u8>,
            attestation: Attestation,
        }

        let key = test_key();
        let sig = key.sign(b"test");

        let t = TestEvent {
            event_time: Utc::now(),
            event_type: EventType::Push { force: false, commits: 1 },
            actor: ActorId::new(key.public_key(), ActorKind::User),
            resource: ResourceId::new(ResourceKind::Repository, "myrepo"),
            outcome: Outcome::Success,
            metadata: vec![],
            attestation: Attestation::new(key.public_key(), sig),
        };

        let bytes = bincode::serialize(&t).expect("serialize");
        println!("TestEvent size: {} bytes", bytes.len());
        let _restored: TestEvent = bincode::deserialize(&bytes).expect("deserialize");
    }
}
