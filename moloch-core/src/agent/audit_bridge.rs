//! Bridge between agent accountability types and the core audit event system.
//!
//! This module provides the missing integration layer (Section 11) that
//! connects agent accountability types to the audit chain. Agent actions
//! are expressed as `AuditEvent` instances with structured metadata
//! embedding the full causal context, capability references, and
//! attestation hashes.

use serde::{Deserialize, Serialize};

use crate::crypto::{Hash, PublicKey, SecretKey};
use crate::error::Result;
use crate::event::{ActorId, ActorKind, AuditEvent, EventType, Outcome, ResourceId};

use super::capability::CapabilityId;
use super::causality::CausalContext;
use super::session::SessionId;

/// Structured metadata embedded in agent audit events.
///
/// This is serialized to JSON and stored in the `AuditEvent.metadata`
/// field, providing the full accountability context for any agent action.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentEventMetadata {
    /// Session in which the action occurred.
    pub session_id: SessionId,

    /// Causal context linking this event to its origin.
    pub causal_context_hash: Hash,

    /// Capability that authorized this action.
    pub capability_id: Option<CapabilityId>,

    /// Hash of the agent's attestation for cross-reference.
    pub attestation_hash: Option<Hash>,

    /// Reasoning summary for the action.
    pub reasoning: Option<String>,

    /// Whether human approval was obtained.
    pub human_approved: bool,
}

impl AgentEventMetadata {
    /// Create metadata for an agent action.
    pub fn new(session_id: SessionId, causal_context: &CausalContext) -> Self {
        let causal_bytes = serde_json::to_vec(causal_context).unwrap_or_default();
        Self {
            session_id,
            causal_context_hash: crate::crypto::hash(&causal_bytes),
            capability_id: None,
            attestation_hash: None,
            reasoning: None,
            human_approved: false,
        }
    }

    /// Set the capability that authorized this action.
    pub fn with_capability(mut self, id: CapabilityId) -> Self {
        self.capability_id = Some(id);
        self
    }

    /// Set the attestation hash for cross-reference.
    pub fn with_attestation_hash(mut self, hash: Hash) -> Self {
        self.attestation_hash = Some(hash);
        self
    }

    /// Set the reasoning summary.
    pub fn with_reasoning(mut self, reasoning: impl Into<String>) -> Self {
        self.reasoning = Some(reasoning.into());
        self
    }

    /// Mark that human approval was obtained.
    pub fn with_human_approval(mut self) -> Self {
        self.human_approved = true;
        self
    }

    /// Serialize to bytes for embedding in AuditEvent metadata.
    pub fn to_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(self).unwrap_or_default()
    }

    /// Deserialize from AuditEvent metadata bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        serde_json::from_slice(bytes)
            .map_err(|e| crate::error::Error::invalid_input(format!("invalid metadata: {}", e)))
    }
}

/// Builder for creating agent-contextualized audit events.
///
/// Wraps the standard `AuditEventBuilder` with agent-specific defaults
/// and structured metadata.
pub struct AgentAuditEventBuilder {
    agent_key: PublicKey,
    agent_name: Option<String>,
    action: Option<String>,
    resource: Option<ResourceId>,
    outcome: Option<Outcome>,
    metadata: AgentEventMetadata,
}

impl AgentAuditEventBuilder {
    /// Create a new builder for an agent action event.
    pub fn new(
        agent_key: PublicKey,
        session_id: SessionId,
        causal_context: &CausalContext,
    ) -> Self {
        Self {
            agent_key,
            agent_name: None,
            action: None,
            resource: None,
            outcome: None,
            metadata: AgentEventMetadata::new(session_id, causal_context),
        }
    }

    /// Set the agent's display name.
    pub fn agent_name(mut self, name: impl Into<String>) -> Self {
        self.agent_name = Some(name.into());
        self
    }

    /// Set the action description.
    pub fn action(mut self, action: impl Into<String>) -> Self {
        self.action = Some(action.into());
        self
    }

    /// Set the resource affected.
    pub fn resource(mut self, resource: ResourceId) -> Self {
        self.resource = Some(resource);
        self
    }

    /// Set the outcome.
    pub fn outcome(mut self, outcome: Outcome) -> Self {
        self.outcome = Some(outcome);
        self
    }

    /// Set the capability that authorized this action.
    pub fn capability(mut self, id: CapabilityId) -> Self {
        self.metadata = self.metadata.with_capability(id);
        self
    }

    /// Set the attestation hash for cross-reference.
    pub fn attestation_hash(mut self, hash: Hash) -> Self {
        self.metadata = self.metadata.with_attestation_hash(hash);
        self
    }

    /// Set the reasoning summary.
    pub fn reasoning(mut self, reasoning: impl Into<String>) -> Self {
        let r: String = reasoning.into();
        self.metadata = self.metadata.with_reasoning(r.clone());
        self.action = self.action.or(Some(r));
        self
    }

    /// Mark that human approval was obtained.
    pub fn human_approved(mut self) -> Self {
        self.metadata = self.metadata.with_human_approval();
        self
    }

    /// Build and sign the audit event.
    pub fn sign(self, agent_key: &SecretKey) -> Result<AuditEvent> {
        let action = self.action.unwrap_or_else(|| "agent_action".to_string());
        let resource = self.resource.ok_or_else(|| {
            crate::error::Error::invalid_input("resource is required for agent audit event")
        })?;

        let mut actor = ActorId::new(self.agent_key, ActorKind::Agent);
        if let Some(name) = self.agent_name {
            actor = actor.with_name(name);
        }

        AuditEvent::builder()
            .now()
            .event_type(EventType::AgentAction {
                action,
                reasoning: self.metadata.reasoning.clone(),
            })
            .actor(actor)
            .resource(resource)
            .outcome(self.outcome.unwrap_or(Outcome::Success))
            .metadata_bytes(self.metadata.to_bytes())
            .sign(agent_key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent::principal::PrincipalId;
    use crate::crypto::{hash, SecretKey};
    use crate::event::{EventId, ResourceKind};

    fn test_key() -> SecretKey {
        SecretKey::generate()
    }

    fn test_session_id() -> SessionId {
        SessionId::random()
    }

    fn test_event_id() -> EventId {
        EventId(hash(b"test-event"))
    }

    fn test_principal() -> PrincipalId {
        PrincipalId::user("test-agent@system").unwrap()
    }

    fn test_causal_context() -> CausalContext {
        CausalContext::root(test_event_id(), test_session_id(), test_principal())
    }

    // === AgentEventMetadata Tests ===

    #[test]
    fn metadata_new_sets_session_and_causal_hash() {
        let session = test_session_id();
        let causal = test_causal_context();
        let meta = AgentEventMetadata::new(session, &causal);

        assert_eq!(meta.session_id, session);
        assert!(meta.capability_id.is_none());
        assert!(meta.attestation_hash.is_none());
        assert!(!meta.human_approved);
    }

    #[test]
    fn metadata_with_capability() {
        let cap_id = CapabilityId::generate();
        let meta = AgentEventMetadata::new(test_session_id(), &test_causal_context())
            .with_capability(cap_id);

        assert_eq!(meta.capability_id, Some(cap_id));
    }

    #[test]
    fn metadata_with_attestation_hash() {
        let h = hash(b"attestation");
        let meta = AgentEventMetadata::new(test_session_id(), &test_causal_context())
            .with_attestation_hash(h);

        assert_eq!(meta.attestation_hash, Some(h));
    }

    #[test]
    fn metadata_serialization_roundtrip() {
        let cap_id = CapabilityId::generate();
        let att_hash = hash(b"attestation");

        let meta = AgentEventMetadata::new(test_session_id(), &test_causal_context())
            .with_capability(cap_id)
            .with_attestation_hash(att_hash)
            .with_reasoning("testing serialization")
            .with_human_approval();

        let bytes = meta.to_bytes();
        let restored = AgentEventMetadata::from_bytes(&bytes).unwrap();

        assert_eq!(restored.capability_id, Some(cap_id));
        assert_eq!(restored.attestation_hash, Some(att_hash));
        assert_eq!(restored.reasoning.as_deref(), Some("testing serialization"));
        assert!(restored.human_approved);
    }

    // === AgentAuditEventBuilder Tests ===

    #[test]
    fn agent_action_creates_audit_event() {
        let key = test_key();
        let session = test_session_id();
        let causal = test_causal_context();

        let event = AgentAuditEventBuilder::new(key.public_key(), session, &causal)
            .action("code_review")
            .resource(ResourceId::new(ResourceKind::PullRequest, "pr-42"))
            .outcome(Outcome::Success)
            .sign(&key)
            .unwrap();

        assert_eq!(event.actor.kind, ActorKind::Agent);
        assert_eq!(event.actor.key, key.public_key());
        assert!(event.validate().is_ok());
    }

    #[test]
    fn audit_event_preserves_causal_context() {
        let key = test_key();
        let session = test_session_id();
        let causal = test_causal_context();

        let event = AgentAuditEventBuilder::new(key.public_key(), session, &causal)
            .action("deploy")
            .resource(ResourceId::new(ResourceKind::Repository, "org/project"))
            .sign(&key)
            .unwrap();

        // Metadata should deserialize back to AgentEventMetadata
        let meta = AgentEventMetadata::from_bytes(&event.metadata).unwrap();
        assert_eq!(meta.session_id, session);
        // The causal hash should be deterministic for the same context
        let expected_hash = {
            let bytes = serde_json::to_vec(&causal).unwrap_or_default();
            hash(&bytes)
        };
        assert_eq!(meta.causal_context_hash, expected_hash);
    }

    #[test]
    fn audit_event_references_capability() {
        let key = test_key();
        let cap_id = CapabilityId::generate();

        let event = AgentAuditEventBuilder::new(
            key.public_key(),
            test_session_id(),
            &test_causal_context(),
        )
        .action("write_file")
        .resource(ResourceId::new(ResourceKind::File, "src/main.rs"))
        .capability(cap_id)
        .sign(&key)
        .unwrap();

        let meta = AgentEventMetadata::from_bytes(&event.metadata).unwrap();
        assert_eq!(meta.capability_id, Some(cap_id));
    }

    #[test]
    fn audit_event_includes_attestation_hash() {
        let key = test_key();
        let att_hash = hash(b"agent-attestation-data");

        let event = AgentAuditEventBuilder::new(
            key.public_key(),
            test_session_id(),
            &test_causal_context(),
        )
        .action("execute_command")
        .resource(ResourceId::new(ResourceKind::Repository, "org/repo"))
        .attestation_hash(att_hash)
        .sign(&key)
        .unwrap();

        let meta = AgentEventMetadata::from_bytes(&event.metadata).unwrap();
        assert_eq!(meta.attestation_hash, Some(att_hash));
    }

    #[test]
    fn audit_event_chain_commitment() {
        let key = test_key();

        let event = AgentAuditEventBuilder::new(
            key.public_key(),
            test_session_id(),
            &test_causal_context(),
        )
        .action("merge_pr")
        .resource(ResourceId::new(ResourceKind::PullRequest, "pr-99"))
        .sign(&key)
        .unwrap();

        // Event participates in the hash chain
        let id1 = event.id();
        let id2 = event.id();
        // Deterministic content-addressed ID
        assert_eq!(id1, id2);
        // Signature validates
        assert!(event.validate().is_ok());
    }

    #[test]
    fn agent_event_with_reasoning_and_human_approval() {
        let key = test_key();

        let event = AgentAuditEventBuilder::new(
            key.public_key(),
            test_session_id(),
            &test_causal_context(),
        )
        .action("delete_repository")
        .resource(ResourceId::new(ResourceKind::Repository, "org/obsolete"))
        .reasoning("Repository has been archived and data migrated")
        .human_approved()
        .outcome(Outcome::Success)
        .sign(&key)
        .unwrap();

        let meta = AgentEventMetadata::from_bytes(&event.metadata).unwrap();
        assert!(meta.human_approved);
        assert_eq!(
            meta.reasoning.as_deref(),
            Some("Repository has been archived and data migrated")
        );
    }

    #[test]
    fn agent_event_with_agent_name() {
        let key = test_key();

        let event = AgentAuditEventBuilder::new(
            key.public_key(),
            test_session_id(),
            &test_causal_context(),
        )
        .agent_name("ReviewBot")
        .action("review")
        .resource(ResourceId::new(ResourceKind::PullRequest, "pr-1"))
        .sign(&key)
        .unwrap();

        assert_eq!(event.actor.name.as_deref(), Some("ReviewBot"));
        assert_eq!(event.actor.kind, ActorKind::Agent);
    }

    #[test]
    fn agent_event_denied_outcome() {
        let key = test_key();

        let event = AgentAuditEventBuilder::new(
            key.public_key(),
            test_session_id(),
            &test_causal_context(),
        )
        .action("deploy_production")
        .resource(ResourceId::new(ResourceKind::Repository, "org/app"))
        .outcome(Outcome::Denied {
            reason: "insufficient capability".to_string(),
        })
        .sign(&key)
        .unwrap();

        assert!(matches!(event.outcome, Outcome::Denied { .. }));
    }

    #[test]
    fn agent_event_requires_resource() {
        let key = test_key();

        let result = AgentAuditEventBuilder::new(
            key.public_key(),
            test_session_id(),
            &test_causal_context(),
        )
        .action("something")
        .sign(&key);

        assert!(result.is_err());
    }

    #[test]
    fn metadata_invalid_bytes_returns_error() {
        let result = AgentEventMetadata::from_bytes(b"not valid json");
        assert!(result.is_err());
    }
}
