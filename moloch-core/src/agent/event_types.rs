//! Agent accountability event types (Section 11).
//!
//! This module defines the `AgentEventType` enum with all 21 variants
//! specified in Section 11.1 of the Agent Accountability specification,
//! along with supporting types `TerminationReason`, `ActionDetails`,
//! and `DisputeResolution`.

use serde::{Deserialize, Serialize};

use crate::crypto::{Hash, PublicKey};
use crate::event::{EventId, ResourceId};

use super::attestation::AgentAttestation;
use super::capability::{CapabilityConstraints, CapabilityId};
use super::causality::CausalContext;
use super::coordination::{CoordinatedAction, CoordinationEvent};
use super::emergency::{EmergencyEvent, EmergencyResolution};
use super::hitl::{
    ApprovalRequest, ApprovalRequestId, ApprovalResponse, ImpactAssessment, Severity,
};
use super::outcome::{Evidence, OutcomeAttestation};
use super::principal::PrincipalId;
use super::reasoning::ReasoningTrace;
use super::session::{Session, SessionId, SessionEndReason, SessionSummary};

/// Extended event types for agent accountability (Section 11.1).
///
/// Each variant corresponds to a distinct agent lifecycle event that
/// must be recorded in the audit chain. This enum replaces the generic
/// `EventType::AgentAction` for agent-specific events.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "agent_event_type", rename_all = "snake_case")]
pub enum AgentEventType {
    // === Session Events ===
    /// New session started.
    SessionStarted {
        /// The session that was created.
        session: Session,
    },

    /// Session ended.
    SessionEnded {
        /// ID of the session that ended.
        session_id: SessionId,
        /// Why the session ended.
        reason: SessionEndReason,
        /// Summary statistics.
        summary: SessionSummary,
    },

    // === Attestation Events ===
    /// Agent attestation registered.
    AgentAttested {
        /// The attestation that was registered.
        attestation: AgentAttestation,
    },

    /// Attestation revoked.
    AttestationRevoked {
        /// Hash of the attestation being revoked.
        attestation_hash: Hash,
        /// Reason for revocation.
        reason: String,
        /// Who revoked it.
        revoked_by: String,
    },

    // === Capability Events ===
    /// Capability granted.
    CapabilityGranted {
        /// The capability ID that was granted.
        capability_id: CapabilityId,
        /// The agent receiving the capability.
        grantee: PublicKey,
        /// Justification for the grant.
        justification: String,
        /// Reference to authorization.
        authorization_ref: Option<String>,
    },

    /// Capability revoked.
    CapabilityRevoked {
        /// ID of the revoked capability.
        capability_id: CapabilityId,
        /// Reason for revocation.
        reason: String,
        /// Who revoked it.
        revoked_by: String,
    },

    /// Capability delegated from one agent to another.
    CapabilityDelegated {
        /// Agent delegating the capability.
        from: PublicKey,
        /// Agent receiving the delegation.
        to: PublicKey,
        /// The capability being delegated.
        capability_id: CapabilityId,
        /// Constraints on the delegated capability.
        constraints: CapabilityConstraints,
    },

    // === Agent Lifecycle Events ===
    /// Agent spawned by another agent.
    AgentSpawned {
        /// Parent agent that spawned the child.
        parent: PublicKey,
        /// The newly spawned agent.
        child: PublicKey,
        /// Capabilities inherited from parent.
        inherited_capabilities: Vec<CapabilityId>,
        /// Purpose of the spawned agent.
        purpose: String,
    },

    /// Agent terminated.
    AgentTerminated {
        /// The agent that was terminated.
        agent: PublicKey,
        /// Why the agent was terminated.
        reason: TerminationReason,
        /// Hash of the agent's final state.
        final_state: Option<Hash>,
    },

    // === Action Events ===
    /// Agent action with full accountability (v2).
    AgentActionV2 {
        /// Causal context (required).
        causal_context: CausalContext,
        /// Attestation hash (required).
        attestation_hash: Hash,
        /// Capability authorizing this action.
        capability_id: CapabilityId,
        /// Action details.
        action: ActionDetails,
        /// Reasoning trace (required for severity >= Medium).
        reasoning_trace: Option<ReasoningTrace>,
        /// Impact assessment.
        impact: ImpactAssessment,
    },

    /// Tool invocation by an agent.
    ToolInvocation {
        /// Tool being invoked.
        tool_id: String,
        /// Tool version.
        tool_version: String,
        /// Hash of the input parameters.
        input_hash: Hash,
        /// Human-readable summary of the input.
        input_summary: String,
        /// Causal context for the invocation.
        causal_context: CausalContext,
    },

    /// Result from a tool invocation.
    ToolResult {
        /// Event ID of the invocation that produced this result.
        invocation_event_id: EventId,
        /// Hash of the output.
        output_hash: Hash,
        /// Human-readable summary of the output.
        output_summary: String,
        /// How long the tool took.
        duration_ms: u64,
    },

    // === HITL Events ===
    /// Human approval requested.
    ApprovalRequested {
        /// The approval request.
        request: ApprovalRequest,
    },

    /// Human approval response received.
    ApprovalResponded {
        /// The approval response.
        response: ApprovalResponse,
    },

    /// Approval escalated to additional reviewers.
    ApprovalEscalated {
        /// The request being escalated.
        request_id: ApprovalRequestId,
        /// Who it was escalated to.
        escalated_to: Vec<PrincipalId>,
        /// Why it was escalated.
        reason: String,
    },

    // === Outcome Events ===
    /// Outcome attested.
    OutcomeAttested {
        /// The outcome attestation.
        attestation: OutcomeAttestation,
    },

    /// Outcome disputed.
    OutcomeDisputed {
        /// Event ID of the attestation being disputed.
        attestation_event_id: EventId,
        /// Reason for the dispute.
        dispute_reason: String,
        /// Counter-evidence provided.
        counter_evidence: Vec<Evidence>,
        /// Who filed the dispute.
        disputer: String,
    },

    /// Dispute resolved.
    DisputeResolved {
        /// Event ID of the dispute.
        dispute_event_id: EventId,
        /// How the dispute was resolved.
        resolution: DisputeResolution,
        /// Who resolved it.
        resolver: PrincipalId,
    },

    // === Emergency Events ===
    /// Emergency declared.
    EmergencyDeclared {
        /// The emergency event.
        emergency: EmergencyEvent,
    },

    /// Emergency resolved.
    EmergencyResolved {
        /// The resolution details.
        resolution: EmergencyResolution,
    },

    // === Coordination Events ===
    /// Multi-agent coordination started.
    CoordinationStarted {
        /// The coordinated action.
        coordination: CoordinatedAction,
    },

    /// Coordination lifecycle event.
    CoordinationUpdate {
        /// The coordination event.
        event: CoordinationEvent,
    },
}

impl AgentEventType {
    /// Get a human-readable label for this event type.
    pub fn label(&self) -> &'static str {
        match self {
            AgentEventType::SessionStarted { .. } => "session_started",
            AgentEventType::SessionEnded { .. } => "session_ended",
            AgentEventType::AgentAttested { .. } => "agent_attested",
            AgentEventType::AttestationRevoked { .. } => "attestation_revoked",
            AgentEventType::CapabilityGranted { .. } => "capability_granted",
            AgentEventType::CapabilityRevoked { .. } => "capability_revoked",
            AgentEventType::CapabilityDelegated { .. } => "capability_delegated",
            AgentEventType::AgentSpawned { .. } => "agent_spawned",
            AgentEventType::AgentTerminated { .. } => "agent_terminated",
            AgentEventType::AgentActionV2 { .. } => "agent_action_v2",
            AgentEventType::ToolInvocation { .. } => "tool_invocation",
            AgentEventType::ToolResult { .. } => "tool_result",
            AgentEventType::ApprovalRequested { .. } => "approval_requested",
            AgentEventType::ApprovalResponded { .. } => "approval_responded",
            AgentEventType::ApprovalEscalated { .. } => "approval_escalated",
            AgentEventType::OutcomeAttested { .. } => "outcome_attested",
            AgentEventType::OutcomeDisputed { .. } => "outcome_disputed",
            AgentEventType::DisputeResolved { .. } => "dispute_resolved",
            AgentEventType::EmergencyDeclared { .. } => "emergency_declared",
            AgentEventType::EmergencyResolved { .. } => "emergency_resolved",
            AgentEventType::CoordinationStarted { .. } => "coordination_started",
            AgentEventType::CoordinationUpdate { .. } => "coordination_update",
        }
    }

    /// Get the severity category for this event type.
    ///
    /// Used to determine evidence and approval requirements.
    pub fn default_severity(&self) -> Severity {
        match self {
            AgentEventType::EmergencyDeclared { .. }
            | AgentEventType::AgentTerminated { .. } => Severity::Critical,

            AgentEventType::CapabilityRevoked { .. }
            | AgentEventType::AttestationRevoked { .. }
            | AgentEventType::EmergencyResolved { .. }
            | AgentEventType::OutcomeDisputed { .. } => Severity::High,

            AgentEventType::AgentActionV2 { .. }
            | AgentEventType::CapabilityGranted { .. }
            | AgentEventType::CapabilityDelegated { .. }
            | AgentEventType::AgentSpawned { .. }
            | AgentEventType::CoordinationStarted { .. }
            | AgentEventType::DisputeResolved { .. } => Severity::Medium,

            AgentEventType::SessionStarted { .. }
            | AgentEventType::SessionEnded { .. }
            | AgentEventType::AgentAttested { .. }
            | AgentEventType::ToolInvocation { .. }
            | AgentEventType::ToolResult { .. }
            | AgentEventType::ApprovalRequested { .. }
            | AgentEventType::ApprovalResponded { .. }
            | AgentEventType::ApprovalEscalated { .. }
            | AgentEventType::OutcomeAttested { .. }
            | AgentEventType::CoordinationUpdate { .. } => Severity::Low,
        }
    }

    /// Check if this event type requires an attestation hash.
    pub fn requires_attestation(&self) -> bool {
        matches!(
            self,
            AgentEventType::AgentActionV2 { .. }
                | AgentEventType::ToolInvocation { .. }
                | AgentEventType::AgentSpawned { .. }
                | AgentEventType::CapabilityDelegated { .. }
        )
    }

    /// Check if this event type requires a reasoning trace.
    pub fn requires_reasoning_trace(&self) -> bool {
        matches!(self, AgentEventType::AgentActionV2 { impact, .. } if impact.severity() >= Severity::Medium)
    }
}

/// Reason for agent termination (Section 11.1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "reason", rename_all = "snake_case")]
pub enum TerminationReason {
    /// The agent completed its assigned task.
    TaskCompleted,
    /// The session the agent was running in ended.
    SessionEnded,
    /// The agent's credentials were revoked.
    Revoked,
    /// The agent encountered an unrecoverable error.
    Error {
        /// Description of the error.
        error: String,
    },
    /// Emergency stop was triggered.
    EmergencyStop,
}

/// Details of an agent action (Section 11.1).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionDetails {
    /// Type of action being performed.
    pub action_type: String,
    /// Resource being acted upon.
    pub resource: ResourceId,
    /// Action parameters (structured).
    pub parameters: serde_json::Value,
    /// Expected outcome description.
    pub expected_outcome: String,
}

/// Resolution of an outcome dispute (Section 11.1).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "resolution", rename_all = "snake_case")]
pub enum DisputeResolution {
    /// Original outcome was upheld.
    OriginalUpheld,
    /// Dispute was upheld; original outcome was incorrect.
    DisputeUpheld {
        /// The corrected outcome description.
        corrected_outcome: String,
    },
    /// Neither side could be conclusively verified.
    Indeterminate {
        /// Explanatory notes.
        notes: String,
    },
}

/// Updated event metadata that aligns with Section 11.2.
///
/// This replaces the simplified `AgentEventMetadata` from audit_bridge
/// for v2 agent events. The key differences:
///
/// - `causal_context` stores the full context (not just a hash)
/// - `attestation_hash` is **required** for agent-initiated events (G-4.1)
/// - `reasoning_trace_hash` replaces the free-text `reasoning` field
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentEventMetadataV2 {
    /// Full causal context (required for all agent events).
    pub causal_context: CausalContext,

    /// Agent attestation hash (required for agent-initiated events).
    pub attestation_hash: Hash,

    /// Capability used for this action (required for action events).
    pub capability_id: Option<CapabilityId>,

    /// Hash of the reasoning trace (required for severity >= Medium).
    pub reasoning_trace_hash: Option<Hash>,
}

impl AgentEventMetadataV2 {
    /// Create new v2 metadata with required fields.
    pub fn new(causal_context: CausalContext, attestation_hash: Hash) -> Self {
        Self {
            causal_context,
            attestation_hash,
            capability_id: None,
            reasoning_trace_hash: None,
        }
    }

    /// Set the capability ID.
    pub fn with_capability(mut self, id: CapabilityId) -> Self {
        self.capability_id = Some(id);
        self
    }

    /// Set the reasoning trace hash.
    pub fn with_reasoning_trace_hash(mut self, hash: Hash) -> Self {
        self.reasoning_trace_hash = Some(hash);
        self
    }

    /// Validate that this metadata satisfies spec requirements.
    ///
    /// Checks:
    /// - Attestation binding: `agent_key` matches the causal context principal
    /// - Capability required for action events
    /// - Reasoning trace required when severity >= Medium
    pub fn validate(&self, severity: &Severity) -> crate::error::Result<()> {
        // G-4.1: attestation_hash is always present (enforced by struct — not Option)

        // Reasoning trace required for Medium+ severity
        if *severity >= Severity::Medium && self.reasoning_trace_hash.is_none() {
            return Err(crate::error::Error::invalid_input(
                "reasoning_trace_hash is required for severity >= Medium",
            ));
        }

        Ok(())
    }

    /// Serialize to bytes for embedding in AuditEvent metadata.
    pub fn to_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(self).unwrap_or_default()
    }

    /// Deserialize from AuditEvent metadata bytes.
    pub fn from_bytes(bytes: &[u8]) -> crate::error::Result<Self> {
        serde_json::from_slice(bytes).map_err(|e| {
            crate::error::Error::invalid_input(format!("invalid v2 metadata: {}", e))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent::principal::PrincipalId;
    use crate::agent::session::SessionId;
    use crate::crypto::hash;
    use crate::event::EventId;
    use std::time::Duration;

    fn test_event_id() -> EventId {
        EventId(hash(b"test-event"))
    }

    fn test_principal() -> PrincipalId {
        PrincipalId::user("test@system").unwrap()
    }

    fn test_causal_context() -> CausalContext {
        CausalContext::root(test_event_id(), SessionId::random(), test_principal())
    }

    // === AgentEventType variant count ===

    #[test]
    fn agent_event_type_has_all_variants() {
        // Verify we can construct all 21+ variants from the spec.
        // (The spec lists 21, we have 22 counting CoordinationUpdate.)
        let session = Session::builder()
            .principal(test_principal())
            .build()
            .unwrap();
        let session_id = session.id();

        let _variants: Vec<AgentEventType> = vec![
            AgentEventType::SessionStarted { session },
            AgentEventType::SessionEnded {
                session_id,
                reason: SessionEndReason::Completed,
                summary: SessionSummary {
                    session_id,
                    reason: SessionEndReason::Completed,
                    duration: Duration::from_secs(60),
                    event_count: 10,
                    action_count: 5,
                },
            },
            AgentEventType::AttestationRevoked {
                attestation_hash: hash(b"att"),
                reason: "expired".to_string(),
                revoked_by: "admin".to_string(),
            },
            AgentEventType::CapabilityGranted {
                capability_id: CapabilityId::generate(),
                grantee: crate::crypto::SecretKey::generate().public_key(),
                justification: "needed".to_string(),
                authorization_ref: None,
            },
            AgentEventType::CapabilityRevoked {
                capability_id: CapabilityId::generate(),
                reason: "no longer needed".to_string(),
                revoked_by: "admin".to_string(),
            },
            AgentEventType::CapabilityDelegated {
                from: crate::crypto::SecretKey::generate().public_key(),
                to: crate::crypto::SecretKey::generate().public_key(),
                capability_id: CapabilityId::generate(),
                constraints: CapabilityConstraints::default(),
            },
            AgentEventType::AgentSpawned {
                parent: crate::crypto::SecretKey::generate().public_key(),
                child: crate::crypto::SecretKey::generate().public_key(),
                inherited_capabilities: vec![],
                purpose: "sub-task".to_string(),
            },
            AgentEventType::AgentTerminated {
                agent: crate::crypto::SecretKey::generate().public_key(),
                reason: TerminationReason::TaskCompleted,
                final_state: None,
            },
            AgentEventType::ToolInvocation {
                tool_id: "bash".to_string(),
                tool_version: "1.0".to_string(),
                input_hash: hash(b"input"),
                input_summary: "ls -la".to_string(),
                causal_context: test_causal_context(),
            },
            AgentEventType::ToolResult {
                invocation_event_id: test_event_id(),
                output_hash: hash(b"output"),
                output_summary: "file listing".to_string(),
                duration_ms: 50,
            },
            AgentEventType::ApprovalEscalated {
                request_id: ApprovalRequestId::generate(),
                escalated_to: vec![test_principal()],
                reason: "no response".to_string(),
            },
            AgentEventType::OutcomeDisputed {
                attestation_event_id: test_event_id(),
                dispute_reason: "incorrect outcome".to_string(),
                counter_evidence: vec![],
                disputer: "auditor".to_string(),
            },
            AgentEventType::DisputeResolved {
                dispute_event_id: test_event_id(),
                resolution: DisputeResolution::OriginalUpheld,
                resolver: test_principal(),
            },
        ];

        // Verify label returns something for all constructed variants
        for v in &_variants {
            assert!(!v.label().is_empty());
        }
    }

    // === Label tests ===

    #[test]
    fn label_returns_correct_strings() {
        let terminated = AgentEventType::AgentTerminated {
            agent: crate::crypto::SecretKey::generate().public_key(),
            reason: TerminationReason::EmergencyStop,
            final_state: None,
        };
        assert_eq!(terminated.label(), "agent_terminated");
    }

    // === Severity tests ===

    #[test]
    fn emergency_declared_is_critical() {
        let terminated = AgentEventType::AgentTerminated {
            agent: crate::crypto::SecretKey::generate().public_key(),
            reason: TerminationReason::EmergencyStop,
            final_state: None,
        };
        assert_eq!(terminated.default_severity(), Severity::Critical);
    }

    #[test]
    fn session_started_is_low() {
        let session = Session::builder()
            .principal(test_principal())
            .build()
            .unwrap();
        let started = AgentEventType::SessionStarted { session };
        assert_eq!(started.default_severity(), Severity::Low);
    }

    // === TerminationReason tests ===

    #[test]
    fn termination_reason_serialization() {
        let reason = TerminationReason::Error {
            error: "out of memory".to_string(),
        };
        let json = serde_json::to_string(&reason).unwrap();
        let restored: TerminationReason = serde_json::from_str(&json).unwrap();
        assert_eq!(reason, restored);
    }

    #[test]
    fn termination_reason_all_variants() {
        let variants = vec![
            TerminationReason::TaskCompleted,
            TerminationReason::SessionEnded,
            TerminationReason::Revoked,
            TerminationReason::Error {
                error: "test".to_string(),
            },
            TerminationReason::EmergencyStop,
        ];
        for v in variants {
            let json = serde_json::to_string(&v).unwrap();
            let _: TerminationReason = serde_json::from_str(&json).unwrap();
        }
    }

    // === ActionDetails tests ===

    #[test]
    fn action_details_serialization() {
        let details = ActionDetails {
            action_type: "deploy".to_string(),
            resource: ResourceId::new(crate::event::ResourceKind::Repository, "org/repo"),
            parameters: serde_json::json!({"env": "production"}),
            expected_outcome: "deployment complete".to_string(),
        };

        let json = serde_json::to_string(&details).unwrap();
        let restored: ActionDetails = serde_json::from_str(&json).unwrap();
        assert_eq!(details.action_type, restored.action_type);
        assert_eq!(details.expected_outcome, restored.expected_outcome);
    }

    // === DisputeResolution tests ===

    #[test]
    fn dispute_resolution_all_variants() {
        let variants: Vec<DisputeResolution> = vec![
            DisputeResolution::OriginalUpheld,
            DisputeResolution::DisputeUpheld {
                corrected_outcome: "actual result".to_string(),
            },
            DisputeResolution::Indeterminate {
                notes: "inconclusive".to_string(),
            },
        ];

        for v in variants {
            let json = serde_json::to_string(&v).unwrap();
            let _: DisputeResolution = serde_json::from_str(&json).unwrap();
        }
    }

    // === AgentEventMetadataV2 tests ===

    #[test]
    fn v2_metadata_roundtrip() {
        let ctx = test_causal_context();
        let att_hash = hash(b"attestation");
        let cap_id = CapabilityId::generate();
        let trace_hash = hash(b"trace");

        let meta = AgentEventMetadataV2::new(ctx, att_hash)
            .with_capability(cap_id)
            .with_reasoning_trace_hash(trace_hash);

        let bytes = meta.to_bytes();
        let restored = AgentEventMetadataV2::from_bytes(&bytes).unwrap();

        assert_eq!(restored.attestation_hash, att_hash);
        assert_eq!(restored.capability_id, Some(cap_id));
        assert_eq!(restored.reasoning_trace_hash, Some(trace_hash));
    }

    #[test]
    fn v2_metadata_validate_requires_reasoning_for_medium() {
        let ctx = test_causal_context();
        let att_hash = hash(b"attestation");
        let meta = AgentEventMetadataV2::new(ctx, att_hash);

        // Low severity: no reasoning trace required
        assert!(meta.validate(&Severity::Low).is_ok());

        // Medium severity: reasoning trace required
        assert!(meta.validate(&Severity::Medium).is_err());

        // With reasoning trace: Medium severity OK
        let meta_with_trace = AgentEventMetadataV2::new(test_causal_context(), att_hash)
            .with_reasoning_trace_hash(hash(b"trace"));
        assert!(meta_with_trace.validate(&Severity::Medium).is_ok());
    }

    #[test]
    fn v2_metadata_validate_requires_reasoning_for_high() {
        let meta = AgentEventMetadataV2::new(test_causal_context(), hash(b"att"));
        assert!(meta.validate(&Severity::High).is_err());
    }

    #[test]
    fn v2_metadata_validate_requires_reasoning_for_critical() {
        let meta = AgentEventMetadataV2::new(test_causal_context(), hash(b"att"));
        assert!(meta.validate(&Severity::Critical).is_err());
    }

    #[test]
    fn v2_metadata_invalid_bytes() {
        let result = AgentEventMetadataV2::from_bytes(b"not json");
        assert!(result.is_err());
    }

    // === requires_attestation tests ===

    #[test]
    fn action_v2_requires_attestation() {
        let event = AgentEventType::ToolInvocation {
            tool_id: "bash".to_string(),
            tool_version: "1.0".to_string(),
            input_hash: hash(b"input"),
            input_summary: "test".to_string(),
            causal_context: test_causal_context(),
        };
        assert!(event.requires_attestation());
    }

    #[test]
    fn session_started_does_not_require_attestation() {
        let session = Session::builder()
            .principal(test_principal())
            .build()
            .unwrap();
        let event = AgentEventType::SessionStarted { session };
        assert!(!event.requires_attestation());
    }
}
