//! Agent accountability types for Moloch.
//!
//! This module implements the Agent Accountability specification,
//! providing types and validation for:
//!
//! - [`principal`] - Human/organization principals responsible for agents
//! - [`session`] - Bounded contexts for agent operations
//! - [`causality`] - Causal chain linking events to their origin
//! - [`attestation`] - Agent identity attestation
//! - [`capability`] - Capability-based authorization
//! - [`hitl`] - Human-in-the-loop approval protocol
//! - [`reasoning`] - Reasoning traces for agent decisions
//! - [`outcome`] - Outcome verification and attestation
//! - [`emergency`] - Emergency control actions
//! - [`coordination`] - Multi-agent coordination
//! - [`id`] - Generic 16-byte identifier type and macro
//! - [`timestamp`] - Type-safe millisecond timestamps
//! - [`audit_bridge`] - Bridge to core audit event system

pub mod attestation;
pub mod audit_bridge;
pub mod capability;
pub mod event_types;
#[macro_use]
pub mod id;
pub mod causality;
pub mod coordination;
pub mod emergency;
pub mod hitl;
pub mod outcome;
pub mod principal;
pub mod reasoning;
pub mod registry;
pub mod session;
pub mod timestamp;

// Re-exports
pub use attestation::{
    AgentAttestation, AgentAttestationBuilder, AttestationError, RequiredCapability,
    RuntimeAttestation, TeeQuote, TeeType, ToolAttestation,
};
pub use audit_bridge::{AgentAuditEventBuilder, AgentEventMetadata};
pub use capability::{
    Capability, CapabilityBuilder, CapabilityCheck, CapabilityConstraints, CapabilityId,
    CapabilityKind, CapabilitySet, CapabilitySetId, CapabilityState, DayOfWeek, DenialReason,
    RateLimit, ResourceScope, TimeOfDay, TimeWindow,
};
pub use causality::{
    CausalChainQuery, CausalContext, CausalContextBuilder, CrossSessionReference,
    InMemoryCausalStore,
};
pub use coordination::{
    Conflict, ConflictId, ConflictResolutionMethod, ConflictStatus, CoordinatedAction,
    CoordinatedActionBuilder, CoordinatedActionSpec, CoordinationCostTracker, CoordinationEvent,
    CoordinationId, CoordinationMetrics, CoordinationProtocol, CoordinationResult,
    CoordinationStatus, CoordinationType, FailureHandling, Participant, ParticipantRole,
    QuorumPolicy, Responsibility, Task, TaskDependency, TaskId,
};
pub use emergency::{
    DurationMs, EmergencyAction, EmergencyEvent, EmergencyEventBuilder, EmergencyPriority,
    EmergencyResolution, EmergencyTrigger, GlobalPauseState, PostMortem, Resolution,
    SuspensionEntry, SuspensionRegistry, SuspensionScope,
};
pub use event_types::{
    ActionDetails, AgentEventMetadataV2, AgentEventType, DisputeResolution, TerminationReason,
};
pub use hitl::{
    ActionModifications, ApprovalContext, ApprovalDecision, ApprovalPolicy, ApprovalRequest,
    ApprovalRequestId, ApprovalResponse, ApprovalStatus, CancellationActor, Cost, EscalationPolicy,
    ImpactAssessment, ProposedAction, ProposedActionBuilder, Severity,
};
pub use id::Id16;
pub use outcome::{
    ActionOutcome, Attestor, DisputeStatus, Evidence, IdempotencyKey, IdempotencyRecord,
    IdempotencyStore, OutcomeAttestation, OutcomeAttestationBuilder, OutcomeDispute,
};
pub use principal::{PrincipalId, PrincipalKind};
pub use reasoning::{
    Alternative, Confidence, Decision, Factor, Goal, GoalSource, Priority, ReasoningStep,
    ReasoningTrace, ReasoningTraceBuilder, StepAction, TraceId,
};
pub use registry::AttestationRegistry;
pub use session::{Session, SessionBuilder, SessionEndReason, SessionId, SessionSummary};
pub use timestamp::Timestamp;
