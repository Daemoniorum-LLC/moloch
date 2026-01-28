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
//! - [`approval`] - Human-in-the-loop approval protocol
//! - [`reasoning`] - Reasoning traces for agent decisions
//! - [`outcome`] - Outcome verification and attestation
//! - [`emergency`] - Emergency control actions
//! - [`coordination`] - Multi-agent coordination

pub mod attestation;
pub mod capability;
pub mod causality;
pub mod hitl;
pub mod principal;
pub mod registry;
pub mod session;

// Re-exports
pub use attestation::{
    AgentAttestation, AgentAttestationBuilder, AttestationError, RequiredCapability,
    RuntimeAttestation, TeeQuote, TeeType, ToolAttestation,
};
pub use capability::{
    Capability, CapabilityBuilder, CapabilityCheck, CapabilityConstraints, CapabilityId,
    CapabilityKind, CapabilitySet, CapabilitySetId, DayOfWeek, DenialReason, RateLimit,
    ResourceScope, TimeOfDay, TimeWindow,
};
pub use causality::{CausalContext, CausalContextBuilder, CrossSessionReference};
pub use hitl::{
    ActionModifications, ApprovalContext, ApprovalDecision, ApprovalPolicy, ApprovalRequest,
    ApprovalRequestId, ApprovalResponse, ApprovalStatus, CancellationActor, Cost,
    EscalationPolicy, ImpactAssessment, ProposedAction, ProposedActionBuilder, Severity,
};
pub use principal::{PrincipalId, PrincipalKind};
pub use registry::AttestationRegistry;
pub use session::{Session, SessionBuilder, SessionEndReason, SessionId, SessionSummary};
