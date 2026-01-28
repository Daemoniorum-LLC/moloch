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

pub mod causality;
pub mod principal;
pub mod session;

// Re-exports
pub use causality::{CausalContext, CausalContextBuilder, CrossSessionReference};
pub use principal::{PrincipalId, PrincipalKind};
pub use session::{Session, SessionBuilder, SessionEndReason, SessionId, SessionSummary};
