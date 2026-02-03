//! Emergency controls for rapid intervention when agent behavior is problematic.
//!
//! Emergency controls answer: "How do we stop this?"

use serde::{Deserialize, Serialize};

use crate::crypto::PublicKey;
use crate::error::{Error, Result};
use crate::event::{EventId, ResourceId};

use super::capability::{CapabilityId, CapabilityKind};
use super::principal::PrincipalId;
use super::session::SessionId;

/// Duration in milliseconds.
pub type DurationMs = i64;

/// An emergency control action.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum EmergencyAction {
    /// Immediately suspend an agent.
    SuspendAgent {
        /// Agent to suspend.
        agent: PublicKey,
        /// Reason for suspension.
        reason: String,
        /// Duration of suspension (None = indefinite).
        duration: Option<DurationMs>,
        /// Scope of suspension.
        scope: SuspensionScope,
    },
    /// Permanently revoke agent credentials.
    RevokeAgent {
        /// Agent to revoke.
        agent: PublicKey,
        /// Reason for revocation.
        reason: String,
    },
    /// Kill an active session.
    TerminateSession {
        /// Session to terminate.
        session_id: SessionId,
        /// Reason for termination.
        reason: String,
    },
    /// Revoke a specific capability.
    RevokeCapability {
        /// Capability to revoke.
        capability_id: CapabilityId,
        /// Reason for revocation.
        reason: String,
    },
    /// Block access to a resource.
    BlockResource {
        /// Resource to block.
        resource: ResourceId,
        /// Actors blocked from the resource.
        blocked_actors: Vec<PublicKey>,
        /// Reason for blocking.
        reason: String,
        /// Duration of block (None = indefinite).
        duration: Option<DurationMs>,
    },
    /// Global pause on all agent actions.
    GlobalPause {
        /// Reason for global pause.
        reason: String,
        /// Duration of pause.
        duration: DurationMs,
        /// Agents exempt from pause.
        exceptions: Vec<PublicKey>,
    },
    /// Rollback actions from an agent.
    RollbackActions {
        /// Agent whose actions to rollback.
        agent: PublicKey,
        /// Rollback all actions since this time (Unix timestamp ms).
        since: i64,
        /// Reason for rollback.
        reason: String,
    },
}

impl EmergencyAction {
    /// Create a suspend agent action.
    pub fn suspend_agent(
        agent: PublicKey,
        reason: impl Into<String>,
        duration: Option<DurationMs>,
        scope: SuspensionScope,
    ) -> Self {
        Self::SuspendAgent {
            agent,
            reason: reason.into(),
            duration,
            scope,
        }
    }

    /// Create a revoke agent action.
    pub fn revoke_agent(agent: PublicKey, reason: impl Into<String>) -> Self {
        Self::RevokeAgent {
            agent,
            reason: reason.into(),
        }
    }

    /// Create a terminate session action.
    pub fn terminate_session(session_id: SessionId, reason: impl Into<String>) -> Self {
        Self::TerminateSession {
            session_id,
            reason: reason.into(),
        }
    }

    /// Create a revoke capability action.
    pub fn revoke_capability(capability_id: CapabilityId, reason: impl Into<String>) -> Self {
        Self::RevokeCapability {
            capability_id,
            reason: reason.into(),
        }
    }

    /// Create a block resource action.
    pub fn block_resource(
        resource: ResourceId,
        blocked_actors: Vec<PublicKey>,
        reason: impl Into<String>,
        duration: Option<DurationMs>,
    ) -> Self {
        Self::BlockResource {
            resource,
            blocked_actors,
            reason: reason.into(),
            duration,
        }
    }

    /// Create a global pause action.
    pub fn global_pause(
        reason: impl Into<String>,
        duration: DurationMs,
        exceptions: Vec<PublicKey>,
    ) -> Self {
        Self::GlobalPause {
            reason: reason.into(),
            duration,
            exceptions,
        }
    }

    /// Create a rollback actions action.
    pub fn rollback_actions(agent: PublicKey, since: i64, reason: impl Into<String>) -> Self {
        Self::RollbackActions {
            agent,
            since,
            reason: reason.into(),
        }
    }

    /// Get the reason for this emergency action.
    pub fn reason(&self) -> &str {
        match self {
            EmergencyAction::SuspendAgent { reason, .. } => reason,
            EmergencyAction::RevokeAgent { reason, .. } => reason,
            EmergencyAction::TerminateSession { reason, .. } => reason,
            EmergencyAction::RevokeCapability { reason, .. } => reason,
            EmergencyAction::BlockResource { reason, .. } => reason,
            EmergencyAction::GlobalPause { reason, .. } => reason,
            EmergencyAction::RollbackActions { reason, .. } => reason,
        }
    }

    /// Check if this action affects a specific agent.
    pub fn affects_agent(&self, agent: &PublicKey) -> bool {
        match self {
            EmergencyAction::SuspendAgent { agent: a, .. } => a == agent,
            EmergencyAction::RevokeAgent { agent: a, .. } => a == agent,
            EmergencyAction::BlockResource { blocked_actors, .. } => blocked_actors.contains(agent),
            EmergencyAction::GlobalPause { exceptions, .. } => !exceptions.contains(agent),
            EmergencyAction::RollbackActions { agent: a, .. } => a == agent,
            _ => false,
        }
    }

    /// Check if this is a permanent action (no duration/indefinite).
    pub fn is_permanent(&self) -> bool {
        match self {
            EmergencyAction::SuspendAgent { duration, .. } => duration.is_none(),
            EmergencyAction::RevokeAgent { .. } => true,
            EmergencyAction::TerminateSession { .. } => true,
            EmergencyAction::RevokeCapability { .. } => true,
            EmergencyAction::BlockResource { duration, .. } => duration.is_none(),
            EmergencyAction::GlobalPause { .. } => false, // Always has duration
            EmergencyAction::RollbackActions { .. } => true,
        }
    }
}

/// Scope of a suspension.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum SuspensionScope {
    /// All actions suspended.
    Full,
    /// Only specific capabilities suspended.
    Capabilities(Vec<CapabilityKind>),
    /// Only specific resources blocked.
    Resources(Vec<ResourceId>),
}

impl Default for SuspensionScope {
    fn default() -> Self {
        Self::Full
    }
}

impl SuspensionScope {
    /// Create a full suspension.
    pub fn full() -> Self {
        Self::Full
    }

    /// Create a capability-limited suspension.
    pub fn capabilities(capabilities: Vec<CapabilityKind>) -> Self {
        Self::Capabilities(capabilities)
    }

    /// Create a resource-limited suspension.
    pub fn resources(resources: Vec<ResourceId>) -> Self {
        Self::Resources(resources)
    }

    /// Check if this scope includes a capability.
    pub fn includes_capability(&self, capability: &CapabilityKind) -> bool {
        match self {
            SuspensionScope::Full => true,
            SuspensionScope::Capabilities(caps) => caps.contains(capability),
            SuspensionScope::Resources(_) => false,
        }
    }

    /// Check if this scope includes a resource.
    pub fn includes_resource(&self, resource: &ResourceId) -> bool {
        match self {
            SuspensionScope::Full => true,
            SuspensionScope::Capabilities(_) => false,
            SuspensionScope::Resources(resources) => resources.contains(resource),
        }
    }
}

/// Priority level of an emergency.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EmergencyPriority {
    /// Respond within hours.
    Low,
    /// Respond within minutes.
    Medium,
    /// Respond immediately.
    High,
    /// Stop everything now.
    Critical,
}

impl EmergencyPriority {
    /// Get the expected response time in milliseconds.
    pub fn expected_response_ms(&self) -> i64 {
        match self {
            EmergencyPriority::Low => 60 * 60 * 1000,   // 1 hour
            EmergencyPriority::Medium => 5 * 60 * 1000, // 5 minutes
            EmergencyPriority::High => 60 * 1000,       // 1 minute
            EmergencyPriority::Critical => 10 * 1000,   // 10 seconds
        }
    }
}

impl std::fmt::Display for EmergencyPriority {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EmergencyPriority::Low => write!(f, "low"),
            EmergencyPriority::Medium => write!(f, "medium"),
            EmergencyPriority::High => write!(f, "high"),
            EmergencyPriority::Critical => write!(f, "critical"),
        }
    }
}

/// Event recording an emergency action.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmergencyEvent {
    /// The emergency action taken.
    action: EmergencyAction,
    /// Who initiated the emergency action.
    initiator: PrincipalId,
    /// Priority level of the emergency.
    priority: EmergencyPriority,
    /// Evidence triggering the emergency.
    trigger_evidence: Vec<EventId>,
    /// When the emergency was declared (Unix timestamp ms).
    declared_at: i64,
    /// Expected resolution time (Unix timestamp ms).
    expected_resolution: Option<i64>,
    /// Notification list.
    notify: Vec<PrincipalId>,
}

impl EmergencyEvent {
    /// Create a new emergency event builder.
    pub fn builder() -> EmergencyEventBuilder {
        EmergencyEventBuilder::new()
    }

    /// Get the action.
    pub fn action(&self) -> &EmergencyAction {
        &self.action
    }

    /// Get the initiator.
    pub fn initiator(&self) -> &PrincipalId {
        &self.initiator
    }

    /// Get the priority.
    pub fn priority(&self) -> EmergencyPriority {
        self.priority
    }

    /// Get the trigger evidence.
    pub fn trigger_evidence(&self) -> &[EventId] {
        &self.trigger_evidence
    }

    /// Get the declaration time.
    pub fn declared_at(&self) -> i64 {
        self.declared_at
    }

    /// Get the expected resolution time.
    pub fn expected_resolution(&self) -> Option<i64> {
        self.expected_resolution
    }

    /// Get the notification list.
    pub fn notify(&self) -> &[PrincipalId] {
        &self.notify
    }

    /// Check if this emergency requires immediate response.
    pub fn is_critical(&self) -> bool {
        self.priority == EmergencyPriority::Critical
    }

    /// Check if the expected response time has passed.
    pub fn is_overdue(&self) -> bool {
        let now = chrono::Utc::now().timestamp_millis();
        let deadline = self.declared_at + self.priority.expected_response_ms();
        now > deadline
    }
}

/// Builder for EmergencyEvent.
#[derive(Debug, Default)]
pub struct EmergencyEventBuilder {
    action: Option<EmergencyAction>,
    initiator: Option<PrincipalId>,
    priority: Option<EmergencyPriority>,
    trigger_evidence: Vec<EventId>,
    declared_at: Option<i64>,
    expected_resolution: Option<i64>,
    notify: Vec<PrincipalId>,
}

impl EmergencyEventBuilder {
    /// Create a new builder.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the action.
    pub fn action(mut self, action: EmergencyAction) -> Self {
        self.action = Some(action);
        self
    }

    /// Set the initiator.
    pub fn initiator(mut self, initiator: PrincipalId) -> Self {
        self.initiator = Some(initiator);
        self
    }

    /// Set the priority.
    pub fn priority(mut self, priority: EmergencyPriority) -> Self {
        self.priority = Some(priority);
        self
    }

    /// Add trigger evidence.
    pub fn trigger_evidence(mut self, evidence: EventId) -> Self {
        self.trigger_evidence.push(evidence);
        self
    }

    /// Set the declaration time.
    pub fn declared_at(mut self, timestamp: i64) -> Self {
        self.declared_at = Some(timestamp);
        self
    }

    /// Set declared to now.
    pub fn declared_now(mut self) -> Self {
        self.declared_at = Some(chrono::Utc::now().timestamp_millis());
        self
    }

    /// Set the expected resolution time.
    pub fn expected_resolution(mut self, timestamp: i64) -> Self {
        self.expected_resolution = Some(timestamp);
        self
    }

    /// Add a principal to notify.
    pub fn notify(mut self, principal: PrincipalId) -> Self {
        self.notify.push(principal);
        self
    }

    /// Build the emergency event.
    pub fn build(self) -> Result<EmergencyEvent> {
        let action = self
            .action
            .ok_or_else(|| Error::invalid_input("action is required"))?;
        let initiator = self
            .initiator
            .ok_or_else(|| Error::invalid_input("initiator is required"))?;
        let priority = self.priority.unwrap_or(EmergencyPriority::High);
        let declared_at = self
            .declared_at
            .unwrap_or_else(|| chrono::Utc::now().timestamp_millis());

        Ok(EmergencyEvent {
            action,
            initiator,
            priority,
            trigger_evidence: self.trigger_evidence,
            declared_at,
            expected_resolution: self.expected_resolution,
            notify: self.notify,
        })
    }
}

/// Resolution of an emergency.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmergencyResolution {
    /// The emergency event being resolved.
    emergency_event_id: EventId,
    /// Resolution action.
    resolution: Resolution,
    /// Who resolved it.
    resolver: PrincipalId,
    /// When it was resolved (Unix timestamp ms).
    resolved_at: i64,
    /// Post-mortem analysis.
    post_mortem: Option<PostMortem>,
}

impl EmergencyResolution {
    /// Create a new resolution.
    pub fn new(emergency_event_id: EventId, resolution: Resolution, resolver: PrincipalId) -> Self {
        Self {
            emergency_event_id,
            resolution,
            resolver,
            resolved_at: chrono::Utc::now().timestamp_millis(),
            post_mortem: None,
        }
    }

    /// Add a post-mortem.
    pub fn with_post_mortem(mut self, post_mortem: PostMortem) -> Self {
        self.post_mortem = Some(post_mortem);
        self
    }

    /// Set the resolution time.
    pub fn with_resolved_at(mut self, timestamp: i64) -> Self {
        self.resolved_at = timestamp;
        self
    }

    /// Get the emergency event ID.
    pub fn emergency_event_id(&self) -> EventId {
        self.emergency_event_id
    }

    /// Get the resolution.
    pub fn resolution(&self) -> &Resolution {
        &self.resolution
    }

    /// Get the resolver.
    pub fn resolver(&self) -> &PrincipalId {
        &self.resolver
    }

    /// Get the resolution time.
    pub fn resolved_at(&self) -> i64 {
        self.resolved_at
    }

    /// Get the post-mortem.
    pub fn post_mortem(&self) -> Option<&PostMortem> {
        self.post_mortem.as_ref()
    }

    /// Check if this resolution indicates the emergency was a false alarm.
    pub fn is_false_alarm(&self) -> bool {
        matches!(self.resolution, Resolution::FalseAlarm { .. })
    }

    /// Check if restrictions are still active.
    pub fn has_active_restrictions(&self) -> bool {
        matches!(self.resolution, Resolution::RestrictionsActive { .. })
    }
}

/// Resolution action for an emergency.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Resolution {
    /// Emergency was false alarm.
    FalseAlarm {
        /// Explanation of why it was a false alarm.
        explanation: String,
    },
    /// Issue was fixed.
    Fixed {
        /// Description of the fix.
        fix_description: String,
    },
    /// Agent was permanently removed.
    AgentRemoved,
    /// Restrictions remain in place.
    RestrictionsActive {
        /// When restrictions will be reviewed (Unix timestamp ms).
        review_date: i64,
    },
    /// Escalated to external authority.
    Escalated {
        /// Authority to which it was escalated.
        authority: String,
    },
}

impl Resolution {
    /// Create a false alarm resolution.
    pub fn false_alarm(explanation: impl Into<String>) -> Self {
        Self::FalseAlarm {
            explanation: explanation.into(),
        }
    }

    /// Create a fixed resolution.
    pub fn fixed(fix_description: impl Into<String>) -> Self {
        Self::Fixed {
            fix_description: fix_description.into(),
        }
    }

    /// Create an agent removed resolution.
    pub fn agent_removed() -> Self {
        Self::AgentRemoved
    }

    /// Create a restrictions active resolution.
    pub fn restrictions_active(review_date: i64) -> Self {
        Self::RestrictionsActive { review_date }
    }

    /// Create an escalated resolution.
    pub fn escalated(authority: impl Into<String>) -> Self {
        Self::Escalated {
            authority: authority.into(),
        }
    }
}

/// Post-mortem analysis of an emergency.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PostMortem {
    /// What happened.
    summary: String,
    /// Root cause.
    root_cause: String,
    /// Impact assessment.
    impact: String,
    /// Actions taken.
    actions_taken: Vec<String>,
    /// Preventive measures.
    prevention: Vec<String>,
    /// Lessons learned.
    lessons: Vec<String>,
}

impl PostMortem {
    /// Create a new post-mortem.
    pub fn new(
        summary: impl Into<String>,
        root_cause: impl Into<String>,
        impact: impl Into<String>,
    ) -> Self {
        Self {
            summary: summary.into(),
            root_cause: root_cause.into(),
            impact: impact.into(),
            actions_taken: Vec::new(),
            prevention: Vec::new(),
            lessons: Vec::new(),
        }
    }

    /// Add an action taken.
    pub fn with_action_taken(mut self, action: impl Into<String>) -> Self {
        self.actions_taken.push(action.into());
        self
    }

    /// Add a preventive measure.
    pub fn with_prevention(mut self, measure: impl Into<String>) -> Self {
        self.prevention.push(measure.into());
        self
    }

    /// Add a lesson learned.
    pub fn with_lesson(mut self, lesson: impl Into<String>) -> Self {
        self.lessons.push(lesson.into());
        self
    }

    /// Get the summary.
    pub fn summary(&self) -> &str {
        &self.summary
    }

    /// Get the root cause.
    pub fn root_cause(&self) -> &str {
        &self.root_cause
    }

    /// Get the impact.
    pub fn impact(&self) -> &str {
        &self.impact
    }

    /// Get the actions taken.
    pub fn actions_taken(&self) -> &[String] {
        &self.actions_taken
    }

    /// Get the preventive measures.
    pub fn prevention(&self) -> &[String] {
        &self.prevention
    }

    /// Get the lessons learned.
    pub fn lessons(&self) -> &[String] {
        &self.lessons
    }
}

/// Trigger for automatic emergency actions.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum EmergencyTrigger {
    /// Agent exceeded rate limits excessively.
    RateLimitViolation {
        /// Factor by which rate limit was exceeded.
        factor: f64,
    },
    /// Agent attempted unauthorized action.
    AuthorizationViolation {
        /// Number of unauthorized attempts.
        attempts: u32,
    },
    /// Agent's attestation expired or revoked.
    AttestationInvalid,
    /// Agent acting outside session bounds.
    SessionViolation,
    /// Anomalous behavior detected.
    AnomalyDetected {
        /// Type of anomaly.
        anomaly_type: String,
        /// Anomaly score (higher = more anomalous).
        score: f64,
    },
    /// Human reported issue.
    HumanReport {
        /// Principal who reported the issue.
        reporter: PrincipalId,
    },
    /// External threat intelligence.
    ThreatIntelligence {
        /// Source of the intelligence.
        source: String,
        /// Threat identifier.
        threat_id: String,
    },
}

impl EmergencyTrigger {
    /// Create a rate limit violation trigger.
    pub fn rate_limit_violation(factor: f64) -> Self {
        Self::RateLimitViolation { factor }
    }

    /// Create an authorization violation trigger.
    pub fn authorization_violation(attempts: u32) -> Self {
        Self::AuthorizationViolation { attempts }
    }

    /// Create an attestation invalid trigger.
    pub fn attestation_invalid() -> Self {
        Self::AttestationInvalid
    }

    /// Create a session violation trigger.
    pub fn session_violation() -> Self {
        Self::SessionViolation
    }

    /// Create an anomaly detected trigger.
    pub fn anomaly_detected(anomaly_type: impl Into<String>, score: f64) -> Self {
        Self::AnomalyDetected {
            anomaly_type: anomaly_type.into(),
            score,
        }
    }

    /// Create a human report trigger.
    pub fn human_report(reporter: PrincipalId) -> Self {
        Self::HumanReport { reporter }
    }

    /// Create a threat intelligence trigger.
    pub fn threat_intelligence(source: impl Into<String>, threat_id: impl Into<String>) -> Self {
        Self::ThreatIntelligence {
            source: source.into(),
            threat_id: threat_id.into(),
        }
    }

    /// Get the recommended priority for this trigger.
    pub fn recommended_priority(&self) -> EmergencyPriority {
        match self {
            EmergencyTrigger::RateLimitViolation { factor } => {
                if *factor >= 10.0 {
                    EmergencyPriority::Critical
                } else if *factor >= 5.0 {
                    EmergencyPriority::High
                } else {
                    EmergencyPriority::Medium
                }
            }
            EmergencyTrigger::AuthorizationViolation { attempts } => {
                if *attempts >= 10 {
                    EmergencyPriority::Critical
                } else if *attempts >= 5 {
                    EmergencyPriority::High
                } else {
                    EmergencyPriority::Medium
                }
            }
            EmergencyTrigger::AttestationInvalid => EmergencyPriority::High,
            EmergencyTrigger::SessionViolation => EmergencyPriority::High,
            EmergencyTrigger::AnomalyDetected { score, .. } => {
                if *score >= 0.9 {
                    EmergencyPriority::Critical
                } else if *score >= 0.7 {
                    EmergencyPriority::High
                } else {
                    EmergencyPriority::Medium
                }
            }
            EmergencyTrigger::HumanReport { .. } => EmergencyPriority::High,
            EmergencyTrigger::ThreatIntelligence { .. } => EmergencyPriority::Critical,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{hash, SecretKey};
    use crate::event::ResourceKind;

    fn test_key() -> SecretKey {
        SecretKey::generate()
    }

    fn test_event_id() -> EventId {
        EventId(hash(b"test-event"))
    }

    fn test_principal() -> PrincipalId {
        PrincipalId::user("admin@example.com").unwrap()
    }

    fn test_session_id() -> SessionId {
        SessionId::random()
    }

    fn test_capability_id() -> CapabilityId {
        CapabilityId::generate()
    }

    fn test_resource_id() -> ResourceId {
        ResourceId::new(ResourceKind::File, "/tmp/test.txt")
    }

    // === EmergencyAction Tests ===

    #[test]
    fn suspend_agent_action() {
        let key = test_key();
        let action = EmergencyAction::suspend_agent(
            key.public_key(),
            "Suspicious behavior",
            Some(3600000),
            SuspensionScope::Full,
        );
        assert_eq!(action.reason(), "Suspicious behavior");
        assert!(action.affects_agent(&key.public_key()));
        assert!(!action.is_permanent());
    }

    #[test]
    fn revoke_agent_action() {
        let key = test_key();
        let action = EmergencyAction::revoke_agent(key.public_key(), "Malicious activity");
        assert!(action.is_permanent());
    }

    #[test]
    fn terminate_session_action() {
        let action = EmergencyAction::terminate_session(test_session_id(), "Session compromised");
        assert!(action.is_permanent());
    }

    #[test]
    fn revoke_capability_action() {
        let action = EmergencyAction::revoke_capability(test_capability_id(), "Capability abused");
        assert!(action.is_permanent());
    }

    #[test]
    fn block_resource_action() {
        let key = test_key();
        let action = EmergencyAction::block_resource(
            test_resource_id(),
            vec![key.public_key()],
            "Resource at risk",
            None,
        );
        assert!(action.is_permanent());
        assert!(action.affects_agent(&key.public_key()));
    }

    #[test]
    fn global_pause_action() {
        let key = test_key();
        let other_key = test_key();
        let action = EmergencyAction::global_pause(
            "System maintenance",
            3600000,
            vec![key.public_key()], // key is exempt
        );
        assert!(!action.is_permanent());
        assert!(!action.affects_agent(&key.public_key())); // exempt
        assert!(action.affects_agent(&other_key.public_key())); // not exempt
    }

    #[test]
    fn rollback_actions_action() {
        let key = test_key();
        let action = EmergencyAction::rollback_actions(key.public_key(), 1000, "Undo damage");
        assert!(action.is_permanent());
    }

    // === SuspensionScope Tests ===

    #[test]
    fn suspension_scope_full() {
        let scope = SuspensionScope::full();
        assert!(scope.includes_capability(&CapabilityKind::Read));
        assert!(scope.includes_resource(&test_resource_id()));
    }

    #[test]
    fn suspension_scope_capabilities() {
        let scope =
            SuspensionScope::capabilities(vec![CapabilityKind::Read, CapabilityKind::Write]);
        assert!(scope.includes_capability(&CapabilityKind::Read));
        assert!(!scope.includes_capability(&CapabilityKind::Execute));
        assert!(!scope.includes_resource(&test_resource_id()));
    }

    #[test]
    fn suspension_scope_resources() {
        let resource = test_resource_id();
        let scope = SuspensionScope::resources(vec![resource.clone()]);
        assert!(scope.includes_resource(&resource));
        assert!(!scope.includes_capability(&CapabilityKind::Read));
    }

    // === EmergencyPriority Tests ===

    #[test]
    fn priority_ordering() {
        assert!(EmergencyPriority::Low < EmergencyPriority::Medium);
        assert!(EmergencyPriority::Medium < EmergencyPriority::High);
        assert!(EmergencyPriority::High < EmergencyPriority::Critical);
    }

    #[test]
    fn priority_response_times() {
        assert!(
            EmergencyPriority::Critical.expected_response_ms()
                < EmergencyPriority::High.expected_response_ms()
        );
        assert!(
            EmergencyPriority::High.expected_response_ms()
                < EmergencyPriority::Medium.expected_response_ms()
        );
        assert!(
            EmergencyPriority::Medium.expected_response_ms()
                < EmergencyPriority::Low.expected_response_ms()
        );
    }

    // === EmergencyEvent Tests ===

    #[test]
    fn emergency_event_build() {
        let key = test_key();
        let event = EmergencyEvent::builder()
            .action(EmergencyAction::suspend_agent(
                key.public_key(),
                "Test",
                None,
                SuspensionScope::Full,
            ))
            .initiator(test_principal())
            .priority(EmergencyPriority::High)
            .declared_now()
            .build()
            .unwrap();

        assert_eq!(event.priority(), EmergencyPriority::High);
        assert!(!event.is_critical());
    }

    #[test]
    fn emergency_event_critical() {
        let key = test_key();
        let event = EmergencyEvent::builder()
            .action(EmergencyAction::revoke_agent(key.public_key(), "Malicious"))
            .initiator(test_principal())
            .priority(EmergencyPriority::Critical)
            .declared_now()
            .build()
            .unwrap();

        assert!(event.is_critical());
    }

    #[test]
    fn emergency_event_requires_action() {
        let result = EmergencyEvent::builder()
            .initiator(test_principal())
            .build();
        assert!(result.is_err());
    }

    #[test]
    fn emergency_event_requires_initiator() {
        let key = test_key();
        let result = EmergencyEvent::builder()
            .action(EmergencyAction::revoke_agent(key.public_key(), "Test"))
            .build();
        assert!(result.is_err());
    }

    // === EmergencyResolution Tests ===

    #[test]
    fn resolution_false_alarm() {
        let resolution = EmergencyResolution::new(
            test_event_id(),
            Resolution::false_alarm("Misconfigured alert"),
            test_principal(),
        );
        assert!(resolution.is_false_alarm());
        assert!(!resolution.has_active_restrictions());
    }

    #[test]
    fn resolution_fixed() {
        let resolution = EmergencyResolution::new(
            test_event_id(),
            Resolution::fixed("Patched vulnerability"),
            test_principal(),
        );
        assert!(!resolution.is_false_alarm());
    }

    #[test]
    fn resolution_with_post_mortem() {
        let post_mortem = PostMortem::new(
            "Agent exceeded rate limits",
            "Misconfigured retry logic",
            "Minor service degradation",
        )
        .with_action_taken("Disabled agent")
        .with_prevention("Add rate limiting at client level")
        .with_lesson("Monitor retry patterns");

        let resolution = EmergencyResolution::new(
            test_event_id(),
            Resolution::fixed("Fixed retry logic"),
            test_principal(),
        )
        .with_post_mortem(post_mortem);

        assert!(resolution.post_mortem().is_some());
        let pm = resolution.post_mortem().unwrap();
        assert_eq!(pm.actions_taken().len(), 1);
        assert_eq!(pm.prevention().len(), 1);
        assert_eq!(pm.lessons().len(), 1);
    }

    #[test]
    fn resolution_restrictions_active() {
        let review_date = chrono::Utc::now().timestamp_millis() + 86400000; // Tomorrow
        let resolution = EmergencyResolution::new(
            test_event_id(),
            Resolution::restrictions_active(review_date),
            test_principal(),
        );
        assert!(resolution.has_active_restrictions());
    }

    // === EmergencyTrigger Tests ===

    #[test]
    fn trigger_rate_limit_priority() {
        let low = EmergencyTrigger::rate_limit_violation(2.0);
        assert_eq!(low.recommended_priority(), EmergencyPriority::Medium);

        let high = EmergencyTrigger::rate_limit_violation(5.0);
        assert_eq!(high.recommended_priority(), EmergencyPriority::High);

        let critical = EmergencyTrigger::rate_limit_violation(10.0);
        assert_eq!(critical.recommended_priority(), EmergencyPriority::Critical);
    }

    #[test]
    fn trigger_authorization_violation_priority() {
        let low = EmergencyTrigger::authorization_violation(2);
        assert_eq!(low.recommended_priority(), EmergencyPriority::Medium);

        let high = EmergencyTrigger::authorization_violation(5);
        assert_eq!(high.recommended_priority(), EmergencyPriority::High);

        let critical = EmergencyTrigger::authorization_violation(10);
        assert_eq!(critical.recommended_priority(), EmergencyPriority::Critical);
    }

    #[test]
    fn trigger_anomaly_priority() {
        let medium = EmergencyTrigger::anomaly_detected("unusual_pattern", 0.5);
        assert_eq!(medium.recommended_priority(), EmergencyPriority::Medium);

        let high = EmergencyTrigger::anomaly_detected("unusual_pattern", 0.7);
        assert_eq!(high.recommended_priority(), EmergencyPriority::High);

        let critical = EmergencyTrigger::anomaly_detected("unusual_pattern", 0.9);
        assert_eq!(critical.recommended_priority(), EmergencyPriority::Critical);
    }

    #[test]
    fn trigger_threat_intelligence_always_critical() {
        let trigger = EmergencyTrigger::threat_intelligence("threat-feed", "CVE-2024-1234");
        assert_eq!(trigger.recommended_priority(), EmergencyPriority::Critical);
    }

    #[test]
    fn trigger_human_report() {
        let trigger = EmergencyTrigger::human_report(test_principal());
        assert_eq!(trigger.recommended_priority(), EmergencyPriority::High);
    }

    // === Builder Error Type Consistency Tests (Finding 5.1) ===

    #[test]
    fn emergency_event_build_error_is_crate_error() {
        let result = EmergencyEvent::builder()
            .initiator(test_principal())
            .build();

        // Should return crate::error::Error, not &'static str
        let err: crate::error::Error = result.unwrap_err();
        assert!(err.to_string().contains("action"));
    }
}
