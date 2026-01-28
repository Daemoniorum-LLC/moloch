//! Human-in-the-Loop (HITL) protocol types.
//!
//! The HITL protocol ensures human oversight of agent actions. It answers:
//! "Did a human approve this?" and "Can a human intervene?"

use serde::{Deserialize, Serialize};
use std::time::Duration;

use crate::crypto::{Hash, PublicKey, Sig};
use crate::error::{Error, Result};
use crate::event::{EventId, ResourceId};

use super::capability::{CapabilityId, ResourceScope};
use super::causality::CausalContext;
use super::principal::PrincipalId;

/// Unique approval request identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ApprovalRequestId(pub [u8; 16]);

impl ApprovalRequestId {
    /// Generate a new random approval request ID.
    pub fn generate() -> Self {
        use rand::RngCore;
        let mut bytes = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut bytes);
        Self(bytes)
    }

    /// Create from bytes.
    pub fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    /// Get the bytes.
    pub fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }

    /// Convert to hex string.
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    /// Parse from hex string.
    pub fn from_hex(s: &str) -> Result<Self> {
        let bytes = hex::decode(s).map_err(|_| Error::invalid_input("invalid hex"))?;
        if bytes.len() != 16 {
            return Err(Error::invalid_input("approval request ID must be 16 bytes"));
        }
        let mut arr = [0u8; 16];
        arr.copy_from_slice(&bytes);
        Ok(Self(arr))
    }
}

impl std::fmt::Display for ApprovalRequestId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

/// Severity level for impact assessment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    /// Informational, easily reversible.
    Low,
    /// Moderate impact, reversible with effort.
    Medium,
    /// Significant impact, difficult to reverse.
    High,
    /// Irreversible or high-stakes.
    Critical,
}

impl Severity {
    /// Check if this severity requires approval.
    pub fn requires_approval(&self) -> bool {
        matches!(self, Severity::High | Severity::Critical)
    }

    /// Get the numeric level (for comparison).
    pub fn level(&self) -> u8 {
        match self {
            Severity::Low => 1,
            Severity::Medium => 2,
            Severity::High => 3,
            Severity::Critical => 4,
        }
    }
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Severity::Low => write!(f, "low"),
            Severity::Medium => write!(f, "medium"),
            Severity::High => write!(f, "high"),
            Severity::Critical => write!(f, "critical"),
        }
    }
}

/// Cost representation for impact assessment.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Cost {
    /// Amount in smallest unit (e.g., cents).
    pub amount: u64,
    /// Currency code (e.g., "USD").
    pub currency: String,
}

impl Cost {
    /// Create a new cost.
    pub fn new(amount: u64, currency: impl Into<String>) -> Self {
        Self {
            amount,
            currency: currency.into(),
        }
    }
}

/// Assessment of action impact.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImpactAssessment {
    /// Severity level.
    severity: Severity,
    /// Affected resources.
    affected_resources: Vec<ResourceId>,
    /// Estimated cost (if applicable).
    estimated_cost: Option<Cost>,
    /// Risk factors.
    risks: Vec<String>,
}

impl ImpactAssessment {
    /// Create a new impact assessment.
    pub fn new(severity: Severity) -> Self {
        Self {
            severity,
            affected_resources: Vec::new(),
            estimated_cost: None,
            risks: Vec::new(),
        }
    }

    /// Create a low severity assessment.
    pub fn low() -> Self {
        Self::new(Severity::Low)
    }

    /// Create a medium severity assessment.
    pub fn medium() -> Self {
        Self::new(Severity::Medium)
    }

    /// Create a high severity assessment.
    pub fn high() -> Self {
        Self::new(Severity::High)
    }

    /// Create a critical severity assessment.
    pub fn critical() -> Self {
        Self::new(Severity::Critical)
    }

    /// Add an affected resource.
    pub fn with_resource(mut self, resource: ResourceId) -> Self {
        self.affected_resources.push(resource);
        self
    }

    /// Add affected resources.
    pub fn with_resources(mut self, resources: Vec<ResourceId>) -> Self {
        self.affected_resources = resources;
        self
    }

    /// Set estimated cost.
    pub fn with_cost(mut self, cost: Cost) -> Self {
        self.estimated_cost = Some(cost);
        self
    }

    /// Add a risk factor.
    pub fn with_risk(mut self, risk: impl Into<String>) -> Self {
        self.risks.push(risk.into());
        self
    }

    /// Get the severity.
    pub fn severity(&self) -> Severity {
        self.severity
    }

    /// Get the affected resources.
    pub fn affected_resources(&self) -> &[ResourceId] {
        &self.affected_resources
    }

    /// Get the estimated cost.
    pub fn estimated_cost(&self) -> Option<&Cost> {
        self.estimated_cost.as_ref()
    }

    /// Get the risks.
    pub fn risks(&self) -> &[String] {
        &self.risks
    }

    /// Check if this assessment requires approval.
    pub fn requires_approval(&self) -> bool {
        self.severity.requires_approval()
    }
}

/// The action being proposed for approval.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProposedAction {
    /// What the agent wants to do.
    action_type: String,
    /// Target resource.
    resource: ResourceId,
    /// Action parameters.
    parameters: serde_json::Value,
    /// Why the agent wants to do this.
    reasoning: String,
    /// Estimated impact.
    impact: ImpactAssessment,
    /// Can this action be undone?
    reversible: bool,
}

impl ProposedAction {
    /// Create a new proposed action builder.
    pub fn builder() -> ProposedActionBuilder {
        ProposedActionBuilder::new()
    }

    /// Get the action type.
    pub fn action_type(&self) -> &str {
        &self.action_type
    }

    /// Get the target resource.
    pub fn resource(&self) -> &ResourceId {
        &self.resource
    }

    /// Get the parameters.
    pub fn parameters(&self) -> &serde_json::Value {
        &self.parameters
    }

    /// Get the reasoning.
    pub fn reasoning(&self) -> &str {
        &self.reasoning
    }

    /// Get the impact assessment.
    pub fn impact(&self) -> &ImpactAssessment {
        &self.impact
    }

    /// Check if the action is reversible.
    pub fn is_reversible(&self) -> bool {
        self.reversible
    }
}

/// Builder for ProposedAction.
#[derive(Debug, Default)]
pub struct ProposedActionBuilder {
    action_type: Option<String>,
    resource: Option<ResourceId>,
    parameters: serde_json::Value,
    reasoning: Option<String>,
    impact: Option<ImpactAssessment>,
    reversible: bool,
}

impl ProposedActionBuilder {
    /// Create a new builder.
    pub fn new() -> Self {
        Self {
            parameters: serde_json::Value::Null,
            ..Default::default()
        }
    }

    /// Set the action type.
    pub fn action_type(mut self, action_type: impl Into<String>) -> Self {
        self.action_type = Some(action_type.into());
        self
    }

    /// Set the target resource.
    pub fn resource(mut self, resource: ResourceId) -> Self {
        self.resource = Some(resource);
        self
    }

    /// Set the parameters.
    pub fn parameters(mut self, parameters: serde_json::Value) -> Self {
        self.parameters = parameters;
        self
    }

    /// Set the reasoning.
    pub fn reasoning(mut self, reasoning: impl Into<String>) -> Self {
        self.reasoning = Some(reasoning.into());
        self
    }

    /// Set the impact assessment.
    pub fn impact(mut self, impact: ImpactAssessment) -> Self {
        self.impact = Some(impact);
        self
    }

    /// Set whether the action is reversible.
    pub fn reversible(mut self, reversible: bool) -> Self {
        self.reversible = reversible;
        self
    }

    /// Build the proposed action.
    pub fn build(self) -> Result<ProposedAction> {
        let action_type = self
            .action_type
            .ok_or_else(|| Error::invalid_input("action_type is required"))?;

        let resource = self
            .resource
            .ok_or_else(|| Error::invalid_input("resource is required"))?;

        let reasoning = self
            .reasoning
            .ok_or_else(|| Error::invalid_input("reasoning is required"))?;

        let impact = self.impact.unwrap_or_else(ImpactAssessment::low);

        Ok(ProposedAction {
            action_type,
            resource,
            parameters: self.parameters,
            reasoning,
            impact,
            reversible: self.reversible,
        })
    }
}

/// Escalation policy configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EscalationPolicy {
    /// Escalate after this duration (milliseconds).
    escalate_after_ms: u64,
    /// Who to escalate to.
    escalate_to: Vec<PrincipalId>,
    /// Maximum escalation levels.
    max_escalations: u32,
}

impl EscalationPolicy {
    /// Create a new escalation policy.
    pub fn new(escalate_after: Duration, escalate_to: Vec<PrincipalId>) -> Self {
        Self {
            escalate_after_ms: escalate_after.as_millis() as u64,
            escalate_to,
            max_escalations: 3,
        }
    }

    /// Set maximum escalation levels.
    pub fn with_max_escalations(mut self, max: u32) -> Self {
        self.max_escalations = max;
        self
    }

    /// Get escalation timeout.
    pub fn escalate_after(&self) -> Duration {
        Duration::from_millis(self.escalate_after_ms)
    }

    /// Get escalation targets.
    pub fn escalate_to(&self) -> &[PrincipalId] {
        &self.escalate_to
    }

    /// Get maximum escalations.
    pub fn max_escalations(&self) -> u32 {
        self.max_escalations
    }
}

/// How approval decisions are made.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalPolicy {
    /// How many approvals needed.
    required_approvals: u32,
    /// Whether any approver can reject.
    any_can_reject: bool,
    /// Auto-approve after timeout (dangerous, use carefully).
    auto_approve_on_timeout: bool,
    /// Escalation path if no response.
    escalation: Option<EscalationPolicy>,
}

impl ApprovalPolicy {
    /// Create a new approval policy requiring one approval.
    pub fn single_approver() -> Self {
        Self {
            required_approvals: 1,
            any_can_reject: true,
            auto_approve_on_timeout: false,
            escalation: None,
        }
    }

    /// Create a policy requiring multiple approvals.
    pub fn multi_approver(required: u32) -> Self {
        Self {
            required_approvals: required,
            any_can_reject: true,
            auto_approve_on_timeout: false,
            escalation: None,
        }
    }

    /// Set whether any approver can reject.
    pub fn with_any_can_reject(mut self, can_reject: bool) -> Self {
        self.any_can_reject = can_reject;
        self
    }

    /// Enable auto-approve on timeout (use with extreme caution).
    pub fn with_auto_approve_on_timeout(mut self, auto_approve: bool) -> Self {
        self.auto_approve_on_timeout = auto_approve;
        self
    }

    /// Set escalation policy.
    pub fn with_escalation(mut self, policy: EscalationPolicy) -> Self {
        self.escalation = Some(policy);
        self
    }

    /// Get required approvals count.
    pub fn required_approvals(&self) -> u32 {
        self.required_approvals
    }

    /// Check if any approver can reject.
    pub fn any_can_reject(&self) -> bool {
        self.any_can_reject
    }

    /// Check if auto-approve on timeout is enabled.
    pub fn auto_approve_on_timeout(&self) -> bool {
        self.auto_approve_on_timeout
    }

    /// Get escalation policy.
    pub fn escalation(&self) -> Option<&EscalationPolicy> {
        self.escalation.as_ref()
    }
}

impl Default for ApprovalPolicy {
    fn default() -> Self {
        Self::single_approver()
    }
}

/// Modifications to the proposed action.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ActionModifications {
    /// Modified parameters.
    pub parameters: Option<serde_json::Value>,
    /// Additional constraints.
    pub constraints: Vec<String>,
    /// Modified scope.
    pub scope: Option<ResourceScope>,
    /// Human-provided instructions.
    pub instructions: Option<String>,
}

impl ActionModifications {
    /// Create empty modifications.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set modified parameters.
    pub fn with_parameters(mut self, params: serde_json::Value) -> Self {
        self.parameters = Some(params);
        self
    }

    /// Add a constraint.
    pub fn with_constraint(mut self, constraint: impl Into<String>) -> Self {
        self.constraints.push(constraint.into());
        self
    }

    /// Set modified scope.
    pub fn with_scope(mut self, scope: ResourceScope) -> Self {
        self.scope = Some(scope);
        self
    }

    /// Set instructions.
    pub fn with_instructions(mut self, instructions: impl Into<String>) -> Self {
        self.instructions = Some(instructions.into());
        self
    }

    /// Check if there are any modifications.
    pub fn has_modifications(&self) -> bool {
        self.parameters.is_some()
            || !self.constraints.is_empty()
            || self.scope.is_some()
            || self.instructions.is_some()
    }
}

/// Actor identifier for cancellation tracking.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum CancellationActor {
    /// Human principal.
    Principal(PrincipalId),
    /// Agent.
    Agent(PublicKey),
    /// System.
    System,
}

/// Current status of an approval request.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum ApprovalStatus {
    /// Awaiting response.
    Pending,
    /// Approved by a human.
    Approved {
        approver: PrincipalId,
        approved_at: i64,
        modifications: Option<ActionModifications>,
    },
    /// Rejected by a human.
    Rejected {
        rejector: PrincipalId,
        rejected_at: i64,
        reason: String,
    },
    /// Request expired without response.
    Expired,
    /// Escalated to higher authority.
    Escalated {
        escalated_to: Vec<PrincipalId>,
        escalated_at: i64,
        escalation_level: u32,
    },
    /// Cancelled by requestor or system.
    Cancelled { cancelled_by: CancellationActor, reason: String },
}

impl ApprovalStatus {
    /// Check if the request is pending.
    pub fn is_pending(&self) -> bool {
        matches!(self, ApprovalStatus::Pending)
    }

    /// Check if the request is approved.
    pub fn is_approved(&self) -> bool {
        matches!(self, ApprovalStatus::Approved { .. })
    }

    /// Check if the request is rejected.
    pub fn is_rejected(&self) -> bool {
        matches!(self, ApprovalStatus::Rejected { .. })
    }

    /// Check if the request is expired.
    pub fn is_expired(&self) -> bool {
        matches!(self, ApprovalStatus::Expired)
    }

    /// Check if the request is escalated.
    pub fn is_escalated(&self) -> bool {
        matches!(self, ApprovalStatus::Escalated { .. })
    }

    /// Check if the request is cancelled.
    pub fn is_cancelled(&self) -> bool {
        matches!(self, ApprovalStatus::Cancelled { .. })
    }

    /// Check if the request is resolved (no longer pending).
    pub fn is_resolved(&self) -> bool {
        !self.is_pending() && !self.is_escalated()
    }

    /// Get modifications if approved with modifications.
    pub fn modifications(&self) -> Option<&ActionModifications> {
        match self {
            ApprovalStatus::Approved { modifications, .. } => modifications.as_ref(),
            _ => None,
        }
    }
}

/// Context provided to approvers.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalContext {
    /// Causal chain leading to this request.
    pub causal_context: CausalContext,
    /// Agent's attestation hash.
    pub agent_attestation_hash: Hash,
    /// Capability being invoked.
    pub capability_id: CapabilityId,
    /// Similar past actions for reference.
    pub similar_actions: Vec<EventId>,
}

impl ApprovalContext {
    /// Create a new approval context.
    pub fn new(
        causal_context: CausalContext,
        agent_attestation_hash: Hash,
        capability_id: CapabilityId,
    ) -> Self {
        Self {
            causal_context,
            agent_attestation_hash,
            capability_id,
            similar_actions: Vec::new(),
        }
    }

    /// Add similar past actions.
    pub fn with_similar_actions(mut self, actions: Vec<EventId>) -> Self {
        self.similar_actions = actions;
        self
    }
}

/// Request for human approval of an agent action.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalRequest {
    /// Unique request identifier.
    id: ApprovalRequestId,
    /// The proposed action awaiting approval.
    proposed_action: ProposedAction,
    /// Agent requesting approval.
    requestor: PublicKey,
    /// Human(s) who can approve.
    approvers: Vec<PrincipalId>,
    /// Approval policy.
    policy: ApprovalPolicy,
    /// When the request was created (Unix timestamp ms).
    created_at: i64,
    /// When the request expires (Unix timestamp ms).
    expires_at: i64,
    /// Current status.
    status: ApprovalStatus,
    /// Context for the approver.
    context: ApprovalContext,
    /// Current escalation level.
    escalation_level: u32,
    /// Collected approvals (for multi-approval policies).
    collected_approvals: Vec<(PrincipalId, i64)>,
}

impl ApprovalRequest {
    /// Create a new approval request.
    pub fn new(
        proposed_action: ProposedAction,
        requestor: PublicKey,
        approvers: Vec<PrincipalId>,
        policy: ApprovalPolicy,
        timeout: Duration,
        context: ApprovalContext,
    ) -> Self {
        let now = chrono::Utc::now().timestamp_millis();
        Self {
            id: ApprovalRequestId::generate(),
            proposed_action,
            requestor,
            approvers,
            policy,
            created_at: now,
            expires_at: now + timeout.as_millis() as i64,
            status: ApprovalStatus::Pending,
            context,
            escalation_level: 0,
            collected_approvals: Vec::new(),
        }
    }

    /// Get the request ID.
    pub fn id(&self) -> ApprovalRequestId {
        self.id
    }

    /// Get the proposed action.
    pub fn proposed_action(&self) -> &ProposedAction {
        &self.proposed_action
    }

    /// Get the requestor.
    pub fn requestor(&self) -> &PublicKey {
        &self.requestor
    }

    /// Get the approvers.
    pub fn approvers(&self) -> &[PrincipalId] {
        &self.approvers
    }

    /// Get the policy.
    pub fn policy(&self) -> &ApprovalPolicy {
        &self.policy
    }

    /// Get when the request was created.
    pub fn created_at(&self) -> i64 {
        self.created_at
    }

    /// Get when the request expires.
    pub fn expires_at(&self) -> i64 {
        self.expires_at
    }

    /// Get the current status.
    pub fn status(&self) -> &ApprovalStatus {
        &self.status
    }

    /// Get the context.
    pub fn context(&self) -> &ApprovalContext {
        &self.context
    }

    /// Check if the request has expired.
    pub fn is_expired(&self) -> bool {
        let now = chrono::Utc::now().timestamp_millis();
        now >= self.expires_at
    }

    /// Check if the request is approved (met required approvals).
    pub fn is_approved(&self) -> bool {
        self.status.is_approved()
            || self.collected_approvals.len() >= self.policy.required_approvals as usize
    }

    /// Check if a principal can approve this request.
    pub fn can_approve(&self, principal: &PrincipalId) -> bool {
        self.approvers.contains(principal)
            && !self.collected_approvals.iter().any(|(p, _)| p == principal)
    }

    /// Apply a response to this request.
    pub fn apply_response(&mut self, response: &ApprovalResponse) -> Result<()> {
        // Verify request ID matches
        if response.request_id != self.id {
            return Err(Error::invalid_input("Response request_id does not match"));
        }

        // Check if already resolved
        if self.status.is_resolved() {
            return Err(Error::invalid_input("Request is already resolved"));
        }

        // Check if expired
        if self.is_expired() {
            self.status = ApprovalStatus::Expired;
            return Err(Error::invalid_input("Request has expired"));
        }

        // Verify responder is an approver
        if !self.can_approve(&response.responder) {
            return Err(Error::invalid_input(
                "Responder is not a valid approver for this request",
            ));
        }

        match &response.decision {
            ApprovalDecision::Approve => {
                self.collected_approvals
                    .push((response.responder.clone(), response.responded_at));

                if self.collected_approvals.len() >= self.policy.required_approvals as usize {
                    self.status = ApprovalStatus::Approved {
                        approver: response.responder.clone(),
                        approved_at: response.responded_at,
                        modifications: None,
                    };
                }
            }
            ApprovalDecision::ApproveWithModifications(mods) => {
                self.collected_approvals
                    .push((response.responder.clone(), response.responded_at));

                if self.collected_approvals.len() >= self.policy.required_approvals as usize {
                    self.status = ApprovalStatus::Approved {
                        approver: response.responder.clone(),
                        approved_at: response.responded_at,
                        modifications: Some(mods.clone()),
                    };
                }
            }
            ApprovalDecision::Reject { reason } => {
                if self.policy.any_can_reject {
                    self.status = ApprovalStatus::Rejected {
                        rejector: response.responder.clone(),
                        rejected_at: response.responded_at,
                        reason: reason.clone(),
                    };
                }
            }
            ApprovalDecision::RequestInfo { .. } => {
                // Keep pending, but record the request for info
            }
            ApprovalDecision::Defer { .. } => {
                // Keep pending, deferral handled separately
            }
        }

        Ok(())
    }

    /// Escalate the request.
    pub fn escalate(&mut self) -> Result<()> {
        let policy = self
            .policy
            .escalation
            .as_ref()
            .ok_or_else(|| Error::invalid_input("No escalation policy configured"))?;

        if self.escalation_level >= policy.max_escalations {
            return Err(Error::invalid_input("Maximum escalations reached"));
        }

        self.escalation_level += 1;
        let now = chrono::Utc::now().timestamp_millis();

        // Add escalation targets to approvers
        for target in &policy.escalate_to {
            if !self.approvers.contains(target) {
                self.approvers.push(target.clone());
            }
        }

        self.status = ApprovalStatus::Escalated {
            escalated_to: policy.escalate_to.clone(),
            escalated_at: now,
            escalation_level: self.escalation_level,
        };

        // Extend expiry
        self.expires_at = now + policy.escalate_after_ms as i64;

        Ok(())
    }

    /// Check if escalation is needed.
    pub fn needs_escalation(&self) -> bool {
        if !self.status.is_pending() {
            return false;
        }

        let policy = match &self.policy.escalation {
            Some(p) => p,
            None => return false,
        };

        if self.escalation_level >= policy.max_escalations {
            return false;
        }

        let now = chrono::Utc::now().timestamp_millis();
        let escalate_at = self.created_at + policy.escalate_after_ms as i64;

        now >= escalate_at
    }

    /// Cancel the request.
    pub fn cancel(&mut self, actor: CancellationActor, reason: impl Into<String>) {
        self.status = ApprovalStatus::Cancelled {
            cancelled_by: actor,
            reason: reason.into(),
        };
    }

    /// Mark as expired.
    pub fn mark_expired(&mut self) {
        if self.status.is_pending() {
            self.status = ApprovalStatus::Expired;
        }
    }
}

/// Decision made by an approver.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ApprovalDecision {
    /// Approve as requested.
    Approve,
    /// Approve with modifications.
    ApproveWithModifications(ActionModifications),
    /// Reject the action.
    Reject { reason: String },
    /// Request more information.
    RequestInfo { questions: Vec<String> },
    /// Defer to another approver.
    Defer { defer_to: PrincipalId },
}

impl ApprovalDecision {
    /// Create an approval.
    pub fn approve() -> Self {
        Self::Approve
    }

    /// Create an approval with modifications.
    pub fn approve_with_modifications(mods: ActionModifications) -> Self {
        Self::ApproveWithModifications(mods)
    }

    /// Create a rejection.
    pub fn reject(reason: impl Into<String>) -> Self {
        Self::Reject {
            reason: reason.into(),
        }
    }

    /// Create an info request.
    pub fn request_info(questions: Vec<String>) -> Self {
        Self::RequestInfo { questions }
    }

    /// Create a deferral.
    pub fn defer(defer_to: PrincipalId) -> Self {
        Self::Defer { defer_to }
    }

    /// Check if this is an approval (with or without modifications).
    pub fn is_approval(&self) -> bool {
        matches!(
            self,
            ApprovalDecision::Approve | ApprovalDecision::ApproveWithModifications(_)
        )
    }

    /// Check if this is a rejection.
    pub fn is_rejection(&self) -> bool {
        matches!(self, ApprovalDecision::Reject { .. })
    }
}

/// Human response to an approval request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalResponse {
    /// The request being responded to.
    pub request_id: ApprovalRequestId,
    /// The human responding.
    pub responder: PrincipalId,
    /// The decision.
    pub decision: ApprovalDecision,
    /// When the response was made (Unix timestamp ms).
    pub responded_at: i64,
    /// Signature proving human involvement.
    pub signature: Sig,
}

impl ApprovalResponse {
    /// Create a new approval response.
    pub fn new(
        request_id: ApprovalRequestId,
        responder: PrincipalId,
        decision: ApprovalDecision,
    ) -> Self {
        Self {
            request_id,
            responder,
            decision,
            responded_at: chrono::Utc::now().timestamp_millis(),
            signature: Sig::empty(),
        }
    }

    /// Sign the response.
    pub fn sign(mut self, secret_key: &crate::crypto::SecretKey) -> Self {
        let bytes = self.canonical_bytes();
        self.signature = secret_key.sign(&bytes);
        self
    }

    /// Compute canonical bytes for signing.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(&self.request_id.0);
        let responder_json = serde_json::to_vec(&self.responder).unwrap_or_default();
        data.extend_from_slice(&responder_json);
        let decision_json = serde_json::to_vec(&self.decision).unwrap_or_default();
        data.extend_from_slice(&decision_json);
        data.extend_from_slice(&self.responded_at.to_le_bytes());
        data
    }

    /// Verify the signature.
    pub fn verify_signature(&self, public_key: &PublicKey) -> Result<()> {
        let bytes = self.canonical_bytes();
        public_key
            .verify(&bytes, &self.signature)
            .map_err(|_| Error::invalid_input("Response signature verification failed"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{hash, SecretKey};
    use crate::event::ResourceKind;

    fn test_principal() -> PrincipalId {
        PrincipalId::user("alice").unwrap()
    }

    fn test_approver() -> PrincipalId {
        PrincipalId::user("bob").unwrap()
    }

    fn test_resource() -> ResourceId {
        ResourceId::new(ResourceKind::Repository, "org/repo")
    }

    fn test_context() -> ApprovalContext {
        let session_id = super::super::session::SessionId::random();
        let event_id = EventId(hash(b"event"));
        let causal = CausalContext::root(event_id, session_id, test_principal());

        ApprovalContext::new(causal, hash(b"attestation"), CapabilityId::generate())
    }

    fn test_proposed_action() -> ProposedAction {
        ProposedAction::builder()
            .action_type("delete_repository")
            .resource(test_resource())
            .reasoning("User requested deletion")
            .impact(ImpactAssessment::high())
            .reversible(false)
            .build()
            .unwrap()
    }

    // === ApprovalRequestId Tests ===

    #[test]
    fn approval_request_id_generates_unique() {
        let id1 = ApprovalRequestId::generate();
        let id2 = ApprovalRequestId::generate();
        assert_ne!(id1, id2);
    }

    #[test]
    fn approval_request_id_hex_roundtrip() {
        let id = ApprovalRequestId::generate();
        let hex = id.to_hex();
        let restored = ApprovalRequestId::from_hex(&hex).unwrap();
        assert_eq!(id, restored);
    }

    // === Severity Tests ===

    #[test]
    fn severity_requires_approval_for_high_and_critical() {
        assert!(!Severity::Low.requires_approval());
        assert!(!Severity::Medium.requires_approval());
        assert!(Severity::High.requires_approval());
        assert!(Severity::Critical.requires_approval());
    }

    #[test]
    fn severity_levels_ordered() {
        assert!(Severity::Low.level() < Severity::Medium.level());
        assert!(Severity::Medium.level() < Severity::High.level());
        assert!(Severity::High.level() < Severity::Critical.level());
    }

    // === ImpactAssessment Tests ===

    #[test]
    fn impact_assessment_requires_approval() {
        let low = ImpactAssessment::low();
        assert!(!low.requires_approval());

        let high = ImpactAssessment::high();
        assert!(high.requires_approval());
    }

    #[test]
    fn impact_assessment_with_resources_and_cost() {
        let impact = ImpactAssessment::medium()
            .with_resource(test_resource())
            .with_cost(Cost::new(1000, "USD"))
            .with_risk("Data may be lost");

        assert_eq!(impact.affected_resources().len(), 1);
        assert!(impact.estimated_cost().is_some());
        assert_eq!(impact.risks().len(), 1);
    }

    // === ProposedAction Tests ===

    #[test]
    fn proposed_action_builder_requires_fields() {
        let result = ProposedAction::builder().build();
        assert!(result.is_err());

        let result = ProposedAction::builder()
            .action_type("test")
            .resource(test_resource())
            .build();
        assert!(result.is_err()); // Missing reasoning

        let result = ProposedAction::builder()
            .action_type("test")
            .resource(test_resource())
            .reasoning("test reason")
            .build();
        assert!(result.is_ok());
    }

    // === ApprovalPolicy Tests ===

    #[test]
    fn approval_policy_single_approver() {
        let policy = ApprovalPolicy::single_approver();
        assert_eq!(policy.required_approvals(), 1);
        assert!(policy.any_can_reject());
        assert!(!policy.auto_approve_on_timeout());
    }

    #[test]
    fn approval_policy_multi_approver() {
        let policy = ApprovalPolicy::multi_approver(3);
        assert_eq!(policy.required_approvals(), 3);
    }

    // === ApprovalRequest Tests ===

    #[test]
    fn approval_request_sets_expiry() {
        let agent_key = SecretKey::generate();
        let req = ApprovalRequest::new(
            test_proposed_action(),
            agent_key.public_key(),
            vec![test_approver()],
            ApprovalPolicy::single_approver(),
            Duration::from_secs(300),
            test_context(),
        );

        assert!(req.expires_at() > req.created_at());
        assert_eq!(req.expires_at() - req.created_at(), 300 * 1000);
    }

    #[test]
    fn approval_request_status_initially_pending() {
        let agent_key = SecretKey::generate();
        let req = ApprovalRequest::new(
            test_proposed_action(),
            agent_key.public_key(),
            vec![test_approver()],
            ApprovalPolicy::single_approver(),
            Duration::from_secs(300),
            test_context(),
        );

        assert!(req.status().is_pending());
    }

    #[test]
    fn approval_request_includes_context() {
        let agent_key = SecretKey::generate();
        let context = test_context();
        let req = ApprovalRequest::new(
            test_proposed_action(),
            agent_key.public_key(),
            vec![test_approver()],
            ApprovalPolicy::single_approver(),
            Duration::from_secs(300),
            context.clone(),
        );

        assert_eq!(
            req.context().capability_id.as_bytes(),
            context.capability_id.as_bytes()
        );
    }

    #[test]
    fn expired_request_cannot_be_approved() {
        let agent_key = SecretKey::generate();
        let mut req = ApprovalRequest::new(
            test_proposed_action(),
            agent_key.public_key(),
            vec![test_approver()],
            ApprovalPolicy::single_approver(),
            Duration::from_secs(0), // Immediate expiry
            test_context(),
        );

        // Wait a tiny bit to ensure expiry
        std::thread::sleep(std::time::Duration::from_millis(10));

        let response = ApprovalResponse::new(
            req.id(),
            test_approver(),
            ApprovalDecision::approve(),
        );

        let result = req.apply_response(&response);
        assert!(result.is_err());
        assert!(req.status().is_expired());
    }

    #[test]
    fn policy_required_approvals_must_be_met() {
        let agent_key = SecretKey::generate();
        let approver1 = PrincipalId::user("approver1").unwrap();
        let approver2 = PrincipalId::user("approver2").unwrap();

        let mut req = ApprovalRequest::new(
            test_proposed_action(),
            agent_key.public_key(),
            vec![approver1.clone(), approver2.clone()],
            ApprovalPolicy::multi_approver(2),
            Duration::from_secs(300),
            test_context(),
        );

        // First approval
        let response1 = ApprovalResponse::new(req.id(), approver1, ApprovalDecision::approve());
        req.apply_response(&response1).unwrap();
        assert!(!req.is_approved());

        // Second approval
        let response2 = ApprovalResponse::new(req.id(), approver2, ApprovalDecision::approve());
        req.apply_response(&response2).unwrap();
        assert!(req.is_approved());
    }

    #[test]
    fn policy_any_can_reject() {
        let agent_key = SecretKey::generate();
        let approver1 = PrincipalId::user("approver1").unwrap();
        let approver2 = PrincipalId::user("approver2").unwrap();

        let mut req = ApprovalRequest::new(
            test_proposed_action(),
            agent_key.public_key(),
            vec![approver1.clone(), approver2],
            ApprovalPolicy::multi_approver(2).with_any_can_reject(true),
            Duration::from_secs(300),
            test_context(),
        );

        // Single rejection should reject the whole request
        let response = ApprovalResponse::new(
            req.id(),
            approver1,
            ApprovalDecision::reject("Not allowed"),
        );
        req.apply_response(&response).unwrap();
        assert!(req.status().is_rejected());
    }

    // === ApprovalResponse Tests ===

    #[test]
    fn response_must_reference_existing_request() {
        let agent_key = SecretKey::generate();
        let mut req = ApprovalRequest::new(
            test_proposed_action(),
            agent_key.public_key(),
            vec![test_approver()],
            ApprovalPolicy::single_approver(),
            Duration::from_secs(300),
            test_context(),
        );

        // Response with wrong request ID
        let wrong_id = ApprovalRequestId::generate();
        let response = ApprovalResponse::new(wrong_id, test_approver(), ApprovalDecision::approve());

        let result = req.apply_response(&response);
        assert!(result.is_err());
    }

    #[test]
    fn response_must_be_from_valid_approver() {
        let agent_key = SecretKey::generate();
        let mut req = ApprovalRequest::new(
            test_proposed_action(),
            agent_key.public_key(),
            vec![test_approver()], // Only bob can approve
            ApprovalPolicy::single_approver(),
            Duration::from_secs(300),
            test_context(),
        );

        // Response from non-approver
        let non_approver = PrincipalId::user("charlie").unwrap();
        let response =
            ApprovalResponse::new(req.id(), non_approver, ApprovalDecision::approve());

        let result = req.apply_response(&response);
        assert!(result.is_err());
    }

    #[test]
    fn response_signature_must_verify() {
        let approver_key = SecretKey::generate();
        let req_id = ApprovalRequestId::generate();

        let response = ApprovalResponse::new(req_id, test_approver(), ApprovalDecision::approve())
            .sign(&approver_key);

        // Verify with correct key
        assert!(response.verify_signature(&approver_key.public_key()).is_ok());

        // Verify with wrong key should fail
        let wrong_key = SecretKey::generate();
        assert!(response.verify_signature(&wrong_key.public_key()).is_err());
    }

    #[test]
    fn approve_with_modifications_recorded() {
        let agent_key = SecretKey::generate();
        let mut req = ApprovalRequest::new(
            test_proposed_action(),
            agent_key.public_key(),
            vec![test_approver()],
            ApprovalPolicy::single_approver(),
            Duration::from_secs(300),
            test_context(),
        );

        let mods = ActionModifications::new()
            .with_parameters(serde_json::json!({"limit": 100}))
            .with_constraint("Must complete within 1 hour");

        let response = ApprovalResponse::new(
            req.id(),
            test_approver(),
            ApprovalDecision::approve_with_modifications(mods),
        );

        req.apply_response(&response).unwrap();

        assert!(req.status().is_approved());
        let modifications = req.status().modifications().unwrap();
        assert!(modifications.parameters.is_some());
        assert_eq!(modifications.constraints.len(), 1);
    }

    // === Escalation Tests ===

    #[test]
    fn escalation_adds_escalation_targets() {
        let agent_key = SecretKey::generate();
        let supervisor = PrincipalId::user("supervisor").unwrap();

        let policy = ApprovalPolicy::single_approver().with_escalation(EscalationPolicy::new(
            Duration::from_secs(60),
            vec![supervisor.clone()],
        ));

        let mut req = ApprovalRequest::new(
            test_proposed_action(),
            agent_key.public_key(),
            vec![test_approver()],
            policy,
            Duration::from_secs(300),
            test_context(),
        );

        req.escalate().unwrap();

        assert!(req.status().is_escalated());
        assert!(req.approvers().contains(&supervisor));
    }

    #[test]
    fn max_escalations_respected() {
        let agent_key = SecretKey::generate();
        let supervisor = PrincipalId::user("supervisor").unwrap();

        let policy = ApprovalPolicy::single_approver().with_escalation(
            EscalationPolicy::new(Duration::from_secs(60), vec![supervisor]).with_max_escalations(2),
        );

        let mut req = ApprovalRequest::new(
            test_proposed_action(),
            agent_key.public_key(),
            vec![test_approver()],
            policy,
            Duration::from_secs(300),
            test_context(),
        );

        // First escalation
        assert!(req.escalate().is_ok());

        // Second escalation
        req.status = ApprovalStatus::Pending; // Reset for testing
        assert!(req.escalate().is_ok());

        // Third escalation should fail
        req.status = ApprovalStatus::Pending;
        assert!(req.escalate().is_err());
    }

    // === ActionModifications Tests ===

    #[test]
    fn action_modifications_has_modifications() {
        let empty = ActionModifications::new();
        assert!(!empty.has_modifications());

        let with_params = ActionModifications::new().with_parameters(serde_json::json!({}));
        assert!(with_params.has_modifications());

        let with_constraint = ActionModifications::new().with_constraint("test");
        assert!(with_constraint.has_modifications());
    }

    // === ApprovalDecision Tests ===

    #[test]
    fn approval_decision_is_approval() {
        assert!(ApprovalDecision::approve().is_approval());
        assert!(ApprovalDecision::approve_with_modifications(ActionModifications::new()).is_approval());
        assert!(!ApprovalDecision::reject("no").is_approval());
    }

    #[test]
    fn approval_decision_is_rejection() {
        assert!(!ApprovalDecision::approve().is_rejection());
        assert!(ApprovalDecision::reject("no").is_rejection());
    }
}
