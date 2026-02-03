# Agent Accountability Specification

**Version**: 1.0.0-draft
**Status**: Draft
**Author**: Specification derived from codebase analysis
**Date**: 2026-01-28

---

## Abstract

This specification defines the data structures, protocols, and invariants required to provide comprehensive accountability for AI agent actions within the Moloch audit chain. It addresses causality tracking, identity attestation, capability-scoped authorization, human oversight, reasoning transparency, outcome verification, emergency controls, and multi-agent coordination.

---

## Table of Contents

1. [Motivation](#1-motivation)
2. [Design Principles](#2-design-principles)
3. [Causality Chain](#3-causality-chain)
4. [Agent Identity Attestation](#4-agent-identity-attestation)
5. [Capability Model](#5-capability-model)
6. [Human-in-the-Loop Protocol](#6-human-in-the-loop-protocol)
7. [Reasoning Traces](#7-reasoning-traces)
8. [Outcome Verification](#8-outcome-verification)
9. [Emergency Controls](#9-emergency-controls)
10. [Multi-Agent Coordination](#10-multi-agent-coordination)
11. [Event Types](#11-event-types)
12. [Invariants](#12-invariants)
13. [Security Considerations](#13-security-considerations)
14. [Migration Path](#14-migration-path)

---

## 1. Motivation

AI agents increasingly perform consequential actions on behalf of humans: executing code, accessing data, making purchases, communicating with third parties. Without rigorous accountability infrastructure, we cannot answer fundamental questions:

- **Attribution**: Which agent performed this action?
- **Authorization**: Was the agent permitted to do this?
- **Causation**: What chain of events led to this action?
- **Intent**: What was the agent's reasoning?
- **Verification**: Did the action actually occur as recorded?
- **Control**: Can we stop a misbehaving agent?

The current Moloch specification provides cryptographic integrity for audit events but lacks the semantic structure required for agent-specific accountability. This specification fills those gaps.

### 1.1 Scope

This specification covers:
- Agent-initiated actions and their audit records
- Human-agent interaction points
- Agent-to-agent delegation and coordination
- Emergency intervention mechanisms

This specification does NOT cover:
- Agent implementation details (model architecture, training)
- Specific tool implementations
- Network transport for agent communication
- User interface requirements

### 1.2 Terminology

| Term | Definition |
|------|------------|
| **Agent** | An autonomous software entity capable of taking actions based on goals |
| **Principal** | A human or organization ultimately responsible for an agent's actions |
| **Capability** | A specific permission granted to an agent |
| **Session** | A bounded context in which an agent operates |
| **Attestation** | Cryptographic proof of agent state at a point in time |
| **Causality Chain** | Linked sequence of events showing cause and effect |

---

## 2. Design Principles

### 2.1 Traceability Over Convenience

Every agent action MUST be traceable to a human principal through an unbroken chain of authorization. Convenience features that break traceability are prohibited.

### 2.2 Attestation Over Trust

Agent identity MUST be bound to verifiable state, not just cryptographic keys. A valid signature is necessary but not sufficient for accountability.

### 2.3 Explicit Over Implicit

Authorization scope MUST be explicitly recorded, not inferred. Default-allow policies are prohibited for agent actions.

### 2.4 Fail-Secure

When accountability data is missing or invalid, the action MUST be treated as unauthorized. Ambiguity resolves to denial.

### 2.5 Human Supremacy

Humans MUST be able to intervene in agent actions at any time. No agent action is irrevocable without human confirmation.

---

## 3. Causality Chain

### 3.1 Purpose

The causality chain answers: "What sequence of events led to this action, and who is ultimately responsible?"

### 3.2 Data Model

#### 3.2.1 CausalContext

Every agent-initiated `AuditEvent` MUST include a `CausalContext`:

```rust
/// Context linking an event to its causal predecessors
pub struct CausalContext {
    /// The event that directly triggered this action
    /// None only for session-initiating events
    pub parent_event_id: Option<EventId>,

    /// The originating human request that started this causal chain
    /// MUST always be present for agent actions
    pub root_event_id: EventId,

    /// Session identifier for grouping related events
    pub session_id: SessionId,

    /// The human principal ultimately responsible
    pub principal: PrincipalId,

    /// Depth in the causal chain (0 = human-initiated)
    pub depth: u32,

    /// Monotonic sequence within session
    pub sequence: u64,
}

/// Unique session identifier
pub struct SessionId(pub [u8; 16]);

/// Human or organization principal
pub struct PrincipalId {
    /// Principal's public key or organizational identifier
    pub id: String,

    /// Type of principal
    pub kind: PrincipalKind,
}

pub enum PrincipalKind {
    /// Individual human user
    User,

    /// Organization (actions require member attribution)
    Organization,

    /// Service account (must have owning principal)
    ServiceAccount { owner: Box<PrincipalId> },
}
```

#### 3.2.2 Session

A session bounds the scope of agent activity:

```rust
/// A bounded context for agent operations
pub struct Session {
    /// Unique session identifier
    pub id: SessionId,

    /// Human principal who initiated the session
    pub principal: PrincipalId,

    /// When the session started
    pub started_at: Timestamp,

    /// When the session ended (None if active)
    pub ended_at: Option<Timestamp>,

    /// Maximum session duration (enforced)
    pub max_duration: Duration,

    /// Session-level capability constraints
    pub capabilities: CapabilitySet,

    /// Maximum causal depth permitted
    pub max_depth: u32,

    /// Human-readable session purpose
    pub purpose: String,
}
```

### 3.3 Causal Chain Rules

#### Rule 3.3.1: Root Requirement
Every agent action MUST have a `root_event_id` pointing to a human-initiated event.

#### Rule 3.3.2: Parent Validity
If `parent_event_id` is Some, the referenced event MUST:
- Exist in the chain
- Have `sequence < this.sequence`
- Have `depth < this.depth`
- Be in the same session OR have explicit cross-session reference

#### Rule 3.3.3: Depth Limits
`depth` MUST NOT exceed `session.max_depth`. Default max_depth is 10.

#### Rule 3.3.4: Sequence Monotonicity
Within a session, `sequence` MUST be strictly increasing.

#### Rule 3.3.5: Principal Immutability
`principal` MUST NOT change within a causal chain. Delegation creates new chains.

### 3.4 Causal Chain Queries

The system MUST support these queries efficiently:

```rust
/// Get all events caused by a specific event
fn get_descendants(event_id: EventId) -> Vec<AuditEvent>;

/// Get the causal chain from an event back to root
fn get_ancestry(event_id: EventId) -> Vec<AuditEvent>;

/// Get all events in a session
fn get_session_events(session_id: SessionId) -> Vec<AuditEvent>;

/// Get all events attributed to a principal
fn get_principal_events(principal: PrincipalId, time_range: Range<Timestamp>) -> Vec<AuditEvent>;
```

### 3.5 Causal Chain Diagram

```
Human Request (depth=0, root=self)
    │
    ├─► Agent A Action (depth=1, parent=human, root=human)
    │       │
    │       ├─► Agent A Tool Call (depth=2, parent=A.action, root=human)
    │       │       │
    │       │       └─► Tool Result (depth=3, parent=A.tool, root=human)
    │       │
    │       └─► Agent A spawns Agent B (depth=2, parent=A.action, root=human)
    │               │
    │               └─► Agent B Action (depth=3, parent=spawn, root=human)
    │
    └─► Human Approval (depth=1, parent=human, root=human)
            │
            └─► Agent A Continues (depth=2, parent=approval, root=human)
```

---

## 4. Agent Identity Attestation

### 4.1 Purpose

Agent identity attestation binds a cryptographic identity to a verifiable agent configuration. This answers: "What exactly was running when this action was taken?"

### 4.2 Data Model

#### 4.2.1 AgentAttestation

```rust
/// Cryptographic attestation of agent state
pub struct AgentAttestation {
    /// Agent's public key (identity)
    pub agent_id: PublicKey,

    /// Hash of agent's executable code or model weights
    pub code_hash: Hash,

    /// Hash of agent's configuration
    pub config_hash: Hash,

    /// Hash of system prompt / instructions
    pub prompt_hash: Hash,

    /// Available tools at time of attestation
    pub tools: Vec<ToolAttestation>,

    /// Runtime environment attestation
    pub runtime: RuntimeAttestation,

    /// When this attestation was created
    pub attested_at: Timestamp,

    /// How long this attestation is valid
    pub validity_period: Duration,

    /// Signature from attestation authority
    pub authority_signature: Sig,

    /// The authority that signed this attestation
    pub authority: PublicKey,
}

/// Attestation of a specific tool
pub struct ToolAttestation {
    /// Tool identifier
    pub tool_id: String,

    /// Tool version
    pub version: String,

    /// Hash of tool implementation
    pub implementation_hash: Hash,

    /// Tool's capability requirements
    pub required_capabilities: Vec<CapabilityKind>,
}

/// Runtime environment attestation
pub struct RuntimeAttestation {
    /// Runtime identifier (e.g., "claude-code-v1.2.3")
    pub runtime_id: String,

    /// Hash of runtime binary
    pub runtime_hash: Hash,

    /// TEE attestation if available
    pub tee_quote: Option<TeeQuote>,

    /// Platform measurements
    pub platform_hash: Option<Hash>,
}

/// Trusted Execution Environment quote
pub struct TeeQuote {
    /// TEE type (SGX, TDX, SEV-SNP, etc.)
    pub tee_type: TeeType,

    /// Raw attestation quote
    pub quote: Vec<u8>,

    /// Measurement registers
    pub measurements: Vec<Hash>,
}

pub enum TeeType {
    IntelSgx,
    IntelTdx,
    AmdSevSnp,
    ArmCca,
    Software, // For testing only
}
```

#### 4.2.2 AttestationRegistry

```rust
/// Registry of valid attestations
pub struct AttestationRegistry {
    /// Active attestations by agent ID
    attestations: HashMap<PublicKey, AgentAttestation>,

    /// Trusted attestation authorities
    authorities: HashSet<PublicKey>,

    /// Revoked attestations
    revocations: HashSet<Hash>,
}

impl AttestationRegistry {
    /// Verify an agent has a valid attestation
    pub fn verify(&self, agent_id: &PublicKey, action_time: Timestamp) -> Result<&AgentAttestation, AttestationError>;

    /// Register a new attestation
    pub fn register(&mut self, attestation: AgentAttestation) -> Result<(), AttestationError>;

    /// Revoke an attestation
    pub fn revoke(&mut self, attestation_hash: Hash, reason: String) -> Result<(), AttestationError>;
}
```

### 4.3 Attestation Rules

#### Rule 4.3.1: Attestation Requirement
Every agent action event MUST reference a valid `AgentAttestation` via `attestation_hash` in event metadata.

#### Rule 4.3.2: Attestation Validity
An attestation is valid if:
- `attested_at + validity_period > action_timestamp`
- `authority_signature` verifies against `authority`
- `authority` is in the trusted authorities set
- Attestation hash is not in revocations set

#### Rule 4.3.3: Attestation Binding
The `agent_id` in the attestation MUST match the `actor` in the `AuditEvent`.

#### Rule 4.3.4: Tool Consistency
Tools invoked by an agent MUST be listed in the agent's current attestation.

#### Rule 4.3.5: Re-attestation
Agents MUST re-attest when:
- Code or model changes
- Configuration changes
- Tools are added or removed
- Previous attestation expires

### 4.4 Attestation Authority

Attestation authorities are responsible for verifying agent state before signing attestations. Requirements for authorities:

1. **Verification Capability**: Must be able to inspect agent code/config
2. **Independence**: Must not be controlled by the agent operator
3. **Accountability**: Authority keys must be traceable to legal entities
4. **Revocation**: Must monitor for compromises and revoke promptly

### 4.5 Attestation Workflow

```
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│  Agent Runtime  │     │   Attestation   │     │    Registry     │
│                 │     │    Authority    │     │                 │
└────────┬────────┘     └────────┬────────┘     └────────┬────────┘
         │                       │                       │
         │  Request Attestation  │                       │
         │  (code_hash, config)  │                       │
         │──────────────────────►│                       │
         │                       │                       │
         │                       │──┐ Verify:            │
         │                       │  │ - Code integrity   │
         │                       │  │ - Config safety    │
         │                       │  │ - Tool permissions │
         │                       │◄─┘                    │
         │                       │                       │
         │  Signed Attestation   │                       │
         │◄──────────────────────│                       │
         │                       │                       │
         │                       │  Publish Attestation  │
         │                       │──────────────────────►│
         │                       │                       │
         │                       │                       │──┐
         │                       │                       │  │ Store and
         │                       │                       │  │ Index
         │                       │                       │◄─┘
         │                       │                       │
         │  Action with attestation_hash                 │
         │──────────────────────────────────────────────►│
         │                       │                       │
         │                       │                       │──┐
         │                       │                       │  │ Verify
         │                       │                       │  │ attestation
         │                       │                       │◄─┘
```

---

## 5. Capability Model

### 5.1 Purpose

The capability model defines what an agent is permitted to do. It answers: "Was this action within the agent's authorized scope?"

### 5.2 Data Model

#### 5.2.1 Capability

```rust
/// A specific permission granted to an agent
pub struct Capability {
    /// Unique capability identifier
    pub id: CapabilityId,

    /// What kind of capability this is
    pub kind: CapabilityKind,

    /// Resource scope (what the capability applies to)
    pub scope: ResourceScope,

    /// Constraints on the capability
    pub constraints: CapabilityConstraints,

    /// Who granted this capability
    pub grantor: PrincipalId,

    /// When this capability was granted
    pub granted_at: Timestamp,

    /// When this capability expires
    pub expires_at: Option<Timestamp>,

    /// Whether this capability can be delegated
    pub delegatable: bool,

    /// Maximum delegation depth if delegatable
    pub max_delegation_depth: u32,

    /// Signature from grantor
    pub signature: Sig,
}

pub struct CapabilityId(pub [u8; 16]);

/// Categories of capabilities
pub enum CapabilityKind {
    // Data capabilities
    Read,
    Write,
    Delete,

    // Execution capabilities
    Execute,

    // Tool capabilities
    InvokeTool { tool_id: String },

    // Agent capabilities
    SpawnAgent,
    DelegateCapability,

    // Communication capabilities
    SendMessage { channel: String },
    ReceiveMessage { channel: String },

    // Financial capabilities
    Spend { currency: String, max_amount: u64 },

    // Administrative capabilities
    ModifyPermissions,
    ViewAuditLog,
}

/// Scope of resources a capability applies to
pub enum ResourceScope {
    /// Specific resource by ID
    Specific(ResourceId),

    /// Pattern match (e.g., "repo:org/*")
    Pattern(String),

    /// All resources of a kind
    Kind(ResourceKind),

    /// All resources (dangerous, requires explicit grant)
    All,
}

/// Constraints on capability usage
pub struct CapabilityConstraints {
    /// Maximum invocations
    pub max_uses: Option<u64>,

    /// Current usage count
    pub current_uses: u64,

    /// Rate limit (invocations per period)
    pub rate_limit: Option<RateLimit>,

    /// Time windows when capability is valid
    pub time_windows: Vec<TimeWindow>,

    /// Required approval for each use
    pub requires_approval: bool,

    /// Approval timeout
    pub approval_timeout: Option<Duration>,

    /// Custom constraints as key-value pairs
    pub custom: HashMap<String, String>,
}

pub struct RateLimit {
    pub max_requests: u64,
    pub period: Duration,
}

pub struct TimeWindow {
    pub start: Time, // Time of day
    pub end: Time,
    pub days: Vec<DayOfWeek>,
    pub timezone: String,
}
```

#### 5.2.2 CapabilitySet

```rust
/// A collection of capabilities granted to an agent
pub struct CapabilitySet {
    /// The capabilities in this set
    pub capabilities: Vec<Capability>,

    /// The agent these capabilities are granted to
    pub grantee: PublicKey,

    /// Parent capability set (for delegation chains)
    pub parent: Option<CapabilitySetId>,

    /// Combined hash of all capabilities
    pub hash: Hash,
}

pub struct CapabilitySetId(pub Hash);

impl CapabilitySet {
    /// Check if an action is permitted
    pub fn permits(&self, action: &AgentAction, context: &ActionContext) -> CapabilityCheck;

    /// Get the specific capability that permits an action (if any)
    pub fn find_capability(&self, action: &AgentAction) -> Option<&Capability>;

    /// Create a delegated subset of capabilities
    pub fn delegate(&self, subset: Vec<CapabilityId>, grantee: PublicKey) -> Result<CapabilitySet, CapabilityError>;
}

pub enum CapabilityCheck {
    Permitted { capability_id: CapabilityId },
    Denied { reason: DenialReason },
    RequiresApproval { capability_id: CapabilityId, timeout: Duration },
}

pub enum DenialReason {
    NoMatchingCapability,
    Expired,
    RateLimitExceeded,
    UsageLimitExceeded,
    OutsideTimeWindow,
    ScopeViolation,
    DelegationDepthExceeded,
    Revoked,
}
```

#### 5.2.3 CapabilityGrant Event

```rust
/// Event recording a capability grant
pub struct CapabilityGrantEvent {
    /// The capability being granted
    pub capability: Capability,

    /// The agent receiving the capability
    pub grantee: PublicKey,

    /// Justification for the grant
    pub justification: String,

    /// Reference to authorization (policy, approval, etc.)
    pub authorization_ref: Option<String>,
}
```

### 5.3 Capability Rules

#### Rule 5.3.1: Explicit Grant
Agents have no capabilities by default. Every capability MUST be explicitly granted.

#### Rule 5.3.2: Grantor Authority
A capability can only be granted by a principal who possesses it (or a superset).

#### Rule 5.3.3: Delegation Limits
Delegated capabilities MUST be a subset of the delegator's capabilities.
Delegation depth MUST NOT exceed `max_delegation_depth`.

#### Rule 5.3.4: Capability Reference
Every agent action event MUST reference the `capability_id` that authorized it.

#### Rule 5.3.5: Constraint Enforcement
All capability constraints MUST be enforced at action time:
- Check `expires_at`
- Check `max_uses` and increment `current_uses`
- Check `rate_limit`
- Check `time_windows`
- If `requires_approval`, wait for approval event

#### Rule 5.3.6: Scope Strictness
Resource scope MUST be checked strictly:
- `Specific(id)` matches only that exact resource
- `Pattern(p)` uses glob matching
- `Kind(k)` matches all resources of that kind
- `All` matches everything (requires explicit grant with justification)

### 5.4 Capability Lifecycle

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│   CREATED   │────►│   ACTIVE    │────►│   EXPIRED   │
└─────────────┘     └──────┬──────┘     └─────────────┘
                           │
                           │ revoke()
                           ▼
                    ┌─────────────┐
                    │   REVOKED   │
                    └─────────────┘
```

---

## 6. Human-in-the-Loop Protocol

### 6.1 Purpose

The Human-in-the-Loop (HITL) protocol ensures human oversight of agent actions. It answers: "Did a human approve this?" and "Can a human intervene?"

### 6.2 Data Model

#### 6.2.1 ApprovalRequest

```rust
/// Request for human approval of an agent action
pub struct ApprovalRequest {
    /// Unique request identifier
    pub id: ApprovalRequestId,

    /// The proposed action awaiting approval
    pub proposed_action: ProposedAction,

    /// Agent requesting approval
    pub requestor: PublicKey,

    /// Human(s) who can approve
    pub approvers: Vec<PrincipalId>,

    /// Approval policy
    pub policy: ApprovalPolicy,

    /// When the request was created
    pub created_at: Timestamp,

    /// When the request expires
    pub expires_at: Timestamp,

    /// Current status
    pub status: ApprovalStatus,

    /// Context for the approver
    pub context: ApprovalContext,
}

pub struct ApprovalRequestId(pub [u8; 16]);

/// The action being proposed
pub struct ProposedAction {
    /// What the agent wants to do
    pub action_type: String,

    /// Target resource
    pub resource: ResourceId,

    /// Action parameters
    pub parameters: serde_json::Value,

    /// Why the agent wants to do this
    pub reasoning: String,

    /// Estimated impact
    pub impact: ImpactAssessment,

    /// Can this action be undone?
    pub reversible: bool,
}

/// Assessment of action impact
pub struct ImpactAssessment {
    /// Severity level
    pub severity: Severity,

    /// Affected resources
    pub affected_resources: Vec<ResourceId>,

    /// Estimated cost (if applicable)
    pub estimated_cost: Option<Cost>,

    /// Risk factors
    pub risks: Vec<String>,
}

pub enum Severity {
    Low,      // Informational, easily reversible
    Medium,   // Moderate impact, reversible with effort
    High,     // Significant impact, difficult to reverse
    Critical, // Irreversible or high-stakes
}

/// How approval decisions are made
pub struct ApprovalPolicy {
    /// How many approvals needed
    pub required_approvals: u32,

    /// Whether any approver can reject
    pub any_can_reject: bool,

    /// Auto-approve after timeout (dangerous, use carefully)
    pub auto_approve_on_timeout: bool,

    /// Escalation path if no response
    pub escalation: Option<EscalationPolicy>,
}

pub struct EscalationPolicy {
    /// Escalate after this duration
    pub escalate_after: Duration,

    /// Who to escalate to
    pub escalate_to: Vec<PrincipalId>,

    /// Maximum escalation levels
    pub max_escalations: u32,
}

pub enum ApprovalStatus {
    Pending,
    Approved {
        approver: PrincipalId,
        approved_at: Timestamp,
        modifications: Option<ActionModifications>,
    },
    Rejected {
        rejector: PrincipalId,
        rejected_at: Timestamp,
        reason: String,
    },
    Expired,
    Escalated {
        escalated_to: Vec<PrincipalId>,
        escalated_at: Timestamp,
    },
    Cancelled {
        cancelled_by: ActorId,
        reason: String,
    },
}

/// Context provided to approvers
pub struct ApprovalContext {
    /// Causal chain leading to this request
    pub causal_context: CausalContext,

    /// Agent's attestation
    pub agent_attestation_hash: Hash,

    /// Capability being invoked
    pub capability_id: CapabilityId,

    /// Similar past actions for reference
    pub similar_actions: Vec<EventId>,

    /// Agent's full reasoning trace
    pub reasoning_trace: Option<ReasoningTrace>,
}

/// Modifications to the proposed action
pub struct ActionModifications {
    /// Modified parameters
    pub parameters: Option<serde_json::Value>,

    /// Additional constraints
    pub constraints: Vec<String>,

    /// Modified scope
    pub scope: Option<ResourceScope>,

    /// Human-provided instructions
    pub instructions: Option<String>,
}
```

#### 6.2.2 ApprovalResponse

```rust
/// Human response to an approval request
pub struct ApprovalResponse {
    /// The request being responded to
    pub request_id: ApprovalRequestId,

    /// The human responding
    pub responder: PrincipalId,

    /// The decision
    pub decision: ApprovalDecision,

    /// When the response was made
    pub responded_at: Timestamp,

    /// Signature proving human involvement
    pub signature: Sig,
}

pub enum ApprovalDecision {
    /// Approve as requested
    Approve,

    /// Approve with modifications
    ApproveWithModifications(ActionModifications),

    /// Reject the action
    Reject { reason: String },

    /// Request more information
    RequestInfo { questions: Vec<String> },

    /// Defer to another approver
    Defer { defer_to: PrincipalId },
}
```

### 6.3 HITL Rules

#### Rule 6.3.1: Approval Triggers
Approval MUST be requested when:
- Capability has `requires_approval = true`
- Action severity is `High` or `Critical`
- Action affects resources outside normal scope
- Agent confidence is below threshold
- Cumulative session cost exceeds threshold

#### Rule 6.3.2: Approval Timeout
If no response by `expires_at`:
- If `auto_approve_on_timeout = false`: Action is denied
- If `auto_approve_on_timeout = true`: Action proceeds (MUST be explicitly configured)
- If escalation configured: Escalate before timeout

#### Rule 6.3.3: Approval Verification
Approval responses MUST:
- Be signed by the responder's key
- Reference the exact request ID
- Be recorded as an audit event before the action proceeds

#### Rule 6.3.4: Modification Binding
If approved with modifications, the agent MUST:
- Apply all modifications
- Record the modifications in the action event
- Fail if modifications cannot be applied

#### Rule 6.3.5: Rejection Handling
If rejected, the agent MUST:
- NOT proceed with the action
- Record the rejection in the audit log
- Notify the user (if interactive)
- Consider alternative approaches (with new approval request)

### 6.4 HITL Sequence

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│    Agent    │     │   Moloch    │     │  Approver   │     │    Audit    │
│             │     │             │     │   (Human)   │     │    Chain    │
└──────┬──────┘     └──────┬──────┘     └──────┬──────┘     └──────┬──────┘
       │                   │                   │                   │
       │ ProposedAction    │                   │                   │
       │ (requires approval)                   │                   │
       │──────────────────►│                   │                   │
       │                   │                   │                   │
       │                   │ Record            │                   │
       │                   │ ApprovalRequest   │                   │
       │                   │───────────────────┼──────────────────►│
       │                   │                   │                   │
       │                   │ Notify            │                   │
       │                   │──────────────────►│                   │
       │                   │                   │                   │
       │                   │                   │ Review request    │
       │                   │                   │ + context         │
       │                   │                   │                   │
       │                   │ ApprovalResponse  │                   │
       │                   │◄──────────────────│                   │
       │                   │                   │                   │
       │                   │ Record            │                   │
       │                   │ ApprovalResponse  │                   │
       │                   │───────────────────┼──────────────────►│
       │                   │                   │                   │
       │ Decision          │                   │                   │
       │◄──────────────────│                   │                   │
       │                   │                   │                   │
       │ [if approved]     │                   │                   │
       │ Execute action    │                   │                   │
       │──────────────────►│                   │                   │
       │                   │ Record            │                   │
       │                   │ ActionEvent       │                   │
       │                   │ (with approval_id)│                   │
       │                   │───────────────────┼──────────────────►│
```

### 6.5 Approval UI Requirements

While UI is out of scope for this spec, approval systems MUST provide:
1. Clear description of proposed action
2. Full reasoning trace from agent
3. Impact assessment
4. Comparison to similar past actions
5. One-click approve/reject
6. Ability to modify and approve
7. Ability to request more information
8. Timeout countdown
9. Escalation status

---

## 7. Reasoning Traces

### 7.1 Purpose

Reasoning traces capture the agent's decision-making process. They answer: "Why did the agent decide to do this?"

### 7.2 Data Model

#### 7.2.1 ReasoningTrace

```rust
/// Complete trace of agent reasoning
pub struct ReasoningTrace {
    /// Unique trace identifier
    pub id: TraceId,

    /// The goal the agent was pursuing
    pub goal: Goal,

    /// Steps in the reasoning process
    pub steps: Vec<ReasoningStep>,

    /// Final decision reached
    pub decision: Decision,

    /// Confidence in the decision
    pub confidence: Confidence,

    /// Alternative actions considered
    pub alternatives: Vec<Alternative>,

    /// Factors that influenced the decision
    pub factors: Vec<Factor>,

    /// Hash of the full trace for integrity
    pub trace_hash: Hash,
}

pub struct TraceId(pub [u8; 16]);

/// The goal driving agent behavior
pub struct Goal {
    /// Human-readable goal description
    pub description: String,

    /// Structured goal representation
    pub structured: Option<serde_json::Value>,

    /// Where this goal came from
    pub source: GoalSource,

    /// Priority level
    pub priority: Priority,
}

pub enum GoalSource {
    /// Direct user instruction
    UserInstruction { event_id: EventId },

    /// Derived from higher-level goal
    Derived { parent_goal: Box<Goal> },

    /// System-defined goal
    System { policy: String },
}

/// A single step in reasoning
pub struct ReasoningStep {
    /// Step sequence number
    pub sequence: u32,

    /// What the agent was thinking
    pub thought: String,

    /// What action was taken (if any)
    pub action: Option<StepAction>,

    /// Observation from the action
    pub observation: Option<String>,

    /// Timestamp of this step
    pub timestamp: Timestamp,
}

pub enum StepAction {
    /// Retrieved information
    Retrieve { query: String, source: String },

    /// Analyzed data
    Analyze { subject: String, method: String },

    /// Invoked a tool
    ToolCall { tool: String, input_hash: Hash },

    /// Delegated to another agent
    Delegate { agent: PublicKey, task: String },

    /// Made a decision
    Decide { decision: String },
}

/// The decision reached
pub struct Decision {
    /// What was decided
    pub action: String,

    /// Why this was chosen
    pub rationale: String,

    /// Expected outcome
    pub expected_outcome: String,

    /// How to verify success
    pub success_criteria: Vec<String>,
}

/// Confidence assessment
pub struct Confidence {
    /// Overall confidence score (0.0 - 1.0)
    pub score: f64,

    /// Confidence breakdown by factor
    pub breakdown: HashMap<String, f64>,

    /// Uncertainty sources
    pub uncertainties: Vec<String>,

    /// What would increase confidence
    pub would_help: Vec<String>,
}

/// An alternative that was considered
pub struct Alternative {
    /// Description of the alternative
    pub description: String,

    /// Why it was not chosen
    pub rejection_reason: String,

    /// Estimated outcome if chosen
    pub estimated_outcome: String,

    /// Confidence if this were chosen
    pub confidence: f64,
}

/// A factor influencing the decision
pub struct Factor {
    /// Factor description
    pub description: String,

    /// How much it influenced (positive = toward, negative = against)
    pub influence: f64,

    /// Evidence supporting this factor
    pub evidence: Vec<String>,
}
```

### 7.3 Reasoning Rules

#### Rule 7.3.1: Trace Requirement
Every agent action event with `severity >= Medium` MUST include a `ReasoningTrace`.

#### Rule 7.3.2: Trace Completeness
Reasoning traces MUST include:
- The goal being pursued
- At least one reasoning step
- The final decision
- Confidence score
- At least one alternative considered (if action is non-trivial)

#### Rule 7.3.3: Trace Integrity
The `trace_hash` MUST be computed over the canonical serialization of the trace.
The action event MUST include this hash for verification.

#### Rule 7.3.4: Trace Authenticity
Reasoning traces MUST be generated by the agent itself, not reconstructed after the fact.

#### Rule 7.3.5: Confidence Thresholds
- If `confidence.score < 0.3`: Action SHOULD be rejected or escalated
- If `confidence.score < 0.5`: Action SHOULD require approval
- If `confidence.score < 0.7`: Action SHOULD flag uncertainties to user

### 7.4 Trace Storage

Reasoning traces MAY be stored:
1. **Inline**: Full trace in event metadata (for short traces)
2. **Reference**: Hash in event, full trace in separate storage (for long traces)
3. **Encrypted**: Trace encrypted, hash in event (for sensitive reasoning)

---

## 8. Outcome Verification

### 8.1 Purpose

Outcome verification confirms that recorded actions actually occurred as described. It answers: "Did this action actually happen?"

### 8.2 Data Model

#### 8.2.1 OutcomeAttestation

```rust
/// Attestation that an action outcome occurred
pub struct OutcomeAttestation {
    /// The action event being attested
    pub action_event_id: EventId,

    /// What outcome occurred
    pub outcome: Outcome,

    /// Evidence supporting the outcome
    pub evidence: Vec<Evidence>,

    /// Who is attesting to this outcome
    pub attestor: Attestor,

    /// When the outcome was observed
    pub observed_at: Timestamp,

    /// Signature from attestor
    pub signature: Sig,
}

pub enum Outcome {
    /// Action succeeded as expected
    Success {
        result: serde_json::Value,
        result_hash: Hash,
    },

    /// Action partially succeeded
    PartialSuccess {
        completed: Vec<String>,
        failed: Vec<String>,
        result: serde_json::Value,
    },

    /// Action failed
    Failure {
        error: String,
        error_code: Option<String>,
        recoverable: bool,
    },

    /// Outcome unknown or pending
    Pending {
        expected_completion: Option<Timestamp>,
    },

    /// Action was rolled back
    RolledBack {
        rollback_reason: String,
        rollback_event_id: EventId,
    },
}

/// Evidence supporting an outcome attestation
pub enum Evidence {
    /// Hash of data that was written
    DataHash {
        resource: ResourceId,
        hash: Hash,
        size: u64,
    },

    /// External system confirmation
    ExternalConfirmation {
        system: String,
        confirmation_id: String,
        timestamp: Timestamp,
    },

    /// Cryptographic receipt
    Receipt {
        issuer: String,
        receipt: Vec<u8>,
    },

    /// Screenshot or visual evidence
    Visual {
        hash: Hash,
        description: String,
    },

    /// Log entries
    LogEntries {
        source: String,
        entries: Vec<String>,
        hash: Hash,
    },

    /// Third-party attestation
    ThirdPartyAttestation {
        attestor: PublicKey,
        attestation: Vec<u8>,
    },
}

/// Who is attesting to the outcome
pub enum Attestor {
    /// The agent that performed the action
    SelfAttestation { agent: PublicKey },

    /// The system that executed the action
    ExecutionSystem { system_id: String, system_key: PublicKey },

    /// A monitoring system
    Monitor { monitor_id: String, monitor_key: PublicKey },

    /// A human observer
    HumanObserver { principal: PrincipalId },

    /// Cryptographic proof (e.g., blockchain confirmation)
    CryptographicProof { proof_type: String },
}
```

#### 8.2.2 IdempotencyRecord

```rust
/// Record for ensuring action idempotency
pub struct IdempotencyRecord {
    /// Unique idempotency key
    pub key: IdempotencyKey,

    /// The original action event
    pub original_event_id: EventId,

    /// Original outcome
    pub outcome: Outcome,

    /// When this record expires
    pub expires_at: Timestamp,
}

pub struct IdempotencyKey {
    /// Agent that performed the action
    pub agent: PublicKey,

    /// Action type
    pub action_type: String,

    /// Unique client-provided key
    pub client_key: String,
}
```

### 8.3 Outcome Verification Rules

#### Rule 8.3.1: Outcome Recording
Every action event SHOULD have a corresponding `OutcomeAttestation` recorded within a reasonable time frame.

#### Rule 8.3.2: Self-Attestation Limitations
Self-attestations (where agent attests its own outcome) are acceptable for `Low` severity actions but SHOULD be supplemented with external evidence for higher severities.

#### Rule 8.3.3: Evidence Requirements
- `Low` severity: Self-attestation sufficient
- `Medium` severity: At least one piece of external evidence
- `High` severity: Multiple independent evidence sources
- `Critical` severity: Cryptographic proof or human verification required

#### Rule 8.3.4: Idempotency
For actions that could be retried:
- Agent MUST provide an idempotency key
- System MUST check for existing idempotency records
- If action already succeeded, return cached outcome
- Record idempotency key with outcome

#### Rule 8.3.5: Outcome Dispute
If an outcome attestation is disputed:
1. Record dispute event with counter-evidence
2. Escalate to human review
3. Human decision is final
4. Record resolution event

### 8.4 Verification Flow

```
Action Event ──► Execution ──► Outcome Observation ──► Evidence Collection
                                                              │
                                                              ▼
                                                     OutcomeAttestation
                                                              │
                                                              ▼
                                                     Verification Check:
                                                     - Evidence sufficient?
                                                     - Attestor trustworthy?
                                                     - Timing reasonable?
                                                              │
                                    ┌─────────────────────────┴───────────┐
                                    │                                     │
                                    ▼                                     ▼
                              [Verified]                            [Disputed]
                                    │                                     │
                                    ▼                                     ▼
                             Record verified                      Human review
                             outcome                              required
```

---

## 9. Emergency Controls

### 9.1 Purpose

Emergency controls enable rapid intervention when agent behavior is problematic. They answer: "How do we stop this?"

### 9.2 Data Model

#### 9.2.1 EmergencyAction

```rust
/// An emergency control action
pub enum EmergencyAction {
    /// Immediately suspend an agent
    SuspendAgent {
        agent: PublicKey,
        reason: String,
        duration: Option<Duration>,
        scope: SuspensionScope,
    },

    /// Permanently revoke agent credentials
    RevokeAgent {
        agent: PublicKey,
        reason: String,
    },

    /// Kill an active session
    TerminateSession {
        session_id: SessionId,
        reason: String,
    },

    /// Revoke a specific capability
    RevokeCapability {
        capability_id: CapabilityId,
        reason: String,
    },

    /// Block access to a resource
    BlockResource {
        resource: ResourceId,
        blocked_actors: Vec<ActorId>,
        reason: String,
        duration: Option<Duration>,
    },

    /// Global pause on all agent actions
    GlobalPause {
        reason: String,
        duration: Duration,
        exceptions: Vec<PublicKey>,
    },

    /// Rollback actions from an agent
    RollbackActions {
        agent: PublicKey,
        since: Timestamp,
        reason: String,
    },
}

pub enum SuspensionScope {
    /// All actions suspended
    Full,

    /// Only specific capabilities suspended
    Capabilities(Vec<CapabilityKind>),

    /// Only specific resources blocked
    Resources(Vec<ResourceId>),
}
```

#### 9.2.2 EmergencyEvent

```rust
/// Event recording an emergency action
pub struct EmergencyEvent {
    /// The emergency action taken
    pub action: EmergencyAction,

    /// Who initiated the emergency action
    pub initiator: PrincipalId,

    /// Priority level of the emergency
    pub priority: EmergencyPriority,

    /// Evidence triggering the emergency
    pub trigger_evidence: Vec<EventId>,

    /// When the emergency was declared
    pub declared_at: Timestamp,

    /// Expected resolution time
    pub expected_resolution: Option<Timestamp>,

    /// Notification list
    pub notify: Vec<PrincipalId>,
}

pub enum EmergencyPriority {
    /// Respond within hours
    Low,

    /// Respond within minutes
    Medium,

    /// Respond immediately
    High,

    /// Stop everything now
    Critical,
}
```

#### 9.2.3 EmergencyResolution

```rust
/// Resolution of an emergency
pub struct EmergencyResolution {
    /// The emergency event being resolved
    pub emergency_event_id: EventId,

    /// Resolution action
    pub resolution: Resolution,

    /// Who resolved it
    pub resolver: PrincipalId,

    /// When it was resolved
    pub resolved_at: Timestamp,

    /// Post-mortem analysis
    pub post_mortem: Option<PostMortem>,
}

pub enum Resolution {
    /// Emergency was false alarm
    FalseAlarm { explanation: String },

    /// Issue was fixed
    Fixed { fix_description: String },

    /// Agent was permanently removed
    AgentRemoved,

    /// Restrictions remain in place
    RestrictionsActive { review_date: Timestamp },

    /// Escalated to external authority
    Escalated { authority: String },
}

pub struct PostMortem {
    /// What happened
    pub summary: String,

    /// Root cause
    pub root_cause: String,

    /// Impact assessment
    pub impact: String,

    /// Actions taken
    pub actions_taken: Vec<String>,

    /// Preventive measures
    pub prevention: Vec<String>,

    /// Lessons learned
    pub lessons: Vec<String>,
}
```

### 9.3 Emergency Control Rules

#### Rule 9.3.1: Authorization
Emergency actions can be initiated by:
- Any human principal in the agent's trust chain
- Designated emergency responders
- Automated systems with explicit emergency authority

#### Rule 9.3.2: Propagation
Emergency actions MUST be propagated immediately:
- To all nodes in the network (via gossip)
- To the affected agent (if reachable)
- To all approvers in the agent's trust chain
- To monitoring systems

#### Rule 9.3.3: Enforcement
Nodes MUST enforce emergency actions:
- Reject events from suspended/revoked agents
- Block access to blocked resources
- Honor global pause
- Log all enforcement actions

#### Rule 9.3.4: Durability
Emergency actions MUST be:
- Persisted to the audit chain immediately
- Stored in local caches for fast enforcement
- Retained even if network partitions

#### Rule 9.3.5: Resolution Requirement
Every emergency action MUST eventually have a resolution event.
Unresolved emergencies MUST be escalated after a timeout.

### 9.4 Emergency Response Timeline

```
T+0     Anomaly detected
        │
T+1s    EmergencyEvent created and broadcast
        │
T+2s    All nodes receive and enforce
        │
T+5s    Affected agent notified (if possible)
        │
T+1m    All principals in trust chain notified
        │
T+5m    Automated escalation if no acknowledgment
        │
T+1h    Secondary escalation
        │
T+24h   Mandatory review if still unresolved
        │
T+7d    Permanent resolution required
```

### 9.5 Emergency Triggers

Automatic emergency actions MAY be triggered by:

```rust
pub enum EmergencyTrigger {
    /// Agent exceeded rate limits excessively
    RateLimitViolation { factor: f64 },

    /// Agent attempted unauthorized action
    AuthorizationViolation { attempts: u32 },

    /// Agent's attestation expired or revoked
    AttestationInvalid,

    /// Agent acting outside session bounds
    SessionViolation,

    /// Anomalous behavior detected
    AnomalyDetected { anomaly_type: String, score: f64 },

    /// Human reported issue
    HumanReport { reporter: PrincipalId },

    /// External threat intelligence
    ThreatIntelligence { source: String, threat_id: String },
}
```

---

## 10. Multi-Agent Coordination

### 10.1 Purpose

Multi-agent coordination enables accountable collaboration between agents. It answers: "How do we track responsibility when multiple agents work together?"

### 10.2 Data Model

#### 10.2.1 CoordinatedAction

```rust
/// An action involving multiple agents
pub struct CoordinatedAction {
    /// Unique coordination identifier
    pub id: CoordinationId,

    /// Type of coordination
    pub coordination_type: CoordinationType,

    /// Participating agents
    pub participants: Vec<Participant>,

    /// The coordinated action
    pub action: CoordinatedActionSpec,

    /// Coordination protocol used
    pub protocol: CoordinationProtocol,

    /// When coordination started
    pub started_at: Timestamp,

    /// Current status
    pub status: CoordinationStatus,

    /// Combined causal context
    pub causal_context: CausalContext,
}

pub struct CoordinationId(pub [u8; 16]);

pub enum CoordinationType {
    /// Agents working on same goal in parallel
    Parallel,

    /// Agents in a pipeline (output → input)
    Pipeline,

    /// Agents voting/consensus
    Consensus,

    /// One agent supervising others
    Supervised,

    /// Agents competing (first to succeed wins)
    Competitive,
}

pub struct Participant {
    /// Agent identity
    pub agent: PublicKey,

    /// Role in the coordination
    pub role: ParticipantRole,

    /// Capabilities this agent is contributing
    pub capabilities: Vec<CapabilityId>,

    /// Responsibility assignment
    pub responsibility: Responsibility,

    /// Agent's commitment (signature on coordination spec)
    pub commitment: Sig,
}

pub enum ParticipantRole {
    /// Leading the coordination
    Coordinator,

    /// Participating as a peer
    Peer,

    /// Supervising the coordination
    Supervisor,

    /// Providing a specific service
    ServiceProvider { service: String },

    /// Observing only
    Observer,
}

/// How responsibility is assigned
pub enum Responsibility {
    /// Full responsibility for own actions
    Individual,

    /// Shared responsibility with other participants
    Shared { share: f64 },

    /// Delegated from another agent
    Delegated { delegator: PublicKey },

    /// Supervised (supervisor bears responsibility)
    Supervised { supervisor: PublicKey },
}

pub struct CoordinatedActionSpec {
    /// What the group is trying to accomplish
    pub goal: String,

    /// Sub-tasks assigned to each participant
    pub tasks: HashMap<PublicKey, Vec<Task>>,

    /// Dependencies between tasks
    pub dependencies: Vec<TaskDependency>,

    /// Success criteria for the coordination
    pub success_criteria: Vec<String>,

    /// What happens if coordination fails
    pub failure_handling: FailureHandling,
}

pub struct Task {
    pub id: TaskId,
    pub description: String,
    pub required_capabilities: Vec<CapabilityKind>,
    pub deadline: Option<Timestamp>,
}

pub struct TaskId(pub [u8; 16]);

pub struct TaskDependency {
    pub task: TaskId,
    pub depends_on: Vec<TaskId>,
}

pub enum FailureHandling {
    /// Abort entire coordination
    AbortAll,

    /// Continue with partial results
    ContinuePartial,

    /// Retry failed tasks
    Retry { max_attempts: u32 },

    /// Escalate to humans
    Escalate,
}

pub enum CoordinationProtocol {
    /// Simple two-phase commit
    TwoPhaseCommit,

    /// Multi-agent consensus
    Consensus { threshold: f64 },

    /// Leader-based coordination
    LeaderFollower,

    /// Asynchronous coordination
    Async { timeout: Duration },

    /// Custom protocol
    Custom { protocol_id: String },
}

pub enum CoordinationStatus {
    /// Coordination is being set up
    Initializing,

    /// Waiting for all participants to commit
    WaitingCommitment,

    /// Coordination is active
    Active { progress: f64 },

    /// All tasks completed successfully
    Completed { result: CoordinationResult },

    /// Coordination failed
    Failed { reason: String, partial_result: Option<CoordinationResult> },

    /// Coordination was aborted
    Aborted { reason: String, aborted_by: ActorId },
}

pub struct CoordinationResult {
    /// Overall outcome
    pub outcome: Outcome,

    /// Per-agent outcomes
    pub agent_outcomes: HashMap<PublicKey, Outcome>,

    /// Combined output
    pub output: serde_json::Value,

    /// Coordination metrics
    pub metrics: CoordinationMetrics,
}

pub struct CoordinationMetrics {
    pub total_duration: Duration,
    pub per_agent_duration: HashMap<PublicKey, Duration>,
    pub communication_overhead: Duration,
    pub retry_count: u32,
}
```

#### 10.2.2 CoordinationEvent

```rust
/// Event recording coordination lifecycle
pub enum CoordinationEvent {
    /// Coordination initiated
    Started(CoordinatedAction),

    /// Participant joined
    ParticipantJoined {
        coordination_id: CoordinationId,
        participant: Participant,
    },

    /// Task assigned
    TaskAssigned {
        coordination_id: CoordinationId,
        agent: PublicKey,
        task: Task,
    },

    /// Task completed
    TaskCompleted {
        coordination_id: CoordinationId,
        task_id: TaskId,
        agent: PublicKey,
        outcome: Outcome,
    },

    /// Agent-to-agent message
    Message {
        coordination_id: CoordinationId,
        from: PublicKey,
        to: PublicKey,
        message_hash: Hash,
    },

    /// Disagreement between agents
    Disagreement {
        coordination_id: CoordinationId,
        agents: Vec<PublicKey>,
        subject: String,
        positions: HashMap<PublicKey, String>,
    },

    /// Coordination completed
    Completed(CoordinationResult),

    /// Coordination failed
    Failed {
        coordination_id: CoordinationId,
        reason: String,
        failed_at: Timestamp,
    },
}
```

### 10.3 Multi-Agent Rules

#### Rule 10.3.1: Coordinator Requirement
Every multi-agent coordination MUST have exactly one coordinator agent.

#### Rule 10.3.2: Commitment Protocol
All participants MUST sign the `CoordinatedActionSpec` before execution begins.

#### Rule 10.3.3: Responsibility Clarity
Every action within a coordination MUST have clear responsibility assignment.
The sum of `Responsibility::Shared` shares MUST equal 1.0.

#### Rule 10.3.4: Atomic Recording
Coordination outcomes MUST be recorded atomically:
- Either all agent contributions are recorded
- Or the entire coordination is marked as failed

#### Rule 10.3.5: Disagreement Resolution
If agents disagree:
1. Record the disagreement event
2. Attempt protocol-defined resolution (voting, supervisor decision)
3. If unresolved, escalate to human
4. Record resolution

#### Rule 10.3.6: Capability Composition
The coordination MUST NOT require capabilities beyond the union of participant capabilities.
Each participant MUST only use capabilities they possess.

### 10.4 Coordination Patterns

#### 10.4.1 Pipeline Pattern

```
Agent A ──► Agent B ──► Agent C ──► Result
   │            │           │
   │            │           └── Responsible for final output
   │            └── Responsible for transformation
   └── Responsible for initial processing
```

#### 10.4.2 Parallel Pattern

```
              ┌──► Agent B ──┐
              │              │
Agent A ──────┼──► Agent C ──┼──► Aggregator ──► Result
              │              │
              └──► Agent D ──┘

All agents share responsibility for their portion.
Aggregator responsible for combination.
```

#### 10.4.3 Supervised Pattern

```
         Supervisor (Human or Agent)
               │
    ┌──────────┼──────────┐
    │          │          │
    ▼          ▼          ▼
Agent A    Agent B    Agent C

Supervisor bears responsibility for oversight.
Each agent responsible for execution within bounds.
```

---

## 11. Event Types

### 11.1 New Event Types

```rust
/// Extended event types for agent accountability
pub enum AgentEventType {
    // === Session Events ===

    /// New session started
    SessionStarted {
        session: Session,
    },

    /// Session ended
    SessionEnded {
        session_id: SessionId,
        reason: SessionEndReason,
        summary: SessionSummary,
    },

    // === Attestation Events ===

    /// Agent attestation registered
    AgentAttested {
        attestation: AgentAttestation,
    },

    /// Attestation revoked
    AttestationRevoked {
        attestation_hash: Hash,
        reason: String,
        revoked_by: ActorId,
    },

    // === Capability Events ===

    /// Capability granted
    CapabilityGranted {
        grant: CapabilityGrantEvent,
    },

    /// Capability revoked
    CapabilityRevoked {
        capability_id: CapabilityId,
        reason: String,
        revoked_by: ActorId,
    },

    /// Capability delegated
    CapabilityDelegated {
        from: PublicKey,
        to: PublicKey,
        capability_id: CapabilityId,
        constraints: CapabilityConstraints,
    },

    // === Agent Lifecycle Events ===

    /// Agent spawned by another agent
    AgentSpawned {
        parent: PublicKey,
        child: PublicKey,
        inherited_capabilities: Vec<CapabilityId>,
        purpose: String,
    },

    /// Agent terminated
    AgentTerminated {
        agent: PublicKey,
        reason: TerminationReason,
        final_state: Option<Hash>,
    },

    // === Action Events ===

    /// Agent action with full accountability
    AgentActionV2 {
        /// Causal context (required)
        causal_context: CausalContext,

        /// Attestation hash (required)
        attestation_hash: Hash,

        /// Capability authorizing this action
        capability_id: CapabilityId,

        /// Action details
        action: ActionDetails,

        /// Reasoning trace (required for severity >= Medium)
        reasoning_trace: Option<ReasoningTrace>,

        /// Impact assessment
        impact: ImpactAssessment,
    },

    /// Tool invocation
    ToolInvocation {
        tool_id: String,
        tool_version: String,
        input_hash: Hash,
        input_summary: String,
        causal_context: CausalContext,
    },

    /// Tool result
    ToolResult {
        invocation_event_id: EventId,
        output_hash: Hash,
        output_summary: String,
        duration: Duration,
    },

    // === HITL Events ===

    /// Approval requested
    ApprovalRequested {
        request: ApprovalRequest,
    },

    /// Approval response received
    ApprovalResponded {
        response: ApprovalResponse,
    },

    /// Approval escalated
    ApprovalEscalated {
        request_id: ApprovalRequestId,
        escalated_to: Vec<PrincipalId>,
        reason: String,
    },

    // === Outcome Events ===

    /// Outcome attested
    OutcomeAttested {
        attestation: OutcomeAttestation,
    },

    /// Outcome disputed
    OutcomeDisputed {
        attestation_event_id: EventId,
        dispute_reason: String,
        counter_evidence: Vec<Evidence>,
        disputer: ActorId,
    },

    /// Dispute resolved
    DisputeResolved {
        dispute_event_id: EventId,
        resolution: DisputeResolution,
        resolver: PrincipalId,
    },

    // === Emergency Events ===

    /// Emergency declared
    EmergencyDeclared {
        emergency: EmergencyEvent,
    },

    /// Emergency resolved
    EmergencyResolved {
        resolution: EmergencyResolution,
    },

    // === Coordination Events ===

    /// Coordination started
    CoordinationStarted {
        coordination: CoordinatedAction,
    },

    /// Coordination event
    CoordinationEvent {
        event: CoordinationEvent,
    },
}

pub enum SessionEndReason {
    Completed,
    Timeout,
    UserTerminated,
    ErrorTerminated { error: String },
    EmergencyTerminated { emergency_id: EventId },
}

pub struct SessionSummary {
    pub events_count: u64,
    pub actions_count: u64,
    pub approvals_requested: u64,
    pub approvals_granted: u64,
    pub errors_count: u64,
    pub duration: Duration,
}

pub enum TerminationReason {
    TaskCompleted,
    SessionEnded,
    Revoked,
    Error { error: String },
    EmergencyStop,
}

pub struct ActionDetails {
    pub action_type: String,
    pub resource: ResourceId,
    pub parameters: serde_json::Value,
    pub expected_outcome: String,
}

pub enum DisputeResolution {
    OriginalUpheld,
    DisputeUpheld { corrected_outcome: Outcome },
    Indeterminate { notes: String },
}
```

### 11.2 Event Metadata Requirements

All agent accountability events MUST include:

```rust
pub struct AgentEventMetadata {
    /// Causal context (always required)
    pub causal_context: CausalContext,

    /// Agent attestation hash (required for agent-initiated events)
    pub attestation_hash: Option<Hash>,

    /// Capability used (required for actions)
    pub capability_id: Option<CapabilityId>,

    /// Reasoning trace hash (required for severity >= Medium)
    pub reasoning_trace_hash: Option<Hash>,
}
```

---

## 12. Invariants

### 12.1 Causality Invariants

```
INV-CAUSAL-1: ∀ event with parent_event_id = Some(p):
              p exists in chain ∧ p.sequence < event.sequence

INV-CAUSAL-2: ∀ event with depth > 0:
              event.root_event_id points to event with depth = 0

INV-CAUSAL-3: ∀ event in session S:
              event.depth ≤ S.max_depth

INV-CAUSAL-4: ∀ session:
              ∃ exactly one event with depth = 0 (root)
```

### 12.2 Attestation Invariants

```
INV-ATTEST-1: ∀ agent action event:
              ∃ valid attestation A where A.agent_id = event.actor

INV-ATTEST-2: ∀ attestation A:
              A.attested_at + A.validity_period > current_time
              ∨ A is revoked

INV-ATTEST-3: ∀ tool invocation by agent with attestation A:
              tool ∈ A.tools
```

### 12.3 Capability Invariants

```
INV-CAP-1: ∀ agent action event with capability_id = C:
           C.grantee = event.actor ∨ C was delegated to event.actor

INV-CAP-2: ∀ capability C:
           C.current_uses ≤ C.constraints.max_uses (if set)

INV-CAP-3: ∀ delegated capability C' from C:
           C'.scope ⊆ C.scope ∧ C'.expires_at ≤ C.expires_at

INV-CAP-4: ∀ delegation chain:
           depth ≤ original_capability.max_delegation_depth
```

### 12.4 HITL Invariants

```
INV-HITL-1: ∀ action requiring approval:
            ∃ ApprovalResponse before action event

INV-HITL-2: ∀ ApprovalResponse:
            response.request_id references existing ApprovalRequest

INV-HITL-3: ∀ approval with modifications:
            action event reflects all modifications
```

### 12.5 Emergency Invariants

```
INV-EMERG-1: ∀ suspended agent A:
             ∄ new events from A until suspension lifted

INV-EMERG-2: ∀ EmergencyEvent:
             ∃ eventual EmergencyResolution

INV-EMERG-3: ∀ global pause:
             only exceptions list can create events
```

### 12.6 Coordination Invariants

```
INV-COORD-1: ∀ coordination:
             exactly one participant has role = Coordinator

INV-COORD-2: ∀ participant P in coordination C:
             P.commitment verifies against C.action specification

INV-COORD-3: ∀ task in coordination:
             sum(responsibility.share) = 1.0 if shared
```

---

## 13. Security Considerations

### 13.1 Threat Model

| Threat | Mitigation |
|--------|------------|
| Compromised agent key | Attestation binding, short validity periods |
| Malicious attestation authority | Multiple authorities, transparency log |
| Capability escalation | Strict subset delegation, depth limits |
| Replay attacks | Sequence numbers, idempotency keys |
| Causal chain manipulation | Hash linking, MMR inclusion proofs |
| Emergency bypass | Cryptographic enforcement, distributed consensus |
| Coordination manipulation | All-participant signatures, atomic recording |

### 13.2 Key Management

- Agent keys SHOULD be generated in TEE when available
- Agent keys MUST NOT be extractable
- Attestation authority keys MUST be HSM-protected
- Key rotation MUST trigger re-attestation

### 13.3 Audit Requirements

The following MUST be auditable:
- All agent actions with full causal context
- All capability grants and revocations
- All attestation lifecycle events
- All HITL interactions
- All emergency actions
- All coordination events

### 13.4 Privacy Considerations

- Reasoning traces MAY contain sensitive information
- Implement trace redaction for public queries
- Support encrypted traces with authorized access
- GDPR/CCPA compliance for personal data in traces

---

## 14. Migration Path

### 14.1 Versioning

This specification introduces `AgentEventType` as a new event type category.
Existing `EventType::AgentAction` events remain valid but are considered v1.

### 14.2 Migration Phases

**Phase 1: Parallel Support**
- Add new event types alongside existing
- Old events continue to work
- New events get full accountability features

**Phase 2: Soft Requirement**
- New agent deployments MUST use v2 events
- Existing agents SHOULD migrate
- Warnings logged for v1 events

**Phase 3: Hard Requirement**
- All agent events MUST use v2 format
- v1 events rejected
- Migration tools provided

### 14.3 Backward Compatibility

```rust
impl From<LegacyAgentAction> for AgentActionV2 {
    fn from(legacy: LegacyAgentAction) -> Self {
        AgentActionV2 {
            causal_context: CausalContext::inferred(&legacy),
            attestation_hash: Hash::zero(), // Grandfathered
            capability_id: CapabilityId::legacy(),
            action: ActionDetails::from(legacy),
            reasoning_trace: None,
            impact: ImpactAssessment::unknown(),
        }
    }
}
```

---

## Appendix A: Example Scenarios

### A.1 Simple Agent Action

```
1. User starts session (SessionStarted)
2. User requests action (depth=0, root=self)
3. Agent attests state (AgentAttested)
4. Agent checks capability (CapabilityGranted earlier)
5. Agent reasons about action (generates ReasoningTrace)
6. Agent executes action (AgentActionV2)
7. System confirms outcome (OutcomeAttested)
8. Session ends (SessionEnded)
```

### A.2 Multi-Agent Pipeline

```
1. User starts session
2. User requests complex task
3. Agent A spawns Agent B (AgentSpawned)
4. Coordination started (CoordinationStarted)
5. Agent A processes (AgentActionV2, depth=1)
6. Agent A passes to Agent B (Message)
7. Agent B processes (AgentActionV2, depth=2)
8. Coordination completes (CoordinationCompleted)
9. Combined outcome attested
```

### A.3 High-Stakes Action with Approval

```
1. Agent identifies high-stakes action
2. Agent creates ApprovalRequest
3. System records ApprovalRequested
4. Human reviews with full context
5. Human approves with modification
6. System records ApprovalResponded
7. Agent applies modification
8. Agent executes (references approval_id)
9. Outcome attested with evidence
```

### A.4 Emergency Response

```
1. Anomaly detected in agent behavior
2. EmergencyDeclared (SuspendAgent)
3. All nodes enforce suspension
4. Human investigates
5. Root cause identified
6. EmergencyResolved (with post-mortem)
7. Agent re-attested (if appropriate)
8. Operations resume
```

---

## Appendix B: Glossary Updates

| Term | Definition |
|------|------------|
| **Attestation** | Cryptographic binding of agent identity to verifiable state |
| **Capability** | Explicit permission scoped by resource, time, and constraints |
| **Causal Context** | Metadata linking an event to its predecessors and origin |
| **Coordination** | Structured collaboration between multiple agents |
| **HITL** | Human-in-the-Loop - protocol for human oversight |
| **Outcome Attestation** | Cryptographic confirmation of action result |
| **Principal** | Human or organization ultimately responsible for agent |
| **Reasoning Trace** | Structured record of agent decision-making process |
| **Session** | Bounded context for agent operations |

---

**End of Specification**

*This specification extends the Moloch Master Specification with agent-specific accountability features.*
