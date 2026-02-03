//! Multi-agent coordination for accountable collaboration.
//!
//! Multi-agent coordination answers: "How do we track responsibility when
//! multiple agents work together?"

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::crypto::{hash, Hash, PublicKey, Sig};
use crate::error::{Error, Result};

use super::capability::{CapabilityId, CapabilityKind};
use super::causality::CausalContext;
use super::outcome::ActionOutcome;

/// Duration in milliseconds.
pub type DurationMs = i64;

/// Unique coordination identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CoordinationId(pub [u8; 16]);

impl CoordinationId {
    /// Generate a new random coordination ID.
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
            return Err(Error::invalid_input("coordination ID must be 16 bytes"));
        }
        let mut arr = [0u8; 16];
        arr.copy_from_slice(&bytes);
        Ok(Self(arr))
    }
}

impl std::fmt::Display for CoordinationId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

/// Unique task identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TaskId(pub [u8; 16]);

impl TaskId {
    /// Generate a new random task ID.
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
}

impl std::fmt::Display for TaskId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

/// Type of coordination between agents.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum CoordinationType {
    /// Agents working on same goal in parallel.
    Parallel,
    /// Agents in a pipeline (output → input).
    Pipeline,
    /// Agents voting/consensus.
    Consensus,
    /// One agent supervising others.
    Supervised,
    /// Agents competing (first to succeed wins).
    Competitive,
}

impl std::fmt::Display for CoordinationType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CoordinationType::Parallel => write!(f, "parallel"),
            CoordinationType::Pipeline => write!(f, "pipeline"),
            CoordinationType::Consensus => write!(f, "consensus"),
            CoordinationType::Supervised => write!(f, "supervised"),
            CoordinationType::Competitive => write!(f, "competitive"),
        }
    }
}

/// Role of a participant in coordination.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "role", rename_all = "snake_case")]
pub enum ParticipantRole {
    /// Leading the coordination.
    Coordinator,
    /// Participating as a peer.
    Peer,
    /// Supervising the coordination.
    Supervisor,
    /// Providing a specific service.
    ServiceProvider {
        /// Service being provided.
        service: String,
    },
    /// Observing only.
    Observer,
}

impl ParticipantRole {
    /// Create a service provider role.
    pub fn service_provider(service: impl Into<String>) -> Self {
        Self::ServiceProvider {
            service: service.into(),
        }
    }

    /// Check if this role can execute tasks.
    pub fn can_execute(&self) -> bool {
        !matches!(self, ParticipantRole::Observer)
    }

    /// Check if this role can supervise.
    pub fn can_supervise(&self) -> bool {
        matches!(
            self,
            ParticipantRole::Coordinator | ParticipantRole::Supervisor
        )
    }
}

/// How responsibility is assigned to a participant.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Responsibility {
    /// Full responsibility for own actions.
    Individual,
    /// Shared responsibility with other participants.
    Shared {
        /// Share of responsibility (0.0 - 1.0).
        share: f64,
    },
    /// Delegated from another agent.
    Delegated {
        /// Agent who delegated responsibility.
        delegator: PublicKey,
    },
    /// Supervised (supervisor bears responsibility).
    Supervised {
        /// Supervisor who bears responsibility.
        supervisor: PublicKey,
    },
}

impl Responsibility {
    /// Create individual responsibility.
    pub fn individual() -> Self {
        Self::Individual
    }

    /// Create shared responsibility.
    pub fn shared(share: f64) -> Self {
        Self::Shared {
            share: share.clamp(0.0, 1.0),
        }
    }

    /// Create delegated responsibility.
    pub fn delegated(delegator: PublicKey) -> Self {
        Self::Delegated { delegator }
    }

    /// Create supervised responsibility.
    pub fn supervised(supervisor: PublicKey) -> Self {
        Self::Supervised { supervisor }
    }

    /// Get the responsibility share (1.0 for individual).
    pub fn share(&self) -> f64 {
        match self {
            Responsibility::Individual => 1.0,
            Responsibility::Shared { share } => *share,
            Responsibility::Delegated { .. } => 0.0, // Delegator bears responsibility
            Responsibility::Supervised { .. } => 0.0, // Supervisor bears responsibility
        }
    }
}

/// A participant in a coordinated action.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Participant {
    /// Agent identity.
    agent: PublicKey,
    /// Role in the coordination.
    role: ParticipantRole,
    /// Capabilities this agent is contributing.
    capabilities: Vec<CapabilityId>,
    /// Responsibility assignment.
    responsibility: Responsibility,
    /// Agent's commitment (signature on coordination spec).
    commitment: Sig,
}

impl Participant {
    /// Create a new participant.
    pub fn new(
        agent: PublicKey,
        role: ParticipantRole,
        responsibility: Responsibility,
        commitment: Sig,
    ) -> Self {
        Self {
            agent,
            role,
            capabilities: Vec::new(),
            responsibility,
            commitment,
        }
    }

    /// Add capabilities.
    pub fn with_capabilities(mut self, capabilities: Vec<CapabilityId>) -> Self {
        self.capabilities = capabilities;
        self
    }

    /// Get the agent.
    pub fn agent(&self) -> &PublicKey {
        &self.agent
    }

    /// Get the role.
    pub fn role(&self) -> &ParticipantRole {
        &self.role
    }

    /// Get the capabilities.
    pub fn capabilities(&self) -> &[CapabilityId] {
        &self.capabilities
    }

    /// Get the responsibility.
    pub fn responsibility(&self) -> &Responsibility {
        &self.responsibility
    }

    /// Get the commitment signature.
    pub fn commitment(&self) -> &Sig {
        &self.commitment
    }

    /// Check if this participant is the coordinator.
    pub fn is_coordinator(&self) -> bool {
        matches!(self.role, ParticipantRole::Coordinator)
    }
}

/// A task within a coordinated action.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Task {
    /// Task identifier.
    id: TaskId,
    /// Description of the task.
    description: String,
    /// Required capabilities.
    required_capabilities: Vec<CapabilityKind>,
    /// Deadline for the task (Unix timestamp ms).
    deadline: Option<i64>,
}

impl Task {
    /// Create a new task.
    pub fn new(description: impl Into<String>) -> Self {
        Self {
            id: TaskId::generate(),
            description: description.into(),
            required_capabilities: Vec::new(),
            deadline: None,
        }
    }

    /// Create with a specific ID.
    pub fn with_id(mut self, id: TaskId) -> Self {
        self.id = id;
        self
    }

    /// Set required capabilities.
    pub fn with_capabilities(mut self, capabilities: Vec<CapabilityKind>) -> Self {
        self.required_capabilities = capabilities;
        self
    }

    /// Set deadline.
    pub fn with_deadline(mut self, deadline: i64) -> Self {
        self.deadline = Some(deadline);
        self
    }

    /// Get the ID.
    pub fn id(&self) -> TaskId {
        self.id
    }

    /// Get the description.
    pub fn description(&self) -> &str {
        &self.description
    }

    /// Get required capabilities.
    pub fn required_capabilities(&self) -> &[CapabilityKind] {
        &self.required_capabilities
    }

    /// Get the deadline.
    pub fn deadline(&self) -> Option<i64> {
        self.deadline
    }

    /// Check if the task is overdue.
    pub fn is_overdue(&self) -> bool {
        if let Some(deadline) = self.deadline {
            chrono::Utc::now().timestamp_millis() > deadline
        } else {
            false
        }
    }
}

/// Dependency between tasks.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskDependency {
    /// Task that has dependencies.
    task: TaskId,
    /// Tasks this task depends on.
    depends_on: Vec<TaskId>,
}

impl TaskDependency {
    /// Create a new task dependency.
    pub fn new(task: TaskId, depends_on: Vec<TaskId>) -> Self {
        Self { task, depends_on }
    }

    /// Get the task.
    pub fn task(&self) -> TaskId {
        self.task
    }

    /// Get dependencies.
    pub fn depends_on(&self) -> &[TaskId] {
        &self.depends_on
    }
}

/// What happens if coordination fails.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum FailureHandling {
    /// Abort entire coordination.
    AbortAll,
    /// Continue with partial results.
    ContinuePartial,
    /// Retry failed tasks.
    Retry {
        /// Maximum retry attempts.
        max_attempts: u32,
    },
    /// Escalate to humans.
    Escalate,
}

impl Default for FailureHandling {
    fn default() -> Self {
        Self::AbortAll
    }
}

/// Specification of a coordinated action.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoordinatedActionSpec {
    /// What the group is trying to accomplish.
    goal: String,
    /// Sub-tasks assigned to each participant.
    tasks: HashMap<String, Vec<Task>>, // Key is hex-encoded public key
    /// Dependencies between tasks.
    dependencies: Vec<TaskDependency>,
    /// Success criteria for the coordination.
    success_criteria: Vec<String>,
    /// What happens if coordination fails.
    failure_handling: FailureHandling,
}

impl CoordinatedActionSpec {
    /// Create a new coordinated action spec.
    pub fn new(goal: impl Into<String>) -> Self {
        Self {
            goal: goal.into(),
            tasks: HashMap::new(),
            dependencies: Vec::new(),
            success_criteria: Vec::new(),
            failure_handling: FailureHandling::default(),
        }
    }

    /// Add tasks for a participant.
    pub fn with_tasks(mut self, agent: &PublicKey, tasks: Vec<Task>) -> Self {
        self.tasks.insert(hex::encode(agent.as_bytes()), tasks);
        self
    }

    /// Add a dependency.
    pub fn with_dependency(mut self, dependency: TaskDependency) -> Self {
        self.dependencies.push(dependency);
        self
    }

    /// Add a success criterion.
    pub fn with_criterion(mut self, criterion: impl Into<String>) -> Self {
        self.success_criteria.push(criterion.into());
        self
    }

    /// Set failure handling.
    pub fn with_failure_handling(mut self, handling: FailureHandling) -> Self {
        self.failure_handling = handling;
        self
    }

    /// Get the goal.
    pub fn goal(&self) -> &str {
        &self.goal
    }

    /// Get tasks for a participant.
    pub fn tasks_for(&self, agent: &PublicKey) -> Option<&[Task]> {
        self.tasks
            .get(&hex::encode(agent.as_bytes()))
            .map(|v| v.as_slice())
    }

    /// Get all tasks.
    pub fn all_tasks(&self) -> impl Iterator<Item = &Task> {
        self.tasks.values().flat_map(|v| v.iter())
    }

    /// Get dependencies.
    pub fn dependencies(&self) -> &[TaskDependency] {
        &self.dependencies
    }

    /// Get success criteria.
    pub fn success_criteria(&self) -> &[String] {
        &self.success_criteria
    }

    /// Get failure handling.
    pub fn failure_handling(&self) -> &FailureHandling {
        &self.failure_handling
    }

    /// Compute a hash of this spec for signing.
    pub fn hash(&self) -> Hash {
        let json = serde_json::to_vec(self).unwrap_or_default();
        hash(&json)
    }
}

/// Coordination protocol used.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum CoordinationProtocol {
    /// Simple two-phase commit.
    TwoPhaseCommit,
    /// Multi-agent consensus.
    Consensus {
        /// Threshold for consensus (0.0 - 1.0).
        threshold: f64,
    },
    /// Leader-based coordination.
    LeaderFollower,
    /// Asynchronous coordination.
    Async {
        /// Timeout in milliseconds.
        timeout: DurationMs,
    },
    /// Custom protocol.
    Custom {
        /// Protocol identifier.
        protocol_id: String,
    },
}

impl CoordinationProtocol {
    /// Create a consensus protocol.
    pub fn consensus(threshold: f64) -> Self {
        Self::Consensus {
            threshold: threshold.clamp(0.0, 1.0),
        }
    }

    /// Create an async protocol.
    pub fn async_with_timeout(timeout: DurationMs) -> Self {
        Self::Async { timeout }
    }

    /// Create a custom protocol.
    pub fn custom(protocol_id: impl Into<String>) -> Self {
        Self::Custom {
            protocol_id: protocol_id.into(),
        }
    }
}

/// Metrics about coordination execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoordinationMetrics {
    /// Total duration in milliseconds.
    total_duration: DurationMs,
    /// Per-agent duration (key is hex-encoded public key).
    per_agent_duration: HashMap<String, DurationMs>,
    /// Communication overhead in milliseconds.
    communication_overhead: DurationMs,
    /// Number of retries.
    retry_count: u32,
}

impl CoordinationMetrics {
    /// Create new metrics.
    pub fn new(total_duration: DurationMs) -> Self {
        Self {
            total_duration,
            per_agent_duration: HashMap::new(),
            communication_overhead: 0,
            retry_count: 0,
        }
    }

    /// Set agent duration.
    pub fn with_agent_duration(mut self, agent: &PublicKey, duration: DurationMs) -> Self {
        self.per_agent_duration
            .insert(hex::encode(agent.as_bytes()), duration);
        self
    }

    /// Set communication overhead.
    pub fn with_overhead(mut self, overhead: DurationMs) -> Self {
        self.communication_overhead = overhead;
        self
    }

    /// Set retry count.
    pub fn with_retries(mut self, count: u32) -> Self {
        self.retry_count = count;
        self
    }

    /// Get total duration.
    pub fn total_duration(&self) -> DurationMs {
        self.total_duration
    }

    /// Get agent duration.
    pub fn agent_duration(&self, agent: &PublicKey) -> Option<DurationMs> {
        self.per_agent_duration
            .get(&hex::encode(agent.as_bytes()))
            .copied()
    }

    /// Get communication overhead.
    pub fn communication_overhead(&self) -> DurationMs {
        self.communication_overhead
    }

    /// Get retry count.
    pub fn retry_count(&self) -> u32 {
        self.retry_count
    }
}

/// Result of a coordination.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoordinationResult {
    /// Overall outcome.
    outcome: ActionOutcome,
    /// Per-agent outcomes (key is hex-encoded public key).
    agent_outcomes: HashMap<String, ActionOutcome>,
    /// Combined output.
    output: serde_json::Value,
    /// Coordination metrics.
    metrics: CoordinationMetrics,
}

impl CoordinationResult {
    /// Create a new coordination result.
    pub fn new(
        outcome: ActionOutcome,
        output: serde_json::Value,
        metrics: CoordinationMetrics,
    ) -> Self {
        Self {
            outcome,
            agent_outcomes: HashMap::new(),
            output,
            metrics,
        }
    }

    /// Add an agent outcome.
    pub fn with_agent_outcome(mut self, agent: &PublicKey, outcome: ActionOutcome) -> Self {
        self.agent_outcomes
            .insert(hex::encode(agent.as_bytes()), outcome);
        self
    }

    /// Get the overall outcome.
    pub fn outcome(&self) -> &ActionOutcome {
        &self.outcome
    }

    /// Get agent outcome.
    pub fn agent_outcome(&self, agent: &PublicKey) -> Option<&ActionOutcome> {
        self.agent_outcomes.get(&hex::encode(agent.as_bytes()))
    }

    /// Get the output.
    pub fn output(&self) -> &serde_json::Value {
        &self.output
    }

    /// Get the metrics.
    pub fn metrics(&self) -> &CoordinationMetrics {
        &self.metrics
    }

    /// Check if coordination succeeded.
    pub fn is_success(&self) -> bool {
        self.outcome.is_success()
    }
}

/// Status of a coordination.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum CoordinationStatus {
    /// Coordination is being set up.
    Initializing,
    /// Waiting for all participants to commit.
    WaitingCommitment,
    /// Coordination is active.
    Active {
        /// Progress (0.0 - 1.0).
        progress: f64,
    },
    /// All tasks completed successfully.
    Completed {
        /// Coordination result.
        result: CoordinationResult,
    },
    /// Coordination failed.
    Failed {
        /// Reason for failure.
        reason: String,
        /// Partial result if any.
        partial_result: Option<CoordinationResult>,
    },
    /// Coordination was aborted.
    Aborted {
        /// Reason for abort.
        reason: String,
        /// Who aborted (agent public key).
        aborted_by: PublicKey,
    },
}

impl CoordinationStatus {
    /// Create an active status.
    pub fn active(progress: f64) -> Self {
        Self::Active {
            progress: progress.clamp(0.0, 1.0),
        }
    }

    /// Create a completed status.
    pub fn completed(result: CoordinationResult) -> Self {
        Self::Completed { result }
    }

    /// Create a failed status.
    pub fn failed(reason: impl Into<String>, partial_result: Option<CoordinationResult>) -> Self {
        Self::Failed {
            reason: reason.into(),
            partial_result,
        }
    }

    /// Create an aborted status.
    pub fn aborted(reason: impl Into<String>, aborted_by: PublicKey) -> Self {
        Self::Aborted {
            reason: reason.into(),
            aborted_by,
        }
    }

    /// Check if coordination is in progress.
    pub fn is_active(&self) -> bool {
        matches!(
            self,
            CoordinationStatus::Initializing
                | CoordinationStatus::WaitingCommitment
                | CoordinationStatus::Active { .. }
        )
    }

    /// Check if coordination is complete (succeeded or failed).
    pub fn is_terminal(&self) -> bool {
        !self.is_active()
    }

    /// Get progress if active.
    pub fn progress(&self) -> Option<f64> {
        match self {
            CoordinationStatus::Active { progress } => Some(*progress),
            _ => None,
        }
    }
}

/// A coordinated action involving multiple agents.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoordinatedAction {
    /// Unique coordination identifier.
    id: CoordinationId,
    /// Type of coordination.
    coordination_type: CoordinationType,
    /// Participating agents.
    participants: Vec<Participant>,
    /// The coordinated action specification.
    action: CoordinatedActionSpec,
    /// Coordination protocol used.
    protocol: CoordinationProtocol,
    /// When coordination started (Unix timestamp ms).
    started_at: i64,
    /// Current status.
    status: CoordinationStatus,
    /// Combined causal context.
    causal_context: CausalContext,
}

impl CoordinatedAction {
    /// Create a new coordinated action builder.
    pub fn builder() -> CoordinatedActionBuilder {
        CoordinatedActionBuilder::new()
    }

    /// Get the ID.
    pub fn id(&self) -> CoordinationId {
        self.id
    }

    /// Get the coordination type.
    pub fn coordination_type(&self) -> &CoordinationType {
        &self.coordination_type
    }

    /// Get the participants.
    pub fn participants(&self) -> &[Participant] {
        &self.participants
    }

    /// Get the action specification.
    pub fn action(&self) -> &CoordinatedActionSpec {
        &self.action
    }

    /// Get the protocol.
    pub fn protocol(&self) -> &CoordinationProtocol {
        &self.protocol
    }

    /// Get the start time.
    pub fn started_at(&self) -> i64 {
        self.started_at
    }

    /// Get the status.
    pub fn status(&self) -> &CoordinationStatus {
        &self.status
    }

    /// Get the causal context.
    pub fn causal_context(&self) -> &CausalContext {
        &self.causal_context
    }

    /// Update the status.
    pub fn set_status(&mut self, status: CoordinationStatus) {
        self.status = status;
    }

    /// Get the coordinator participant.
    pub fn coordinator(&self) -> Option<&Participant> {
        self.participants.iter().find(|p| p.is_coordinator())
    }

    /// Validate that the coordination has exactly one coordinator per rule 10.3.1.
    pub fn validate_coordinator(&self) -> Result<()> {
        let coordinator_count = self
            .participants
            .iter()
            .filter(|p| p.is_coordinator())
            .count();

        if coordinator_count != 1 {
            return Err(Error::invalid_input(format!(
                "coordination must have exactly one coordinator, found {}",
                coordinator_count
            )));
        }

        Ok(())
    }

    /// Validate that shared responsibility sums to 1.0 per rule 10.3.3.
    pub fn validate_responsibility(&self) -> Result<()> {
        let shared_sum: f64 = self
            .participants
            .iter()
            .filter_map(|p| match &p.responsibility {
                Responsibility::Shared { share } => Some(*share),
                _ => None,
            })
            .sum();

        // If there are shared responsibilities, they must sum to 1.0
        if shared_sum > 0.0 && (shared_sum - 1.0).abs() > 0.001 {
            return Err(Error::invalid_input(format!(
                "shared responsibility must sum to 1.0, got {}",
                shared_sum
            )));
        }

        Ok(())
    }
}

/// Builder for CoordinatedAction.
#[derive(Debug, Default)]
pub struct CoordinatedActionBuilder {
    id: Option<CoordinationId>,
    coordination_type: Option<CoordinationType>,
    participants: Vec<Participant>,
    action: Option<CoordinatedActionSpec>,
    protocol: Option<CoordinationProtocol>,
    started_at: Option<i64>,
    status: Option<CoordinationStatus>,
    causal_context: Option<CausalContext>,
}

impl CoordinatedActionBuilder {
    /// Create a new builder.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the ID.
    pub fn id(mut self, id: CoordinationId) -> Self {
        self.id = Some(id);
        self
    }

    /// Set the coordination type.
    pub fn coordination_type(mut self, coordination_type: CoordinationType) -> Self {
        self.coordination_type = Some(coordination_type);
        self
    }

    /// Add a participant.
    pub fn participant(mut self, participant: Participant) -> Self {
        self.participants.push(participant);
        self
    }

    /// Set the action specification.
    pub fn action(mut self, action: CoordinatedActionSpec) -> Self {
        self.action = Some(action);
        self
    }

    /// Set the protocol.
    pub fn protocol(mut self, protocol: CoordinationProtocol) -> Self {
        self.protocol = Some(protocol);
        self
    }

    /// Set the start time.
    pub fn started_at(mut self, timestamp: i64) -> Self {
        self.started_at = Some(timestamp);
        self
    }

    /// Set started to now.
    pub fn started_now(mut self) -> Self {
        self.started_at = Some(chrono::Utc::now().timestamp_millis());
        self
    }

    /// Set the status.
    pub fn status(mut self, status: CoordinationStatus) -> Self {
        self.status = Some(status);
        self
    }

    /// Set the causal context.
    pub fn causal_context(mut self, context: CausalContext) -> Self {
        self.causal_context = Some(context);
        self
    }

    /// Build the coordinated action.
    pub fn build(self) -> Result<CoordinatedAction> {
        let id = self.id.unwrap_or_else(CoordinationId::generate);

        let coordination_type = self
            .coordination_type
            .ok_or_else(|| Error::invalid_input("coordination_type is required"))?;

        if self.participants.is_empty() {
            return Err(Error::invalid_input("at least one participant is required"));
        }

        let action = self
            .action
            .ok_or_else(|| Error::invalid_input("action is required"))?;

        let protocol = self
            .protocol
            .ok_or_else(|| Error::invalid_input("protocol is required"))?;

        let started_at = self
            .started_at
            .unwrap_or_else(|| chrono::Utc::now().timestamp_millis());

        let status = self.status.unwrap_or(CoordinationStatus::Initializing);

        let causal_context = self
            .causal_context
            .ok_or_else(|| Error::invalid_input("causal_context is required"))?;

        let coordination = CoordinatedAction {
            id,
            coordination_type,
            participants: self.participants,
            action,
            protocol,
            started_at,
            status,
            causal_context,
        };

        // Validate
        coordination.validate_coordinator()?;
        coordination.validate_responsibility()?;

        Ok(coordination)
    }
}

/// Event recording coordination lifecycle.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum CoordinationEvent {
    /// Coordination initiated.
    Started {
        /// The coordinated action.
        action: CoordinatedAction,
    },
    /// Participant joined.
    ParticipantJoined {
        /// Coordination ID.
        coordination_id: CoordinationId,
        /// Participant who joined.
        participant: Participant,
    },
    /// Task assigned.
    TaskAssigned {
        /// Coordination ID.
        coordination_id: CoordinationId,
        /// Agent assigned the task.
        agent: PublicKey,
        /// The task.
        task: Task,
    },
    /// Task completed.
    TaskCompleted {
        /// Coordination ID.
        coordination_id: CoordinationId,
        /// Task ID.
        task_id: TaskId,
        /// Agent who completed.
        agent: PublicKey,
        /// Outcome.
        outcome: ActionOutcome,
    },
    /// Agent-to-agent message.
    Message {
        /// Coordination ID.
        coordination_id: CoordinationId,
        /// Sender.
        from: PublicKey,
        /// Recipient.
        to: PublicKey,
        /// Hash of message content.
        message_hash: Hash,
    },
    /// Disagreement between agents.
    Disagreement {
        /// Coordination ID.
        coordination_id: CoordinationId,
        /// Agents involved.
        agents: Vec<PublicKey>,
        /// Subject of disagreement.
        subject: String,
        /// Positions (key is hex-encoded public key).
        positions: HashMap<String, String>,
    },
    /// Coordination completed.
    Completed {
        /// Coordination ID.
        coordination_id: CoordinationId,
        /// Result.
        result: CoordinationResult,
    },
    /// Coordination failed.
    Failed {
        /// Coordination ID.
        coordination_id: CoordinationId,
        /// Reason.
        reason: String,
        /// When failed (Unix timestamp ms).
        failed_at: i64,
    },
}

impl CoordinationEvent {
    /// Create a started event.
    pub fn started(action: CoordinatedAction) -> Self {
        Self::Started { action }
    }

    /// Create a participant joined event.
    pub fn participant_joined(coordination_id: CoordinationId, participant: Participant) -> Self {
        Self::ParticipantJoined {
            coordination_id,
            participant,
        }
    }

    /// Create a task assigned event.
    pub fn task_assigned(coordination_id: CoordinationId, agent: PublicKey, task: Task) -> Self {
        Self::TaskAssigned {
            coordination_id,
            agent,
            task,
        }
    }

    /// Create a task completed event.
    pub fn task_completed(
        coordination_id: CoordinationId,
        task_id: TaskId,
        agent: PublicKey,
        outcome: ActionOutcome,
    ) -> Self {
        Self::TaskCompleted {
            coordination_id,
            task_id,
            agent,
            outcome,
        }
    }

    /// Create a message event.
    pub fn message(
        coordination_id: CoordinationId,
        from: PublicKey,
        to: PublicKey,
        message_hash: Hash,
    ) -> Self {
        Self::Message {
            coordination_id,
            from,
            to,
            message_hash,
        }
    }

    /// Create a disagreement event.
    pub fn disagreement(
        coordination_id: CoordinationId,
        agents: Vec<PublicKey>,
        subject: impl Into<String>,
    ) -> Self {
        Self::Disagreement {
            coordination_id,
            agents,
            subject: subject.into(),
            positions: HashMap::new(),
        }
    }

    /// Create a completed event.
    pub fn completed(coordination_id: CoordinationId, result: CoordinationResult) -> Self {
        Self::Completed {
            coordination_id,
            result,
        }
    }

    /// Create a failed event.
    pub fn failed(coordination_id: CoordinationId, reason: impl Into<String>) -> Self {
        Self::Failed {
            coordination_id,
            reason: reason.into(),
            failed_at: chrono::Utc::now().timestamp_millis(),
        }
    }

    /// Get the coordination ID from any event variant.
    pub fn coordination_id(&self) -> CoordinationId {
        match self {
            CoordinationEvent::Started { action } => action.id(),
            CoordinationEvent::ParticipantJoined {
                coordination_id, ..
            } => *coordination_id,
            CoordinationEvent::TaskAssigned {
                coordination_id, ..
            } => *coordination_id,
            CoordinationEvent::TaskCompleted {
                coordination_id, ..
            } => *coordination_id,
            CoordinationEvent::Message {
                coordination_id, ..
            } => *coordination_id,
            CoordinationEvent::Disagreement {
                coordination_id, ..
            } => *coordination_id,
            CoordinationEvent::Completed {
                coordination_id, ..
            } => *coordination_id,
            CoordinationEvent::Failed {
                coordination_id, ..
            } => *coordination_id,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent::principal::PrincipalId;
    use crate::agent::session::SessionId;
    use crate::crypto::SecretKey;
    use crate::event::EventId;

    fn test_key() -> SecretKey {
        SecretKey::generate()
    }

    fn test_causal_context() -> CausalContext {
        let principal = PrincipalId::user("test@example.com").unwrap();
        CausalContext::builder()
            .parent_event_id(EventId(hash(b"parent")))
            .root_event_id(EventId(hash(b"root")))
            .session_id(SessionId::random())
            .principal(principal)
            .sequence(1)
            .depth(1)
            .build()
            .unwrap()
    }

    // === CoordinationId Tests ===

    #[test]
    fn coordination_id_generates_unique() {
        let id1 = CoordinationId::generate();
        let id2 = CoordinationId::generate();
        assert_ne!(id1, id2);
    }

    #[test]
    fn coordination_id_hex_roundtrip() {
        let id = CoordinationId::generate();
        let hex = id.to_hex();
        let restored = CoordinationId::from_hex(&hex).unwrap();
        assert_eq!(id, restored);
    }

    // === TaskId Tests ===

    #[test]
    fn task_id_generates_unique() {
        let id1 = TaskId::generate();
        let id2 = TaskId::generate();
        assert_ne!(id1, id2);
    }

    // === CoordinationType Tests ===

    #[test]
    fn coordination_type_display() {
        assert_eq!(CoordinationType::Parallel.to_string(), "parallel");
        assert_eq!(CoordinationType::Pipeline.to_string(), "pipeline");
        assert_eq!(CoordinationType::Consensus.to_string(), "consensus");
    }

    // === ParticipantRole Tests ===

    #[test]
    fn participant_role_can_execute() {
        assert!(ParticipantRole::Coordinator.can_execute());
        assert!(ParticipantRole::Peer.can_execute());
        assert!(!ParticipantRole::Observer.can_execute());
    }

    #[test]
    fn participant_role_can_supervise() {
        assert!(ParticipantRole::Coordinator.can_supervise());
        assert!(ParticipantRole::Supervisor.can_supervise());
        assert!(!ParticipantRole::Peer.can_supervise());
        assert!(!ParticipantRole::Observer.can_supervise());
    }

    // === Responsibility Tests ===

    #[test]
    fn responsibility_share() {
        assert_eq!(Responsibility::individual().share(), 1.0);
        assert_eq!(Responsibility::shared(0.5).share(), 0.5);

        let key = test_key();
        assert_eq!(Responsibility::delegated(key.public_key()).share(), 0.0);
        assert_eq!(Responsibility::supervised(key.public_key()).share(), 0.0);
    }

    #[test]
    fn responsibility_share_clamped() {
        assert_eq!(Responsibility::shared(1.5).share(), 1.0);
        assert_eq!(Responsibility::shared(-0.5).share(), 0.0);
    }

    // === Task Tests ===

    #[test]
    fn task_creation() {
        let task = Task::new("Process data")
            .with_capabilities(vec![CapabilityKind::Read])
            .with_deadline(chrono::Utc::now().timestamp_millis() + 60000);

        assert_eq!(task.description(), "Process data");
        assert_eq!(task.required_capabilities().len(), 1);
        assert!(task.deadline().is_some());
    }

    #[test]
    fn task_overdue() {
        let past = chrono::Utc::now().timestamp_millis() - 1000;
        let task = Task::new("Late task").with_deadline(past);
        assert!(task.is_overdue());

        let future = chrono::Utc::now().timestamp_millis() + 60000;
        let task = Task::new("Future task").with_deadline(future);
        assert!(!task.is_overdue());
    }

    // === CoordinatedActionSpec Tests ===

    #[test]
    fn action_spec_hash_deterministic() {
        let spec1 = CoordinatedActionSpec::new("Complete task");
        let spec2 = CoordinatedActionSpec::new("Complete task");
        assert_eq!(spec1.hash(), spec2.hash());
    }

    // === CoordinationStatus Tests ===

    #[test]
    fn coordination_status_is_active() {
        assert!(CoordinationStatus::Initializing.is_active());
        assert!(CoordinationStatus::WaitingCommitment.is_active());
        assert!(CoordinationStatus::active(0.5).is_active());

        let key = test_key();
        assert!(!CoordinationStatus::aborted("test", key.public_key()).is_active());
    }

    #[test]
    fn coordination_status_progress() {
        assert_eq!(CoordinationStatus::active(0.75).progress(), Some(0.75));
        assert_eq!(CoordinationStatus::Initializing.progress(), None);
    }

    // === CoordinatedAction Tests ===

    #[test]
    fn coordinated_action_requires_coordinator() {
        let key = test_key();
        let participant = Participant::new(
            key.public_key(),
            ParticipantRole::Peer, // Not a coordinator
            Responsibility::individual(),
            Sig::empty(),
        );

        let result = CoordinatedAction::builder()
            .coordination_type(CoordinationType::Parallel)
            .participant(participant)
            .action(CoordinatedActionSpec::new("Test"))
            .protocol(CoordinationProtocol::TwoPhaseCommit)
            .causal_context(test_causal_context())
            .started_now()
            .build();

        assert!(result.is_err());
    }

    #[test]
    fn coordinated_action_valid() {
        let coordinator_key = test_key();
        let peer_key = test_key();

        let coordinator = Participant::new(
            coordinator_key.public_key(),
            ParticipantRole::Coordinator,
            Responsibility::individual(),
            Sig::empty(),
        );

        let peer = Participant::new(
            peer_key.public_key(),
            ParticipantRole::Peer,
            Responsibility::individual(),
            Sig::empty(),
        );

        let action = CoordinatedAction::builder()
            .coordination_type(CoordinationType::Parallel)
            .participant(coordinator)
            .participant(peer)
            .action(CoordinatedActionSpec::new("Complete task together"))
            .protocol(CoordinationProtocol::TwoPhaseCommit)
            .causal_context(test_causal_context())
            .started_now()
            .build()
            .unwrap();

        assert!(action.coordinator().is_some());
        assert_eq!(action.participants().len(), 2);
    }

    #[test]
    fn coordinated_action_shared_responsibility_must_sum() {
        let key1 = test_key();
        let key2 = test_key();

        // Shared responsibilities that don't sum to 1.0
        let p1 = Participant::new(
            key1.public_key(),
            ParticipantRole::Coordinator,
            Responsibility::shared(0.3),
            Sig::empty(),
        );

        let p2 = Participant::new(
            key2.public_key(),
            ParticipantRole::Peer,
            Responsibility::shared(0.3), // Total = 0.6, not 1.0
            Sig::empty(),
        );

        let result = CoordinatedAction::builder()
            .coordination_type(CoordinationType::Parallel)
            .participant(p1)
            .participant(p2)
            .action(CoordinatedActionSpec::new("Test"))
            .protocol(CoordinationProtocol::TwoPhaseCommit)
            .causal_context(test_causal_context())
            .build();

        assert!(result.is_err());
    }

    #[test]
    fn coordinated_action_valid_shared_responsibility() {
        let key1 = test_key();
        let key2 = test_key();

        let p1 = Participant::new(
            key1.public_key(),
            ParticipantRole::Coordinator,
            Responsibility::shared(0.6),
            Sig::empty(),
        );

        let p2 = Participant::new(
            key2.public_key(),
            ParticipantRole::Peer,
            Responsibility::shared(0.4), // Total = 1.0
            Sig::empty(),
        );

        let result = CoordinatedAction::builder()
            .coordination_type(CoordinationType::Parallel)
            .participant(p1)
            .participant(p2)
            .action(CoordinatedActionSpec::new("Test"))
            .protocol(CoordinationProtocol::TwoPhaseCommit)
            .causal_context(test_causal_context())
            .build();

        assert!(result.is_ok());
    }

    // === CoordinationEvent Tests ===

    #[test]
    fn coordination_event_started() {
        let key = test_key();
        let coordinator = Participant::new(
            key.public_key(),
            ParticipantRole::Coordinator,
            Responsibility::individual(),
            Sig::empty(),
        );

        let action = CoordinatedAction::builder()
            .coordination_type(CoordinationType::Pipeline)
            .participant(coordinator)
            .action(CoordinatedActionSpec::new("Pipeline task"))
            .protocol(CoordinationProtocol::LeaderFollower)
            .causal_context(test_causal_context())
            .started_now()
            .build()
            .unwrap();

        let coord_id = action.id();
        let event = CoordinationEvent::started(action);
        assert_eq!(event.coordination_id(), coord_id);
    }

    #[test]
    fn coordination_event_task_completed() {
        let key = test_key();
        let coord_id = CoordinationId::generate();
        let task_id = TaskId::generate();

        let event = CoordinationEvent::task_completed(
            coord_id,
            task_id,
            key.public_key(),
            ActionOutcome::success(serde_json::json!({"status": "done"})),
        );

        assert_eq!(event.coordination_id(), coord_id);
    }

    #[test]
    fn coordination_event_message() {
        let key1 = test_key();
        let key2 = test_key();
        let coord_id = CoordinationId::generate();

        let event = CoordinationEvent::message(
            coord_id,
            key1.public_key(),
            key2.public_key(),
            hash(b"message content"),
        );

        assert_eq!(event.coordination_id(), coord_id);
    }

    // === CoordinationResult Tests ===

    #[test]
    fn coordination_result_with_agent_outcomes() {
        let key1 = test_key();
        let key2 = test_key();

        let result = CoordinationResult::new(
            ActionOutcome::success(serde_json::json!({})),
            serde_json::json!({"combined": true}),
            CoordinationMetrics::new(5000),
        )
        .with_agent_outcome(
            &key1.public_key(),
            ActionOutcome::success(serde_json::json!({})),
        )
        .with_agent_outcome(
            &key2.public_key(),
            ActionOutcome::success(serde_json::json!({})),
        );

        assert!(result.is_success());
        assert!(result.agent_outcome(&key1.public_key()).is_some());
        assert!(result.agent_outcome(&key2.public_key()).is_some());
    }

    // === CoordinationMetrics Tests ===

    #[test]
    fn coordination_metrics() {
        let key = test_key();
        let metrics = CoordinationMetrics::new(10000)
            .with_agent_duration(&key.public_key(), 5000)
            .with_overhead(500)
            .with_retries(2);

        assert_eq!(metrics.total_duration(), 10000);
        assert_eq!(metrics.agent_duration(&key.public_key()), Some(5000));
        assert_eq!(metrics.communication_overhead(), 500);
        assert_eq!(metrics.retry_count(), 2);
    }
}
