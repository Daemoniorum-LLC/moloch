//! Reasoning traces for agent decision transparency.
//!
//! Reasoning traces capture the agent's decision-making process. They answer:
//! "Why did the agent decide to do this?"

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::crypto::{hash, Hash, PublicKey};
use crate::error::{Error, Result};
use crate::event::EventId;

/// Unique trace identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TraceId(pub [u8; 16]);

impl TraceId {
    /// Generate a new random trace ID.
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
            return Err(Error::invalid_input("trace ID must be 16 bytes"));
        }
        let mut arr = [0u8; 16];
        arr.copy_from_slice(&bytes);
        Ok(Self(arr))
    }
}

impl std::fmt::Display for TraceId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

/// Priority level for goals.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Priority {
    /// Background task, can be deferred.
    Low,
    /// Normal priority.
    Normal,
    /// Should be handled soon.
    High,
    /// Requires immediate attention.
    Critical,
}

impl Default for Priority {
    fn default() -> Self {
        Self::Normal
    }
}

impl std::fmt::Display for Priority {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Priority::Low => write!(f, "low"),
            Priority::Normal => write!(f, "normal"),
            Priority::High => write!(f, "high"),
            Priority::Critical => write!(f, "critical"),
        }
    }
}

/// Source of a goal.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum GoalSource {
    /// Direct user instruction.
    UserInstruction { event_id: EventId },
    /// Derived from higher-level goal.
    Derived { parent_goal_description: String },
    /// System-defined goal.
    System { policy: String },
}

/// The goal driving agent behavior.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Goal {
    /// Human-readable goal description.
    description: String,
    /// Structured goal representation.
    structured: Option<serde_json::Value>,
    /// Where this goal came from.
    source: GoalSource,
    /// Priority level.
    priority: Priority,
}

impl Goal {
    /// Create a new goal from user instruction.
    pub fn from_user(description: impl Into<String>, event_id: EventId) -> Self {
        Self {
            description: description.into(),
            structured: None,
            source: GoalSource::UserInstruction { event_id },
            priority: Priority::Normal,
        }
    }

    /// Create a derived goal.
    pub fn derived(description: impl Into<String>, parent_description: impl Into<String>) -> Self {
        Self {
            description: description.into(),
            structured: None,
            source: GoalSource::Derived {
                parent_goal_description: parent_description.into(),
            },
            priority: Priority::Normal,
        }
    }

    /// Create a system goal.
    pub fn system(description: impl Into<String>, policy: impl Into<String>) -> Self {
        Self {
            description: description.into(),
            structured: None,
            source: GoalSource::System {
                policy: policy.into(),
            },
            priority: Priority::Normal,
        }
    }

    /// Set structured representation.
    pub fn with_structured(mut self, structured: serde_json::Value) -> Self {
        self.structured = Some(structured);
        self
    }

    /// Set priority.
    pub fn with_priority(mut self, priority: Priority) -> Self {
        self.priority = priority;
        self
    }

    /// Get the description.
    pub fn description(&self) -> &str {
        &self.description
    }

    /// Get the structured representation.
    pub fn structured(&self) -> Option<&serde_json::Value> {
        self.structured.as_ref()
    }

    /// Get the source.
    pub fn source(&self) -> &GoalSource {
        &self.source
    }

    /// Get the priority.
    pub fn priority(&self) -> Priority {
        self.priority
    }
}

/// Action taken during a reasoning step.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum StepAction {
    /// Retrieved information.
    Retrieve { query: String, source: String },
    /// Analyzed data.
    Analyze { subject: String, method: String },
    /// Invoked a tool.
    ToolCall { tool: String, input_hash: Hash },
    /// Delegated to another agent.
    Delegate { agent: PublicKey, task: String },
    /// Made a decision.
    Decide { decision: String },
}

impl StepAction {
    /// Create a retrieve action.
    pub fn retrieve(query: impl Into<String>, source: impl Into<String>) -> Self {
        Self::Retrieve {
            query: query.into(),
            source: source.into(),
        }
    }

    /// Create an analyze action.
    pub fn analyze(subject: impl Into<String>, method: impl Into<String>) -> Self {
        Self::Analyze {
            subject: subject.into(),
            method: method.into(),
        }
    }

    /// Create a tool call action.
    pub fn tool_call(tool: impl Into<String>, input_hash: Hash) -> Self {
        Self::ToolCall {
            tool: tool.into(),
            input_hash,
        }
    }

    /// Create a delegate action.
    pub fn delegate(agent: PublicKey, task: impl Into<String>) -> Self {
        Self::Delegate {
            agent,
            task: task.into(),
        }
    }

    /// Create a decide action.
    pub fn decide(decision: impl Into<String>) -> Self {
        Self::Decide {
            decision: decision.into(),
        }
    }
}

/// A single step in reasoning.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReasoningStep {
    /// Step sequence number.
    sequence: u32,
    /// What the agent was thinking.
    thought: String,
    /// What action was taken (if any).
    action: Option<StepAction>,
    /// Observation from the action.
    observation: Option<String>,
    /// Timestamp of this step (Unix timestamp ms).
    timestamp: i64,
}

impl ReasoningStep {
    /// Create a new reasoning step.
    pub fn new(sequence: u32, thought: impl Into<String>) -> Self {
        Self {
            sequence,
            thought: thought.into(),
            action: None,
            observation: None,
            timestamp: chrono::Utc::now().timestamp_millis(),
        }
    }

    /// Set the action.
    pub fn with_action(mut self, action: StepAction) -> Self {
        self.action = Some(action);
        self
    }

    /// Set the observation.
    pub fn with_observation(mut self, observation: impl Into<String>) -> Self {
        self.observation = Some(observation.into());
        self
    }

    /// Set the timestamp.
    pub fn with_timestamp(mut self, timestamp: i64) -> Self {
        self.timestamp = timestamp;
        self
    }

    /// Get the sequence number.
    pub fn sequence(&self) -> u32 {
        self.sequence
    }

    /// Get the thought.
    pub fn thought(&self) -> &str {
        &self.thought
    }

    /// Get the action.
    pub fn action(&self) -> Option<&StepAction> {
        self.action.as_ref()
    }

    /// Get the observation.
    pub fn observation(&self) -> Option<&str> {
        self.observation.as_deref()
    }

    /// Get the timestamp.
    pub fn timestamp(&self) -> i64 {
        self.timestamp
    }
}

/// The decision reached.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Decision {
    /// What was decided.
    action: String,
    /// Why this was chosen.
    rationale: String,
    /// Expected outcome.
    expected_outcome: String,
    /// How to verify success.
    success_criteria: Vec<String>,
}

impl Decision {
    /// Create a new decision.
    pub fn new(
        action: impl Into<String>,
        rationale: impl Into<String>,
        expected_outcome: impl Into<String>,
    ) -> Self {
        Self {
            action: action.into(),
            rationale: rationale.into(),
            expected_outcome: expected_outcome.into(),
            success_criteria: Vec::new(),
        }
    }

    /// Add a success criterion.
    pub fn with_criterion(mut self, criterion: impl Into<String>) -> Self {
        self.success_criteria.push(criterion.into());
        self
    }

    /// Add multiple success criteria.
    pub fn with_criteria(mut self, criteria: Vec<String>) -> Self {
        self.success_criteria = criteria;
        self
    }

    /// Get the action.
    pub fn action(&self) -> &str {
        &self.action
    }

    /// Get the rationale.
    pub fn rationale(&self) -> &str {
        &self.rationale
    }

    /// Get the expected outcome.
    pub fn expected_outcome(&self) -> &str {
        &self.expected_outcome
    }

    /// Get the success criteria.
    pub fn success_criteria(&self) -> &[String] {
        &self.success_criteria
    }
}

/// Confidence assessment.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Confidence {
    /// Overall confidence score (0.0 - 1.0).
    score: f64,
    /// Confidence breakdown by factor.
    breakdown: HashMap<String, f64>,
    /// Uncertainty sources.
    uncertainties: Vec<String>,
    /// What would increase confidence.
    would_help: Vec<String>,
}

impl Confidence {
    /// Create a new confidence assessment.
    pub fn new(score: f64) -> Self {
        Self {
            score: score.clamp(0.0, 1.0),
            breakdown: HashMap::new(),
            uncertainties: Vec::new(),
            would_help: Vec::new(),
        }
    }

    /// Create high confidence (0.9).
    pub fn high() -> Self {
        Self::new(0.9)
    }

    /// Create medium confidence (0.7).
    pub fn medium() -> Self {
        Self::new(0.7)
    }

    /// Create low confidence (0.4).
    pub fn low() -> Self {
        Self::new(0.4)
    }

    /// Add a breakdown factor.
    pub fn with_factor(mut self, factor: impl Into<String>, score: f64) -> Self {
        self.breakdown.insert(factor.into(), score.clamp(0.0, 1.0));
        self
    }

    /// Add an uncertainty.
    pub fn with_uncertainty(mut self, uncertainty: impl Into<String>) -> Self {
        self.uncertainties.push(uncertainty.into());
        self
    }

    /// Add something that would help.
    pub fn with_would_help(mut self, help: impl Into<String>) -> Self {
        self.would_help.push(help.into());
        self
    }

    /// Get the score.
    pub fn score(&self) -> f64 {
        self.score
    }

    /// Get the breakdown.
    pub fn breakdown(&self) -> &HashMap<String, f64> {
        &self.breakdown
    }

    /// Get the uncertainties.
    pub fn uncertainties(&self) -> &[String] {
        &self.uncertainties
    }

    /// Get what would help.
    pub fn would_help(&self) -> &[String] {
        &self.would_help
    }

    /// Check if confidence is below the rejection threshold (0.3).
    pub fn should_reject(&self) -> bool {
        self.score < 0.3
    }

    /// Check if confidence is below the approval threshold (0.5).
    pub fn requires_approval(&self) -> bool {
        self.score < 0.5
    }

    /// Check if confidence is below the warning threshold (0.7).
    pub fn should_warn(&self) -> bool {
        self.score < 0.7
    }
}

/// An alternative that was considered.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Alternative {
    /// Description of the alternative.
    description: String,
    /// Why it was not chosen.
    rejection_reason: String,
    /// Estimated outcome if chosen.
    estimated_outcome: String,
    /// Confidence if this were chosen.
    confidence: f64,
}

impl Alternative {
    /// Create a new alternative.
    pub fn new(
        description: impl Into<String>,
        rejection_reason: impl Into<String>,
        estimated_outcome: impl Into<String>,
        confidence: f64,
    ) -> Self {
        Self {
            description: description.into(),
            rejection_reason: rejection_reason.into(),
            estimated_outcome: estimated_outcome.into(),
            confidence: confidence.clamp(0.0, 1.0),
        }
    }

    /// Get the description.
    pub fn description(&self) -> &str {
        &self.description
    }

    /// Get the rejection reason.
    pub fn rejection_reason(&self) -> &str {
        &self.rejection_reason
    }

    /// Get the estimated outcome.
    pub fn estimated_outcome(&self) -> &str {
        &self.estimated_outcome
    }

    /// Get the confidence.
    pub fn confidence(&self) -> f64 {
        self.confidence
    }
}

/// A factor influencing the decision.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Factor {
    /// Factor description.
    description: String,
    /// How much it influenced (positive = toward, negative = against).
    influence: f64,
    /// Evidence supporting this factor.
    evidence: Vec<String>,
}

impl Factor {
    /// Create a new factor.
    pub fn new(description: impl Into<String>, influence: f64) -> Self {
        Self {
            description: description.into(),
            influence: influence.clamp(-1.0, 1.0),
            evidence: Vec::new(),
        }
    }

    /// Create a positive factor (toward the decision).
    pub fn positive(description: impl Into<String>, influence: f64) -> Self {
        Self::new(description, influence.abs())
    }

    /// Create a negative factor (against the decision).
    pub fn negative(description: impl Into<String>, influence: f64) -> Self {
        Self::new(description, -influence.abs())
    }

    /// Add evidence.
    pub fn with_evidence(mut self, evidence: impl Into<String>) -> Self {
        self.evidence.push(evidence.into());
        self
    }

    /// Get the description.
    pub fn description(&self) -> &str {
        &self.description
    }

    /// Get the influence.
    pub fn influence(&self) -> f64 {
        self.influence
    }

    /// Get the evidence.
    pub fn evidence(&self) -> &[String] {
        &self.evidence
    }

    /// Check if this factor supports the decision.
    pub fn is_supportive(&self) -> bool {
        self.influence > 0.0
    }
}

/// Complete trace of agent reasoning.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReasoningTrace {
    /// Unique trace identifier.
    id: TraceId,
    /// The goal the agent was pursuing.
    goal: Goal,
    /// Steps in the reasoning process.
    steps: Vec<ReasoningStep>,
    /// Final decision reached.
    decision: Decision,
    /// Confidence in the decision.
    confidence: Confidence,
    /// Alternative actions considered.
    alternatives: Vec<Alternative>,
    /// Factors that influenced the decision.
    factors: Vec<Factor>,
    /// Hash of the full trace for integrity.
    trace_hash: Hash,
}

impl ReasoningTrace {
    /// Create a new reasoning trace builder.
    pub fn builder() -> ReasoningTraceBuilder {
        ReasoningTraceBuilder::new()
    }

    /// Get the trace ID.
    pub fn id(&self) -> TraceId {
        self.id
    }

    /// Get the goal.
    pub fn goal(&self) -> &Goal {
        &self.goal
    }

    /// Get the steps.
    pub fn steps(&self) -> &[ReasoningStep] {
        &self.steps
    }

    /// Get the decision.
    pub fn decision(&self) -> &Decision {
        &self.decision
    }

    /// Get the confidence.
    pub fn confidence(&self) -> &Confidence {
        &self.confidence
    }

    /// Get the alternatives.
    pub fn alternatives(&self) -> &[Alternative] {
        &self.alternatives
    }

    /// Get the factors.
    pub fn factors(&self) -> &[Factor] {
        &self.factors
    }

    /// Get the trace hash.
    pub fn trace_hash(&self) -> Hash {
        self.trace_hash
    }

    /// Compute the canonical bytes for hashing.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(&self.id.0);

        // Include goal
        let goal_json = serde_json::to_vec(&self.goal).unwrap_or_default();
        data.extend_from_slice(&goal_json);

        // Include steps
        for step in &self.steps {
            let step_json = serde_json::to_vec(step).unwrap_or_default();
            data.extend_from_slice(&step_json);
        }

        // Include decision
        let decision_json = serde_json::to_vec(&self.decision).unwrap_or_default();
        data.extend_from_slice(&decision_json);

        // Include confidence
        data.extend_from_slice(&self.confidence.score.to_le_bytes());

        // Include alternatives
        for alt in &self.alternatives {
            let alt_json = serde_json::to_vec(alt).unwrap_or_default();
            data.extend_from_slice(&alt_json);
        }

        // Include factors
        for factor in &self.factors {
            let factor_json = serde_json::to_vec(factor).unwrap_or_default();
            data.extend_from_slice(&factor_json);
        }

        data
    }

    /// Verify the trace hash matches the content.
    pub fn verify_integrity(&self) -> bool {
        let computed = hash(&self.canonical_bytes());
        computed == self.trace_hash
    }

    /// Check if this trace is complete per spec rule 7.3.2.
    pub fn is_complete(&self) -> bool {
        // Must have goal
        if self.goal.description.is_empty() {
            return false;
        }

        // Must have at least one step
        if self.steps.is_empty() {
            return false;
        }

        // Must have decision
        if self.decision.action.is_empty() {
            return false;
        }

        // Confidence score must be valid
        if !(0.0..=1.0).contains(&self.confidence.score) {
            return false;
        }

        true
    }
}

/// Builder for ReasoningTrace.
#[derive(Debug, Default)]
pub struct ReasoningTraceBuilder {
    id: Option<TraceId>,
    goal: Option<Goal>,
    steps: Vec<ReasoningStep>,
    decision: Option<Decision>,
    confidence: Option<Confidence>,
    alternatives: Vec<Alternative>,
    factors: Vec<Factor>,
}

impl ReasoningTraceBuilder {
    /// Create a new builder.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the trace ID.
    pub fn id(mut self, id: TraceId) -> Self {
        self.id = Some(id);
        self
    }

    /// Set the goal.
    pub fn goal(mut self, goal: Goal) -> Self {
        self.goal = Some(goal);
        self
    }

    /// Add a reasoning step.
    pub fn step(mut self, step: ReasoningStep) -> Self {
        self.steps.push(step);
        self
    }

    /// Add multiple steps.
    pub fn steps(mut self, steps: Vec<ReasoningStep>) -> Self {
        self.steps = steps;
        self
    }

    /// Set the decision.
    pub fn decision(mut self, decision: Decision) -> Self {
        self.decision = Some(decision);
        self
    }

    /// Set the confidence.
    pub fn confidence(mut self, confidence: Confidence) -> Self {
        self.confidence = Some(confidence);
        self
    }

    /// Add an alternative.
    pub fn alternative(mut self, alternative: Alternative) -> Self {
        self.alternatives.push(alternative);
        self
    }

    /// Add a factor.
    pub fn factor(mut self, factor: Factor) -> Self {
        self.factors.push(factor);
        self
    }

    /// Build the reasoning trace.
    pub fn build(self) -> Result<ReasoningTrace> {
        let id = self.id.unwrap_or_else(TraceId::generate);

        let goal = self
            .goal
            .ok_or_else(|| Error::invalid_input("goal is required"))?;

        if self.steps.is_empty() {
            return Err(Error::invalid_input(
                "at least one reasoning step is required",
            ));
        }

        let decision = self
            .decision
            .ok_or_else(|| Error::invalid_input("decision is required"))?;

        let confidence = self.confidence.unwrap_or_else(Confidence::medium);

        let mut trace = ReasoningTrace {
            id,
            goal,
            steps: self.steps,
            decision,
            confidence,
            alternatives: self.alternatives,
            factors: self.factors,
            trace_hash: Hash::from_bytes([0u8; 32]), // Placeholder
        };

        // Compute the hash
        trace.trace_hash = hash(&trace.canonical_bytes());

        Ok(trace)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_event_id() -> EventId {
        EventId(hash(b"test-event"))
    }

    // === TraceId Tests ===

    #[test]
    fn trace_id_generates_unique() {
        let id1 = TraceId::generate();
        let id2 = TraceId::generate();
        assert_ne!(id1, id2);
    }

    #[test]
    fn trace_id_hex_roundtrip() {
        let id = TraceId::generate();
        let hex = id.to_hex();
        let restored = TraceId::from_hex(&hex).unwrap();
        assert_eq!(id, restored);
    }

    // === Priority Tests ===

    #[test]
    fn priority_ordering() {
        assert!(Priority::Low < Priority::Normal);
        assert!(Priority::Normal < Priority::High);
        assert!(Priority::High < Priority::Critical);
    }

    // === Goal Tests ===

    #[test]
    fn goal_from_user() {
        let goal = Goal::from_user("Complete the task", test_event_id());
        assert_eq!(goal.description(), "Complete the task");
        assert!(matches!(goal.source(), GoalSource::UserInstruction { .. }));
    }

    #[test]
    fn goal_derived() {
        let goal = Goal::derived("Sub-task", "Parent task");
        assert_eq!(goal.description(), "Sub-task");
        assert!(matches!(goal.source(), GoalSource::Derived { .. }));
    }

    #[test]
    fn goal_with_priority() {
        let goal =
            Goal::from_user("Urgent task", test_event_id()).with_priority(Priority::Critical);
        assert_eq!(goal.priority(), Priority::Critical);
    }

    // === ReasoningStep Tests ===

    #[test]
    fn reasoning_step_basic() {
        let step = ReasoningStep::new(1, "Analyzing the problem");
        assert_eq!(step.sequence(), 1);
        assert_eq!(step.thought(), "Analyzing the problem");
        assert!(step.action().is_none());
    }

    #[test]
    fn reasoning_step_with_action() {
        let step = ReasoningStep::new(1, "Looking up information")
            .with_action(StepAction::retrieve("user data", "database"));
        assert!(step.action().is_some());
    }

    #[test]
    fn reasoning_step_with_observation() {
        let step = ReasoningStep::new(1, "Checking status").with_observation("Status is active");
        assert_eq!(step.observation(), Some("Status is active"));
    }

    // === Decision Tests ===

    #[test]
    fn decision_basic() {
        let decision = Decision::new(
            "Proceed with option A",
            "It has the highest success probability",
            "Task completed successfully",
        );
        assert_eq!(decision.action(), "Proceed with option A");
        assert_eq!(
            decision.rationale(),
            "It has the highest success probability"
        );
    }

    #[test]
    fn decision_with_criteria() {
        let decision = Decision::new("Execute", "Best option", "Success")
            .with_criterion("Output matches expected format")
            .with_criterion("No errors in logs");
        assert_eq!(decision.success_criteria().len(), 2);
    }

    // === Confidence Tests ===

    #[test]
    fn confidence_clamped() {
        let conf = Confidence::new(1.5);
        assert_eq!(conf.score(), 1.0);

        let conf2 = Confidence::new(-0.5);
        assert_eq!(conf2.score(), 0.0);
    }

    #[test]
    fn confidence_thresholds() {
        let low = Confidence::new(0.2);
        assert!(low.should_reject());
        assert!(low.requires_approval());
        assert!(low.should_warn());

        let medium = Confidence::new(0.6);
        assert!(!medium.should_reject());
        assert!(!medium.requires_approval());
        assert!(medium.should_warn());

        let high = Confidence::new(0.8);
        assert!(!high.should_reject());
        assert!(!high.requires_approval());
        assert!(!high.should_warn());
    }

    #[test]
    fn confidence_with_breakdown() {
        let conf = Confidence::medium()
            .with_factor("data_quality", 0.8)
            .with_factor("model_accuracy", 0.6)
            .with_uncertainty("Limited training data");

        assert_eq!(conf.breakdown().len(), 2);
        assert_eq!(conf.uncertainties().len(), 1);
    }

    // === Alternative Tests ===

    #[test]
    fn alternative_basic() {
        let alt = Alternative::new(
            "Option B",
            "Higher cost",
            "Same result but more expensive",
            0.6,
        );
        assert_eq!(alt.description(), "Option B");
        assert_eq!(alt.rejection_reason(), "Higher cost");
    }

    // === Factor Tests ===

    #[test]
    fn factor_positive() {
        let factor = Factor::positive("Strong evidence", 0.8);
        assert!(factor.is_supportive());
        assert_eq!(factor.influence(), 0.8);
    }

    #[test]
    fn factor_negative() {
        let factor = Factor::negative("Risk of failure", 0.3);
        assert!(!factor.is_supportive());
        assert_eq!(factor.influence(), -0.3);
    }

    #[test]
    fn factor_with_evidence() {
        let factor = Factor::positive("Proven approach", 0.9)
            .with_evidence("Study A shows 95% success rate")
            .with_evidence("Historical data confirms");
        assert_eq!(factor.evidence().len(), 2);
    }

    // === ReasoningTrace Tests ===

    #[test]
    fn reasoning_trace_requires_goal() {
        let result = ReasoningTrace::builder()
            .step(ReasoningStep::new(1, "Thinking"))
            .decision(Decision::new("Do it", "Because", "Success"))
            .build();
        assert!(result.is_err());
    }

    #[test]
    fn reasoning_trace_requires_steps() {
        let result = ReasoningTrace::builder()
            .goal(Goal::from_user("Task", test_event_id()))
            .decision(Decision::new("Do it", "Because", "Success"))
            .build();
        assert!(result.is_err());
    }

    #[test]
    fn reasoning_trace_requires_decision() {
        let result = ReasoningTrace::builder()
            .goal(Goal::from_user("Task", test_event_id()))
            .step(ReasoningStep::new(1, "Thinking"))
            .build();
        assert!(result.is_err());
    }

    #[test]
    fn reasoning_trace_complete() {
        let trace = ReasoningTrace::builder()
            .goal(Goal::from_user("Complete the task", test_event_id()))
            .step(ReasoningStep::new(1, "Analyzing requirements"))
            .step(ReasoningStep::new(2, "Evaluating options"))
            .decision(Decision::new(
                "Use approach A",
                "Most efficient",
                "Task completed",
            ))
            .confidence(Confidence::high())
            .alternative(Alternative::new("Approach B", "Slower", "Same result", 0.7))
            .factor(Factor::positive("Clear requirements", 0.9))
            .build()
            .unwrap();

        assert!(trace.is_complete());
        assert_eq!(trace.steps().len(), 2);
        assert_eq!(trace.alternatives().len(), 1);
        assert_eq!(trace.factors().len(), 1);
    }

    #[test]
    fn reasoning_trace_hash_computed() {
        let trace = ReasoningTrace::builder()
            .goal(Goal::from_user("Task", test_event_id()))
            .step(ReasoningStep::new(1, "Thinking"))
            .decision(Decision::new("Do it", "Because", "Success"))
            .build()
            .unwrap();

        // Hash should not be all zeros
        assert_ne!(trace.trace_hash().as_bytes(), &[0u8; 32]);
    }

    #[test]
    fn reasoning_trace_integrity_verification() {
        let trace = ReasoningTrace::builder()
            .goal(Goal::from_user("Task", test_event_id()))
            .step(ReasoningStep::new(1, "Thinking"))
            .decision(Decision::new("Do it", "Because", "Success"))
            .build()
            .unwrap();

        assert!(trace.verify_integrity());
    }

    #[test]
    fn reasoning_trace_tamper_detected() {
        let mut trace = ReasoningTrace::builder()
            .goal(Goal::from_user("Task", test_event_id()))
            .step(ReasoningStep::new(1, "Thinking"))
            .decision(Decision::new("Do it", "Because", "Success"))
            .build()
            .unwrap();

        // Tamper with the decision
        trace.decision = Decision::new("Do something else", "Changed", "Different");

        // Integrity check should fail
        assert!(!trace.verify_integrity());
    }

    // === StepAction Tests ===

    #[test]
    fn step_action_variants() {
        let retrieve = StepAction::retrieve("query", "db");
        assert!(matches!(retrieve, StepAction::Retrieve { .. }));

        let analyze = StepAction::analyze("data", "statistical");
        assert!(matches!(analyze, StepAction::Analyze { .. }));

        let tool = StepAction::tool_call("bash", hash(b"input"));
        assert!(matches!(tool, StepAction::ToolCall { .. }));

        let decide = StepAction::decide("Go ahead");
        assert!(matches!(decide, StepAction::Decide { .. }));
    }
}
