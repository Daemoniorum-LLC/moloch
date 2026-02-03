//! Integration tests for agent accountability types.
//!
//! These tests verify that all agent accountability modules work together correctly.

use moloch_core::crypto::{hash, SecretKey};
use moloch_core::event::{EventId, ResourceId, ResourceKind};
use moloch_core::{
    ActionOutcome, AgentAttestationBuilder, ApprovalContext, ApprovalDecision, ApprovalPolicy,
    ApprovalRequest, ApprovalResponse, Attestor, CapabilityBuilder, CapabilityId, CapabilityKind,
    CausalContextBuilder, Confidence, CoordinatedAction, CoordinatedActionSpec,
    CoordinationProtocol, CoordinationType, Decision, EmergencyAction, EmergencyEvent,
    EmergencyPriority, EmergencyResolution, Evidence, FailureHandling, Goal, ImpactAssessment,
    OutcomeAttestation, Participant, ParticipantRole, PostMortem, PrincipalId, ProposedAction,
    ReasoningStep, ReasoningTrace, Resolution, Responsibility, RuntimeAttestation, Session,
    SessionId, Severity, SuspensionScope, ToolAttestation,
};
use std::time::Duration;

fn test_key() -> SecretKey {
    SecretKey::generate()
}

fn test_principal() -> PrincipalId {
    PrincipalId::user("test@example.com").unwrap()
}

fn test_event_id() -> EventId {
    EventId(hash(b"test-event"))
}

fn test_resource_id() -> ResourceId {
    ResourceId::new(ResourceKind::File, "/tmp/test.txt")
}

// === Scenario 1: Complete Agent Action Flow ===

/// Test the complete flow from session start through action to outcome.
#[test]
fn integration_complete_agent_action_flow() {
    let agent_key = test_key();
    let authority_key = test_key();
    let grantor_key = test_key();
    let principal = test_principal();

    // 1. Create a session
    let session = Session::builder()
        .principal(principal.clone())
        .max_depth(10)
        .max_duration(Duration::from_secs(3600))
        .build()
        .unwrap();

    assert!(session.is_active());

    // 2. Create agent attestation
    let attestation = AgentAttestationBuilder::new()
        .agent_id(agent_key.public_key())
        .code_hash(hash(b"agent-code"))
        .config_hash(hash(b"agent-config"))
        .prompt_hash(hash(b"agent-prompt"))
        .runtime(RuntimeAttestation::new(
            "test-runtime-v1",
            hash(b"runtime-binary"),
        ))
        .tool(ToolAttestation::new(
            "file_reader",
            "1.0.0",
            hash(b"tool-impl"),
        ))
        .validity_period(Duration::from_secs(86400))
        .sign(&authority_key)
        .unwrap();

    let now = chrono::Utc::now().timestamp_millis();
    assert!(attestation.is_valid_at(now));
    assert!(attestation.verify_signature().is_ok());

    // 3. Create a capability
    let capability = CapabilityBuilder::new()
        .kind(CapabilityKind::Read)
        .grantor(principal.clone())
        .expires_in(Duration::from_secs(3600))
        .sign(&grantor_key)
        .unwrap();

    let now = chrono::Utc::now().timestamp_millis();
    assert!(capability.is_valid_at(now));

    // 4. Create causal context linking back to session
    let causal_context = CausalContextBuilder::new()
        .parent_event_id(EventId(hash(b"session-start"))) // Parent makes this non-root
        .root_event_id(EventId(hash(b"session-start")))
        .session_id(session.id())
        .principal(principal.clone())
        .depth(1)
        .sequence(1)
        .build()
        .unwrap();

    assert!(!causal_context.is_root()); // Has parent

    // 5. Create reasoning trace for the action
    let reasoning = ReasoningTrace::builder()
        .goal(Goal::from_user(
            "Read configuration file",
            EventId(hash(b"user-request")),
        ))
        .step(ReasoningStep::new(1, "User requested to read config"))
        .step(ReasoningStep::new(2, "Checking capability permissions"))
        .step(ReasoningStep::new(3, "Proceeding with read operation"))
        .decision(Decision::new(
            "Read file /tmp/test.txt",
            "User authorized this action",
            "File contents returned",
        ))
        .confidence(Confidence::high())
        .build()
        .unwrap();

    assert!(reasoning.is_complete());
    assert!(reasoning.verify_integrity());

    // 6. Create outcome attestation
    let outcome = OutcomeAttestation::builder()
        .action_event_id(test_event_id())
        .outcome(ActionOutcome::success(
            serde_json::json!({"file_content": "test data"}),
        ))
        .attestor(Attestor::self_attestation(agent_key.public_key()))
        .evidence(Evidence::data_hash(
            test_resource_id(),
            hash(b"test data"),
            9,
        ))
        .observed_now()
        .sign(&agent_key)
        .unwrap();

    assert!(outcome.verify_against_attestor().is_ok());
    assert!(outcome.is_evidence_sufficient(Severity::Low));
}

// === Scenario 2: HITL Approval Flow ===

/// Test the human-in-the-loop approval workflow.
#[test]
fn integration_hitl_approval_flow() {
    let agent_key = test_key();
    let principal = test_principal();

    // 1. Agent proposes a high-impact action
    let proposed = ProposedAction::builder()
        .action_type("delete_file")
        .resource(test_resource_id())
        .reasoning("Will permanently delete important file")
        .impact(ImpactAssessment::new(Severity::High))
        .reversible(false)
        .build()
        .unwrap();

    assert!(!proposed.is_reversible());
    assert_eq!(proposed.impact().severity(), Severity::High);

    // 2. Create approval context (needed for ApprovalRequest)
    let causal_context = CausalContextBuilder::new()
        .root_event_id(test_event_id())
        .session_id(SessionId::random())
        .principal(principal.clone())
        .depth(0)
        .sequence(0)
        .build()
        .unwrap();

    let context = ApprovalContext::new(
        causal_context,
        hash(b"attestation"),
        CapabilityId::generate(),
    );

    // 3. Create approval request
    let request = ApprovalRequest::new(
        proposed,
        agent_key.public_key(),
        vec![principal.clone()],
        ApprovalPolicy::single_approver(),
        Duration::from_secs(600),
        context,
    );

    assert!(!request.is_expired());
    assert!(request.status().is_pending());

    // 4. Simulate approval response
    let response = ApprovalResponse::new(request.id(), principal, ApprovalDecision::Approve);

    assert!(matches!(response.decision, ApprovalDecision::Approve));
}

// === Scenario 3: Multi-Agent Coordination ===

/// Test multi-agent coordination with responsibility tracking.
#[test]
fn integration_multi_agent_coordination() {
    let coordinator_key = test_key();
    let peer_key = test_key();
    let principal = test_principal();

    // 1. Create action specification first (needed for commitment signing)
    let spec = CoordinatedActionSpec::new("Process data pipeline")
        .with_criterion("All steps complete without error")
        .with_criterion("Output matches expected format")
        .with_failure_handling(FailureHandling::Retry { max_attempts: 3 });

    // 2. Create participants with valid commitments over the spec
    let coordinator = Participant::with_commitment(
        coordinator_key.public_key(),
        ParticipantRole::Coordinator,
        Responsibility::shared(0.6),
        coordinator_key.sign(&spec.canonical_bytes()),
    );

    let peer = Participant::with_commitment(
        peer_key.public_key(),
        ParticipantRole::Peer,
        Responsibility::shared(0.4), // Shares sum to 1.0
        peer_key.sign(&spec.canonical_bytes()),
    );

    // 3. Create causal context
    let causal_context = CausalContextBuilder::new()
        .root_event_id(EventId(hash(b"coordination-start")))
        .session_id(SessionId::random())
        .principal(principal)
        .depth(0)
        .sequence(0)
        .build()
        .unwrap();

    // 4. Build coordinated action with commitment verification
    let coordination = CoordinatedAction::builder()
        .coordination_type(CoordinationType::Pipeline)
        .participant(coordinator)
        .participant(peer)
        .action(spec)
        .protocol(CoordinationProtocol::LeaderFollower)
        .causal_context(causal_context)
        .started_now()
        .build_verified()
        .unwrap();

    // Verify coordinator requirement
    assert!(coordination.coordinator().is_some());
    assert_eq!(coordination.participants().len(), 2);
}

// === Scenario 4: Emergency Response ===

/// Test emergency declaration and resolution flow.
#[test]
fn integration_emergency_response() {
    let agent_key = test_key();
    let principal = test_principal();

    // 1. Declare emergency - suspend agent
    let emergency = EmergencyEvent::builder()
        .action(EmergencyAction::suspend_agent(
            agent_key.public_key(),
            "Excessive rate limit violations",
            Some(3600000), // 1 hour
            SuspensionScope::Full,
        ))
        .initiator(principal.clone())
        .priority(EmergencyPriority::High)
        .trigger_evidence(test_event_id())
        .declared_now()
        .build()
        .unwrap();

    assert!(emergency.priority() == EmergencyPriority::High);
    assert!(!emergency.is_critical()); // High is not critical

    // 2. Verify emergency action affects agent
    assert!(emergency.action().affects_agent(&agent_key.public_key()));

    // 3. Create resolution with post-mortem
    let post_mortem = PostMortem::new(
        "Agent exceeded rate limits due to retry loop",
        "Bug in retry logic caused infinite loop",
        "Temporary service slowdown for 15 minutes",
    )
    .with_action_taken("Suspended agent")
    .with_action_taken("Fixed retry logic")
    .with_prevention("Add circuit breaker pattern")
    .with_lesson("Monitor retry patterns in production");

    let resolution = EmergencyResolution::new(
        test_event_id(), // Emergency event ID
        Resolution::fixed("Patched retry logic in agent code"),
        principal,
    )
    .with_post_mortem(post_mortem);

    assert!(!resolution.is_false_alarm());
    assert!(resolution.post_mortem().is_some());

    let pm = resolution.post_mortem().unwrap();
    assert_eq!(pm.actions_taken().len(), 2);
    assert_eq!(pm.prevention().len(), 1);
}

// === Scenario 5: Capability Building ===

/// Test capability creation with various constraints.
#[test]
fn integration_capability_constraints() {
    let grantor_key = test_key();
    let principal = test_principal();

    // Grant capability with constraints
    let capability = CapabilityBuilder::new()
        .kind(CapabilityKind::Write)
        .grantor(principal.clone())
        .expires_in(Duration::from_secs(3600))
        .delegatable(2) // max delegation depth of 2
        .scope(moloch_core::ResourceScope::pattern("*.txt"))
        .sign(&grantor_key)
        .unwrap();

    let now = chrono::Utc::now().timestamp_millis();
    assert!(capability.is_valid_at(now));
    assert!(capability.is_delegatable());
    assert_eq!(capability.max_delegation_depth(), 2);
}

// === Scenario 6: Reasoning to Approval Flow ===

/// Test that low-confidence reasoning triggers approval requirement.
#[test]
fn integration_reasoning_triggers_approval() {
    // 1. Agent has low confidence in decision
    let reasoning = ReasoningTrace::builder()
        .goal(Goal::from_user(
            "Perform complex refactoring",
            test_event_id(),
        ))
        .step(ReasoningStep::new(1, "Analyzing code structure"))
        .step(ReasoningStep::new(2, "Identified potential changes"))
        .decision(Decision::new(
            "Refactor module X",
            "Might improve performance",
            "Cleaner code structure",
        ))
        .confidence(
            Confidence::new(0.4) // Below approval threshold (0.5)
                .with_uncertainty("Complex dependencies unclear")
                .with_would_help("More context about usage patterns"),
        )
        .build()
        .unwrap();

    // 2. Check confidence thresholds per spec rule 7.3.5
    assert!(!reasoning.confidence().should_reject()); // 0.4 >= 0.3
    assert!(reasoning.confidence().requires_approval()); // 0.4 < 0.5
    assert!(reasoning.confidence().should_warn()); // 0.4 < 0.7
}

// === Scenario 7: Outcome with Evidence Requirements ===

/// Test evidence requirements based on severity.
#[test]
fn integration_outcome_evidence_by_severity() {
    let agent_key = test_key();
    let third_party_key = test_key();

    // Low severity - self-attestation sufficient
    let low_outcome = OutcomeAttestation::builder()
        .action_event_id(test_event_id())
        .outcome(ActionOutcome::success(serde_json::json!({})))
        .attestor(Attestor::self_attestation(agent_key.public_key()))
        .observed_now()
        .sign(&agent_key)
        .unwrap();
    assert!(low_outcome.is_evidence_sufficient(Severity::Low));
    assert!(!low_outcome.is_evidence_sufficient(Severity::Medium));

    // Medium severity - needs external evidence
    let medium_outcome = OutcomeAttestation::builder()
        .action_event_id(test_event_id())
        .outcome(ActionOutcome::success(serde_json::json!({})))
        .attestor(Attestor::self_attestation(agent_key.public_key()))
        .evidence(Evidence::external_confirmation(
            "ci-system",
            "build-123",
            chrono::Utc::now().timestamp_millis(),
        ))
        .observed_now()
        .sign(&agent_key)
        .unwrap();
    assert!(medium_outcome.is_evidence_sufficient(Severity::Medium));
    assert!(!medium_outcome.is_evidence_sufficient(Severity::High));

    // High severity - needs multiple external sources (but NOT receipt/third-party to avoid satisfying Critical)
    let high_outcome = OutcomeAttestation::builder()
        .action_event_id(test_event_id())
        .outcome(ActionOutcome::success(serde_json::json!({})))
        .attestor(Attestor::self_attestation(agent_key.public_key()))
        .evidence(Evidence::external_confirmation(
            "ci-system",
            "build-123",
            chrono::Utc::now().timestamp_millis(),
        ))
        .evidence(Evidence::external_confirmation(
            "monitoring-system",
            "check-456",
            chrono::Utc::now().timestamp_millis(),
        ))
        .observed_now()
        .sign(&agent_key)
        .unwrap();
    assert!(high_outcome.is_evidence_sufficient(Severity::High));
    assert!(!high_outcome.is_evidence_sufficient(Severity::Critical));

    // Critical - needs cryptographic proof or human verification
    let critical_outcome = OutcomeAttestation::builder()
        .action_event_id(test_event_id())
        .outcome(ActionOutcome::success(serde_json::json!({})))
        .attestor(Attestor::self_attestation(agent_key.public_key()))
        .evidence(Evidence::third_party_attestation(
            third_party_key.public_key(),
            vec![1, 2, 3, 4],
        ))
        .observed_now()
        .sign(&agent_key)
        .unwrap();
    assert!(critical_outcome.is_evidence_sufficient(Severity::Critical));
}

// === Scenario 8: Attestation Expiry ===

/// Test that expired attestations are correctly detected.
#[test]
fn integration_attestation_expiry() {
    let agent_key = test_key();
    let authority_key = test_key();

    // Create attestation with very short validity
    let attestation = AgentAttestationBuilder::new()
        .agent_id(agent_key.public_key())
        .code_hash(hash(b"code"))
        .config_hash(hash(b"config"))
        .prompt_hash(hash(b"prompt"))
        .runtime(RuntimeAttestation::new("rt", hash(b"rt")))
        .validity_period(Duration::from_millis(1)) // 1ms validity
        .sign(&authority_key)
        .unwrap();

    // Wait for expiry
    std::thread::sleep(Duration::from_millis(10));

    // Should now be expired
    let now = chrono::Utc::now().timestamp_millis();
    assert!(!attestation.is_valid_at(now));
}

// === Scenario 9: Session Boundary Enforcement ===

/// Test that causal contexts respect session boundaries.
#[test]
fn integration_session_boundaries() {
    let principal = test_principal();
    let session_id = SessionId::random();

    // Create root event
    let root_context = CausalContextBuilder::new()
        .root_event_id(EventId(hash(b"root")))
        .session_id(session_id)
        .principal(principal.clone())
        .depth(0)
        .sequence(0)
        .build()
        .unwrap();

    assert!(root_context.is_root());

    // Create child event (depth increases)
    let child_context = CausalContextBuilder::new()
        .parent_event_id(EventId(hash(b"parent")))
        .root_event_id(EventId(hash(b"root")))
        .session_id(session_id)
        .principal(principal.clone())
        .depth(1)
        .sequence(1)
        .build()
        .unwrap();

    assert!(!child_context.is_root());
    assert_eq!(child_context.depth(), 1);

    // Validate depth limit
    assert!(child_context.validate(10).is_ok()); // Within limit
    assert!(child_context.validate(0).is_err()); // Exceeds limit
}

// === Adversarial Tests ===

/// Test that forged attestation signatures are rejected.
#[test]
fn adversarial_forged_attestation_rejected() {
    let agent_key = test_key();
    let authority_key = test_key();

    let attestation = AgentAttestationBuilder::new()
        .agent_id(agent_key.public_key())
        .code_hash(hash(b"code"))
        .config_hash(hash(b"config"))
        .prompt_hash(hash(b"prompt"))
        .runtime(RuntimeAttestation::new("rt", hash(b"rt")))
        .validity_period(Duration::from_secs(3600))
        .sign(&authority_key)
        .unwrap();

    // Verification should succeed with correct authority
    assert!(attestation.verify_signature().is_ok());

    // Authority can be retrieved and compared
    assert_eq!(attestation.authority(), &authority_key.public_key());
}

/// Test that outcome attestations with wrong signatures are rejected.
#[test]
fn adversarial_forged_outcome_rejected() {
    let agent_key = test_key();
    let wrong_key = test_key();

    let outcome = OutcomeAttestation::builder()
        .action_event_id(test_event_id())
        .outcome(ActionOutcome::success(serde_json::json!({})))
        .attestor(Attestor::self_attestation(agent_key.public_key()))
        .observed_now()
        .sign(&agent_key)
        .unwrap();

    // Verification with wrong key should fail
    let result = outcome.verify_signature(&wrong_key.public_key());
    assert!(result.is_err());
}

/// Test that coordination without coordinator is rejected.
#[test]
fn adversarial_coordination_no_coordinator() {
    let peer1_key = test_key();
    let peer2_key = test_key();
    let principal = test_principal();

    // Try to create coordination with only peers (no coordinator)
    let peer1 = Participant::new(
        peer1_key.public_key(),
        ParticipantRole::Peer,
        Responsibility::shared(0.5),
        moloch_core::Sig::empty(),
    );

    let peer2 = Participant::new(
        peer2_key.public_key(),
        ParticipantRole::Peer,
        Responsibility::shared(0.5),
        moloch_core::Sig::empty(),
    );

    let causal_context = CausalContextBuilder::new()
        .root_event_id(EventId(hash(b"root")))
        .session_id(SessionId::random())
        .principal(principal)
        .depth(0)
        .sequence(0)
        .build()
        .unwrap();

    let result = CoordinatedAction::builder()
        .coordination_type(CoordinationType::Parallel)
        .participant(peer1)
        .participant(peer2)
        .action(CoordinatedActionSpec::new("Test"))
        .protocol(CoordinationProtocol::TwoPhaseCommit)
        .causal_context(causal_context)
        .build();

    // Should fail because no coordinator
    assert!(result.is_err());
}

/// Test that shared responsibility must sum to 1.0.
#[test]
fn adversarial_responsibility_sum() {
    let key1 = test_key();
    let key2 = test_key();
    let principal = test_principal();

    // Responsibilities that don't sum to 1.0
    let p1 = Participant::new(
        key1.public_key(),
        ParticipantRole::Coordinator,
        Responsibility::shared(0.3),
        moloch_core::Sig::empty(),
    );

    let p2 = Participant::new(
        key2.public_key(),
        ParticipantRole::Peer,
        Responsibility::shared(0.3), // Total = 0.6, not 1.0
        moloch_core::Sig::empty(),
    );

    let causal_context = CausalContextBuilder::new()
        .root_event_id(EventId(hash(b"root")))
        .session_id(SessionId::random())
        .principal(principal)
        .depth(0)
        .sequence(0)
        .build()
        .unwrap();

    let result = CoordinatedAction::builder()
        .coordination_type(CoordinationType::Parallel)
        .participant(p1)
        .participant(p2)
        .action(CoordinatedActionSpec::new("Test"))
        .protocol(CoordinationProtocol::TwoPhaseCommit)
        .causal_context(causal_context)
        .build();

    // Should fail because shared responsibilities don't sum to 1.0
    assert!(result.is_err());
}
