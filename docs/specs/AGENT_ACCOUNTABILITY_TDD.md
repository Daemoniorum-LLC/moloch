# Agent Accountability TDD Roadmap

**Version**: 1.0.0
**Status**: Draft
**Date**: 2026-01-28
**Spec Reference**: `docs/specs/AGENT_ACCOUNTABILITY.md`

---

## Overview

This roadmap defines the test-driven development plan for implementing the Agent Accountability specification. Following Agent-TDD methodology, tests are written first to crystallize understanding of requirements before implementation.

### Principles

1. **Tests as Specification**: Each test encodes a specific requirement from the spec
2. **Red-Green-Refactor**: Write failing test → implement → refactor
3. **Invariant Coverage**: Every spec invariant has corresponding test(s)
4. **Property-Based Testing**: Use proptest for complex invariants
5. **Integration Before Unit**: Start with integration tests to validate understanding

---

## Test Categories

| Category | Purpose | Location |
|----------|---------|----------|
| **Unit** | Individual type/function behavior | `*/src/*.rs` (inline) |
| **Integration** | Cross-module interactions | `*/tests/*.rs` |
| **Property** | Invariant verification via randomized inputs | `*/tests/props/*.rs` |
| **Scenario** | End-to-end accountability workflows | `moloch-api/tests/scenarios/*.rs` |
| **Adversarial** | Security boundary testing | `*/tests/adversarial/*.rs` |

---

## Phase 1: Core Types and Causality Chain

**Priority**: Critical
**Estimated Tests**: 45
**Spec Sections**: 3 (Causality Chain)

### 1.1 CausalContext Types

```rust
// moloch-core/src/agent/causality.rs

#[cfg(test)]
mod tests {
    use super::*;

    // === Construction Tests ===

    #[test]
    fn causal_context_requires_session_id() {
        // CausalContext cannot be created without a valid SessionId
    }

    #[test]
    fn causal_context_root_event_must_be_set() {
        // root_event_id is mandatory for all agent events
    }

    #[test]
    fn causal_context_depth_zero_has_no_parent() {
        // When depth=0, parent_event_id must be None
    }

    #[test]
    fn causal_context_depth_nonzero_requires_parent() {
        // When depth>0, parent_event_id must be Some
    }

    // === Validation Tests ===

    #[test]
    fn validate_rejects_depth_exceeding_max() {
        // depth > session.max_depth should fail validation
    }

    #[test]
    fn validate_rejects_parent_with_greater_sequence() {
        // parent.sequence must be < child.sequence
    }

    #[test]
    fn validate_rejects_parent_with_greater_depth() {
        // parent.depth must be < child.depth
    }

    #[test]
    fn validate_accepts_cross_session_reference_with_explicit_link() {
        // Cross-session parent is allowed with CrossSessionReference
    }
}
```

### 1.2 Session Types

```rust
// moloch-core/src/agent/session.rs

#[cfg(test)]
mod tests {
    // === Lifecycle Tests ===

    #[test]
    fn session_generates_unique_id() {
        // Two sessions should have different IDs
    }

    #[test]
    fn session_tracks_started_at() {
        // started_at should be set on creation
    }

    #[test]
    fn session_ended_at_none_when_active() {
        // Active session has ended_at = None
    }

    #[test]
    fn session_end_sets_ended_at() {
        // Calling end() sets ended_at to current time
    }

    #[test]
    fn session_cannot_end_twice() {
        // Calling end() on ended session returns error
    }

    // === Duration Tests ===

    #[test]
    fn session_is_expired_after_max_duration() {
        // Session should report expired when max_duration exceeded
    }

    #[test]
    fn session_remaining_duration_decreases() {
        // remaining_duration() decreases over time
    }

    // === Capability Tests ===

    #[test]
    fn session_capabilities_constrain_actions() {
        // Actions not in session.capabilities are rejected
    }
}
```

### 1.3 Causal Chain Queries

```rust
// moloch-chain/tests/causality_queries.rs

#[test]
fn get_descendants_returns_all_caused_events() {
    // Given: A -> B -> C, A -> D
    // When: get_descendants(A)
    // Then: Returns [B, C, D]
}

#[test]
fn get_descendants_empty_for_leaf_event() {
    // Event with no children returns empty vec
}

#[test]
fn get_ancestry_returns_path_to_root() {
    // Given: A -> B -> C
    // When: get_ancestry(C)
    // Then: Returns [C, B, A]
}

#[test]
fn get_ancestry_single_element_for_root() {
    // Root event ancestry is just itself
}

#[test]
fn get_session_events_returns_all_in_session() {
    // All events with matching session_id returned
}

#[test]
fn get_session_events_excludes_other_sessions() {
    // Events from other sessions not included
}

#[test]
fn get_principal_events_filters_by_principal() {
    // Only events with matching principal returned
}

#[test]
fn get_principal_events_respects_time_range() {
    // Events outside time range excluded
}
```

### 1.4 Causality Invariants (Property Tests)

```rust
// moloch-chain/tests/props/causality_props.rs

use proptest::prelude::*;

proptest! {
    /// INV-CAUSAL-1: Parent exists and has lower sequence
    #[test]
    fn prop_parent_precedes_child(events in arb_causal_chain(1..100)) {
        for event in &events {
            if let Some(parent_id) = &event.causal_context.parent_event_id {
                let parent = events.iter().find(|e| &e.id == parent_id).unwrap();
                prop_assert!(parent.causal_context.sequence < event.causal_context.sequence);
            }
        }
    }

    /// INV-CAUSAL-2: Root event has depth 0
    #[test]
    fn prop_root_has_depth_zero(events in arb_causal_chain(1..100)) {
        for event in &events {
            let root_id = &event.causal_context.root_event_id;
            let root = events.iter().find(|e| &e.id == root_id).unwrap();
            prop_assert_eq!(root.causal_context.depth, 0);
        }
    }

    /// INV-CAUSAL-3: Depth respects session max
    #[test]
    fn prop_depth_within_session_max(
        session in arb_session(),
        events in arb_events_in_session(1..50)
    ) {
        for event in &events {
            prop_assert!(event.causal_context.depth <= session.max_depth);
        }
    }

    /// INV-CAUSAL-4: Exactly one root per session
    #[test]
    fn prop_one_root_per_session(events in arb_causal_chain(1..100)) {
        let roots: Vec<_> = events.iter()
            .filter(|e| e.causal_context.depth == 0)
            .collect();
        prop_assert_eq!(roots.len(), 1);
    }
}
```

---

## Phase 2: Agent Identity Attestation

**Priority**: Critical
**Estimated Tests**: 40
**Spec Sections**: 4 (Agent Identity Attestation)

### 2.1 AgentAttestation Types

```rust
// moloch-core/src/agent/attestation.rs

#[cfg(test)]
mod tests {
    // === Construction Tests ===

    #[test]
    fn attestation_requires_code_hash() {
        // AgentAttestation cannot have empty code_hash
    }

    #[test]
    fn attestation_requires_valid_signature() {
        // authority_signature must verify against authority key
    }

    #[test]
    fn attestation_validity_period_must_be_positive() {
        // Zero or negative validity_period rejected
    }

    // === Validity Tests ===

    #[test]
    fn attestation_valid_within_validity_period() {
        // attested_at + validity_period > now => valid
    }

    #[test]
    fn attestation_invalid_after_expiry() {
        // attested_at + validity_period < now => invalid
    }

    #[test]
    fn attestation_invalid_if_revoked() {
        // Attestation in revocation list is invalid
    }

    #[test]
    fn attestation_invalid_if_authority_untrusted() {
        // Authority not in trusted set => invalid
    }

    // === Tool Attestation Tests ===

    #[test]
    fn tool_attestation_includes_version() {
        // Each tool has version recorded
    }

    #[test]
    fn tool_attestation_includes_implementation_hash() {
        // Tool implementation hash must be present
    }
}
```

### 2.2 AttestationRegistry

```rust
// moloch-core/src/agent/registry.rs

#[cfg(test)]
mod tests {
    // === Registration Tests ===

    #[test]
    fn register_stores_attestation() {
        // After register(), attestation is retrievable
    }

    #[test]
    fn register_rejects_invalid_signature() {
        // Attestation with bad signature rejected
    }

    #[test]
    fn register_rejects_expired_attestation() {
        // Already-expired attestation rejected
    }

    #[test]
    fn register_rejects_untrusted_authority() {
        // Authority not in trusted set => rejected
    }

    // === Verification Tests ===

    #[test]
    fn verify_returns_attestation_if_valid() {
        // Valid attestation returned by verify()
    }

    #[test]
    fn verify_fails_if_not_registered() {
        // Unknown agent_id => AttestationError::NotFound
    }

    #[test]
    fn verify_fails_if_expired_at_action_time() {
        // action_time > attested_at + validity_period => error
    }

    #[test]
    fn verify_fails_if_revoked() {
        // Revoked attestation => AttestationError::Revoked
    }

    // === Revocation Tests ===

    #[test]
    fn revoke_adds_to_revocation_list() {
        // Revoked attestation hash in revocations set
    }

    #[test]
    fn revoke_makes_verify_fail() {
        // After revoke(), verify() returns error
    }

    #[test]
    fn revoke_is_permanent() {
        // Cannot un-revoke an attestation
    }
}
```

### 2.3 Attestation Invariants (Property Tests)

```rust
// moloch-core/tests/props/attestation_props.rs

proptest! {
    /// INV-ATTEST-1: Every agent action has valid attestation
    #[test]
    fn prop_action_has_valid_attestation(
        registry in arb_registry(),
        action in arb_agent_action()
    ) {
        let result = registry.verify(&action.actor, action.timestamp);
        prop_assert!(result.is_ok());
    }

    /// INV-ATTEST-2: Attestation validity is time-bounded
    #[test]
    fn prop_attestation_expires(
        attestation in arb_attestation(),
        time_offset in 0u64..1000000
    ) {
        let check_time = attestation.attested_at + Duration::from_secs(time_offset);
        let expected_valid = check_time < attestation.attested_at + attestation.validity_period;
        prop_assert_eq!(attestation.is_valid_at(check_time), expected_valid);
    }

    /// INV-ATTEST-3: Tool invocations match attestation
    #[test]
    fn prop_tool_in_attestation(
        attestation in arb_attestation_with_tools(1..10),
        tool_invocation in arb_tool_invocation()
    ) {
        let tool_allowed = attestation.tools.iter()
            .any(|t| t.tool_id == tool_invocation.tool_id);
        // Test setup ensures invocation matches attestation
    }
}
```

---

## Phase 3: Capability Model

**Priority**: Critical
**Estimated Tests**: 55
**Spec Sections**: 5 (Capability Model)

### 3.1 Capability Types

```rust
// moloch-core/src/agent/capability.rs

#[cfg(test)]
mod tests {
    // === Scope Tests ===

    #[test]
    fn scope_specific_matches_exact_resource() {
        let scope = ResourceScope::Specific(resource_id("repo:org/project"));
        assert!(scope.matches(&resource_id("repo:org/project")));
        assert!(!scope.matches(&resource_id("repo:org/other")));
    }

    #[test]
    fn scope_pattern_matches_glob() {
        let scope = ResourceScope::Pattern("repo:org/*".into());
        assert!(scope.matches(&resource_id("repo:org/project")));
        assert!(scope.matches(&resource_id("repo:org/other")));
        assert!(!scope.matches(&resource_id("repo:other/project")));
    }

    #[test]
    fn scope_kind_matches_all_of_kind() {
        let scope = ResourceScope::Kind(ResourceKind::Repository);
        assert!(scope.matches(&resource_id("repo:anything")));
        assert!(!scope.matches(&resource_id("file:anything")));
    }

    #[test]
    fn scope_all_matches_everything() {
        let scope = ResourceScope::All;
        assert!(scope.matches(&resource_id("anything:at/all")));
    }

    // === Constraint Tests ===

    #[test]
    fn constraint_max_uses_enforced() {
        let mut cap = capability_with_max_uses(5);
        for _ in 0..5 {
            assert!(cap.try_use().is_ok());
        }
        assert!(cap.try_use().is_err());
    }

    #[test]
    fn constraint_rate_limit_enforced() {
        let cap = capability_with_rate_limit(10, Duration::from_secs(60));
        // 10 uses should succeed
        // 11th should fail
        // After 60s, should work again
    }

    #[test]
    fn constraint_time_window_enforced() {
        let cap = capability_with_time_window(
            TimeWindow::weekdays(Time::from_hms(9, 0, 0), Time::from_hms(17, 0, 0))
        );
        // During window: allowed
        // Outside window: denied
    }

    #[test]
    fn constraint_expiry_enforced() {
        let cap = capability_expiring_at(Timestamp::now() - Duration::from_secs(1));
        assert!(!cap.is_valid());
    }
}
```

### 3.2 CapabilitySet

```rust
// moloch-core/src/agent/capability_set.rs

#[cfg(test)]
mod tests {
    // === Permit Tests ===

    #[test]
    fn permits_returns_permitted_with_matching_capability() {
        let set = capability_set_with(vec![
            capability(CapabilityKind::Read, ResourceScope::All),
        ]);
        let check = set.permits(&read_action("any:resource"), &context());
        assert!(matches!(check, CapabilityCheck::Permitted { .. }));
    }

    #[test]
    fn permits_returns_denied_when_no_matching_capability() {
        let set = capability_set_with(vec![
            capability(CapabilityKind::Read, ResourceScope::All),
        ]);
        let check = set.permits(&write_action("any:resource"), &context());
        assert!(matches!(check, CapabilityCheck::Denied { .. }));
    }

    #[test]
    fn permits_returns_requires_approval_when_flagged() {
        let set = capability_set_with(vec![
            capability_requiring_approval(CapabilityKind::Write),
        ]);
        let check = set.permits(&write_action("any:resource"), &context());
        assert!(matches!(check, CapabilityCheck::RequiresApproval { .. }));
    }

    // === Delegation Tests ===

    #[test]
    fn delegate_creates_subset() {
        let parent = capability_set_with(vec![
            capability(CapabilityKind::Read, ResourceScope::All),
            capability(CapabilityKind::Write, ResourceScope::All),
        ]);
        let child = parent.delegate(
            vec![parent.capabilities[0].id],
            child_agent_key()
        ).unwrap();

        assert_eq!(child.capabilities.len(), 1);
        assert!(child.permits(&read_action("x"), &ctx()).is_permitted());
        assert!(child.permits(&write_action("x"), &ctx()).is_denied());
    }

    #[test]
    fn delegate_fails_for_non_delegatable_capability() {
        let parent = capability_set_with(vec![
            capability_non_delegatable(CapabilityKind::Read),
        ]);
        let result = parent.delegate(vec![parent.capabilities[0].id], child_key());
        assert!(result.is_err());
    }

    #[test]
    fn delegate_enforces_depth_limit() {
        let parent = capability_with_max_delegation_depth(2);
        let child1 = parent.delegate(...).unwrap();  // depth 1
        let child2 = child1.delegate(...).unwrap();  // depth 2
        let child3 = child2.delegate(...);           // depth 3 - should fail
        assert!(child3.is_err());
    }

    #[test]
    fn delegate_scope_must_be_subset() {
        let parent = capability_with_scope(ResourceScope::Pattern("org/*"));
        // Cannot delegate broader scope
        let result = parent.delegate_with_scope(ResourceScope::All, ...);
        assert!(result.is_err());
    }
}
```

### 3.3 Capability Invariants (Property Tests)

```rust
// moloch-core/tests/props/capability_props.rs

proptest! {
    /// INV-CAP-1: Capability grantee matches action actor
    #[test]
    fn prop_capability_grantee_matches_actor(
        cap in arb_capability(),
        action in arb_action()
    ) {
        if cap.grantee == action.actor || cap.was_delegated_to(action.actor) {
            // Valid
        } else {
            // Should be denied
            prop_assert!(matches!(
                cap.check(&action),
                CapabilityCheck::Denied { .. }
            ));
        }
    }

    /// INV-CAP-2: Usage count respects max
    #[test]
    fn prop_usage_within_max(
        cap in arb_capability_with_max_uses(1..100),
        uses in 0usize..200
    ) {
        let mut cap = cap;
        let max = cap.constraints.max_uses.unwrap() as usize;
        let successful = (0..uses).filter(|_| cap.try_use().is_ok()).count();
        prop_assert!(successful <= max);
    }

    /// INV-CAP-3: Delegated capability is subset
    #[test]
    fn prop_delegation_is_subset(
        parent in arb_capability(),
        child in arb_delegated_capability()
    ) {
        prop_assert!(child.scope.is_subset_of(&parent.scope));
        prop_assert!(child.expires_at <= parent.expires_at);
    }

    /// INV-CAP-4: Delegation depth bounded
    #[test]
    fn prop_delegation_depth_bounded(chain in arb_delegation_chain(1..20)) {
        let original = &chain[0];
        let max_depth = original.max_delegation_depth as usize;
        prop_assert!(chain.len() <= max_depth + 1);
    }
}
```

---

## Phase 4: Human-in-the-Loop Protocol

**Priority**: High
**Estimated Tests**: 50
**Spec Sections**: 6 (Human-in-the-Loop Protocol)

### 4.1 ApprovalRequest Types

```rust
// moloch-core/src/agent/hitl.rs

#[cfg(test)]
mod tests {
    // === Request Creation ===

    #[test]
    fn approval_request_sets_expiry() {
        let req = ApprovalRequest::new(action, policy, Duration::from_secs(300));
        assert!(req.expires_at > req.created_at);
    }

    #[test]
    fn approval_request_status_initially_pending() {
        let req = ApprovalRequest::new(...);
        assert!(matches!(req.status, ApprovalStatus::Pending));
    }

    #[test]
    fn approval_request_includes_context() {
        let req = ApprovalRequest::new(...);
        assert!(req.context.causal_context.is_some());
        assert!(req.context.agent_attestation_hash.is_some());
    }

    // === Expiry Tests ===

    #[test]
    fn approval_request_expires_after_timeout() {
        let req = ApprovalRequest::new(..., Duration::from_secs(0));
        assert!(req.is_expired());
    }

    #[test]
    fn expired_request_cannot_be_approved() {
        let mut req = expired_request();
        let result = req.apply_response(approval_response());
        assert!(result.is_err());
    }

    // === Policy Tests ===

    #[test]
    fn policy_required_approvals_must_be_met() {
        let mut req = request_requiring_approvals(2);
        req.apply_response(approval_from(approver1)).unwrap();
        assert!(!req.is_approved());
        req.apply_response(approval_from(approver2)).unwrap();
        assert!(req.is_approved());
    }

    #[test]
    fn policy_any_can_reject() {
        let mut req = request_with_any_can_reject();
        req.apply_response(rejection_from(approver1)).unwrap();
        assert!(req.is_rejected());
    }
}
```

### 4.2 ApprovalResponse

```rust
// moloch-core/src/agent/hitl.rs

#[cfg(test)]
mod tests {
    // === Response Validation ===

    #[test]
    fn response_must_reference_existing_request() {
        let response = ApprovalResponse {
            request_id: non_existent_id(),
            ..
        };
        assert!(validate_response(&response, &registry).is_err());
    }

    #[test]
    fn response_must_be_from_valid_approver() {
        let response = approval_from(non_approver);
        assert!(validate_response(&response, &registry).is_err());
    }

    #[test]
    fn response_signature_must_verify() {
        let response = approval_with_bad_signature();
        assert!(validate_response(&response, &registry).is_err());
    }

    // === Modification Tests ===

    #[test]
    fn approve_with_modifications_recorded() {
        let mods = ActionModifications {
            parameters: Some(json!({"limit": 100})),
            ..Default::default()
        };
        let response = ApprovalResponse {
            decision: ApprovalDecision::ApproveWithModifications(mods.clone()),
            ..
        };
        req.apply_response(response).unwrap();
        assert_eq!(req.status.modifications(), Some(&mods));
    }

    #[test]
    fn agent_must_apply_modifications() {
        // Integration test: action event must reflect modifications
    }
}
```

### 4.3 Escalation

```rust
// moloch-core/tests/hitl_escalation.rs

#[test]
fn escalation_triggers_after_timeout() {
    let req = request_with_escalation_after(Duration::from_secs(60));
    advance_time(Duration::from_secs(61));
    let result = process_pending_requests(&[req]);
    assert!(result.escalated.contains(&req.id));
}

#[test]
fn escalation_notifies_escalation_targets() {
    let req = request_with_escalation_to(vec![supervisor]);
    escalate(&req);
    assert!(notifications_sent_to(&[supervisor]));
}

#[test]
fn max_escalations_respected() {
    let mut req = request_with_max_escalations(2);
    escalate(&mut req); // level 1
    escalate(&mut req); // level 2
    let result = escalate(&mut req); // level 3 - should fail
    assert!(result.is_err());
}
```

### 4.4 HITL Invariants (Property Tests)

```rust
// moloch-core/tests/props/hitl_props.rs

proptest! {
    /// INV-HITL-1: Approved action has prior approval response
    #[test]
    fn prop_approval_before_action(
        chain in arb_event_chain_with_approvals()
    ) {
        for event in &chain {
            if event.required_approval() {
                let approval = chain.iter()
                    .find(|e| e.is_approval_for(&event.proposed_action_id()));
                prop_assert!(approval.is_some());
                prop_assert!(approval.unwrap().timestamp < event.timestamp);
            }
        }
    }

    /// INV-HITL-2: Response references existing request
    #[test]
    fn prop_response_references_request(
        requests in arb_approval_requests(1..20),
        response in arb_approval_response()
    ) {
        let valid = requests.iter().any(|r| r.id == response.request_id);
        prop_assert!(valid == response.is_valid_reference(&requests));
    }

    /// INV-HITL-3: Modifications applied to action
    #[test]
    fn prop_modifications_in_action(
        approval in arb_approval_with_modifications(),
        action in arb_resulting_action()
    ) {
        if let Some(mods) = approval.modifications() {
            if let Some(params) = &mods.parameters {
                prop_assert!(action.parameters.contains(params));
            }
        }
    }
}
```

---

## Phase 5: Reasoning Traces

**Priority**: High
**Estimated Tests**: 35
**Spec Sections**: 7 (Reasoning Traces)

### 5.1 ReasoningTrace Types

```rust
// moloch-core/src/agent/reasoning.rs

#[cfg(test)]
mod tests {
    // === Structure Tests ===

    #[test]
    fn trace_requires_goal() {
        let trace = ReasoningTrace::builder()
            .steps(vec![step()])
            .decision(decision())
            .build();
        assert!(trace.is_err()); // Missing goal
    }

    #[test]
    fn trace_requires_at_least_one_step() {
        let trace = ReasoningTrace::builder()
            .goal(goal())
            .steps(vec![])
            .decision(decision())
            .build();
        assert!(trace.is_err()); // No steps
    }

    #[test]
    fn trace_requires_decision() {
        let trace = ReasoningTrace::builder()
            .goal(goal())
            .steps(vec![step()])
            .build();
        assert!(trace.is_err()); // Missing decision
    }

    // === Confidence Tests ===

    #[test]
    fn confidence_score_in_valid_range() {
        let confidence = Confidence::new(0.75);
        assert!(confidence.is_ok());

        let invalid = Confidence::new(1.5);
        assert!(invalid.is_err());
    }

    #[test]
    fn confidence_below_threshold_flags_uncertainty() {
        let trace = trace_with_confidence(0.3);
        assert!(trace.should_escalate());
    }

    // === Hash Integrity ===

    #[test]
    fn trace_hash_computed_correctly() {
        let trace = complete_trace();
        let expected = hash(&trace.canonical_bytes());
        assert_eq!(trace.trace_hash, expected);
    }

    #[test]
    fn trace_hash_changes_with_content() {
        let trace1 = trace_with_decision("A");
        let trace2 = trace_with_decision("B");
        assert_ne!(trace1.trace_hash, trace2.trace_hash);
    }
}
```

### 5.2 Reasoning Step Types

```rust
// moloch-core/src/agent/reasoning.rs

#[cfg(test)]
mod tests {
    #[test]
    fn step_sequence_must_be_monotonic() {
        let steps = vec![
            step_with_sequence(1),
            step_with_sequence(3),
            step_with_sequence(2), // Out of order
        ];
        let trace = ReasoningTrace::builder().steps(steps).build();
        assert!(trace.is_err());
    }

    #[test]
    fn step_action_links_to_tool_invocation() {
        let step = ReasoningStep {
            action: Some(StepAction::ToolCall {
                tool: "search".into(),
                input_hash: hash(b"query"),
            }),
            ..
        };
        // Verify linkable to ToolInvocation event
    }

    #[test]
    fn step_observation_follows_action() {
        // If action is Some, observation can be Some
        // If action is None, observation should be None
    }
}
```

### 5.3 Alternatives and Factors

```rust
// moloch-core/src/agent/reasoning.rs

#[cfg(test)]
mod tests {
    #[test]
    fn alternative_must_have_rejection_reason() {
        let alt = Alternative {
            description: "Do X instead".into(),
            rejection_reason: "".into(), // Empty
            ..
        };
        assert!(alt.validate().is_err());
    }

    #[test]
    fn factor_influence_in_valid_range() {
        let factor = Factor {
            influence: 1.5, // Invalid: should be -1.0 to 1.0
            ..
        };
        assert!(factor.validate().is_err());
    }

    #[test]
    fn nontrivial_action_requires_alternatives() {
        let trace = trace_for_severity(Severity::Medium);
        assert!(!trace.alternatives.is_empty());
    }
}
```

---

## Phase 6: Outcome Verification

**Priority**: High
**Estimated Tests**: 40
**Spec Sections**: 8 (Outcome Verification)

### 6.1 OutcomeAttestation Types

```rust
// moloch-core/src/agent/outcome.rs

#[cfg(test)]
mod tests {
    // === Outcome Types ===

    #[test]
    fn success_outcome_includes_result_hash() {
        let outcome = Outcome::Success {
            result: json!({"key": "value"}),
            result_hash: Hash::zero(), // Should be computed
        };
        // Verify hash matches result
    }

    #[test]
    fn failure_outcome_includes_error_details() {
        let outcome = Outcome::Failure {
            error: "Connection timeout".into(),
            error_code: Some("E_TIMEOUT".into()),
            recoverable: true,
        };
        assert!(outcome.is_failure());
        assert!(outcome.is_recoverable());
    }

    #[test]
    fn partial_success_lists_completed_and_failed() {
        let outcome = Outcome::PartialSuccess {
            completed: vec!["step1".into(), "step2".into()],
            failed: vec!["step3".into()],
            result: json!({}),
        };
        assert!(outcome.is_partial());
    }

    // === Attestor Types ===

    #[test]
    fn self_attestation_uses_agent_key() {
        let attestor = Attestor::SelfAttestation { agent: agent_key() };
        // Valid for low severity
    }

    #[test]
    fn execution_system_attestor_requires_key() {
        let attestor = Attestor::ExecutionSystem {
            system_id: "docker".into(),
            system_key: system_key(),
        };
        // Signature must verify
    }
}
```

### 6.2 Evidence Types

```rust
// moloch-core/src/agent/outcome.rs

#[cfg(test)]
mod tests {
    #[test]
    fn data_hash_evidence_verifiable() {
        let evidence = Evidence::DataHash {
            resource: resource_id("file:/path"),
            hash: hash(b"content"),
            size: 7,
        };
        // Can verify by hashing resource content
    }

    #[test]
    fn external_confirmation_includes_timestamp() {
        let evidence = Evidence::ExternalConfirmation {
            system: "stripe".into(),
            confirmation_id: "ch_123".into(),
            timestamp: Timestamp::now(),
        };
        // Timestamp must be recent
    }

    #[test]
    fn evidence_requirements_by_severity() {
        // Low: self-attestation OK
        assert!(sufficient_evidence(Severity::Low, &[self_attest()]));

        // Medium: needs external
        assert!(!sufficient_evidence(Severity::Medium, &[self_attest()]));
        assert!(sufficient_evidence(Severity::Medium, &[external()]));

        // High: needs multiple
        assert!(!sufficient_evidence(Severity::High, &[external()]));
        assert!(sufficient_evidence(Severity::High, &[ext1(), ext2()]));

        // Critical: needs crypto proof or human
        assert!(sufficient_evidence(Severity::Critical, &[crypto_proof()]));
    }
}
```

### 6.3 Idempotency

```rust
// moloch-core/src/agent/idempotency.rs

#[cfg(test)]
mod tests {
    #[test]
    fn idempotency_key_prevents_duplicate() {
        let key = IdempotencyKey::new(&agent, "transfer", "txn-123");
        record_success(&key, outcome1);

        let result = check_idempotency(&key);
        assert!(matches!(result, IdempotencyResult::AlreadySucceeded(..)));
    }

    #[test]
    fn idempotency_key_unique_per_agent() {
        let key1 = IdempotencyKey::new(&agent1, "action", "id");
        let key2 = IdempotencyKey::new(&agent2, "action", "id");
        assert_ne!(key1, key2);
    }

    #[test]
    fn idempotency_record_expires() {
        let key = IdempotencyKey::new(...);
        record_success(&key, outcome);
        advance_time(Duration::from_days(8));

        let result = check_idempotency(&key);
        assert!(matches!(result, IdempotencyResult::NotFound));
    }
}
```

---

## Phase 7: Emergency Controls

**Priority**: Critical
**Estimated Tests**: 45
**Spec Sections**: 9 (Emergency Controls)

### 7.1 EmergencyAction Types

```rust
// moloch-core/src/agent/emergency.rs

#[cfg(test)]
mod tests {
    // === Suspension Tests ===

    #[test]
    fn suspend_agent_takes_effect_immediately() {
        let action = EmergencyAction::SuspendAgent {
            agent: agent_key(),
            reason: "Anomaly detected".into(),
            duration: Some(Duration::from_hours(1)),
            scope: SuspensionScope::Full,
        };
        apply_emergency(&action);

        assert!(!can_act(&agent_key()));
    }

    #[test]
    fn suspension_scope_partial_allows_some_actions() {
        let action = EmergencyAction::SuspendAgent {
            scope: SuspensionScope::Capabilities(vec![CapabilityKind::Write]),
            ..
        };
        apply_emergency(&action);

        assert!(can_read(&agent));  // Still allowed
        assert!(!can_write(&agent)); // Blocked
    }

    #[test]
    fn suspension_duration_auto_expires() {
        suspend_for(&agent, Duration::from_secs(60));
        assert!(!can_act(&agent));

        advance_time(Duration::from_secs(61));
        assert!(can_act(&agent));
    }

    // === Revocation Tests ===

    #[test]
    fn revoke_agent_is_permanent() {
        let action = EmergencyAction::RevokeAgent {
            agent: agent_key(),
            reason: "Compromised".into(),
        };
        apply_emergency(&action);

        assert!(!can_act(&agent));
        // Cannot be undone
    }

    // === Global Pause Tests ===

    #[test]
    fn global_pause_stops_all_agents() {
        let action = EmergencyAction::GlobalPause {
            reason: "Security incident".into(),
            duration: Duration::from_hours(1),
            exceptions: vec![],
        };
        apply_emergency(&action);

        assert!(!can_act(&agent1));
        assert!(!can_act(&agent2));
    }

    #[test]
    fn global_pause_allows_exceptions() {
        let action = EmergencyAction::GlobalPause {
            exceptions: vec![emergency_responder_key()],
            ..
        };
        apply_emergency(&action);

        assert!(can_act(&emergency_responder_key()));
        assert!(!can_act(&regular_agent_key()));
    }
}
```

### 7.2 Emergency Propagation

```rust
// moloch-net/tests/emergency_propagation.rs

#[test]
fn emergency_propagates_via_gossip() {
    let emergency = EmergencyEvent::new(SuspendAgent { .. });
    node1.declare_emergency(emergency.clone());

    wait_for_propagation();

    assert!(node2.has_emergency(&emergency.id));
    assert!(node3.has_emergency(&emergency.id));
}

#[test]
fn emergency_survives_network_partition() {
    // Partition network
    partition(&[node1, node2], &[node3]);

    // Declare emergency on node1
    node1.declare_emergency(emergency);

    // Heal partition
    heal_partition();

    // node3 should receive emergency
    wait_for_propagation();
    assert!(node3.has_emergency(&emergency.id));
}

#[test]
fn emergency_stored_in_local_cache() {
    node1.declare_emergency(emergency);

    // Restart node
    node1.restart();

    // Emergency still enforced
    assert!(node1.is_emergency_active(&emergency.id));
}
```

### 7.3 Emergency Invariants (Property Tests)

```rust
// moloch-core/tests/props/emergency_props.rs

proptest! {
    /// INV-EMERG-1: Suspended agent cannot act
    #[test]
    fn prop_suspended_cannot_act(
        agent in arb_agent(),
        emergency in arb_suspension_for(&agent)
    ) {
        let mut system = System::new();
        system.apply_emergency(emergency);

        let action = arb_action_by(&agent);
        prop_assert!(system.submit(action).is_err());
    }

    /// INV-EMERG-2: Every emergency has resolution
    #[test]
    fn prop_emergency_resolved(
        emergencies in arb_emergency_sequence(1..10),
        resolutions in arb_resolutions()
    ) {
        // In a complete history, every emergency should have resolution
        for e in &emergencies {
            prop_assert!(resolutions.iter().any(|r| r.emergency_event_id == e.id));
        }
    }

    /// INV-EMERG-3: Global pause exceptions honored
    #[test]
    fn prop_pause_exceptions_honored(
        pause in arb_global_pause(),
        agent in arb_agent()
    ) {
        let is_exception = pause.exceptions.contains(&agent.public_key);
        let can_act = system_with_pause(&pause).can_act(&agent);
        prop_assert_eq!(is_exception, can_act);
    }
}
```

---

## Phase 8: Multi-Agent Coordination

**Priority**: Medium
**Estimated Tests**: 50
**Spec Sections**: 10 (Multi-Agent Coordination)

### 8.1 CoordinatedAction Types

```rust
// moloch-core/src/agent/coordination.rs

#[cfg(test)]
mod tests {
    // === Participant Tests ===

    #[test]
    fn coordination_requires_coordinator() {
        let coordination = CoordinatedAction::builder()
            .participants(vec![
                participant(ParticipantRole::Peer),
                participant(ParticipantRole::Peer),
            ])
            .build();
        assert!(coordination.is_err()); // No coordinator
    }

    #[test]
    fn coordination_exactly_one_coordinator() {
        let coordination = CoordinatedAction::builder()
            .participants(vec![
                participant(ParticipantRole::Coordinator),
                participant(ParticipantRole::Coordinator),
            ])
            .build();
        assert!(coordination.is_err()); // Two coordinators
    }

    #[test]
    fn participant_commitment_required() {
        let mut coordination = pending_coordination();
        assert!(matches!(coordination.status, CoordinationStatus::WaitingCommitment));

        for p in &coordination.participants {
            coordination.record_commitment(p.agent, p.signature);
        }
        assert!(matches!(coordination.status, CoordinationStatus::Active { .. }));
    }

    // === Responsibility Tests ===

    #[test]
    fn shared_responsibility_sums_to_one() {
        let participants = vec![
            participant_with_responsibility(Responsibility::Shared { share: 0.5 }),
            participant_with_responsibility(Responsibility::Shared { share: 0.5 }),
        ];
        let coordination = CoordinatedAction::builder()
            .participants(participants)
            .build();
        assert!(coordination.is_ok());

        // Invalid: doesn't sum to 1.0
        let participants = vec![
            participant_with_responsibility(Responsibility::Shared { share: 0.3 }),
            participant_with_responsibility(Responsibility::Shared { share: 0.3 }),
        ];
        let coordination = CoordinatedAction::builder()
            .participants(participants)
            .build();
        assert!(coordination.is_err());
    }

    #[test]
    fn individual_responsibility_no_sharing() {
        let participants = vec![
            participant_with_responsibility(Responsibility::Individual),
            participant_with_responsibility(Responsibility::Individual),
        ];
        // Each is fully responsible for their own actions
    }
}
```

### 8.2 Task Dependencies

```rust
// moloch-core/src/agent/coordination.rs

#[cfg(test)]
mod tests {
    #[test]
    fn task_dependency_prevents_early_start() {
        let spec = CoordinatedActionSpec {
            tasks: hashmap! {
                agent1 => vec![task_a],
                agent2 => vec![task_b],
            },
            dependencies: vec![
                TaskDependency { task: task_b.id, depends_on: vec![task_a.id] }
            ],
            ..
        };

        // task_b cannot start until task_a completes
        assert!(!can_start(&spec, &task_b, &completed_tasks(vec![])));
        assert!(can_start(&spec, &task_b, &completed_tasks(vec![task_a.id])));
    }

    #[test]
    fn circular_dependency_rejected() {
        let spec = CoordinatedActionSpec {
            dependencies: vec![
                TaskDependency { task: a, depends_on: vec![b] },
                TaskDependency { task: b, depends_on: vec![a] },
            ],
            ..
        };
        assert!(spec.validate().is_err());
    }
}
```

### 8.3 Coordination Patterns

```rust
// moloch-core/tests/coordination_patterns.rs

#[test]
fn pipeline_pattern_sequential_execution() {
    let coordination = pipeline_coordination(vec![agent_a, agent_b, agent_c]);

    // A's output becomes B's input
    complete_task(&mut coordination, agent_a, output_a);
    let b_input = coordination.get_input_for(agent_b);
    assert_eq!(b_input, Some(&output_a));

    // B's output becomes C's input
    complete_task(&mut coordination, agent_b, output_b);
    let c_input = coordination.get_input_for(agent_c);
    assert_eq!(c_input, Some(&output_b));
}

#[test]
fn parallel_pattern_concurrent_execution() {
    let coordination = parallel_coordination(vec![agent_a, agent_b, agent_c]);

    // All can start immediately
    assert!(can_start(&coordination, agent_a));
    assert!(can_start(&coordination, agent_b));
    assert!(can_start(&coordination, agent_c));

    // Results aggregated at end
    complete_task(&mut coordination, agent_a, output_a);
    complete_task(&mut coordination, agent_b, output_b);
    complete_task(&mut coordination, agent_c, output_c);

    let result = coordination.aggregate();
    assert!(result.contains(&output_a));
    assert!(result.contains(&output_b));
    assert!(result.contains(&output_c));
}

#[test]
fn supervised_pattern_supervisor_can_intervene() {
    let coordination = supervised_coordination(supervisor, vec![agent_a, agent_b]);

    // Supervisor can cancel any agent's task
    coordination.supervisor_cancel(agent_a, "Taking too long");
    assert!(coordination.task_status(agent_a).is_cancelled());

    // Supervisor can reassign
    coordination.supervisor_reassign(agent_a_task, agent_b);
}
```

### 8.4 Disagreement Resolution

```rust
// moloch-core/tests/coordination_disagreement.rs

#[test]
fn disagreement_recorded() {
    let mut coordination = active_coordination();

    coordination.record_disagreement(
        vec![agent_a, agent_b],
        "Output format",
        hashmap! {
            agent_a => "Use JSON",
            agent_b => "Use YAML",
        }
    );

    assert!(coordination.has_disagreement());
}

#[test]
fn consensus_resolves_disagreement() {
    let mut coordination = coordination_with_consensus_protocol(0.67);

    coordination.record_vote(agent_a, "JSON");
    coordination.record_vote(agent_b, "JSON");
    coordination.record_vote(agent_c, "YAML");

    let resolution = coordination.resolve_disagreement();
    assert_eq!(resolution, Some("JSON")); // 2/3 voted JSON
}

#[test]
fn unresolved_disagreement_escalates() {
    let mut coordination = coordination_without_resolution();

    coordination.record_disagreement(...);
    let result = coordination.resolve_disagreement();

    assert!(result.is_none());
    assert!(coordination.needs_human_resolution());
}
```

---

## Phase 9: Integration and Scenario Tests

**Priority**: High
**Estimated Tests**: 30
**Spec Sections**: All

### 9.1 End-to-End Scenarios

```rust
// moloch-api/tests/scenarios/simple_agent_action.rs

#[tokio::test]
async fn scenario_simple_agent_action() {
    // Setup
    let system = TestSystem::new();
    let user = system.create_user();
    let agent = system.create_agent(&user);

    // 1. User starts session
    let session = system.start_session(&user).await;

    // 2. Agent attests
    let attestation = system.attest_agent(&agent).await;

    // 3. Grant capability
    let cap = system.grant_capability(&user, &agent, CapabilityKind::Read).await;

    // 4. Agent takes action
    let action = AgentActionV2 {
        causal_context: CausalContext::rooted(&session, &user),
        attestation_hash: attestation.hash(),
        capability_id: cap.id,
        action: read_action("resource:1"),
        reasoning_trace: Some(simple_trace()),
        impact: ImpactAssessment::low(),
    };
    let event_id = system.submit_action(&agent, action).await.unwrap();

    // 5. Verify outcome
    let outcome = system.attest_outcome(event_id, Outcome::Success { .. }).await;

    // 6. End session
    system.end_session(&session).await;

    // Verify chain
    let chain = system.get_session_events(&session.id).await;
    assert_eq!(chain.len(), 5); // start, attest, grant, action, outcome
    verify_causal_chain(&chain);
}
```

```rust
// moloch-api/tests/scenarios/multi_agent_pipeline.rs

#[tokio::test]
async fn scenario_multi_agent_pipeline() {
    let system = TestSystem::new();
    let user = system.create_user();
    let agent_a = system.create_agent(&user);
    let agent_b = system.create_agent(&user);

    // User requests complex task
    let session = system.start_session(&user).await;
    let user_request = system.user_request(&session, "Process and transform data").await;

    // Agent A spawns Agent B
    let spawn_event = system.spawn_agent(&agent_a, &agent_b, &session).await;

    // Start coordination
    let coordination = system.start_coordination(
        CoordinationType::Pipeline,
        vec![
            Participant::coordinator(&agent_a),
            Participant::peer(&agent_b),
        ],
    ).await;

    // Agent A processes
    let a_output = system.agent_action(&agent_a, ...).await;

    // Agent B receives and processes
    let b_input = system.get_coordination_input(&agent_b, &coordination).await;
    assert_eq!(b_input, a_output);
    let b_output = system.agent_action(&agent_b, ...).await;

    // Complete coordination
    system.complete_coordination(&coordination, b_output).await;

    // Verify causal chain traces back to user
    let ancestry = system.get_ancestry(b_output.event_id).await;
    assert!(ancestry.iter().any(|e| e.id == user_request.id));
}
```

```rust
// moloch-api/tests/scenarios/high_stakes_approval.rs

#[tokio::test]
async fn scenario_high_stakes_with_approval() {
    let system = TestSystem::new();
    let user = system.create_user();
    let agent = system.create_agent(&user);

    // Grant capability requiring approval
    let cap = system.grant_capability_requiring_approval(&user, &agent).await;

    // Agent proposes high-stakes action
    let proposed = ProposedAction {
        action_type: "transfer_funds".into(),
        resource: resource_id("account:12345"),
        impact: ImpactAssessment::critical(),
        ..
    };

    let request_id = system.request_approval(&agent, proposed).await;

    // Verify agent is blocked
    let action_result = system.try_action(&agent, ...).await;
    assert!(action_result.is_err());

    // User approves with modification
    let response = ApprovalResponse {
        request_id,
        decision: ApprovalDecision::ApproveWithModifications(ActionModifications {
            parameters: Some(json!({"max_amount": 1000})),
            ..
        }),
        ..
    };
    system.respond_approval(&user, response).await;

    // Agent can now act (with modifications)
    let action_result = system.try_action_with_modifications(&agent, ...).await;
    assert!(action_result.is_ok());
}
```

```rust
// moloch-api/tests/scenarios/emergency_response.rs

#[tokio::test]
async fn scenario_emergency_suspension() {
    let system = TestSystem::new();
    let agent = system.create_and_activate_agent().await;

    // Agent is operating normally
    assert!(system.agent_can_act(&agent).await);

    // Anomaly detected - trigger emergency
    let emergency = system.declare_emergency(EmergencyAction::SuspendAgent {
        agent: agent.public_key,
        reason: "Anomalous behavior detected".into(),
        duration: Some(Duration::from_hours(1)),
        scope: SuspensionScope::Full,
    }).await;

    // Agent immediately blocked
    assert!(!system.agent_can_act(&agent).await);

    // All nodes enforce
    for node in system.nodes() {
        assert!(!node.agent_can_act(&agent).await);
    }

    // Investigation and resolution
    let resolution = EmergencyResolution {
        emergency_event_id: emergency.id,
        resolution: Resolution::FalseAlarm {
            explanation: "Behavior was expected given context".into(),
        },
        post_mortem: Some(PostMortem { .. }),
        ..
    };
    system.resolve_emergency(resolution).await;

    // Agent restored
    assert!(system.agent_can_act(&agent).await);
}
```

### 9.2 Adversarial Tests

```rust
// moloch-core/tests/adversarial/attestation_bypass.rs

#[test]
fn adversarial_expired_attestation_rejected() {
    let agent = agent_with_expired_attestation();
    let action = agent.create_action();

    let result = system.submit(action);
    assert!(matches!(result, Err(Error::AttestationExpired)));
}

#[test]
fn adversarial_forged_attestation_rejected() {
    let agent = agent_with_forged_attestation();
    let action = agent.create_action();

    let result = system.submit(action);
    assert!(matches!(result, Err(Error::InvalidAttestationSignature)));
}

#[test]
fn adversarial_capability_escalation_rejected() {
    let agent = agent_with_read_only_capability();
    let action = agent.create_write_action();

    let result = system.submit(action);
    assert!(matches!(result, Err(Error::CapabilityDenied { .. })));
}

#[test]
fn adversarial_causal_chain_manipulation_rejected() {
    let agent = agent();
    let action = action_with_fake_root_event();

    let result = system.submit(action);
    assert!(matches!(result, Err(Error::InvalidCausalContext)));
}

#[test]
fn adversarial_replay_attack_rejected() {
    let action = valid_action();
    system.submit(action.clone()).unwrap();

    let result = system.submit(action); // Replay
    assert!(matches!(result, Err(Error::DuplicateEvent)));
}

#[test]
fn adversarial_suspended_agent_rejected() {
    let agent = suspended_agent();
    let action = agent.create_action();

    let result = system.submit(action);
    assert!(matches!(result, Err(Error::AgentSuspended)));
}
```

---

## Test Infrastructure

### Generators for Property Tests

```rust
// moloch-core/tests/generators.rs

use proptest::prelude::*;

pub fn arb_causal_chain(size: impl Into<SizeRange>) -> impl Strategy<Value = Vec<AuditEvent>> {
    size.into().prop_flat_map(|len| {
        // Generate chain of events with valid causal relationships
    })
}

pub fn arb_session() -> impl Strategy<Value = Session> {
    (
        arb_session_id(),
        arb_principal(),
        arb_timestamp(),
        arb_duration(),
        arb_capability_set(),
        1u32..20,
        any::<String>(),
    ).prop_map(|(id, principal, started, max_dur, caps, max_depth, purpose)| {
        Session { id, principal, started_at: started, max_duration: max_dur, capabilities: caps, max_depth, purpose, ended_at: None }
    })
}

pub fn arb_attestation() -> impl Strategy<Value = AgentAttestation> {
    // Generate valid attestation with proper signature
}

pub fn arb_capability() -> impl Strategy<Value = Capability> {
    (
        arb_capability_kind(),
        arb_resource_scope(),
        arb_capability_constraints(),
        arb_principal(),
        arb_timestamp(),
        any::<bool>(),
        0u32..10,
    ).prop_map(|(kind, scope, constraints, grantor, granted_at, delegatable, max_depth)| {
        Capability { id: CapabilityId::random(), kind, scope, constraints, grantor, granted_at, expires_at: None, delegatable, max_delegation_depth: max_depth, signature: Sig::placeholder() }
    })
}

// ... more generators
```

### Test Fixtures

```rust
// moloch-core/tests/fixtures.rs

pub fn minimal_causal_context() -> CausalContext {
    let session = test_session();
    CausalContext {
        parent_event_id: None,
        root_event_id: EventId::random(),
        session_id: session.id,
        principal: test_principal(),
        depth: 0,
        sequence: 0,
    }
}

pub fn test_session() -> Session {
    Session {
        id: SessionId::random(),
        principal: test_principal(),
        started_at: Timestamp::now(),
        ended_at: None,
        max_duration: Duration::from_hours(1),
        capabilities: CapabilitySet::default(),
        max_depth: 10,
        purpose: "test".into(),
    }
}

pub fn test_attestation(agent: &PublicKey) -> AgentAttestation {
    AgentAttestation {
        agent_id: *agent,
        code_hash: Hash::random(),
        config_hash: Hash::random(),
        prompt_hash: Hash::random(),
        tools: vec![],
        runtime: test_runtime(),
        attested_at: Timestamp::now(),
        validity_period: Duration::from_hours(24),
        authority_signature: sign_attestation(...),
        authority: test_authority(),
    }
}

// ... more fixtures
```

---

## Execution Plan

### Phase Order

| Phase | Section | Est. Tests | Dependencies | Priority |
|-------|---------|------------|--------------|----------|
| 1 | Causality Chain | 45 | None | P0 |
| 2 | Attestation | 40 | Phase 1 | P0 |
| 3 | Capabilities | 55 | Phase 1, 2 | P0 |
| 4 | HITL | 50 | Phase 1, 3 | P1 |
| 5 | Reasoning | 35 | Phase 1 | P1 |
| 6 | Outcomes | 40 | Phase 1 | P1 |
| 7 | Emergency | 45 | Phase 1, 2, 3 | P0 |
| 8 | Coordination | 50 | Phase 1, 2, 3 | P2 |
| 9 | Integration | 30 | All | P1 |

**Total: ~390 tests**

### Definition of Done per Phase

- [ ] All unit tests pass
- [ ] All property tests pass (1000+ iterations)
- [ ] Integration tests with other phases pass
- [ ] Adversarial tests pass
- [ ] Code coverage > 90% for phase module
- [ ] Invariants documented and tested
- [ ] API documented with examples

### CI Integration

```yaml
# .github/workflows/agent-accountability.yml
name: Agent Accountability Tests

on: [push, pull_request]

jobs:
  unit-tests:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Run unit tests
        run: cargo test --lib -p moloch-core -- agent::

  property-tests:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Run property tests
        run: cargo test --test props -p moloch-core -- --test-threads=4
        env:
          PROPTEST_CASES: 10000

  integration-tests:
    runs-on: ubuntu-latest
    needs: [unit-tests]
    steps:
      - uses: actions/checkout@v4
      - name: Run integration tests
        run: cargo test --test '*' -p moloch-api

  adversarial-tests:
    runs-on: ubuntu-latest
    needs: [unit-tests]
    steps:
      - uses: actions/checkout@v4
      - name: Run adversarial tests
        run: cargo test --test adversarial -p moloch-core
```

---

## Appendix: Test Naming Conventions

```
<module>_<aspect>_<condition>_<expected>

Examples:
- causal_context_parent_missing_when_depth_zero_succeeds
- attestation_verify_expired_fails
- capability_delegate_exceeds_depth_rejected
- approval_request_timeout_escalates
- emergency_suspend_agent_blocks_actions
```

---

**End of TDD Roadmap**
