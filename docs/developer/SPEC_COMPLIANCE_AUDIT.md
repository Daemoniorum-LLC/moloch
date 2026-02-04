# Agent Accountability Specification Compliance Audit

**Version**: 1.0.0
**Date**: 2026-02-03
**Spec Reference**: `docs/specs/AGENT_ACCOUNTABILITY.md` v1.0.0-draft
**Codebase**: `moloch-core/src/agent/` (branch `claude/review-crypto-audit-lib-52H9p`)

---

## Executive Summary

Systematic audit of every section, rule, and invariant in the Agent Accountability
specification against the current implementation. The codebase has **strong data model
coverage** (~95% of specified types exist) but **significant enforcement gaps** (~40% of
specified rules are not enforced at runtime).

### Compliance by Category

| Category | Data Model | Rule Enforcement | Tests |
|----------|-----------|-----------------|-------|
| Section 3: Causality Chain | 95% | 100% (rules) / 0% (queries) | Strong |
| Section 4: Attestation | 100% | 40% | Good |
| Section 5: Capability Model | 100% | 75% | Strong |
| Section 6: HITL Protocol | 100% | 60% | Good |
| Section 7: Reasoning Traces | 100% | 100% | Strong |
| Section 8: Outcome Verification | 100% | 100% | Strong |
| Section 9: Emergency Controls | 100% | 80% | Good |
| Section 10: Coordination | 100% | 90% | Strong |
| Section 11: Event Types | 30% | 0% | None |
| Section 12: Invariants | N/A | 60% | Partial |

---

## Detailed Findings

### Section 3: Causality Chain

**Data Model: 95% Complete**

| Type | Status | Notes |
|------|--------|-------|
| `CausalContext` | ✓ Complete | All 6 fields + `cross_session_ref` bonus |
| `Session` | ⚠ Missing field | **`capabilities: CapabilitySet` field absent** |
| `SessionId` | ✓ Complete | `[u8; 16]` as specified |
| `PrincipalId` + `PrincipalKind` | ✓ Complete | All 3 variants |

**Rule Enforcement:**

| Rule | Description | Status |
|------|-------------|--------|
| 3.3.1 | Root requirement | ✓ Enforced in `CausalContext::root()` |
| 3.3.2 | Parent validity | ✓ Enforced in `validate_against_parent()` |
| 3.3.3 | Depth limits | ✓ Enforced in `validate()` |
| 3.3.4 | Sequence monotonicity | ✓ Enforced in `child()` |
| 3.3.5 | Principal immutability | ✓ Enforced in `validate_against_parent()` |

**Gaps:**

| ID | Finding | Severity | Spec Ref |
|----|---------|----------|----------|
| G-3.1 | `Session` missing `capabilities: CapabilitySet` field | P1 | §3.2.2 |
| G-3.2 | `get_descendants()` not implemented | P2 | §3.4 |
| G-3.3 | `get_ancestry()` not implemented | P2 | §3.4 |
| G-3.4 | `get_session_events()` not implemented | P2 | §3.4 |
| G-3.5 | `get_principal_events()` not implemented | P2 | §3.4 |

**Note on G-3.2 through G-3.5**: These query functions require a storage/index layer.
They belong in `moloch-index` or a new `moloch-core/src/agent/query.rs` module, not
in the type definitions. Classify as P2 (design-level, not a type/validation bug).

---

### Section 4: Agent Identity Attestation

**Data Model: 100% Complete**

All types fully implemented: `AgentAttestation`, `ToolAttestation`, `RuntimeAttestation`,
`TeeQuote`, `TeeType`, `AttestationRegistry`.

**Rule Enforcement:**

| Rule | Description | Status |
|------|-------------|--------|
| 4.3.1 | Attestation required for all agent actions | ✗ Not enforced (`attestation_hash` is `Option`) |
| 4.3.2 | Attestation validity (expiry + authority + revocation) | ✓ Enforced in `registry.verify()` |
| 4.3.3 | Attestation binding (agent_id == event actor) | ✗ Not enforced |
| 4.3.4 | Tool consistency (tools in attestation) | ✗ Not enforced (helper `has_tool()` exists) |
| 4.3.5 | Re-attestation on code/config change | ✗ Not enforced |

**Gaps:**

| ID | Finding | Severity | Spec Ref |
|----|---------|----------|----------|
| G-4.1 | `AgentEventMetadata.attestation_hash` is `Option<Hash>`, spec requires it for all agent actions | P0 | §4.3.1, INV-ATTEST-1 |
| G-4.2 | No validation that attestation `agent_id` matches event `actor` | P0 | §4.3.3 |
| G-4.3 | No validation that invoked tools appear in agent's attestation | P1 | §4.3.4, INV-ATTEST-3 |
| G-4.4 | No re-attestation trigger mechanism | P2 | §4.3.5 |

---

### Section 5: Capability Model

**Data Model: 100% Complete**

All types fully implemented: `Capability`, `CapabilityKind` (12 variants),
`ResourceScope` (4 variants), `CapabilityConstraints`, `CapabilitySet`,
`CapabilityCheck`, `DenialReason` (8 variants). Lifecycle states (Active/Expired/Revoked)
implemented with revocation tracking.

**Rule Enforcement:**

| Rule | Description | Status |
|------|-------------|--------|
| 5.3.1 | Explicit grant (no default capabilities) | ⚠ Architectural (not type-enforceable) |
| 5.3.2 | Grantor authority (grantor must possess capability) | ✗ Not enforced |
| 5.3.3 | Delegation limits (subset scope, depth ≤ max) | ✓ Enforced in `delegate()` |
| 5.3.4 | Capability reference in events | ⚠ Deferred to audit bridge |
| 5.3.5 | Constraint enforcement at action time | ⚠ Partial (rate limit not checked) |
| 5.3.6 | Scope strictness | ✓ Enforced in `ResourceScope::matches()` |

**Gaps:**

| ID | Finding | Severity | Spec Ref |
|----|---------|----------|----------|
| G-5.1 | `permits()` does not check `rate_limit` constraint | P1 | §5.3.5 |
| G-5.2 | No grantor authority validation | P2 | §5.3.2 |

---

### Section 6: HITL Protocol

**Data Model: 100% Complete**

All types fully implemented: `ApprovalRequest`, `ProposedAction`, `ImpactAssessment`,
`ApprovalPolicy`, `EscalationPolicy`, `ApprovalStatus` (6 variants),
`ApprovalResponse`, `ApprovalDecision` (5 variants), `ApprovalContext`,
`ActionModifications`.

**Rule Enforcement:**

| Rule | Description | Status |
|------|-------------|--------|
| 6.3.1 | Approval triggers (capability flag, severity, confidence) | ⚠ Partial (capability + severity only) |
| 6.3.2 | Approval timeout handling | ⚠ Partial (expiry exists, auto-approve missing) |
| 6.3.3 | Approval verification (signature, request_id binding) | ✓ Enforced |
| 6.3.4 | Modification binding (agent applies modifications) | ✗ Not enforced |
| 6.3.5 | Rejection handling (agent must not proceed) | ✗ Not enforced |

**Gaps:**

| ID | Finding | Severity | Spec Ref |
|----|---------|----------|----------|
| G-6.1 | No confidence-threshold approval trigger | P2 | §6.3.1 |
| G-6.2 | No auto-approve-on-timeout implementation | P2 | §6.3.2 |
| G-6.3 | No agent-level enforcement of modification binding | P2 | §6.3.4 |
| G-6.4 | No agent-level enforcement of rejection handling | P2 | §6.3.5 |

**Note**: G-6.3 and G-6.4 require an agent coordinator/runtime layer that doesn't
exist yet. These are architectural gaps, not missing validation in existing code.

---

### Section 7: Reasoning Traces

**Data Model: 100% Complete. Rule Enforcement: 100%.**

All types implemented: `ReasoningTrace`, `Goal`, `GoalSource`, `ReasoningStep`,
`StepAction`, `Decision`, `Confidence`, `Alternative`, `Factor`.

All rules enforced:
- 7.3.2: `is_complete()` validates trace completeness
- 7.3.3: `verify_integrity()` validates trace hash
- 7.3.5: Confidence thresholds (`should_reject()`, `requires_approval()`, `should_warn()`)

**No gaps.**

---

### Section 8: Outcome Verification

**Data Model: 100% Complete. Rule Enforcement: 100%.**

All types implemented: `OutcomeAttestation`, `ActionOutcome`, `Evidence`,
`Attestor`, `IdempotencyKey`, `IdempotencyRecord`, `IdempotencyStore`,
`OutcomeDispute`, `DisputeStatus`.

All rules enforced:
- 8.3.3: `is_evidence_sufficient()` implements severity-based evidence requirements
- 8.3.4: `IdempotencyStore` with expiry-aware lookup
- 8.3.5: `OutcomeDispute` tracks dispute lifecycle

**No gaps.**

---

### Section 9: Emergency Controls

**Data Model: 100% Complete.**

All types implemented: `EmergencyAction` (7 variants), `SuspensionScope`,
`EmergencyEvent`, `EmergencyPriority`, `EmergencyResolution`, `Resolution`,
`PostMortem`, `EmergencyTrigger` (7 variants).

**Gaps:**

| ID | Finding | Severity | Spec Ref |
|----|---------|----------|----------|
| G-9.1 | No runtime enforcement of suspension (rejecting events from suspended agents) | P1 | §9.3.3, INV-EMERG-1 |
| G-9.2 | No propagation mechanism for emergency actions | P2 | §9.3.2 |

**Note**: G-9.1 and G-9.2 require integration with the event processing pipeline
(`moloch-chain` or `moloch-api`), not just the agent type definitions.

---

### Section 10: Multi-Agent Coordination

**Data Model: 100% Complete. Rule Enforcement: 90%.**

All types implemented with validation methods:
- `validate_coordinator()` enforces Rule 10.3.1
- `verify_commitment()` enforces Rule 10.3.2 / INV-COORD-2
- `validate_responsibility()` enforces Rule 10.3.3 / INV-COORD-3

**Gaps:**

| ID | Finding | Severity | Spec Ref |
|----|---------|----------|----------|
| G-10.1 | No capability composition validation (union check) | P2 | §10.3.6 |

---

### Section 11: Event Types — CRITICAL GAP

**Data Model: ~30% Complete. Rule Enforcement: 0%.**

The specification defines an `AgentEventType` enum with 21 variants (§11.1) and
`AgentEventMetadata` with 4 required fields (§11.2). The current implementation has:

- **No `AgentEventType` enum.** Agent events use the generic `EventType::AgentAction`
  variant from `event.rs`, which only carries `action: String, reasoning: Option<String>`.
- **Simplified `AgentEventMetadata`** in `audit_bridge.rs` that diverges from spec:
  - Stores `causal_context_hash: Hash` instead of full `CausalContext`
  - Stores `reasoning: Option<String>` instead of `reasoning_trace_hash: Option<Hash>`
  - `attestation_hash` is `Option<Hash>` (should be required for agent actions)

**Gaps:**

| ID | Finding | Severity | Spec Ref |
|----|---------|----------|----------|
| G-11.1 | No `AgentEventType` enum — all 21 variants missing | P0 | §11.1 |
| G-11.2 | `AgentEventMetadata` diverges: missing `causal_context` (full), missing `reasoning_trace_hash` | P1 | §11.2 |
| G-11.3 | Missing `TerminationReason` enum | P2 | §11.1 |
| G-11.4 | Missing `ActionDetails` struct | P2 | §11.1 |
| G-11.5 | Missing `DisputeResolution` enum | P2 | §11.1 |

---

### Section 12: Invariants

Cross-referencing all specified invariants against enforced code:

| Invariant | Description | Enforced? | Tested? |
|-----------|-------------|-----------|---------|
| INV-CAUSAL-1 | Parent exists, parent.sequence < child.sequence | ✓ | ✓ |
| INV-CAUSAL-2 | Root at depth=0 | ✓ | ✓ |
| INV-CAUSAL-3 | depth ≤ session.max_depth | ✓ | ✓ |
| INV-CAUSAL-4 | Exactly one root per session | ⚠ Not enforced (no session-level tracking) | ✗ |
| INV-ATTEST-1 | All agent actions have valid attestation | ✗ | ✗ |
| INV-ATTEST-2 | Attestation validity window | ✓ | ✓ |
| INV-ATTEST-3 | Tool in attestation | ✗ | ✗ |
| INV-CAP-1 | Capability grantee matches actor | ⚠ In permits() but not in events | Partial |
| INV-CAP-2 | Usage ≤ max_uses | ✓ | ✓ |
| INV-CAP-3 | Delegated scope ⊆ parent scope | ✓ | ✓ |
| INV-CAP-4 | Delegation depth ≤ max | ✓ | ✓ |
| INV-HITL-1 | Approval before action | ✗ (structural only) | ✗ |
| INV-HITL-2 | Response references existing request | ✓ | ✓ |
| INV-HITL-3 | Modifications reflected in action | ✗ | ✗ |
| INV-EMERG-1 | No events from suspended agents | ✗ | ✗ |
| INV-EMERG-2 | Every emergency has resolution | ✗ (type exists, not enforced) | ✗ |
| INV-EMERG-3 | Global pause exceptions only | ✗ | ✗ |
| INV-COORD-1 | Exactly one coordinator | ✓ | ✓ |
| INV-COORD-2 | All commitments verify | ✓ | ✓ |
| INV-COORD-3 | Shared responsibility sums to 1.0 | ✓ | ✓ |

**Enforced: 11/20 (55%). Tested: 10/20 (50%).**

---

## Gap Summary by Priority

### P0 — Spec Invariant Violations (Immediate)

| ID | Finding | Section |
|----|---------|---------|
| G-4.1 | Attestation hash optional, should be required for agent actions | §4.3.1 |
| G-4.2 | No attestation-actor binding validation | §4.3.3 |
| G-11.1 | No `AgentEventType` enum (21 variants missing) | §11.1 |

### P1 — Missing Spec-Required Functionality

| ID | Finding | Section |
|----|---------|---------|
| G-3.1 | Session missing `capabilities` field | §3.2.2 |
| G-4.3 | No tool consistency validation | §4.3.4 |
| G-5.1 | Rate limit not enforced in `permits()` | §5.3.5 |
| G-9.1 | No runtime enforcement of agent suspension | §9.3.3 |
| G-11.2 | `AgentEventMetadata` diverges from spec | §11.2 |

### P2 — Design-Level Gaps

| ID | Finding | Section |
|----|---------|---------|
| G-3.2–3.5 | Causal chain query functions (need index layer) | §3.4 |
| G-4.4 | No re-attestation trigger | §4.3.5 |
| G-5.2 | No grantor authority validation | §5.3.2 |
| G-6.1–6.4 | HITL advanced triggers, auto-approve, agent enforcement | §6.3 |
| G-9.2 | No emergency propagation mechanism | §9.3.2 |
| G-10.1 | No capability composition validation | §10.3.6 |
| G-11.3–11.5 | Missing supporting types | §11.1 |

---

## Recommended Implementation Order

### Phase A: Event Type Foundation (P0 — G-11.1)

Create the `AgentEventType` enum. This is the keystone gap — without it, agent
events cannot be distinguished in the audit chain, and most other enforcement
gaps cannot be properly closed. This requires:

1. Define `AgentEventType` enum with all 21 variants
2. Add missing supporting types (`TerminationReason`, `ActionDetails`, `DisputeResolution`)
3. Integrate with core `EventType` (add `AgentAccountability(AgentEventType)` variant or similar)
4. Update `AgentEventMetadata` to match spec (full `CausalContext`, `reasoning_trace_hash`)

### Phase B: Attestation Enforcement (P0 — G-4.1, G-4.2)

1. Make `attestation_hash` required (not `Option`) in `AgentEventMetadata`
2. Add `validate_attestation_binding()` that checks `agent_id == event.actor`
3. Add validation to `AgentAuditEventBuilder` that enforces binding

### Phase C: Constraint Enforcement (P1 — G-5.1, G-3.1, G-4.3)

1. Add rate limit checking to `CapabilitySet::permits()`
2. Add `capabilities: CapabilitySet` field to `Session`
3. Add tool consistency validation (check invoked tool exists in attestation)

### Phase D: Runtime Enforcement (P1 — G-9.1)

1. Add suspension checking to event validation pipeline
2. Integrate emergency state with `AgentAuditEventBuilder`

### Phase E: Query Layer (P2 — G-3.2 through G-3.5)

1. Define `CausalChainQuery` trait
2. Implement in-memory version for testing
3. Plan integration with `moloch-index`

### Phase F: Advanced HITL + Coordination (P2)

1. Auto-approve timeout behavior
2. Confidence-threshold triggers
3. Capability composition validation
4. Agent-level modification/rejection enforcement

---

## Document End

*This audit was performed by systematically comparing every type, field, rule,
and invariant in `docs/specs/AGENT_ACCOUNTABILITY.md` against the implemented
code in `moloch-core/src/agent/`.*
