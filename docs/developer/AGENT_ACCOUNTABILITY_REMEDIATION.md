# Agent Accountability Remediation Roadmap

**Version**: 1.0.0
**Status**: Draft
**Date**: 2026-01-29
**Spec Reference**: `docs/specs/AGENT_ACCOUNTABILITY.md`
**TDD Reference**: `docs/specs/AGENT_ACCOUNTABILITY_TDD.md`
**Context**: Code review of Phases 1-9 implementation (361 tests, branch `claude/review-crypto-audit-lib-52H9p`)

---

## Overview

This roadmap addresses findings from the full branch code review of the Agent Accountability implementation. Each finding is classified by severity, mapped to spec invariants, and expressed as a RED-GREEN-REFACTOR cycle per SDD+TDD methodology.

### Methodology

1. **RED**: Write failing tests that expose the deficiency
2. **GREEN**: Implement the minimal fix
3. **REFACTOR**: Clean up without changing behavior

### Finding Classification

| Priority | Criteria | Response SLA |
|----------|----------|--------------|
| **P0** | Security vulnerability or spec invariant violation | Immediate |
| **P1** | Missing spec-required functionality | Before merge |
| **P2** | Design deficiency affecting extensibility | Next iteration |
| **P3** | Code quality / maintainability | Backlog |

---

## Phase 1: Signature Verification Hardening (P0)

**Priority**: Critical
**Estimated Tests**: 12
**Spec References**: INV-COORD-2, Section 8.3, Section 10.3
**Files**: `outcome.rs`, `coordination.rs`

### Finding 1.1: OutcomeAttestation Signature-Attestor Binding

**Current State**: `moloch-core/src/agent/outcome.rs:90-93`

`OutcomeAttestation::verify_signature()` accepts an arbitrary `PublicKey` from the caller. Nothing enforces that the key used for verification matches the `Attestor` embedded in the struct. An attacker can construct an `OutcomeAttestation` with `Attestor::SelfAttestation { agent: VictimKey }` but sign it with `AttackerKey`, then pass `AttackerKey` to `verify_signature()` -- the signature verifies, but the attestation falsely attributes the outcome to the victim.

`AgentAttestation::verify_signature()` correctly verifies against its own embedded `authority` field.

**Spec Rule**: Section 8.3 requires outcome attestations to be cryptographically bound to their attestor identity.

#### RED - Write Failing Tests

```rust
// moloch-core/src/agent/outcome.rs - Add to #[cfg(test)] mod tests

#[test]
fn verify_against_attestor_rejects_key_mismatch() {
    // An OutcomeAttestation signed by key A but claiming
    // attestor with key B must fail verify_against_attestor()
    let real_key = SecretKey::generate();
    let fake_key = SecretKey::generate();

    let attestation = OutcomeAttestation::builder()
        .action_event_id(test_event_id())
        .outcome(ActionOutcome::success(serde_json::json!({})))
        .attestor(Attestor::self_attestation(fake_key.public_key())) // Claims fake
        .observed_now()
        .sign(&real_key) // Signed by real
        .unwrap();

    // Raw verify with real_key would pass - this is the vulnerability
    assert!(attestation.verify_signature(&real_key.public_key()).is_ok());

    // verify_against_attestor must reject: attestor says fake_key, sig is real_key
    assert!(attestation.verify_against_attestor().is_err());
}

#[test]
fn verify_against_attestor_accepts_matching_key() {
    let key = SecretKey::generate();

    let attestation = OutcomeAttestation::builder()
        .action_event_id(test_event_id())
        .outcome(ActionOutcome::success(serde_json::json!({})))
        .attestor(Attestor::self_attestation(key.public_key()))
        .observed_now()
        .sign(&key)
        .unwrap();

    assert!(attestation.verify_against_attestor().is_ok());
}

#[test]
fn verify_against_attestor_for_human_observer_returns_error() {
    // HumanObserver has no public key, so attestor-based verify
    // must return an appropriate error (not silently pass)
    let key = SecretKey::generate();
    let principal = PrincipalId::user("admin@example.com").unwrap();

    let attestation = OutcomeAttestation::builder()
        .action_event_id(test_event_id())
        .outcome(ActionOutcome::success(serde_json::json!({})))
        .attestor(Attestor::human_observer(principal))
        .observed_now()
        .sign(&key)
        .unwrap();

    let result = attestation.verify_against_attestor();
    assert!(result.is_err());
    // Error should indicate the attestor type doesn't carry a key
}

#[test]
fn verify_against_attestor_for_execution_system() {
    let system_key = SecretKey::generate();

    let attestation = OutcomeAttestation::builder()
        .action_event_id(test_event_id())
        .outcome(ActionOutcome::success(serde_json::json!({})))
        .attestor(Attestor::execution_system("docker", system_key.public_key()))
        .observed_now()
        .sign(&system_key)
        .unwrap();

    assert!(attestation.verify_against_attestor().is_ok());
}
```

#### GREEN - Implementation

Add `verify_against_attestor()` to `OutcomeAttestation`:

```rust
// outcome.rs

impl OutcomeAttestation {
    /// Verify the signature against the attestor's embedded public key.
    ///
    /// Unlike `verify_signature()` which accepts an arbitrary key, this method
    /// extracts the expected key from the `Attestor` and verifies against it,
    /// ensuring the signature matches the claimed attestor identity.
    pub fn verify_against_attestor(&self) -> Result<()> {
        let public_key = self.attestor.public_key().ok_or_else(|| {
            Error::invalid_input(
                "Attestor type does not carry a public key; \
                 use external verification for HumanObserver/CryptographicProof"
            )
        })?;
        self.verify_signature(public_key)
    }
}
```

Deprecate the raw `verify_signature()` with a doc comment directing callers to `verify_against_attestor()`.

#### REFACTOR

- Update all call sites in integration tests to prefer `verify_against_attestor()`
- Add `#[deprecated]` attribute to bare `verify_signature()` or make it `pub(crate)`

---

### Finding 1.2: CoordinatedAction Commitment Verification

**Current State**: `moloch-core/src/agent/coordination.rs:226-256`

`Participant.commitment` is stored as `Sig` but is never verified against the `CoordinatedActionSpec`. Tests universally use `Sig::empty()`. This violates INV-COORD-2.

**Spec Invariant**: `INV-COORD-2: ∀ participant P in coordination C: P.commitment verifies against C.action specification`

#### RED - Write Failing Tests

```rust
// moloch-core/src/agent/coordination.rs - Add to #[cfg(test)] mod tests

#[test]
fn participant_commitment_verifies_against_spec() {
    let key = SecretKey::generate();
    let spec = CoordinatedActionSpec::new("deploy-service");

    // Create participant with proper commitment
    let spec_bytes = spec.canonical_bytes();
    let commitment = key.sign(&spec_bytes);
    let participant = Participant::with_commitment(
        key.public_key(),
        ParticipantRole::Coordinator,
        Responsibility::individual(),
        commitment,
    );

    assert!(participant.verify_commitment(&spec, &key.public_key()).is_ok());
}

#[test]
fn participant_commitment_wrong_spec_rejected() {
    let key = SecretKey::generate();
    let spec_a = CoordinatedActionSpec::new("deploy-service");
    let spec_b = CoordinatedActionSpec::new("rollback-service");

    let commitment = key.sign(&spec_a.canonical_bytes());
    let participant = Participant::with_commitment(
        key.public_key(),
        ParticipantRole::Executor,
        Responsibility::individual(),
        commitment,
    );

    // Commitment was for spec_a, verifying against spec_b must fail
    assert!(participant.verify_commitment(&spec_b, &key.public_key()).is_err());
}

#[test]
fn participant_commitment_wrong_key_rejected() {
    let real_key = SecretKey::generate();
    let wrong_key = SecretKey::generate();
    let spec = CoordinatedActionSpec::new("deploy-service");

    let commitment = real_key.sign(&spec.canonical_bytes());
    let participant = Participant::with_commitment(
        wrong_key.public_key(), // claims wrong_key identity
        ParticipantRole::Executor,
        Responsibility::individual(),
        commitment, // signed by real_key
    );

    assert!(participant.verify_commitment(&spec, &wrong_key.public_key()).is_err());
}

#[test]
fn coordinated_action_build_validates_all_commitments() {
    let coord_key = SecretKey::generate();
    let exec_key = SecretKey::generate();
    let spec = CoordinatedActionSpec::new("deploy");

    let coord_commitment = coord_key.sign(&spec.canonical_bytes());
    let p1 = Participant::with_commitment(
        coord_key.public_key(),
        ParticipantRole::Coordinator,
        Responsibility::individual(),
        coord_commitment,
    );

    // Executor has empty (invalid) commitment
    let p2 = Participant::new(
        exec_key.public_key(),
        ParticipantRole::Executor,
        Responsibility::individual(),
        Sig::empty(), // Not a valid commitment
    );

    let result = CoordinatedAction::builder()
        .coordination_type(CoordinationType::Supervised)
        .participant(p1)
        .participant(p2)
        .action(spec)
        .protocol(CoordinationProtocol::TwoPhaseCommit)
        .causal_context(test_causal_context())
        .build_verified(); // New method that validates commitments

    assert!(result.is_err());
}
```

#### GREEN - Implementation

```rust
// coordination.rs

impl CoordinatedActionSpec {
    /// Compute canonical bytes for commitment signing.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(self).unwrap_or_default()
    }
}

impl Participant {
    /// Verify that this participant's commitment is a valid signature
    /// over the given spec, using the participant's own public key.
    pub fn verify_commitment(
        &self,
        spec: &CoordinatedActionSpec,
        expected_key: &PublicKey,
    ) -> Result<()> {
        if self.agent != *expected_key {
            return Err(Error::invalid_input("Key does not match participant agent"));
        }
        let message = spec.canonical_bytes();
        expected_key.verify(&message, &self.commitment)
    }
}
```

---

## Phase 2: Capability Lifecycle Completion (P1)

**Priority**: High
**Estimated Tests**: 18
**Spec References**: Section 5.4, INV-CAP-1 through INV-CAP-4, Rule 5.3.3
**Files**: `capability.rs` (new: revocation support, delegation chain)

### Finding 2.1: Capability Revocation

**Current State**: `capability.rs` has `is_valid_at()` checking only expiry.

The spec (Section 5.4) defines a four-state lifecycle: CREATED -> ACTIVE -> EXPIRED/REVOKED. Revocation is entirely missing. `is_valid_at()` cannot distinguish between active and revoked capabilities.

**Spec Rule**: "5.3.6 Revocation Propagation: Revoking a capability MUST revoke all capabilities derived from it" (lifecycle diagram at line 676)

#### RED - Write Failing Tests

```rust
// moloch-core/src/agent/capability.rs - Add to #[cfg(test)] mod tests

#[test]
fn capability_revoke_transitions_to_revoked() {
    let key = SecretKey::generate();
    let principal = test_principal();

    let mut cap = CapabilityBuilder::new()
        .kind(CapabilityKind::Write)
        .grantor(principal)
        .expires_in(Duration::from_secs(3600))
        .sign(&key)
        .unwrap();

    let now = chrono::Utc::now().timestamp_millis();
    assert!(cap.is_valid_at(now));
    assert!(!cap.is_revoked());

    cap.revoke("Policy violation");

    assert!(cap.is_revoked());
    assert!(!cap.is_valid_at(now)); // Revoked overrides not-expired
}

#[test]
fn capability_revoked_at_recorded() {
    let key = SecretKey::generate();
    let principal = test_principal();

    let mut cap = CapabilityBuilder::new()
        .kind(CapabilityKind::Read)
        .grantor(principal)
        .expires_in(Duration::from_secs(3600))
        .sign(&key)
        .unwrap();

    cap.revoke("Testing");
    assert!(cap.revoked_at().is_some());
    assert!(cap.revocation_reason().is_some());
}

#[test]
fn capability_revocation_reason_preserved() {
    let key = SecretKey::generate();
    let principal = test_principal();

    let mut cap = CapabilityBuilder::new()
        .kind(CapabilityKind::Execute)
        .grantor(principal)
        .expires_in(Duration::from_secs(3600))
        .sign(&key)
        .unwrap();

    cap.revoke("Agent exceeded scope");
    assert_eq!(cap.revocation_reason().unwrap(), "Agent exceeded scope");
}

#[test]
fn capability_lifecycle_states() {
    let key = SecretKey::generate();
    let principal = test_principal();

    let cap = CapabilityBuilder::new()
        .kind(CapabilityKind::Read)
        .grantor(principal)
        .expires_in(Duration::from_secs(3600))
        .sign(&key)
        .unwrap();

    let now = chrono::Utc::now().timestamp_millis();
    assert_eq!(cap.lifecycle_state(now), CapabilityState::Active);
}
```

#### GREEN - Implementation

```rust
// capability.rs - additions

/// Lifecycle state of a capability.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CapabilityState {
    Active,
    Expired,
    Revoked,
}

// Add fields to Capability struct:
// revoked_at: Option<i64>,
// revocation_reason: Option<String>,

impl Capability {
    pub fn revoke(&mut self, reason: impl Into<String>) {
        self.revoked_at = Some(chrono::Utc::now().timestamp_millis());
        self.revocation_reason = Some(reason.into());
    }

    pub fn is_revoked(&self) -> bool {
        self.revoked_at.is_some()
    }

    pub fn revoked_at(&self) -> Option<i64> {
        self.revoked_at
    }

    pub fn revocation_reason(&self) -> Option<&str> {
        self.revocation_reason.as_deref()
    }

    pub fn lifecycle_state(&self, now_ms: i64) -> CapabilityState {
        if self.is_revoked() {
            CapabilityState::Revoked
        } else if now_ms >= self.expires_at {
            CapabilityState::Expired
        } else {
            CapabilityState::Active
        }
    }

    // Update is_valid_at to check revocation
    pub fn is_valid_at(&self, now_ms: i64) -> bool {
        !self.is_revoked() && now_ms < self.expires_at
    }
}
```

---

### Finding 2.2: Delegation Chain Verification

**Current State**: `capability.rs` tracks `max_delegation_depth` but has no chain verification.

**Spec Invariants**:
- `INV-CAP-3: ∀ delegated capability C' from C: C'.scope ⊆ C.scope ∧ C'.expires_at ≤ C.expires_at`
- `INV-CAP-4: ∀ delegation chain: depth ≤ original_capability.max_delegation_depth`

#### RED - Write Failing Tests

```rust
// moloch-core/src/agent/capability.rs - Add to #[cfg(test)] mod tests

#[test]
fn delegate_creates_child_capability() {
    let grantor_key = SecretKey::generate();
    let delegate_key = SecretKey::generate();
    let principal = test_principal();

    let parent = CapabilityBuilder::new()
        .kind(CapabilityKind::Write)
        .grantor(principal)
        .expires_in(Duration::from_secs(3600))
        .delegatable(2)
        .scope(ResourceScope::pattern("*.txt"))
        .sign(&grantor_key)
        .unwrap();

    let child = parent.delegate(
        &grantor_key,
        delegate_key.public_key(),
        None, // Inherit scope
        None, // Inherit expiry
    ).unwrap();

    assert_eq!(child.delegation_depth(), 1);
    assert_eq!(child.max_delegation_depth(), 2);
    assert!(child.parent_capability_id().is_some());
}

#[test]
fn delegate_rejects_exceeding_max_depth() {
    let key1 = SecretKey::generate();
    let key2 = SecretKey::generate();
    let key3 = SecretKey::generate();
    let principal = test_principal();

    let root = CapabilityBuilder::new()
        .kind(CapabilityKind::Read)
        .grantor(principal)
        .expires_in(Duration::from_secs(3600))
        .delegatable(1) // Only 1 level of delegation
        .sign(&key1)
        .unwrap();

    let child = root.delegate(&key1, key2.public_key(), None, None).unwrap();

    // Second delegation should fail: depth 1 is the max
    let result = child.delegate(&key2, key3.public_key(), None, None);
    assert!(result.is_err());
}

#[test]
fn delegate_scope_must_be_subset() {
    let grantor_key = SecretKey::generate();
    let delegate_key = SecretKey::generate();
    let principal = test_principal();

    let parent = CapabilityBuilder::new()
        .kind(CapabilityKind::Write)
        .grantor(principal)
        .expires_in(Duration::from_secs(3600))
        .delegatable(2)
        .scope(ResourceScope::pattern("src/*.rs"))
        .sign(&grantor_key)
        .unwrap();

    // Trying to widen scope should fail
    let result = parent.delegate(
        &grantor_key,
        delegate_key.public_key(),
        Some(ResourceScope::all()), // Wider than parent
        None,
    );
    assert!(result.is_err());
}

#[test]
fn delegate_expiry_must_not_exceed_parent() {
    let grantor_key = SecretKey::generate();
    let delegate_key = SecretKey::generate();
    let principal = test_principal();

    let parent = CapabilityBuilder::new()
        .kind(CapabilityKind::Read)
        .grantor(principal)
        .expires_in(Duration::from_secs(3600))
        .delegatable(2)
        .sign(&grantor_key)
        .unwrap();

    // Trying to extend expiry beyond parent should fail
    let result = parent.delegate(
        &grantor_key,
        delegate_key.public_key(),
        None,
        Some(Duration::from_secs(7200)), // Longer than parent
    );
    assert!(result.is_err());
}

#[test]
fn delegate_non_delegatable_capability_fails() {
    let grantor_key = SecretKey::generate();
    let delegate_key = SecretKey::generate();
    let principal = test_principal();

    let cap = CapabilityBuilder::new()
        .kind(CapabilityKind::Read)
        .grantor(principal)
        .expires_in(Duration::from_secs(3600))
        // No .delegatable() call - delegation depth = 0
        .sign(&grantor_key)
        .unwrap();

    let result = cap.delegate(&grantor_key, delegate_key.public_key(), None, None);
    assert!(result.is_err());
}
```

#### GREEN - Implementation

Add to `Capability`:
- `delegation_depth: u32` field (0 for root capabilities)
- `parent_capability_id: Option<CapabilityId>` field
- `delegate()` method enforcing INV-CAP-3 and INV-CAP-4

---

## Phase 3: Type System Hardening (P1)

**Priority**: High
**Estimated Tests**: 10
**Spec References**: Section 3.2, Section 6.2
**Files**: `hitl.rs`, new `timestamp.rs`

### Finding 3.1: ApprovalResponse Field Encapsulation

**Current State**: `moloch-core/src/agent/hitl.rs:978-989`

`ApprovalResponse` has all fields `pub`, breaking encapsulation. This allows callers to mutate immutable data (e.g., changing `decision` after construction or modifying `responded_at`). Every other struct in the agent module uses private fields with accessor methods.

#### RED - Write Failing Tests

```rust
// This test validates API ergonomics after the change.
// The test should compile and pass with accessor methods.

#[test]
fn approval_response_accessed_through_methods() {
    let req_id = ApprovalRequestId::generate();
    let principal = test_approver();

    let response = ApprovalResponse::new(
        req_id,
        principal.clone(),
        ApprovalDecision::approve(),
    );

    assert_eq!(response.request_id(), req_id);
    assert_eq!(response.responder(), &principal);
    assert!(response.decision().is_approval());
    assert!(response.responded_at() > 0);
}
```

#### GREEN - Implementation

```rust
// hitl.rs - change pub fields to private, add accessors

pub struct ApprovalResponse {
    request_id: ApprovalRequestId,     // was: pub
    responder: PrincipalId,            // was: pub
    decision: ApprovalDecision,        // was: pub
    responded_at: i64,                 // was: pub
    signature: Sig,                    // was: pub
}

impl ApprovalResponse {
    pub fn request_id(&self) -> ApprovalRequestId { self.request_id }
    pub fn responder(&self) -> &PrincipalId { &self.responder }
    pub fn decision(&self) -> &ApprovalDecision { &self.decision }
    pub fn responded_at(&self) -> i64 { self.responded_at }
    pub fn signature(&self) -> &Sig { &self.signature }
}
```

**Breaking Change**: This changes integration tests that use `response.decision` (direct field access) to `response.decision()` (method call). Update `agent_integration.rs` accordingly.

---

### Finding 3.2: Timestamp Consistency

**Current State**: All modules use raw `i64` for timestamps with no type safety. Easy to confuse milliseconds with seconds, or to pass an arbitrary integer where a timestamp is expected.

**Spec Reference**: Section 3.2.2 uses `Timestamp` type in spec pseudocode.

#### RED - Write Failing Tests

```rust
// moloch-core/src/agent/timestamp.rs (new file)

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timestamp_now_returns_milliseconds() {
        let ts = Timestamp::now();
        // Must be after 2020-01-01 in millis
        assert!(ts.as_millis() > 1_577_836_800_000);
    }

    #[test]
    fn timestamp_ordering() {
        let t1 = Timestamp::now();
        std::thread::sleep(std::time::Duration::from_millis(2));
        let t2 = Timestamp::now();
        assert!(t2 > t1);
    }

    #[test]
    fn timestamp_elapsed_since() {
        let t1 = Timestamp::now();
        std::thread::sleep(std::time::Duration::from_millis(10));
        let elapsed = t1.elapsed();
        assert!(elapsed.as_millis() >= 10);
    }

    #[test]
    fn timestamp_from_millis_roundtrip() {
        let ms = 1706500000000_i64;
        let ts = Timestamp::from_millis(ms);
        assert_eq!(ts.as_millis(), ms);
    }

    #[test]
    fn timestamp_is_expired_after_duration() {
        let ts = Timestamp::from_millis(
            chrono::Utc::now().timestamp_millis() - 5000
        );
        let ttl = std::time::Duration::from_secs(3);
        assert!(ts.is_expired(ttl));
    }

    #[test]
    fn timestamp_is_not_expired_within_duration() {
        let ts = Timestamp::now();
        let ttl = std::time::Duration::from_secs(3600);
        assert!(!ts.is_expired(ttl));
    }
}
```

#### GREEN - Implementation

```rust
/// Millisecond-precision UTC timestamp.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Timestamp(i64);

impl Timestamp {
    pub fn now() -> Self { Self(chrono::Utc::now().timestamp_millis()) }
    pub fn from_millis(ms: i64) -> Self { Self(ms) }
    pub fn as_millis(&self) -> i64 { self.0 }
    pub fn elapsed(&self) -> std::time::Duration {
        let now = chrono::Utc::now().timestamp_millis();
        std::time::Duration::from_millis((now - self.0).max(0) as u64)
    }
    pub fn is_expired(&self, ttl: std::time::Duration) -> bool {
        self.elapsed() > ttl
    }
}
```

#### REFACTOR

Migrate all `i64` timestamp fields across agent modules to `Timestamp`. This is a large refactor touching every module but purely mechanical. The `Serialize`/`Deserialize` implementations ensure wire compatibility (still `i64` on the wire).

---

## Phase 4: Evidence Classification Refinement (P2)

**Priority**: Medium
**Estimated Tests**: 8
**Spec References**: Section 8.3.3
**Files**: `outcome.rs`

### Finding 4.1: Evidence Sufficiency Ambiguity

**Current State**: `outcome.rs:96-121`

The `is_evidence_sufficient()` implementation conflates `Receipt` with `ThirdPartyAttestation` for `Critical` severity. A `Receipt` could be from the agent's own system, making it self-referential rather than independent third-party verification.

Additionally, `ExternalConfirmation` (which could represent a blockchain confirmation) is excluded from `Critical`, while a generic `Receipt` (which could be a simple HTTP receipt) qualifies.

#### RED - Write Failing Tests

```rust
// moloch-core/src/agent/outcome.rs - Add to #[cfg(test)] mod tests

#[test]
fn evidence_receipt_alone_insufficient_for_critical() {
    // A receipt without additional corroboration should not satisfy Critical
    let key = test_key();
    let attestation = OutcomeAttestation::builder()
        .action_event_id(test_event_id())
        .outcome(ActionOutcome::success(serde_json::json!({})))
        .attestor(Attestor::self_attestation(key.public_key()))
        .evidence(Evidence::receipt("self-system", vec![1, 2, 3]))
        .sign(&key)
        .unwrap();

    // With the refined rule, a lone Receipt from a non-verified issuer
    // should NOT satisfy Critical
    assert!(!attestation.is_evidence_sufficient(Severity::Critical));
}

#[test]
fn evidence_third_party_attestation_satisfies_critical() {
    // ThirdPartyAttestation (with separate key) always satisfies Critical
    let key = test_key();
    let third_party_key = SecretKey::generate();
    let attestation = OutcomeAttestation::builder()
        .action_event_id(test_event_id())
        .outcome(ActionOutcome::success(serde_json::json!({})))
        .attestor(Attestor::self_attestation(key.public_key()))
        .evidence(Evidence::third_party_attestation(
            third_party_key.public_key(),
            vec![1, 2, 3],
        ))
        .sign(&key)
        .unwrap();

    assert!(attestation.is_evidence_sufficient(Severity::Critical));
}

#[test]
fn evidence_human_observer_satisfies_critical() {
    let key = test_key();
    let principal = PrincipalId::user("admin@example.com").unwrap();
    let attestation = OutcomeAttestation::builder()
        .action_event_id(test_event_id())
        .outcome(ActionOutcome::success(serde_json::json!({})))
        .attestor(Attestor::human_observer(principal))
        .sign(&key)
        .unwrap();

    assert!(attestation.is_evidence_sufficient(Severity::Critical));
}

#[test]
fn evidence_receipt_plus_external_confirmation_satisfies_critical() {
    // Receipt + ExternalConfirmation together provide sufficient
    // independent corroboration for Critical
    let key = test_key();
    let attestation = OutcomeAttestation::builder()
        .action_event_id(test_event_id())
        .outcome(ActionOutcome::success(serde_json::json!({})))
        .attestor(Attestor::self_attestation(key.public_key()))
        .evidence(Evidence::receipt("notary-service", vec![1, 2, 3]))
        .evidence(Evidence::external_confirmation(
            "monitoring", "check-456",
            chrono::Utc::now().timestamp_millis(),
        ))
        .sign(&key)
        .unwrap();

    assert!(attestation.is_evidence_sufficient(Severity::Critical));
}
```

#### GREEN - Implementation

Refine the `Critical` branch:

```rust
Severity::Critical => {
    // Cryptographic third-party attestation always suffices
    let has_third_party = self.evidence.iter().any(|e| {
        matches!(e, Evidence::ThirdPartyAttestation { .. })
    });
    // Human observer always suffices
    let has_human = matches!(self.attestor, Attestor::HumanObserver { .. });
    // Receipt + additional external evidence = sufficient corroboration
    let has_receipt = self.evidence.iter().any(|e| {
        matches!(e, Evidence::Receipt { .. })
    });
    let external_count = self.evidence.iter().filter(|e| e.is_external()).count();
    let has_corroborated_receipt = has_receipt && external_count >= 2;

    has_third_party || has_human || has_corroborated_receipt
}
```

---

## Phase 5: Builder and Error Consistency (P2)

**Priority**: Medium
**Estimated Tests**: 6
**Spec References**: General code quality
**Files**: `emergency.rs`, `coordination.rs`

### Finding 5.1: EmergencyEventBuilder Returns Wrong Error Type

**Current State**: `emergency.rs:430`

```rust
pub fn build(self) -> Result<EmergencyEvent, &'static str> { ... }
```

Every other builder in the agent module returns `Result<T, Error>` using `crate::error::Error`. This inconsistency forces callers to handle different error types depending on which builder they use.

#### RED - Write Failing Tests

```rust
// moloch-core/src/agent/emergency.rs - modify existing tests

#[test]
fn emergency_event_build_error_is_crate_error() {
    let result = EmergencyEvent::builder()
        .initiator(test_principal())
        .build();

    // Should return crate::error::Error, not &'static str
    let err: crate::error::Error = result.unwrap_err();
    assert!(err.to_string().contains("action"));
}
```

#### GREEN - Implementation

```rust
// emergency.rs - change return type
use crate::error::{Error, Result};

impl EmergencyEventBuilder {
    pub fn build(self) -> Result<EmergencyEvent> {
        let action = self.action
            .ok_or_else(|| Error::invalid_input("action is required"))?;
        let initiator = self.initiator
            .ok_or_else(|| Error::invalid_input("initiator is required"))?;
        // ...
    }
}
```

---

### Finding 5.2: ID Generation Duplication

**Current State**: Multiple files

Identical ID generation logic repeated across `SessionId::random()`, `CapabilityId::generate()`, `ApprovalRequestId::generate()`, `CoordinationId::generate()`, `TaskId::generate()` -- all using:

```rust
use rand::RngCore;
let mut bytes = [0u8; 16];
rand::thread_rng().fill_bytes(&mut bytes);
Self(bytes)
```

#### RED - Write Failing Tests

```rust
// moloch-core/src/agent/id.rs (new file)

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn random_id_uniqueness() {
        let id1 = Id16::random();
        let id2 = Id16::random();
        assert_ne!(id1, id2);
    }

    #[test]
    fn random_id_hex_roundtrip() {
        let id = Id16::random();
        let hex = id.to_hex();
        let restored = Id16::from_hex(&hex).unwrap();
        assert_eq!(id, restored);
    }

    #[test]
    fn random_id_display() {
        let id = Id16::random();
        let display = format!("{}", id);
        assert_eq!(display.len(), 32); // 16 bytes = 32 hex chars
    }
}
```

#### GREEN - Implementation

Create a generic `Id16` type and a macro for defining typed IDs:

```rust
// moloch-core/src/agent/id.rs

/// 16-byte random identifier base.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Id16(pub [u8; 16]);

impl Id16 {
    pub fn random() -> Self { ... }
    pub fn from_bytes(bytes: [u8; 16]) -> Self { Self(bytes) }
    pub fn as_bytes(&self) -> &[u8; 16] { &self.0 }
    pub fn to_hex(&self) -> String { hex::encode(self.0) }
    pub fn from_hex(s: &str) -> Result<Self> { ... }
}

/// Macro for defining typed IDs backed by Id16.
macro_rules! define_id {
    ($name:ident) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
        pub struct $name(Id16);
        // impl generate(), from_bytes(), as_bytes(), to_hex(), from_hex(), Display
    };
}
```

#### REFACTOR

Replace all five ID types with `define_id!` invocations. This is purely mechanical and preserves all existing APIs.

---

## Phase 6: Audit Event Integration (P2)

**Priority**: Medium
**Estimated Tests**: 15
**Spec References**: Section 11 (Event Types)
**Files**: `moloch-core/src/event.rs`, `moloch-core/src/agent/mod.rs`

### Finding 6.1: No Audit Event Bridging

**Current State**: Agent accountability types exist in isolation from the core `AuditEvent` system. There is no way to record an agent action as an event in the audit chain.

This is the largest gap in the implementation. All the types are well-defined but disconnected from the chain they're supposed to be recorded in.

#### RED - Write Failing Tests

```rust
// moloch-core/tests/agent_audit_bridge.rs (new file)

#[test]
fn agent_action_creates_audit_event() {
    // An agent action should be expressible as an AuditEvent
    // with full causal context embedded
}

#[test]
fn audit_event_preserves_causal_context() {
    // CausalContext round-trips through AuditEvent serialization
}

#[test]
fn audit_event_references_capability() {
    // capability_id is preserved in the audit event
}

#[test]
fn audit_event_includes_attestation_hash() {
    // The agent's attestation hash is included for verification
}

#[test]
fn audit_event_chain_commitment() {
    // Agent events participate in the MMR/hash chain
}
```

#### GREEN - Implementation

This requires designing the bridge between agent types and the existing `AuditEvent` system. The implementation approach depends on the existing event architecture. Key design decision: embed agent context as structured metadata vs. define new event variants.

**Note**: This phase requires deeper analysis of the existing `event.rs` architecture and may spawn a separate design document.

---

## Phase 7: Test Coverage Hardening (P2)

**Priority**: Medium
**Estimated Tests**: 20
**Spec References**: General robustness
**Files**: `moloch-core/tests/agent_adversarial.rs` (new), `moloch-core/tests/props/agent_props.rs` (new)

### Finding 7.1: Missing Timing Edge Cases

#### RED - Write Failing Tests

```rust
// moloch-core/tests/agent_adversarial.rs (new file)

#[test]
fn attestation_valid_at_exact_expiry_boundary() {
    // Test behavior at the exact millisecond of expiry
    // is_valid_at(expires_at) should return false (expired AT that time)
    // is_valid_at(expires_at - 1) should return true
}

#[test]
fn session_expired_at_exact_max_duration() {
    // Session should report expired when duration == max_duration
}

#[test]
fn approval_request_at_exact_expiry() {
    // ApprovalRequest should be expired when now == expires_at
}

#[test]
fn idempotency_record_at_exact_expiry() {
    // Record should be expired when now == expires_at
}
```

### Finding 7.2: Missing Property Tests

```rust
// moloch-core/tests/props/agent_props.rs (new file)

use proptest::prelude::*;

proptest! {
    /// INV-CAUSAL-1: Parent always has lower sequence
    #[test]
    fn prop_causal_depth_monotonic(
        depth in 0u32..100,
        sequence in 0u64..10000,
    ) {
        // If depth > 0, context requires parent
        // Parent must have lower sequence
    }

    /// INV-CAP-3: Delegated scope is subset
    #[test]
    fn prop_delegated_scope_subset(
        parent_scope in arb_resource_scope(),
        child_scope in arb_resource_scope(),
    ) {
        // If delegate() succeeds, child.scope ⊆ parent.scope
    }

    /// INV-COORD-3: Shared responsibility sums to 1.0
    #[test]
    fn prop_shared_responsibility_sum(
        shares in prop::collection::vec(0.0f64..1.0, 2..10),
    ) {
        // Build coordination with given shares
        // If sum != 1.0, build must fail
    }

    /// Severity ordering is consistent
    #[test]
    fn prop_severity_level_ordering(a in arb_severity(), b in arb_severity()) {
        if a.level() < b.level() {
            prop_assert!(a != b);
        }
    }
}
```

---

## Phase 8: Idempotency Store (P2)

**Priority**: Medium
**Estimated Tests**: 10
**Spec References**: Section 8 (idempotency)
**Files**: `outcome.rs` or new `idempotency.rs`

### Finding 8.1: Orphaned Idempotency Types

**Current State**: `IdempotencyKey` and `IdempotencyRecord` are defined but have no store, lookup, or cleanup mechanism. They cannot be used without an in-memory or persistent store.

#### RED - Write Failing Tests

```rust
// moloch-core/src/agent/outcome.rs or new idempotency.rs

#[test]
fn idempotency_store_insert_and_lookup() {
    let store = IdempotencyStore::new();
    let key = test_key();
    let idem_key = IdempotencyKey::new(key.public_key(), "write", "req-1");
    let record = IdempotencyRecord::new(
        idem_key.clone(),
        test_event_id(),
        ActionOutcome::success(serde_json::json!({})),
        60000,
    );

    store.insert(record.clone());
    let found = store.lookup(&idem_key);
    assert!(found.is_some());
    assert_eq!(found.unwrap().original_event_id(), record.original_event_id());
}

#[test]
fn idempotency_store_returns_none_for_unknown() {
    let store = IdempotencyStore::new();
    let key = test_key();
    let idem_key = IdempotencyKey::new(key.public_key(), "write", "unknown");
    assert!(store.lookup(&idem_key).is_none());
}

#[test]
fn idempotency_store_expired_records_not_returned() {
    let store = IdempotencyStore::new();
    let key = test_key();
    let idem_key = IdempotencyKey::new(key.public_key(), "write", "req-1");
    let record = IdempotencyRecord::new(
        idem_key.clone(),
        test_event_id(),
        ActionOutcome::success(serde_json::json!({})),
        -1, // Already expired
    );

    store.insert(record);
    assert!(store.lookup(&idem_key).is_none()); // Expired = invisible
}

#[test]
fn idempotency_store_cleanup_removes_expired() {
    let store = IdempotencyStore::new();
    // Insert 10 expired + 5 valid records
    // cleanup() should remove only expired
    // len() should return 5
}
```

#### GREEN - Implementation

```rust
/// In-memory idempotency store with expiration.
pub struct IdempotencyStore {
    records: HashMap<Hash, IdempotencyRecord>,
}

impl IdempotencyStore {
    pub fn new() -> Self { ... }
    pub fn insert(&mut self, record: IdempotencyRecord) { ... }
    pub fn lookup(&self, key: &IdempotencyKey) -> Option<&IdempotencyRecord> { ... }
    pub fn cleanup(&mut self) -> usize { /* remove expired, return count */ }
    pub fn len(&self) -> usize { ... }
}
```

---

## Phase 9: HashMap Key Type Safety (P3)

**Priority**: Low
**Estimated Tests**: 4
**Spec References**: General code quality
**Files**: `coordination.rs`

### Finding 9.1: String Keys for PublicKey Lookups

**Current State**: `CoordinatedActionSpec` uses `HashMap<String, Vec<Task>>` where the key is `hex::encode(agent.as_bytes())`. This is error-prone and lacks type safety.

#### RED - Write Failing Tests

```rust
#[test]
fn coordination_task_lookup_by_public_key() {
    let key = SecretKey::generate();
    let spec = CoordinatedActionSpec::new("deploy");
    spec.assign_task(key.public_key(), task);

    // Lookup should work with PublicKey directly, not hex string
    let tasks = spec.tasks_for(&key.public_key());
    assert_eq!(tasks.len(), 1);
}
```

#### GREEN - Implementation

Either implement `Hash + Eq` for `PublicKey` or create a `PublicKeyId` wrapper that implements these traits by hashing the key bytes. Replace `HashMap<String, _>` with `HashMap<PublicKeyId, _>`.

---

## Summary

| Phase | Priority | Tests | Description |
|-------|----------|-------|-------------|
| 1 | P0 | 12 | Signature verification hardening |
| 2 | P1 | 18 | Capability lifecycle (revocation + delegation chain) |
| 3 | P1 | 10 | Type system (encapsulation + timestamps) |
| 4 | P2 | 8 | Evidence classification refinement |
| 5 | P2 | 6 | Builder/error consistency + ID dedup |
| 6 | P2 | 15 | Audit event integration |
| 7 | P2 | 20 | Test coverage (timing, property, concurrency) |
| 8 | P2 | 10 | Idempotency store |
| 9 | P3 | 4 | HashMap key type safety |
| **Total** | | **~103** | |

### Execution Order

```
Phase 1 (P0) ─────────────────────────────┐
                                           ├──► Phase 4 (P2)
Phase 2 (P1) ──► Phase 6 (P2) ────────────┤
                                           ├──► Phase 7 (P2)
Phase 3 (P1) ──► Phase 5 (P2) ──► Phase 8 (P2)
                                           │
                                Phase 9 (P3) (independent)
```

Phases 1, 2, and 3 can proceed in parallel. Phase 6 depends on Phase 2 (revocation must exist before audit bridging). Phase 7 depends on all prior phases being complete. Phase 9 is independent and can be done at any time.

### Success Criteria

- All 103+ new tests pass
- Existing 361 tests continue to pass
- `cargo clippy -- -D warnings` clean
- No `#[allow(unused)]` annotations on public API items
- Every spec invariant (INV-*) has at least one corresponding test
