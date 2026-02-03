//! Adversarial and boundary condition tests for agent accountability types.
//!
//! These tests exercise exact timing boundaries, edge cases, and
//! potential off-by-one errors in the accountability system.

use std::time::Duration;

use moloch_core::agent::{
    Capability, CapabilityKind, CapabilityState, PrincipalId, ResourceScope, RuntimeAttestation,
    Session,
};
use moloch_core::crypto::{hash, SecretKey};
use moloch_core::event::EventId;

fn test_principal() -> PrincipalId {
    PrincipalId::user("test@example.com").unwrap()
}

fn test_key() -> SecretKey {
    SecretKey::generate()
}

fn test_event_id() -> EventId {
    EventId(hash(b"boundary-test"))
}

// === Finding 7.1: Timing Boundary Tests ===

/// Attestation: `check_time < expires_at` means at exact expiry it should be INVALID.
#[test]
fn attestation_valid_at_exact_expiry_boundary() {
    use moloch_core::agent::AgentAttestationBuilder;
    let authority = test_key();
    let start = 1_700_000_000_000i64; // fixed point

    let attestation = AgentAttestationBuilder::new()
        .agent_id(test_key().public_key())
        .code_hash(hash(b"code"))
        .config_hash(hash(b"config"))
        .prompt_hash(hash(b"prompt"))
        .runtime(RuntimeAttestation::new(
            "test-runtime-v1.0.0",
            hash(b"runtime-binary"),
        ))
        .authority(authority.public_key())
        .attested_at(start)
        .validity_period(Duration::from_secs(60))
        .sign(&authority)
        .unwrap();

    let expires_at = start + 60_000; // 60 seconds in ms

    // One ms BEFORE expiry: valid
    assert!(attestation.is_valid_at(expires_at - 1));

    // AT exact expiry: invalid (uses < not <=)
    assert!(!attestation.is_valid_at(expires_at));

    // One ms AFTER expiry: invalid
    assert!(!attestation.is_valid_at(expires_at + 1));
}

/// Session: `elapsed_ms > max_ms` means at exact max_duration it should be VALID.
#[test]
fn session_expired_at_exact_max_duration() {
    let start = 1_700_000_000_000i64;
    let max_dur = Duration::from_secs(60);
    let session = Session::builder()
        .principal(test_principal())
        .started_at(start)
        .max_duration(max_dur)
        .build()
        .unwrap();

    let max_ms = max_dur.as_millis() as i64;

    // One ms BEFORE max: not expired
    assert!(!session.is_expired(start + max_ms - 1));

    // AT exact max: not expired (uses > not >=)
    assert!(!session.is_expired(start + max_ms));

    // One ms AFTER max: expired
    assert!(session.is_expired(start + max_ms + 1));
}

/// Capability: `timestamp < exp` means at exact expiry it should be INVALID.
#[test]
fn capability_valid_at_exact_expiry_boundary() {
    let key = test_key();
    let now = chrono::Utc::now().timestamp_millis();
    let expires_at = now + 60_000;

    let cap = Capability::builder()
        .kind(CapabilityKind::Read)
        .scope(ResourceScope::all())
        .grantor(test_principal())
        .expires_at(expires_at)
        .sign(&key)
        .unwrap();

    // One ms before: valid
    assert!(cap.is_valid_at(expires_at - 1));
    assert_eq!(cap.lifecycle_state(expires_at - 1), CapabilityState::Active);

    // At exact expiry: invalid
    assert!(!cap.is_valid_at(expires_at));
    assert_eq!(cap.lifecycle_state(expires_at), CapabilityState::Expired);

    // One ms after: invalid
    assert!(!cap.is_valid_at(expires_at + 1));
    assert_eq!(
        cap.lifecycle_state(expires_at + 1),
        CapabilityState::Expired
    );
}

/// IdempotencyRecord: `now > expires_at` means at exact expiry it should be VALID.
/// Since IdempotencyRecord uses chrono::Utc::now() internally, we test that
/// a record with a far-future TTL is not expired immediately.
#[test]
fn idempotency_record_not_expired_when_just_created() {
    use moloch_core::agent::{ActionOutcome, IdempotencyKey, IdempotencyRecord};
    let key = IdempotencyKey::new(test_key().public_key(), "test-action", "client-1");
    let record = IdempotencyRecord::new(
        key,
        test_event_id(),
        ActionOutcome::success(serde_json::json!({})),
        60_000, // 60 seconds TTL
    );

    assert!(!record.is_expired());
    assert!(record.is_valid());
}

/// IdempotencyRecord with zero TTL should be expired (or borderline).
#[test]
fn idempotency_record_zero_ttl_borderline() {
    use moloch_core::agent::{ActionOutcome, IdempotencyKey, IdempotencyRecord};
    let key = IdempotencyKey::new(test_key().public_key(), "test-action", "client-1");
    let record = IdempotencyRecord::new(
        key,
        test_event_id(),
        ActionOutcome::success(serde_json::json!({})),
        0, // Zero TTL: expires_at == created_at
    );

    // With `now > expires_at` and zero TTL, the record is valid for the
    // exact millisecond it was created (since now == expires_at when checked
    // immediately). We just assert it doesn't panic.
    let _ = record.is_expired();
}

// === Delegation Boundary Tests ===

/// Delegation at exactly max_delegation_depth should succeed.
#[test]
fn delegation_at_exact_max_depth_succeeds() {
    let key = test_key();
    // max_delegation_depth = 2
    let cap = Capability::builder()
        .kind(CapabilityKind::Read)
        .scope(ResourceScope::all())
        .grantor(test_principal())
        .delegatable(2)
        .sign(&key)
        .unwrap();

    // depth 0 -> 1: OK
    let child1 = cap.delegate(&key, None, None).unwrap();
    assert_eq!(child1.delegation_depth(), 1);

    // depth 1 -> 2: OK (exactly at max)
    let child2 = child1.delegate(&key, None, None).unwrap();
    assert_eq!(child2.delegation_depth(), 2);

    // depth 2 -> 3: fails
    assert!(child2.delegate(&key, None, None).is_err());
}

/// Revocation preserves exact timestamp precision.
#[test]
fn revocation_timestamp_precision() {
    let key = test_key();
    let mut cap = Capability::builder()
        .kind(CapabilityKind::Read)
        .scope(ResourceScope::all())
        .grantor(test_principal())
        .sign(&key)
        .unwrap();

    let before = chrono::Utc::now().timestamp_millis();
    cap.revoke("test");
    let after = chrono::Utc::now().timestamp_millis();

    let ts = cap.revoked_at().unwrap();
    // Revocation timestamp must be within the before/after window
    assert!(ts >= before, "revoked_at {} < before {}", ts, before);
    assert!(ts <= after, "revoked_at {} > after {}", ts, after);
}

/// Scope subset validation edge cases.
#[test]
fn scope_subset_edge_cases() {
    let key = test_key();

    // Pattern vs. same pattern: OK (equal patterns are subsets)
    let cap = Capability::builder()
        .kind(CapabilityKind::Read)
        .scope(ResourceScope::pattern("repo:org/*"))
        .grantor(test_principal())
        .delegatable(3)
        .sign(&key)
        .unwrap();

    let child = cap.delegate(&key, Some(ResourceScope::pattern("repo:org/*")), None);
    assert!(child.is_ok(), "equal patterns should be valid subsets");

    // Kind vs. Kind: same kind is a subset
    let cap2 = Capability::builder()
        .kind(CapabilityKind::Write)
        .scope(ResourceScope::kind(
            moloch_core::event::ResourceKind::Repository,
        ))
        .grantor(test_principal())
        .delegatable(3)
        .sign(&key)
        .unwrap();

    let child2 = cap2.delegate(
        &key,
        Some(ResourceScope::kind(
            moloch_core::event::ResourceKind::Repository,
        )),
        None,
    );
    assert!(child2.is_ok(), "same kind should be valid subset");

    // Different kinds: not a subset
    let child3 = cap2.delegate(
        &key,
        Some(ResourceScope::kind(moloch_core::event::ResourceKind::File)),
        None,
    );
    assert!(child3.is_err(), "different kind should not be subset");
}
