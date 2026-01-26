//! Property-based tests for core types.
//!
//! Uses proptest to verify invariants hold for arbitrary inputs.

use proptest::prelude::*;

use crate::block::{Block, BlockBuilder, SealerId};
use crate::crypto::{hash, Hash, PublicKey, SecretKey, Sig};
use crate::event::{
    ActorId, ActorKind, AuditEvent, EventType, Outcome, ResourceId, ResourceKind, ReviewVerdict,
};

// ============================================================================
// Arbitrary Implementations
// ============================================================================

/// Generate arbitrary 32-byte arrays.
fn arb_bytes32() -> impl Strategy<Value = [u8; 32]> {
    prop::array::uniform32(any::<u8>())
}

/// Generate arbitrary 64-byte arrays.
#[allow(dead_code)]
fn arb_bytes64() -> impl Strategy<Value = [u8; 64]> {
    prop::array::uniform32(any::<u8>()).prop_flat_map(|first| {
        prop::array::uniform32(any::<u8>()).prop_map(move |second| {
            let mut arr = [0u8; 64];
            arr[..32].copy_from_slice(&first);
            arr[32..].copy_from_slice(&second);
            arr
        })
    })
}

/// Generate arbitrary Hash values.
#[allow(dead_code)]
fn arb_hash() -> impl Strategy<Value = Hash> {
    arb_bytes32().prop_map(Hash::from_bytes)
}

/// Generate arbitrary SecretKey values.
fn arb_secret_key() -> impl Strategy<Value = SecretKey> {
    Just(()).prop_map(|_| SecretKey::generate())
}

/// Generate arbitrary ActorKind values.
fn arb_actor_kind() -> impl Strategy<Value = ActorKind> {
    prop_oneof![
        Just(ActorKind::User),
        Just(ActorKind::System),
        Just(ActorKind::Agent),
        Just(ActorKind::Integration),
    ]
}

/// Generate arbitrary ResourceKind values.
fn arb_resource_kind() -> impl Strategy<Value = ResourceKind> {
    prop_oneof![
        Just(ResourceKind::Repository),
        Just(ResourceKind::Commit),
        Just(ResourceKind::Branch),
        Just(ResourceKind::Tag),
        Just(ResourceKind::PullRequest),
        Just(ResourceKind::Issue),
        Just(ResourceKind::File),
        Just(ResourceKind::User),
        Just(ResourceKind::Organization),
        Just(ResourceKind::Credential),
        Just(ResourceKind::Config),
        Just(ResourceKind::Document),
        Just(ResourceKind::Other),
    ]
}

/// Generate arbitrary ReviewVerdict values.
fn arb_review_verdict() -> impl Strategy<Value = ReviewVerdict> {
    prop_oneof![
        Just(ReviewVerdict::Approved),
        Just(ReviewVerdict::ChangesRequested),
        Just(ReviewVerdict::Commented),
    ]
}

/// Generate arbitrary EventType values.
fn arb_event_type() -> impl Strategy<Value = EventType> {
    prop_oneof![
        // Repository events
        Just(EventType::RepoCreated),
        Just(EventType::RepoDeleted),
        Just(EventType::RepoTransferred),
        Just(EventType::RepoVisibilityChanged),
        // Git events
        (any::<bool>(), 0u32..1000u32)
            .prop_map(|(force, commits)| EventType::Push { force, commits }),
        Just(EventType::BranchCreated),
        Just(EventType::BranchDeleted),
        Just(EventType::BranchProtectionChanged),
        Just(EventType::TagCreated),
        Just(EventType::TagDeleted),
        // Collaboration events
        Just(EventType::PullRequestOpened),
        Just(EventType::PullRequestMerged),
        Just(EventType::PullRequestClosed),
        arb_review_verdict().prop_map(|verdict| EventType::ReviewSubmitted { verdict }),
        Just(EventType::IssueOpened),
        Just(EventType::IssueClosed),
        // Access events
        "[a-z]{3,10}".prop_map(|permission| EventType::AccessGranted { permission }),
        Just(EventType::AccessRevoked),
        "[a-z]{3,10}".prop_map(|method| EventType::Login { method }),
        Just(EventType::Logout),
        "[a-z]{5,20}".prop_map(|reason| EventType::LoginFailed { reason }),
        Just(EventType::MfaConfigured),
        // Agent events
        ("[a-z]{3,15}", prop::option::of("[a-z ]{10,50}"))
            .prop_map(|(action, reasoning)| EventType::AgentAction { action, reasoning }),
        prop::collection::vec("[a-z]{3,10}", 1..5)
            .prop_map(|scope| EventType::AgentAuthorized { scope }),
        Just(EventType::AgentRevoked),
        // Compliance events
        Just(EventType::DataExportRequested),
        Just(EventType::DataExportCompleted),
        Just(EventType::DataDeletionRequested),
        Just(EventType::DataDeletionCompleted),
        "[a-z]{5,15}".prop_map(|purpose| EventType::ConsentGiven { purpose }),
        "[a-z]{5,15}".prop_map(|purpose| EventType::ConsentRevoked { purpose }),
        // System events
        "[a-z._]{3,20}".prop_map(|key| EventType::ConfigChanged { key }),
        "[0-9]+\\.[0-9]+\\.[0-9]+".prop_map(|version| EventType::ReleasePublished { version }),
        Just(EventType::BackupCreated),
        (0u32..100u32).prop_map(|findings| EventType::SecurityScan { findings }),
        // Generic
        "[a-z_]{5,20}".prop_map(|name| EventType::Custom { name }),
    ]
}

/// Generate arbitrary Outcome values.
fn arb_outcome() -> impl Strategy<Value = Outcome> {
    prop_oneof![
        Just(Outcome::Success),
        "[a-z ]{5,30}".prop_map(|reason| Outcome::Failure { reason }),
        "[a-z ]{5,30}".prop_map(|reason| Outcome::Denied { reason }),
        Just(Outcome::Pending),
    ]
}

/// Generate arbitrary ResourceId values.
fn arb_resource_id() -> impl Strategy<Value = ResourceId> {
    (arb_resource_kind(), "[a-z0-9-]{3,20}").prop_map(|(kind, id)| ResourceId::new(kind, id))
}

/// Generate arbitrary ActorId values.
fn arb_actor_id() -> impl Strategy<Value = (SecretKey, ActorId)> {
    (
        arb_secret_key(),
        arb_actor_kind(),
        prop::option::of("[a-z]{3,15}"),
    )
        .prop_map(|(key, kind, name)| {
            let actor = ActorId::new(key.public_key(), kind);
            let actor = match name {
                Some(n) => actor.with_name(n),
                None => actor,
            };
            (key, actor)
        })
}

/// Generate an arbitrary signed AuditEvent.
fn arb_audit_event() -> impl Strategy<Value = AuditEvent> {
    (
        arb_actor_id(),
        arb_event_type(),
        arb_resource_id(),
        arb_outcome(),
        prop::collection::vec(any::<u8>(), 0..100),
    )
        .prop_map(|((key, actor), event_type, resource, outcome, metadata)| {
            AuditEvent::builder()
                .now()
                .event_type(event_type)
                .actor(actor)
                .resource(resource)
                .outcome(outcome)
                .metadata_bytes(metadata)
                .sign(&key)
                .expect("signing should succeed")
        })
}

/// Generate arbitrary Block with given number of events.
fn arb_block(event_count: usize) -> impl Strategy<Value = Block> {
    (
        arb_secret_key(),
        prop::collection::vec(arb_audit_event(), event_count),
    )
        .prop_map(|(sealer_key, events)| {
            let sealer = SealerId::new(sealer_key.public_key());
            BlockBuilder::new(sealer).events(events).seal(&sealer_key)
        })
}

// ============================================================================
// Property Tests: Hash
// ============================================================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(1000))]

    /// Hash bytes roundtrip: from_bytes(h.as_bytes()) == h
    #[test]
    fn prop_hash_bytes_roundtrip(bytes in arb_bytes32()) {
        let h = Hash::from_bytes(bytes);
        prop_assert_eq!(h.as_bytes(), &bytes);
    }

    /// Hash hex roundtrip: from_hex(h.to_hex()) == h
    #[test]
    fn prop_hash_hex_roundtrip(bytes in arb_bytes32()) {
        let h = Hash::from_bytes(bytes);
        let hex_str = h.to_hex();
        let restored = Hash::from_hex(&hex_str).expect("hex roundtrip should succeed");
        prop_assert_eq!(h, restored);
    }

    /// Hash bincode roundtrip
    #[test]
    fn prop_hash_bincode_roundtrip(bytes in arb_bytes32()) {
        let h = Hash::from_bytes(bytes);
        let encoded = bincode::serialize(&h).expect("serialize should succeed");
        let decoded: Hash = bincode::deserialize(&encoded).expect("deserialize should succeed");
        prop_assert_eq!(h, decoded);
    }

    /// Hash JSON roundtrip
    #[test]
    fn prop_hash_json_roundtrip(bytes in arb_bytes32()) {
        let h = Hash::from_bytes(bytes);
        let json = serde_json::to_string(&h).expect("json serialize should succeed");
        let decoded: Hash = serde_json::from_str(&json).expect("json deserialize should succeed");
        prop_assert_eq!(h, decoded);
    }

    /// Hash determinism: hash(data) always produces same result
    #[test]
    fn prop_hash_deterministic(data in prop::collection::vec(any::<u8>(), 0..1000)) {
        let h1 = hash(&data);
        let h2 = hash(&data);
        prop_assert_eq!(h1, h2);
    }

    /// Hash avalanche: different inputs produce different outputs
    #[test]
    fn prop_hash_avalanche(data in prop::collection::vec(any::<u8>(), 1..100)) {
        let h1 = hash(&data);
        let mut modified = data.clone();
        modified[0] = modified[0].wrapping_add(1);
        let h2 = hash(&modified);
        prop_assert_ne!(h1, h2);
    }
}

// ============================================================================
// Property Tests: Signature
// ============================================================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    /// Sig bincode roundtrip
    #[test]
    fn prop_sig_bincode_roundtrip(_seed in any::<u64>()) {
        let key = SecretKey::generate();
        let sig = key.sign(b"test message");

        let encoded = bincode::serialize(&sig).expect("serialize should succeed");
        let decoded: Sig = bincode::deserialize(&encoded).expect("deserialize should succeed");

        prop_assert_eq!(sig.to_bytes(), decoded.to_bytes());
    }

    /// Sig JSON roundtrip
    #[test]
    fn prop_sig_json_roundtrip(_seed in any::<u64>()) {
        let key = SecretKey::generate();
        let sig = key.sign(b"test message");

        let json = serde_json::to_string(&sig).expect("json serialize should succeed");
        let decoded: Sig = serde_json::from_str(&json).expect("json deserialize should succeed");

        prop_assert_eq!(sig.to_bytes(), decoded.to_bytes());
    }

    /// Sign/verify roundtrip
    #[test]
    fn prop_sig_verify_roundtrip(message in prop::collection::vec(any::<u8>(), 0..1000)) {
        let key = SecretKey::generate();
        let pk = key.public_key();
        let sig = key.sign(&message);

        prop_assert!(pk.verify(&message, &sig).is_ok());
    }

    /// Different messages produce different signatures
    #[test]
    fn prop_sig_different_messages(
        msg1 in prop::collection::vec(any::<u8>(), 1..100),
        msg2 in prop::collection::vec(any::<u8>(), 1..100)
    ) {
        prop_assume!(msg1 != msg2);
        let key = SecretKey::generate();
        let sig1 = key.sign(&msg1);
        let sig2 = key.sign(&msg2);
        prop_assert_ne!(sig1.to_bytes(), sig2.to_bytes());
    }

    /// Wrong key fails verification
    #[test]
    fn prop_sig_wrong_key_fails(message in prop::collection::vec(any::<u8>(), 1..100)) {
        let key1 = SecretKey::generate();
        let key2 = SecretKey::generate();
        let sig = key1.sign(&message);

        prop_assert!(key2.public_key().verify(&message, &sig).is_err());
    }

    /// Wrong message fails verification
    #[test]
    fn prop_sig_wrong_message_fails(
        msg1 in prop::collection::vec(any::<u8>(), 1..100),
        msg2 in prop::collection::vec(any::<u8>(), 1..100)
    ) {
        prop_assume!(msg1 != msg2);
        let key = SecretKey::generate();
        let sig = key.sign(&msg1);
        prop_assert!(key.public_key().verify(&msg2, &sig).is_err());
    }
}

// ============================================================================
// Property Tests: PublicKey
// ============================================================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    /// PublicKey bincode roundtrip
    #[test]
    fn prop_pubkey_bincode_roundtrip(_seed in any::<u64>()) {
        let key = SecretKey::generate();
        let pk = key.public_key();

        let encoded = bincode::serialize(&pk).expect("serialize should succeed");
        let decoded: PublicKey = bincode::deserialize(&encoded).expect("deserialize should succeed");

        prop_assert_eq!(pk.as_bytes(), decoded.as_bytes());
    }

    /// PublicKey JSON roundtrip
    #[test]
    fn prop_pubkey_json_roundtrip(_seed in any::<u64>()) {
        let key = SecretKey::generate();
        let pk = key.public_key();

        let json = serde_json::to_string(&pk).expect("json serialize should succeed");
        let decoded: PublicKey = serde_json::from_str(&json).expect("json deserialize should succeed");

        prop_assert_eq!(pk.as_bytes(), decoded.as_bytes());
    }

    /// PublicKey bytes roundtrip
    #[test]
    fn prop_pubkey_bytes_roundtrip(_seed in any::<u64>()) {
        let key = SecretKey::generate();
        let pk = key.public_key();
        let bytes = pk.as_bytes();
        let restored = PublicKey::from_bytes(&bytes).expect("bytes roundtrip should succeed");
        prop_assert_eq!(pk.as_bytes(), restored.as_bytes());
    }

    /// PublicKey id is deterministic
    #[test]
    fn prop_pubkey_id_deterministic(_seed in any::<u64>()) {
        let key = SecretKey::generate();
        let pk = key.public_key();
        let id1 = pk.id();
        let id2 = pk.id();
        prop_assert_eq!(id1, id2);
    }
}

// ============================================================================
// Property Tests: SecretKey
// ============================================================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    /// SecretKey bytes roundtrip
    #[test]
    fn prop_secret_key_bytes_roundtrip(_seed in any::<u64>()) {
        let key = SecretKey::generate();
        let bytes = key.as_bytes();
        let restored = SecretKey::from_bytes(&bytes).expect("bytes roundtrip should succeed");

        // Same public key means same key
        prop_assert_eq!(key.public_key().as_bytes(), restored.public_key().as_bytes());
    }

    /// Different keys produce different public keys
    #[test]
    fn prop_different_keys_different_pubkeys(_seed1 in any::<u64>(), _seed2 in any::<u64>()) {
        let key1 = SecretKey::generate();
        let key2 = SecretKey::generate();
        // Extremely unlikely to collide
        prop_assert_ne!(key1.public_key().as_bytes(), key2.public_key().as_bytes());
    }
}

// ============================================================================
// Property Tests: AuditEvent
// ============================================================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(50))]

    /// AuditEvent bincode roundtrip
    #[test]
    fn prop_event_bincode_roundtrip(event in arb_audit_event()) {
        let encoded = bincode::serialize(&event).expect("serialize should succeed");
        let decoded: AuditEvent = bincode::deserialize(&encoded).expect("deserialize should succeed");
        prop_assert_eq!(event.id(), decoded.id());
    }

    /// AuditEvent JSON roundtrip
    #[test]
    fn prop_event_json_roundtrip(event in arb_audit_event()) {
        let json = serde_json::to_string(&event).expect("json serialize should succeed");
        let decoded: AuditEvent = serde_json::from_str(&json).expect("json deserialize should succeed");
        prop_assert_eq!(event.id(), decoded.id());
    }

    /// AuditEvent validation succeeds for properly signed events
    #[test]
    fn prop_event_validates(event in arb_audit_event()) {
        prop_assert!(event.validate().is_ok());
    }

    /// AuditEvent id is deterministic
    #[test]
    fn prop_event_id_deterministic(event in arb_audit_event()) {
        let id1 = event.id();
        let id2 = event.id();
        prop_assert_eq!(id1, id2);
    }

    /// Tampering breaks validation
    #[test]
    fn prop_event_tamper_detected(event in arb_audit_event()) {
        let mut tampered = event.clone();
        // Modify outcome
        tampered.outcome = Outcome::Failure { reason: "tampered".into() };
        prop_assert!(tampered.validate().is_err());
    }
}

// ============================================================================
// Property Tests: Block
// ============================================================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(20))]

    /// Block bincode roundtrip (small blocks)
    #[test]
    fn prop_block_bincode_roundtrip_small(block in arb_block(3)) {
        let encoded = bincode::serialize(&block).expect("serialize should succeed");
        let decoded: Block = bincode::deserialize(&encoded).expect("deserialize should succeed");
        prop_assert_eq!(block.hash(), decoded.hash());
    }

    /// Block JSON roundtrip (small blocks)
    #[test]
    fn prop_block_json_roundtrip_small(block in arb_block(3)) {
        let json = serde_json::to_string(&block).expect("json serialize should succeed");
        let decoded: Block = serde_json::from_str(&json).expect("json deserialize should succeed");
        prop_assert_eq!(block.hash(), decoded.hash());
    }

    /// Block validation succeeds for properly sealed blocks
    #[test]
    fn prop_block_validates(block in arb_block(5)) {
        prop_assert!(block.validate(None).is_ok());
    }

    /// Block hash is deterministic
    #[test]
    fn prop_block_hash_deterministic(block in arb_block(3)) {
        let h1 = block.hash();
        let h2 = block.hash();
        prop_assert_eq!(h1, h2);
    }

    /// Block event count matches
    #[test]
    fn prop_block_event_count(event_count in 0usize..10usize) {
        let key = SecretKey::generate();
        let sealer = SealerId::new(key.public_key());
        let events: Vec<_> = (0..event_count)
            .map(|_| {
                let actor = ActorId::new(key.public_key(), ActorKind::User);
                let resource = ResourceId::new(ResourceKind::Repository, "test");
                AuditEvent::builder()
                    .now()
                    .event_type(EventType::RepoCreated)
                    .actor(actor)
                    .resource(resource)
                    .sign(&key)
                    .unwrap()
            })
            .collect();

        let block = BlockBuilder::new(sealer).events(events).seal(&key);

        prop_assert_eq!(block.header.events_count as usize, event_count);
        prop_assert_eq!(block.events.len(), event_count);
    }

    /// Tampering with block height breaks validation
    #[test]
    fn prop_block_height_tamper_detected(block in arb_block(2)) {
        let mut tampered = block.clone();
        tampered.header.height = 999;
        prop_assert!(tampered.validate(None).is_err());
    }
}

// ============================================================================
// Property Tests: EventType
// ============================================================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(200))]

    /// EventType bincode roundtrip
    #[test]
    fn prop_event_type_bincode_roundtrip(et in arb_event_type()) {
        let encoded = bincode::serialize(&et).expect("serialize should succeed");
        let decoded: EventType = bincode::deserialize(&encoded).expect("deserialize should succeed");
        prop_assert_eq!(et, decoded);
    }

    /// EventType JSON roundtrip
    #[test]
    fn prop_event_type_json_roundtrip(et in arb_event_type()) {
        let json = serde_json::to_string(&et).expect("json serialize should succeed");
        let decoded: EventType = serde_json::from_str(&json).expect("json deserialize should succeed");
        prop_assert_eq!(et, decoded);
    }
}

// ============================================================================
// Property Tests: ResourceId
// ============================================================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(200))]

    /// ResourceId bincode roundtrip
    #[test]
    fn prop_resource_id_bincode_roundtrip(r in arb_resource_id()) {
        let encoded = bincode::serialize(&r).expect("serialize should succeed");
        let decoded: ResourceId = bincode::deserialize(&encoded).expect("deserialize should succeed");
        prop_assert_eq!(r, decoded);
    }

    /// ResourceId JSON roundtrip
    #[test]
    fn prop_resource_id_json_roundtrip(r in arb_resource_id()) {
        let json = serde_json::to_string(&r).expect("json serialize should succeed");
        let decoded: ResourceId = serde_json::from_str(&json).expect("json deserialize should succeed");
        prop_assert_eq!(r, decoded);
    }
}

// ============================================================================
// Property Tests: Outcome
// ============================================================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(200))]

    /// Outcome bincode roundtrip
    #[test]
    fn prop_outcome_bincode_roundtrip(o in arb_outcome()) {
        let encoded = bincode::serialize(&o).expect("serialize should succeed");
        let decoded: Outcome = bincode::deserialize(&encoded).expect("deserialize should succeed");
        prop_assert_eq!(o, decoded);
    }

    /// Outcome JSON roundtrip
    #[test]
    fn prop_outcome_json_roundtrip(o in arb_outcome()) {
        let json = serde_json::to_string(&o).expect("json serialize should succeed");
        let decoded: Outcome = serde_json::from_str(&json).expect("json deserialize should succeed");
        prop_assert_eq!(o, decoded);
    }
}
