//! Cryptographic operation benchmarks for Moloch.
//!
//! Benchmarks:
//! - HoloCrypt seal/unseal
//! - Zero-knowledge proof generation/verification
//! - Threshold encryption operations
//! - Post-quantum cryptography (ML-KEM)

// Link mimalloc global allocator from the bench library
use moloch_bench as _;

use criterion::{black_box, criterion_group, criterion_main, Criterion};

use moloch_core::crypto::SecretKey;
use moloch_core::event::{
    ActorId, ActorKind, AuditEvent, EventType, Outcome, ResourceId, ResourceKind,
};
use moloch_holocrypt::{
    generate_keypair, EncryptedEventBuilder, EncryptionPolicy, EventPqcKeyPair, EventProof,
    KeyShareSet, PqcEvent, QuantumSafeEvent, ThresholdConfig, ThresholdEvent,
};

fn create_test_event(key: &SecretKey) -> AuditEvent {
    let actor = ActorId::new(key.public_key(), ActorKind::User);
    let resource = ResourceId::new(ResourceKind::Repository, "benchmark-repo");

    AuditEvent::builder()
        .now()
        .event_type(EventType::Push {
            force: false,
            commits: 10,
        })
        .actor(actor)
        .resource(resource)
        .outcome(Outcome::Success)
        .metadata(serde_json::json!({
            "branch": "main",
            "message": "Benchmark commit message"
        }))
        .sign(key)
        .unwrap()
}

fn bench_holocrypt_seal(c: &mut Criterion) {
    let signing_key = SecretKey::generate();
    let event = create_test_event(&signing_key);
    let (sealing_key, _) = generate_keypair("bench-key");

    let mut group = c.benchmark_group("holocrypt/seal");

    // Default policy (partial encryption)
    group.bench_function("default_policy", |b| {
        b.iter(|| {
            EncryptedEventBuilder::new()
                .event(black_box(event.clone()))
                .policy(EncryptionPolicy::default())
                .build(&sealing_key)
                .unwrap()
        })
    });

    // All encrypted policy
    group.bench_function("all_encrypted", |b| {
        b.iter(|| {
            EncryptedEventBuilder::new()
                .event(black_box(event.clone()))
                .policy(EncryptionPolicy::all_encrypted())
                .build(&sealing_key)
                .unwrap()
        })
    });

    // All public policy (minimal encryption)
    group.bench_function("all_public", |b| {
        b.iter(|| {
            EncryptedEventBuilder::new()
                .event(black_box(event.clone()))
                .policy(EncryptionPolicy::all_public())
                .build(&sealing_key)
                .unwrap()
        })
    });

    group.finish();
}

fn bench_holocrypt_unseal(c: &mut Criterion) {
    let signing_key = SecretKey::generate();
    let event = create_test_event(&signing_key);
    let (sealing_key, opening_key) = generate_keypair("bench-key");

    let encrypted = EncryptedEventBuilder::new()
        .event(event)
        .policy(EncryptionPolicy::default())
        .build(&sealing_key)
        .unwrap();

    c.bench_function("holocrypt/unseal", |b| {
        b.iter(|| encrypted.decrypt(black_box(&opening_key)).unwrap())
    });
}

fn bench_holocrypt_verify(c: &mut Criterion) {
    let signing_key = SecretKey::generate();
    let event = create_test_event(&signing_key);
    let (sealing_key, opening_key) = generate_keypair("bench-key");

    let encrypted = EncryptedEventBuilder::new()
        .event(event)
        .policy(EncryptionPolicy::default())
        .build(&sealing_key)
        .unwrap();

    c.bench_function("holocrypt/verify_structure", |b| {
        b.iter(|| encrypted.verify_structure(black_box(&opening_key)).unwrap())
    });
}

fn bench_zk_proof_generation(c: &mut Criterion) {
    let signing_key = SecretKey::generate();
    let event = create_test_event(&signing_key);
    let (sealing_key, _) = generate_keypair("bench-key");

    let encrypted = EncryptedEventBuilder::new()
        .event(event)
        .policy(EncryptionPolicy::default())
        .build(&sealing_key)
        .unwrap();

    let mut group = c.benchmark_group("zk/prove");

    group.bench_function("existence", |b| {
        b.iter(|| {
            EventProof::builder()
                .event(black_box(encrypted.clone()))
                .prove_existence()
                .build()
                .unwrap()
        })
    });

    group.bench_function("event_type", |b| {
        b.iter(|| {
            EventProof::builder()
                .event(black_box(encrypted.clone()))
                .prove_event_type("Push")
                .build()
                .unwrap()
        })
    });

    group.bench_function("actor_membership", |b| {
        let actors = vec!["alice", "bob", "charlie", "dave", "eve"];
        b.iter(|| {
            EventProof::builder()
                .event(black_box(encrypted.clone()))
                .prove_actor_membership(black_box(actors.clone()))
                .build()
                .unwrap()
        })
    });

    group.finish();
}

fn bench_zk_proof_verification(c: &mut Criterion) {
    let signing_key = SecretKey::generate();
    let event = create_test_event(&signing_key);
    let (sealing_key, _) = generate_keypair("bench-key");

    let encrypted = EncryptedEventBuilder::new()
        .event(event)
        .policy(EncryptionPolicy::default())
        .build(&sealing_key)
        .unwrap();

    let proof = EventProof::builder()
        .event(encrypted.clone())
        .prove_existence()
        .build()
        .unwrap();

    c.bench_function("zk/verify", |b| {
        b.iter(|| proof.verify(black_box(&encrypted)).unwrap())
    });
}

fn bench_threshold_seal(c: &mut Criterion) {
    let signing_key = SecretKey::generate();
    let event = create_test_event(&signing_key);

    let configs = [
        ("2_of_3", ThresholdConfig::two_of_three()),
        ("3_of_5", ThresholdConfig::three_of_five()),
        ("5_of_7", ThresholdConfig::five_of_seven()),
    ];

    let mut group = c.benchmark_group("threshold/seal");

    for (name, config) in configs {
        group.bench_function(name, |b| {
            b.iter(|| ThresholdEvent::seal(black_box(&event), black_box(config.clone())).unwrap())
        });
    }

    group.finish();
}

fn bench_threshold_unseal(c: &mut Criterion) {
    let signing_key = SecretKey::generate();
    let event = create_test_event(&signing_key);

    let configs = [
        ("2_of_3", ThresholdConfig::two_of_three(), 2),
        ("3_of_5", ThresholdConfig::three_of_five(), 3),
    ];

    let mut group = c.benchmark_group("threshold/unseal");

    for (name, config, threshold) in configs {
        let (threshold_event, shares) = ThresholdEvent::seal(&event, config).unwrap();

        let mut share_set = KeyShareSet::new();
        for share in shares.into_iter().take(threshold) {
            share_set.add(share);
        }

        group.bench_function(name, |b| {
            b.iter(|| threshold_event.unseal(black_box(&share_set)).unwrap())
        });
    }

    group.finish();
}

fn bench_pqc_keygen(c: &mut Criterion) {
    c.bench_function("pqc/keygen_mlkem768", |b| {
        b.iter(|| EventPqcKeyPair::generate("bench-key"))
    });
}

fn bench_pqc_seal(c: &mut Criterion) {
    let signing_key = SecretKey::generate();
    let event = create_test_event(&signing_key);
    let pqc_key = EventPqcKeyPair::generate("bench-key");

    let mut group = c.benchmark_group("pqc/seal");

    group.bench_function("pqc_event", |b| {
        b.iter(|| PqcEvent::seal(black_box(&event), black_box(&pqc_key)).unwrap())
    });

    group.bench_function("quantum_safe_event", |b| {
        b.iter(|| QuantumSafeEvent::seal(black_box(&event), black_box(&pqc_key)).unwrap())
    });

    group.finish();
}

fn bench_pqc_unseal(c: &mut Criterion) {
    let signing_key = SecretKey::generate();
    let event = create_test_event(&signing_key);
    let pqc_key = EventPqcKeyPair::generate("bench-key");

    let pqc_event = PqcEvent::seal(&event, &pqc_key).unwrap();
    let qs_event = QuantumSafeEvent::seal(&event, &pqc_key).unwrap();

    let mut group = c.benchmark_group("pqc/unseal");

    group.bench_function("pqc_event", |b| {
        b.iter(|| pqc_event.unseal(black_box(&pqc_key)).unwrap())
    });

    group.bench_function("quantum_safe_event", |b| {
        b.iter(|| qs_event.unseal(black_box(&pqc_key)).unwrap())
    });

    group.finish();
}

fn bench_ed25519_vs_mlkem(c: &mut Criterion) {
    let mut group = c.benchmark_group("comparison/keygen");

    group.bench_function("ed25519", |b| b.iter(SecretKey::generate));

    group.bench_function("mlkem768", |b| b.iter(|| EventPqcKeyPair::generate("key")));

    group.finish();
}

criterion_group!(
    benches,
    bench_holocrypt_seal,
    bench_holocrypt_unseal,
    bench_holocrypt_verify,
    bench_zk_proof_generation,
    bench_zk_proof_verification,
    bench_threshold_seal,
    bench_threshold_unseal,
    bench_pqc_keygen,
    bench_pqc_seal,
    bench_pqc_unseal,
    bench_ed25519_vs_mlkem,
);

criterion_main!(benches);
