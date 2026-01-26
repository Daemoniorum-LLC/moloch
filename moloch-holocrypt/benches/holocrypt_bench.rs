//! Comprehensive benchmarks for moloch-holocrypt.
//!
//! Coverage: Every public function in every module.
//!
//! Benchmark categories:
//! 1. Encrypted Events - HoloCrypt container operations
//! 2. ZKP - Bulletproof range proofs and Schnorr proofs
//! 3. Threshold - Shamir secret sharing
//! 4. PQC - ML-KEM-768 encryption
//! 5. Composite - Ed25519 + ML-DSA-65 signatures
//! 6. Agile - Algorithm-agnostic encryption
//! 7. FROST - Threshold signing

use chrono::Utc;
use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};

use moloch_holocrypt::agile::{AgileConfig, AgileEncryptedEvent, Policy};
use moloch_holocrypt::composite::{CompositeSignature, CompositeSigningKey, CompositeVerifyingKey};
use moloch_holocrypt::encrypted::{
    generate_keypair, EncryptedEvent, EncryptedEventBuilder, EncryptionPolicy, EventSealingKey,
    FieldVisibility, KeyManager,
};
use moloch_holocrypt::frost::{FrostConfig, FrostCoordinator, FrostSignedEvent};
use moloch_holocrypt::pqc::{EventPqcKeyPair, KeyMigration, PqcEvent, QuantumSafeEvent};
use moloch_holocrypt::proofs::{
    BulletproofRangeData, EventProof, ProofAggregator, ProofVerifier, SchnorrProofData,
};
use moloch_holocrypt::threshold::{
    KeyShare, KeyShareSet, ShareDistributor, ShareRefresher, ThresholdConfig, ThresholdEvent,
};

use moloch_core::crypto::SecretKey;
use moloch_core::event::{
    ActorId, ActorKind, AuditEvent, EventType, Outcome, ResourceId, ResourceKind,
};

// ═══════════════════════════════════════════════════════════════════════════════
// TEST HELPERS
// ═══════════════════════════════════════════════════════════════════════════════

fn make_test_event(signing_key: &SecretKey) -> AuditEvent {
    let actor = ActorId::new(signing_key.public_key(), ActorKind::User);
    let resource = ResourceId::new(ResourceKind::Repository, "test-repo");

    AuditEvent::builder()
        .now()
        .event_type(EventType::RepoCreated)
        .actor(actor)
        .resource(resource)
        .outcome(Outcome::Success)
        .metadata(serde_json::json!({"benchmark": true, "count": 42}))
        .sign(signing_key)
        .unwrap()
}

fn make_encrypted_event(sealing_key: &EventSealingKey) -> EncryptedEvent {
    let signing_key = SecretKey::generate();
    let event = make_test_event(&signing_key);

    EncryptedEventBuilder::new()
        .event(event)
        .policy(EncryptionPolicy::default())
        .build(sealing_key)
        .unwrap()
}

// ═══════════════════════════════════════════════════════════════════════════════
// 1. ENCRYPTED EVENT BENCHMARKS
// ═══════════════════════════════════════════════════════════════════════════════

fn bench_encrypted_events(c: &mut Criterion) {
    let mut group = c.benchmark_group("encrypted_events");

    // Key generation
    group.bench_function("keypair_generation", |b| {
        b.iter(|| black_box(generate_keypair("bench-key")))
    });

    // Event encryption with different policies
    let signing_key = SecretKey::generate();
    let event = make_test_event(&signing_key);
    let (sealing_key, opening_key) = generate_keypair("bench-key");

    // All policy types
    group.bench_function("seal_default_policy", |b| {
        b.iter(|| {
            EncryptedEventBuilder::new()
                .event(event.clone())
                .policy(EncryptionPolicy::default())
                .build(black_box(&sealing_key))
                .unwrap()
        })
    });

    group.bench_function("seal_all_public_policy", |b| {
        b.iter(|| {
            EncryptedEventBuilder::new()
                .event(event.clone())
                .policy(EncryptionPolicy::all_public())
                .build(black_box(&sealing_key))
                .unwrap()
        })
    });

    group.bench_function("seal_all_encrypted_policy", |b| {
        b.iter(|| {
            EncryptedEventBuilder::new()
                .event(event.clone())
                .policy(EncryptionPolicy::all_encrypted())
                .build(black_box(&sealing_key))
                .unwrap()
        })
    });

    group.bench_function("seal_all_private_policy", |b| {
        b.iter(|| {
            EncryptedEventBuilder::new()
                .event(event.clone())
                .policy(EncryptionPolicy::all_private())
                .build(black_box(&sealing_key))
                .unwrap()
        })
    });

    // Builder with individual visibility settings
    group.bench_function("seal_custom_visibility", |b| {
        b.iter(|| {
            EncryptedEventBuilder::new()
                .event(event.clone())
                .event_type_visibility(FieldVisibility::Public)
                .actor_visibility(FieldVisibility::Encrypted)
                .resource_visibility(FieldVisibility::Private)
                .outcome_visibility(FieldVisibility::Public)
                .metadata_visibility(FieldVisibility::Private)
                .timestamp_visibility(FieldVisibility::Public)
                .build(black_box(&sealing_key))
                .unwrap()
        })
    });

    // Decryption and verification
    let encrypted = make_encrypted_event(&sealing_key);

    group.bench_function("unseal", |b| {
        b.iter(|| {
            black_box(&encrypted)
                .decrypt(black_box(&opening_key))
                .unwrap()
        })
    });

    group.bench_function("verify_structure", |b| {
        b.iter(|| {
            black_box(&encrypted)
                .verify_structure(black_box(&opening_key))
                .unwrap()
        })
    });

    // Accessor methods
    group.bench_function("id", |b| b.iter(|| black_box(&encrypted).id()));

    group.bench_function("commitment", |b| {
        b.iter(|| black_box(&encrypted).commitment())
    });

    group.bench_function("merkle_root", |b| {
        b.iter(|| black_box(&encrypted).merkle_root())
    });

    group.bench_function("public_fields", |b| {
        b.iter(|| black_box(&encrypted).public_fields())
    });

    group.bench_function("is_field_public", |b| {
        b.iter(|| black_box(&encrypted).is_field_public("event_type"))
    });

    // Serialization
    group.bench_function("to_bytes", |b| b.iter(|| black_box(&encrypted).to_bytes()));

    let bytes = encrypted.to_bytes();
    group.bench_function("from_bytes", |b| {
        b.iter(|| EncryptedEvent::from_bytes(black_box(&bytes)).unwrap())
    });

    // KeyManager operations
    let mut manager = KeyManager::new();
    let (_, opening_key2) = generate_keypair("key-2");
    manager.add_key(opening_key.clone());
    manager.add_key(opening_key2);

    group.bench_function("key_manager_get_key", |b| {
        b.iter(|| black_box(&manager).get_key(black_box("bench-key")))
    });

    group.bench_function("key_manager_decrypt", |b| {
        b.iter(|| black_box(&manager).decrypt(black_box(&encrypted)).unwrap())
    });

    group.finish();
}

// ═══════════════════════════════════════════════════════════════════════════════
// 2. ZKP BENCHMARKS
// ═══════════════════════════════════════════════════════════════════════════════

fn bench_zkp(c: &mut Criterion) {
    let mut group = c.benchmark_group("zkp");

    // Bulletproof range proofs with different bit sizes
    for n_bits in [8, 16, 32, 64] {
        group.bench_with_input(
            BenchmarkId::new("bulletproof_prove", n_bits),
            &n_bits,
            |b, &n_bits| {
                b.iter(|| BulletproofRangeData::prove(black_box(42), black_box(n_bits)).unwrap())
            },
        );
    }

    // Bulletproof verification
    for n_bits in [8, 16, 32, 64] {
        let proof = BulletproofRangeData::prove(42, n_bits).unwrap();
        group.bench_with_input(
            BenchmarkId::new("bulletproof_verify", n_bits),
            &proof,
            |b, proof| b.iter(|| black_box(proof).verify().unwrap()),
        );
    }

    // Schnorr discrete log proof
    let mut secret = [0u8; 32];
    getrandom::getrandom(&mut secret).unwrap();

    group.bench_function("schnorr_prove", |b| {
        b.iter(|| SchnorrProofData::prove(black_box(&secret)).unwrap())
    });

    let schnorr_proof = SchnorrProofData::prove(&secret).unwrap();
    group.bench_function("schnorr_verify", |b| {
        b.iter(|| black_box(&schnorr_proof).verify().unwrap())
    });

    // Full EventProof construction - all proof types
    let (sealing_key, _) = generate_keypair("bench-key");
    let encrypted = make_encrypted_event(&sealing_key);

    group.bench_function("event_proof_existence", |b| {
        b.iter(|| {
            EventProof::builder()
                .event(encrypted.clone())
                .prove_existence()
                .build()
                .unwrap()
        })
    });

    group.bench_function("event_proof_time_range", |b| {
        let from = Utc::now() - chrono::Duration::hours(1);
        let to = Utc::now() + chrono::Duration::hours(1);
        b.iter(|| {
            EventProof::builder()
                .event(encrypted.clone())
                .prove_time_range(from, to)
                .build()
                .unwrap()
        })
    });

    group.bench_function("event_proof_actor_membership", |b| {
        b.iter(|| {
            EventProof::builder()
                .event(encrypted.clone())
                .prove_actor_membership(vec!["alice", "bob", "charlie"])
                .build()
                .unwrap()
        })
    });

    group.bench_function("event_proof_resource_membership", |b| {
        b.iter(|| {
            EventProof::builder()
                .event(encrypted.clone())
                .prove_resource_membership(vec!["repo-1", "repo-2"])
                .build()
                .unwrap()
        })
    });

    group.bench_function("event_proof_event_type", |b| {
        b.iter(|| {
            EventProof::builder()
                .event(encrypted.clone())
                .prove_event_type("RepoCreated")
                .build()
                .unwrap()
        })
    });

    group.bench_function("event_proof_outcome", |b| {
        b.iter(|| {
            EventProof::builder()
                .event(encrypted.clone())
                .prove_outcome("Success")
                .build()
                .unwrap()
        })
    });

    group.bench_function("event_proof_metadata_range", |b| {
        b.iter(|| {
            EventProof::builder()
                .event(encrypted.clone())
                .prove_metadata_range("count", 0, 100)
                .build()
                .unwrap()
        })
    });

    group.bench_function("event_proof_bulletproof_32", |b| {
        b.iter(|| {
            EventProof::builder()
                .event(encrypted.clone())
                .with_bulletproof_range(42, 32)
                .unwrap()
                .build()
                .unwrap()
        })
    });

    group.bench_function("event_proof_bulletproof_custom_range", |b| {
        b.iter(|| {
            EventProof::builder()
                .event(encrypted.clone())
                .with_bulletproof_range_custom(50, 10, 100)
                .unwrap()
                .build()
                .unwrap()
        })
    });

    group.bench_function("event_proof_schnorr", |b| {
        b.iter(|| {
            EventProof::builder()
                .event(encrypted.clone())
                .with_discrete_log_proof(&secret)
                .unwrap()
                .build()
                .unwrap()
        })
    });

    // Proof verification
    let existence_proof = EventProof::builder()
        .event(encrypted.clone())
        .prove_existence()
        .build()
        .unwrap();

    group.bench_function("event_proof_verify", |b| {
        b.iter(|| {
            black_box(&existence_proof)
                .verify(black_box(&encrypted))
                .unwrap()
        })
    });

    // Proof serialization
    group.bench_function("event_proof_to_bytes", |b| {
        b.iter(|| black_box(&existence_proof).to_bytes())
    });

    let proof_bytes = existence_proof.to_bytes();
    group.bench_function("event_proof_from_bytes", |b| {
        b.iter(|| EventProof::from_bytes(black_box(&proof_bytes)).unwrap())
    });

    // ProofVerifier
    let mut verifier = ProofVerifier::new();
    verifier.add_trusted_root(*encrypted.merkle_root());

    group.bench_function("proof_verifier_verify", |b| {
        b.iter(|| {
            black_box(&verifier)
                .verify(black_box(&existence_proof), black_box(&encrypted))
                .unwrap()
        })
    });

    // Multiple proofs verification
    let proof2 = EventProof::builder()
        .event(encrypted.clone())
        .prove_event_type("RepoCreated")
        .build()
        .unwrap();
    let proofs = vec![existence_proof.clone(), proof2];

    group.bench_function("proof_verifier_verify_all", |b| {
        b.iter(|| {
            black_box(&verifier)
                .verify_all(black_box(&proofs), black_box(&encrypted))
                .unwrap()
        })
    });

    // ProofAggregator
    group.bench_function("proof_aggregator_aggregate", |b| {
        b.iter_batched(
            || {
                let mut agg = ProofAggregator::new();
                let p1 = EventProof::builder()
                    .event(encrypted.clone())
                    .prove_existence()
                    .build()
                    .unwrap();
                let p2 = EventProof::builder()
                    .event(encrypted.clone())
                    .prove_event_type("RepoCreated")
                    .build()
                    .unwrap();
                agg.add(p1);
                agg.add(p2);
                agg
            },
            |agg| agg.aggregate(black_box(&encrypted)).unwrap(),
            criterion::BatchSize::SmallInput,
        )
    });

    group.finish();
}

// ═══════════════════════════════════════════════════════════════════════════════
// 3. THRESHOLD BENCHMARKS
// ═══════════════════════════════════════════════════════════════════════════════

fn bench_threshold(c: &mut Criterion) {
    let mut group = c.benchmark_group("threshold");

    let signing_key = SecretKey::generate();
    let event = make_test_event(&signing_key);

    // ThresholdConfig creation
    group.bench_function("config_new", |b| {
        b.iter(|| ThresholdConfig::new(black_box(2), black_box(3)).unwrap())
    });

    group.bench_function("config_two_of_three", |b| {
        b.iter(|| ThresholdConfig::two_of_three())
    });

    group.bench_function("config_three_of_five", |b| {
        b.iter(|| ThresholdConfig::three_of_five())
    });

    group.bench_function("config_five_of_seven", |b| {
        b.iter(|| ThresholdConfig::five_of_seven())
    });

    // Threshold configurations for seal/unseal
    let configs = [
        ("2_of_3", ThresholdConfig::two_of_three()),
        ("3_of_5", ThresholdConfig::three_of_five()),
        ("5_of_7", ThresholdConfig::five_of_seven()),
    ];

    for (name, config) in &configs {
        group.bench_function(format!("seal_{}", name), |b| {
            b.iter(|| ThresholdEvent::seal(black_box(&event), config.clone()).unwrap())
        });
    }

    // Unseal benchmarks
    for (name, config) in &configs {
        let (threshold_event, shares) = ThresholdEvent::seal(&event, config.clone()).unwrap();
        let mut share_set = KeyShareSet::with_config(config.clone());
        for share in shares.iter().take(config.threshold) {
            share_set.add(share.clone());
        }

        group.bench_function(format!("unseal_{}", name), |b| {
            b.iter(|| {
                black_box(&threshold_event)
                    .unseal(black_box(&share_set))
                    .unwrap()
            })
        });
    }

    // ThresholdEvent verify_structure
    let config = ThresholdConfig::two_of_three();
    let (threshold_event, shares) = ThresholdEvent::seal(&event, config.clone()).unwrap();

    group.bench_function("verify_structure", |b| {
        b.iter(|| black_box(&threshold_event).verify_structure().unwrap())
    });

    // ThresholdEvent serialization
    group.bench_function("threshold_event_to_bytes", |b| {
        b.iter(|| black_box(&threshold_event).to_bytes())
    });

    let te_bytes = threshold_event.to_bytes();
    group.bench_function("threshold_event_from_bytes", |b| {
        b.iter(|| ThresholdEvent::from_bytes(black_box(&te_bytes)).unwrap())
    });

    // KeyShare operations
    let share = &shares[0];
    group.bench_function("key_share_to_bytes", |b| {
        b.iter(|| black_box(share).to_bytes())
    });

    let share_bytes = share.to_bytes();
    group.bench_function("key_share_from_bytes", |b| {
        b.iter(|| KeyShare::from_bytes(black_box(&share_bytes)).unwrap())
    });

    // KeyShareSet operations
    group.bench_function("key_share_set_add", |b| {
        b.iter_batched(
            || KeyShareSet::with_config(config.clone()),
            |mut set| {
                set.add(shares[0].clone());
                set
            },
            criterion::BatchSize::SmallInput,
        )
    });

    let mut share_set = KeyShareSet::with_config(config.clone());
    for share in &shares {
        share_set.add(share.clone());
    }

    group.bench_function("key_share_set_has_threshold", |b| {
        b.iter(|| black_box(&share_set).has_threshold())
    });

    // Share refresh
    group.bench_function("share_refresh", |b| {
        b.iter(|| ShareRefresher::refresh(black_box(&share_set), black_box(&config)).unwrap())
    });

    // Share distribution
    let owners = vec!["alice", "bob", "charlie"];
    group.bench_function("share_distribute", |b| {
        let (_, shares) = ThresholdEvent::seal(&event, config.clone()).unwrap();
        b.iter(|| {
            ShareDistributor::distribute(black_box(shares.clone()), black_box(&owners)).unwrap()
        })
    });

    // ShareDistributor::collect
    let (_, shares) = ThresholdEvent::seal(&event, config.clone()).unwrap();
    let distributor = ShareDistributor::distribute(shares, &owners).unwrap();

    group.bench_function("share_distributor_collect", |b| {
        b.iter(|| black_box(&distributor).collect(black_box(["alice", "bob"])))
    });

    group.bench_function("share_distributor_get_shares", |b| {
        b.iter(|| black_box(&distributor).get_shares(black_box("alice")))
    });

    group.finish();
}

// ═══════════════════════════════════════════════════════════════════════════════
// 4. PQC BENCHMARKS
// ═══════════════════════════════════════════════════════════════════════════════

fn bench_pqc(c: &mut Criterion) {
    let mut group = c.benchmark_group("pqc");

    // ML-KEM-768 keypair generation
    group.bench_function("keypair_generation", |b| {
        b.iter(|| EventPqcKeyPair::generate(black_box("bench-key")))
    });

    let signing_key = SecretKey::generate();
    let event = make_test_event(&signing_key);
    let pqc_key = EventPqcKeyPair::generate("bench-key");

    // Key accessors
    group.bench_function("public_key_bytes", |b| {
        b.iter(|| black_box(&pqc_key).public_key_bytes())
    });

    group.bench_function("private_key_bytes", |b| {
        b.iter(|| black_box(&pqc_key).private_key_bytes())
    });

    // PqcEvent seal/unseal
    group.bench_function("pqc_event_seal", |b| {
        b.iter(|| PqcEvent::seal(black_box(&event), black_box(&pqc_key)).unwrap())
    });

    let pqc_event = PqcEvent::seal(&event, &pqc_key).unwrap();
    group.bench_function("pqc_event_unseal", |b| {
        b.iter(|| black_box(&pqc_event).unseal(black_box(&pqc_key)).unwrap())
    });

    group.bench_function("pqc_event_verify_structure", |b| {
        b.iter(|| black_box(&pqc_event).verify_structure().unwrap())
    });

    // PqcEvent accessors
    group.bench_function("pqc_event_commitment", |b| {
        b.iter(|| black_box(&pqc_event).commitment())
    });

    group.bench_function("pqc_event_merkle_root", |b| {
        b.iter(|| black_box(&pqc_event).merkle_root())
    });

    // PqcEvent serialization
    group.bench_function("pqc_event_to_bytes", |b| {
        b.iter(|| black_box(&pqc_event).to_bytes())
    });

    let bytes = pqc_event.to_bytes();
    group.bench_function("pqc_event_from_bytes", |b| {
        b.iter(|| PqcEvent::from_bytes(black_box(&bytes)).unwrap())
    });

    // QuantumSafeEvent (hybrid) seal/unseal
    group.bench_function("quantum_safe_seal", |b| {
        b.iter(|| QuantumSafeEvent::seal(black_box(&event), black_box(&pqc_key)).unwrap())
    });

    let qs_event = QuantumSafeEvent::seal(&event, &pqc_key).unwrap();
    group.bench_function("quantum_safe_unseal", |b| {
        b.iter(|| black_box(&qs_event).unseal(black_box(&pqc_key)).unwrap())
    });

    // QuantumSafeEvent serialization
    group.bench_function("quantum_safe_to_bytes", |b| {
        b.iter(|| black_box(&qs_event).to_bytes())
    });

    let qs_bytes = qs_event.to_bytes();
    group.bench_function("quantum_safe_from_bytes", |b| {
        b.iter(|| QuantumSafeEvent::from_bytes(black_box(&qs_bytes)).unwrap())
    });

    // Key rotation
    let old_key = EventPqcKeyPair::generate("old-key");
    let new_key = EventPqcKeyPair::generate("new-key");
    let old_event = PqcEvent::seal(&event, &old_key).unwrap();

    group.bench_function("key_rotation", |b| {
        b.iter(|| {
            KeyMigration::rotate_pqc_key(
                black_box(&old_event),
                black_box(&old_key),
                black_box(&new_key),
            )
            .unwrap()
        })
    });

    group.finish();
}

// ═══════════════════════════════════════════════════════════════════════════════
// 5. COMPOSITE SIGNATURE BENCHMARKS
// ═══════════════════════════════════════════════════════════════════════════════

fn bench_composite(c: &mut Criterion) {
    let mut group = c.benchmark_group("composite");

    // Key generation (Ed25519 + ML-DSA-65)
    group.bench_function("keypair_generation", |b| {
        b.iter(|| CompositeSigningKey::generate())
    });

    let signing_key = CompositeSigningKey::generate();
    let verifying_key = signing_key.verifying_key();

    // Verifying key derivation
    group.bench_function("verifying_key", |b| {
        b.iter(|| black_box(&signing_key).verifying_key())
    });

    // Message sizes for sign/verify
    let messages: Vec<(&str, Vec<u8>)> = vec![
        ("32B", vec![0u8; 32]),
        ("256B", vec![0u8; 256]),
        ("1KB", vec![0u8; 1024]),
        ("4KB", vec![0u8; 4096]),
        ("16KB", vec![0u8; 16384]),
    ];

    for (name, message) in &messages {
        group.throughput(Throughput::Bytes(message.len() as u64));

        group.bench_with_input(BenchmarkId::new("sign", name), message, |b, msg| {
            b.iter(|| black_box(&signing_key).sign(black_box(msg)))
        });
    }

    // Verification
    for (name, message) in &messages {
        let signature = signing_key.sign(message);
        group.throughput(Throughput::Bytes(message.len() as u64));

        group.bench_with_input(
            BenchmarkId::new("verify", name),
            &(message, signature),
            |b, (msg, sig)| {
                b.iter(|| {
                    black_box(&verifying_key)
                        .verify(black_box(msg), black_box(sig))
                        .unwrap()
                })
            },
        );
    }

    // Signing key serialization
    group.bench_function("signing_key_to_bytes", |b| {
        b.iter(|| black_box(&signing_key).to_bytes())
    });

    let sk_bytes = signing_key.to_bytes();
    group.bench_function("signing_key_from_bytes", |b| {
        b.iter(|| CompositeSigningKey::from_bytes(black_box(&sk_bytes)).unwrap())
    });

    // Verifying key serialization
    group.bench_function("verifying_key_to_bytes", |b| {
        b.iter(|| black_box(&verifying_key).to_bytes())
    });

    let vk_bytes = verifying_key.to_bytes();
    group.bench_function("verifying_key_from_bytes", |b| {
        b.iter(|| CompositeVerifyingKey::from_bytes(black_box(&vk_bytes)).unwrap())
    });

    // Verifying key hex encoding
    group.bench_function("verifying_key_to_hex", |b| {
        b.iter(|| black_box(&verifying_key).to_hex())
    });

    let vk_hex = verifying_key.to_hex();
    group.bench_function("verifying_key_from_hex", |b| {
        b.iter(|| CompositeVerifyingKey::from_hex(black_box(&vk_hex)).unwrap())
    });

    // Signature serialization
    let signature = signing_key.sign(b"test message");
    group.bench_function("signature_to_bytes", |b| {
        b.iter(|| black_box(&signature).to_bytes())
    });

    let sig_bytes = signature.to_bytes();
    group.bench_function("signature_from_bytes", |b| {
        b.iter(|| CompositeSignature::from_bytes(black_box(&sig_bytes)).unwrap())
    });

    group.bench_function("signature_to_hex", |b| {
        b.iter(|| black_box(&signature).to_hex())
    });

    // Component access
    group.bench_function("ed25519_key_access", |b| {
        b.iter(|| black_box(&verifying_key).ed25519_key())
    });

    group.bench_function("ml_dsa_key_access", |b| {
        b.iter(|| black_box(&verifying_key).ml_dsa_key())
    });

    group.finish();
}

// ═══════════════════════════════════════════════════════════════════════════════
// 6. AGILE ENCRYPTION BENCHMARKS
// ═══════════════════════════════════════════════════════════════════════════════

fn bench_agile(c: &mut Criterion) {
    let mut group = c.benchmark_group("agile");

    // Config creation
    group.bench_function("config_default", |b| b.iter(|| AgileConfig::default()));

    group.bench_function("config_fips_140_3", |b| {
        b.iter(|| AgileConfig::fips_140_3())
    });

    group.bench_function("config_post_quantum", |b| {
        b.iter(|| AgileConfig::post_quantum())
    });

    group.bench_function("config_high_security", |b| {
        b.iter(|| AgileConfig::high_security())
    });

    // Config validation
    let config = AgileConfig::default();
    group.bench_function("config_validate", |b| {
        b.iter(|| black_box(&config).validate().unwrap())
    });

    let key = [0u8; 32];
    let plaintext = b"This is test data for agile encryption benchmarking";

    // Seal with different configurations
    let configs = [
        ("default_chacha20", AgileConfig::default()),
        ("fips_aes256gcm", AgileConfig::fips_140_3()),
        ("post_quantum", AgileConfig::post_quantum()),
        ("high_security_xchacha20", AgileConfig::high_security()),
    ];

    for (name, config) in &configs {
        group.bench_function(format!("seal_{}", name), |b| {
            b.iter(|| {
                AgileEncryptedEvent::seal(black_box(plaintext), black_box(&key), black_box(config))
                    .unwrap()
            })
        });
    }

    // Unseal
    for (name, config) in &configs {
        let event = AgileEncryptedEvent::seal(plaintext, &key, config).unwrap();
        group.bench_function(format!("unseal_{}", name), |b| {
            b.iter(|| black_box(&event).unseal(black_box(&key)).unwrap())
        });
    }

    // Event accessors
    let event = AgileEncryptedEvent::seal(plaintext, &key, &AgileConfig::default()).unwrap();

    group.bench_function("algorithm", |b| b.iter(|| black_box(&event).algorithm()));

    group.bench_function("config", |b| b.iter(|| black_box(&event).config()));

    group.bench_function("commitment", |b| b.iter(|| black_box(&event).commitment()));

    group.bench_function("merkle_root", |b| {
        b.iter(|| black_box(&event).merkle_root())
    });

    group.bench_function("needs_migration", |b| {
        b.iter(|| black_box(&event).needs_migration())
    });

    group.bench_function("migration_recommendation", |b| {
        b.iter(|| black_box(&event).migration_recommendation())
    });

    // Policy compliance
    let fips_policy = Policy::fips_140_3();
    group.bench_function("complies_with_fips", |b| {
        b.iter(|| black_box(&event).complies_with(black_box(&fips_policy)))
    });

    let default_policy = Policy::default();
    group.bench_function("complies_with_default", |b| {
        b.iter(|| black_box(&event).complies_with(black_box(&default_policy)))
    });

    // Migration
    let old_config = AgileConfig::default();
    let new_config = AgileConfig::fips_140_3();
    let old_key = [0u8; 32];
    let new_key = [1u8; 32];
    let old_event = AgileEncryptedEvent::seal(plaintext, &old_key, &old_config).unwrap();

    group.bench_function("migrate_chacha_to_aes", |b| {
        b.iter(|| {
            black_box(&old_event)
                .migrate(
                    black_box(&old_key),
                    black_box(&new_key),
                    black_box(&new_config),
                )
                .unwrap()
        })
    });

    // Serialization
    group.bench_function("to_bytes", |b| b.iter(|| black_box(&event).to_bytes()));

    let bytes = event.to_bytes();
    group.bench_function("from_bytes", |b| {
        b.iter(|| AgileEncryptedEvent::from_bytes(black_box(&bytes)).unwrap())
    });

    group.finish();
}

// ═══════════════════════════════════════════════════════════════════════════════
// 7. FROST BENCHMARKS
// ═══════════════════════════════════════════════════════════════════════════════

fn bench_frost(c: &mut Criterion) {
    let mut group = c.benchmark_group("frost");

    // FrostConfig creation
    group.bench_function("config_new", |b| {
        b.iter(|| FrostConfig::new(black_box(2), black_box(3)))
    });

    // Setup with different thresholds
    let configs = [
        ("2_of_3", FrostConfig::new(2, 3)),
        ("3_of_5", FrostConfig::new(3, 5)),
        ("5_of_7", FrostConfig::new(5, 7)),
    ];

    for (name, config) in &configs {
        group.bench_function(format!("setup_{}", name), |b| {
            b.iter(|| FrostCoordinator::setup(black_box(config)).unwrap())
        });
    }

    // Full signing ceremony (2-of-3)
    let config = FrostConfig::new(2, 3);
    let (coordinator, participants) = FrostCoordinator::setup(&config).unwrap();
    let message = b"Message to sign with FROST";

    // Config accessors
    group.bench_function("config_threshold", |b| {
        b.iter(|| black_box(&config).threshold())
    });

    group.bench_function("config_total", |b| b.iter(|| black_box(&config).total()));

    group.bench_function("config_has_quorum", |b| {
        b.iter(|| black_box(&config).has_quorum(black_box(2)))
    });

    // Coordinator accessors
    group.bench_function("coordinator_group_key", |b| {
        b.iter(|| black_box(&coordinator).group_key())
    });

    group.bench_function("coordinator_config", |b| {
        b.iter(|| black_box(&coordinator).config())
    });

    // Participant operations
    group.bench_function("participant_id", |b| {
        b.iter(|| black_box(&participants[0]).id())
    });

    group.bench_function("round1", |b| b.iter(|| participants[0].round1().unwrap()));

    group.bench_function("create_signing_package", |b| {
        b.iter_batched(
            || {
                participants
                    .iter()
                    .take(2)
                    .map(|p| p.round1().unwrap())
                    .collect::<Vec<_>>()
            },
            |outputs| {
                coordinator
                    .create_signing_package(black_box(&outputs), black_box(message))
                    .unwrap()
            },
            criterion::BatchSize::SmallInput,
        )
    });

    // Round 2 - must use matching round1 outputs and signing package
    group.bench_function("round2", |b| {
        b.iter_batched(
            || {
                let r1s: Vec<_> = participants
                    .iter()
                    .take(2)
                    .map(|p| p.round1().unwrap())
                    .collect();
                let pkg = coordinator.create_signing_package(&r1s, message).unwrap();
                (r1s, pkg)
            },
            |(r1s, pkg)| {
                participants[0]
                    .round2(
                        black_box(message),
                        black_box(&r1s[0].nonces),
                        black_box(&pkg),
                    )
                    .unwrap()
            },
            criterion::BatchSize::SmallInput,
        )
    });

    // Aggregation
    group.bench_function("aggregate", |b| {
        b.iter_batched(
            || {
                let r1s: Vec<_> = participants
                    .iter()
                    .take(2)
                    .map(|p| p.round1().unwrap())
                    .collect();
                let pkg = coordinator.create_signing_package(&r1s, message).unwrap();
                let shares: Vec<_> = r1s
                    .iter()
                    .zip(participants.iter().take(2))
                    .map(|(r1, p)| p.round2(message, &r1.nonces, &pkg).unwrap())
                    .collect();
                (pkg, shares)
            },
            |(pkg, shares)| {
                coordinator
                    .aggregate(black_box(&pkg), black_box(&shares))
                    .unwrap()
            },
            criterion::BatchSize::SmallInput,
        )
    });

    // Full ceremony (includes setup)
    group.bench_function("full_ceremony_2_of_3", |b| {
        b.iter_batched(
            || FrostCoordinator::setup(&FrostConfig::new(2, 3)).unwrap(),
            |(coord, parts)| {
                let r1s: Vec<_> = parts.iter().take(2).map(|p| p.round1().unwrap()).collect();
                let pkg = coord.create_signing_package(&r1s, message).unwrap();
                let shares: Vec<_> = r1s
                    .iter()
                    .zip(parts.iter().take(2))
                    .map(|(r1, p)| p.round2(message, &r1.nonces, &pkg).unwrap())
                    .collect();
                coord.aggregate(&pkg, &shares).unwrap()
            },
            criterion::BatchSize::SmallInput,
        )
    });

    // Signature operations
    let r1s: Vec<_> = participants
        .iter()
        .take(2)
        .map(|p| p.round1().unwrap())
        .collect();
    let pkg = coordinator.create_signing_package(&r1s, message).unwrap();
    let shares: Vec<_> = r1s
        .iter()
        .zip(participants.iter().take(2))
        .map(|(r1, p)| p.round2(message, &r1.nonces, &pkg).unwrap())
        .collect();
    let signature = coordinator.aggregate(&pkg, &shares).unwrap();

    group.bench_function("signature_verify", |b| {
        b.iter(|| black_box(&signature).verify(black_box(message)).unwrap())
    });

    group.bench_function("coordinator_verify", |b| {
        b.iter(|| {
            black_box(&coordinator)
                .verify(black_box(message), black_box(&signature))
                .unwrap()
        })
    });

    group.bench_function("signature_as_bytes", |b| {
        b.iter(|| black_box(&signature).as_bytes())
    });

    group.bench_function("signature_group_key", |b| {
        b.iter(|| black_box(&signature).group_key())
    });

    // FrostSignedEvent - need to sign the correct message
    let ciphertext = b"encrypted data".to_vec();
    let nonce = vec![0u8; 12];
    let commitment = [1u8; 32];
    let merkle_root = [2u8; 32];

    // Create message that verify_signature expects
    let mut event_message = Vec::new();
    event_message.extend_from_slice(&ciphertext);
    event_message.extend_from_slice(&commitment);
    event_message.extend_from_slice(&merkle_root);

    // Sign the event message
    let (event_coord, event_parts) = FrostCoordinator::setup(&config).unwrap();
    let event_r1s: Vec<_> = event_parts
        .iter()
        .take(2)
        .map(|p| p.round1().unwrap())
        .collect();
    let event_pkg = event_coord
        .create_signing_package(&event_r1s, &event_message)
        .unwrap();
    let event_shares: Vec<_> = event_r1s
        .iter()
        .zip(event_parts.iter().take(2))
        .map(|(r1, p)| p.round2(&event_message, &r1.nonces, &event_pkg).unwrap())
        .collect();
    let event_signature = event_coord.aggregate(&event_pkg, &event_shares).unwrap();

    let frost_event = FrostSignedEvent::new(
        ciphertext.clone(),
        nonce.clone(),
        commitment,
        merkle_root,
        event_signature.clone(),
        config,
    );

    group.bench_function("frost_signed_event_new", |b| {
        b.iter(|| {
            FrostSignedEvent::new(
                black_box(ciphertext.clone()),
                black_box(nonce.clone()),
                black_box(commitment),
                black_box(merkle_root),
                black_box(event_signature.clone()),
                black_box(config),
            )
        })
    });

    group.bench_function("frost_signed_event_verify_signature", |b| {
        b.iter(|| black_box(&frost_event).verify_signature().unwrap())
    });

    // FrostSignedEvent accessors
    group.bench_function("frost_signed_event_ciphertext", |b| {
        b.iter(|| black_box(&frost_event).ciphertext())
    });

    group.bench_function("frost_signed_event_nonce", |b| {
        b.iter(|| black_box(&frost_event).nonce())
    });

    group.bench_function("frost_signed_event_commitment", |b| {
        b.iter(|| black_box(&frost_event).commitment())
    });

    group.bench_function("frost_signed_event_merkle_root", |b| {
        b.iter(|| black_box(&frost_event).merkle_root())
    });

    group.bench_function("frost_signed_event_signature", |b| {
        b.iter(|| black_box(&frost_event).signature())
    });

    group.bench_function("frost_signed_event_config", |b| {
        b.iter(|| black_box(&frost_event).config())
    });

    group.finish();
}

// ═══════════════════════════════════════════════════════════════════════════════
// CRITERION MAIN
// ═══════════════════════════════════════════════════════════════════════════════

criterion_group!(
    benches,
    bench_encrypted_events,
    bench_zkp,
    bench_threshold,
    bench_pqc,
    bench_composite,
    bench_agile,
    bench_frost,
);

criterion_main!(benches);
