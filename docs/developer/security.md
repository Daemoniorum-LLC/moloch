# Moloch Security Guide

Security considerations, threat model, and best practices for deploying Moloch.

## Threat Model

### Assets

1. **Audit Events**: Immutable records of actions
2. **Private Keys**: Signing keys for validators and users
3. **Encryption Keys**: HoloCrypt keys for field encryption
4. **MMR State**: Cryptographic commitment to event history

### Threat Actors

| Actor | Capability | Goal |
|-------|------------|------|
| External Attacker | Network access | Forge events, DoS |
| Malicious Validator | Consensus participation | Censor, reorder events |
| Insider | Key access | Decrypt protected data |
| Quantum Adversary | Future quantum computer | Break classical crypto |

## Cryptographic Security

### Signature Security

- **Algorithm**: Ed25519 (128-bit security)
- **Key Generation**: CSPRNG via `getrandom`
- **Batch Verification**: Constant-time implementation

Best practices:
```rust
// Always use secure key generation
let key = SecretKey::generate(); // Uses OS entropy

// Never reuse nonces (handled internally)
// Never expose secret key bytes
```

### Post-Quantum Protection

For long-term confidentiality (>10 years), use ML-KEM:

```rust
use moloch_holocrypt::{EventPqcKeyPair, QuantumSafeEvent};

let pqc_key = EventPqcKeyPair::generate("archive-key");
let sealed = QuantumSafeEvent::seal(&event, &pqc_key)?;
```

ML-KEM-768 provides NIST Level 3 security (equivalent to AES-192).

### Zero-Knowledge Proofs

ZK proofs reveal only what you choose:

| Proof Type | Reveals | Hides |
|------------|---------|-------|
| Existence | Event exists in chain | All content |
| Type | Event type (e.g., "push") | Actor, resource, metadata |
| Actor Membership | Actor is in allowed set | Which specific actor |
| Time Range | Event within time bounds | Exact timestamp |

## Consensus Security

### Byzantine Fault Tolerance

Aura-style PoA tolerates:
- `f < n/3` Byzantine validators
- Network partitions (with liveness trade-off)

### Attack Mitigations

| Attack | Mitigation |
|--------|------------|
| Double-signing | Slashing, evidence collection |
| Censorship | Validator rotation, multiple validators |
| Long-range | Checkpoints, anchor confirmations |
| Eclipse | Peer diversity, authenticated connections |

## Network Security

### Transport

- TLS 1.3 for all connections
- Ed25519 peer identity
- Certificate pinning for validators

### DoS Protection

```toml
[network]
max_connections = 100
rate_limit_per_peer = 1000  # msgs/sec
ban_duration_secs = 3600
```

## Storage Security

### At-Rest Encryption

For sensitive deployments, enable storage encryption:

```toml
[storage]
encryption = true
key_source = "vault"  # or "env", "file"
```

### Backup Security

- Encrypt backups with separate key
- Store keys in HSM or secrets manager
- Test restore procedures regularly

## Key Management

### Validator Keys

1. Generate on air-gapped machine
2. Store in HSM or secure enclave
3. Use key rotation schedule
4. Maintain secure backup

### Threshold Keys

For high-security deployments, use threshold signatures:

```rust
use moloch_holocrypt::ThresholdConfig;

// 3-of-5: Requires 3 key holders to sign
let config = ThresholdConfig::new(3, 5)?;
```

### Key Rotation

Rotate keys periodically:

```rust
// Generate new keypair
let new_key = SecretKey::generate();

// Register rotation in chain
chain.rotate_key(&old_key, &new_key)?;

// Securely destroy old key
old_key.zeroize();
```

## API Security

### Authentication

Always use authentication in production:

```toml
[api]
require_auth = true
jwt_secret = "${JWT_SECRET}"  # from environment
api_key_hash_algo = "argon2id"
```

### Rate Limiting

Protect against abuse:

```toml
[api.rate_limit]
requests_per_minute = 600
burst_size = 100
```

### Input Validation

All inputs are validated:
- Event size limits
- Metadata schema validation
- Actor/resource ID format
- Timestamp bounds

## Deployment Checklist

### Pre-Production

- [ ] Generate validator keys securely
- [ ] Configure TLS certificates
- [ ] Set up key backup procedures
- [ ] Enable audit logging
- [ ] Configure rate limits
- [ ] Set up monitoring/alerting

### Production

- [ ] Use HSM for validator keys
- [ ] Enable storage encryption
- [ ] Configure firewall rules
- [ ] Set up intrusion detection
- [ ] Establish incident response plan
- [ ] Schedule security audits

## Incident Response

### Event Forgery Detected

1. Identify compromised key
2. Rotate affected keys
3. Publish revocation
4. Analyze event timeline
5. Notify affected parties

### Validator Compromise

1. Remove from validator set (requires supermajority)
2. Collect slashing evidence
3. Rotate remaining validator keys
4. Audit affected block range

## Reporting Vulnerabilities

See [SECURITY.md](../../SECURITY.md) for responsible disclosure procedures.

**Do NOT disclose vulnerabilities publicly before coordinated fix.**

Contact: security@daemoniorum.com
PGP Key: Available at https://daemoniorum.com/.well-known/security.txt
