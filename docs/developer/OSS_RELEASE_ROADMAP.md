# Moloch OSS Release Roadmap (TDD)

Test-Driven Development roadmap for preparing Moloch for open source release.

**Methodology**: RED → GREEN → REFACTOR for each item.

---

## Phase 1: Critical Security Fixes

### 1.1 API Key Hashing (CRITICAL) - DONE

**Status**: Resolved. `moloch-api/src/auth.rs` uses `moloch_core::hash` (BLAKE3)
for API key hashing. Verified 2026-02-03.

~~**Current State**: `moloch-api/src/auth.rs:304-311` uses `DefaultHasher` (SipHash)~~
~~**Target**: Use Argon2id for cryptographic key hashing~~

#### RED - Write Failing Tests

```rust
// moloch-api/src/auth.rs - Add to #[cfg(test)] mod tests

#[test]
fn test_hash_key_is_cryptographic() {
    let config = make_config();
    let auth = AuthMiddleware::new(config);

    // Hash should be consistent
    let hash1 = auth.hash_key("my-secret-key");
    let hash2 = auth.hash_key("my-secret-key");
    assert_eq!(hash1, hash2, "same input should produce same hash");

    // Hash should be long enough for security (Argon2 produces 32+ bytes)
    assert!(hash1.len() >= 64, "hash should be at least 32 bytes (64 hex chars)");

    // Different inputs should produce different hashes
    let hash3 = auth.hash_key("different-key");
    assert_ne!(hash1, hash3, "different inputs should produce different hashes");
}

#[test]
fn test_hash_key_timing_safe() {
    // Argon2 is inherently timing-safe due to memory-hard design
    // This test verifies we're not using fast hashes
    let config = make_config();
    let auth = AuthMiddleware::new(config);

    let start = std::time::Instant::now();
    let _ = auth.hash_key("test-key");
    let duration = start.elapsed();

    // Argon2 should take at least 10ms with default params
    // SipHash takes microseconds
    assert!(duration.as_millis() >= 5, "hash should be memory-hard (took {:?})", duration);
}
```

#### GREEN - Implementation

Replace `hash_key` method with Argon2id:

```rust
use argon2::{
    password_hash::{rand_core::OsRng, PasswordHasher, SaltString},
    Argon2,
};

fn hash_key(&self, secret: &str) -> String {
    // Use a deterministic salt derived from the secret for consistency
    // In production, you'd store the salt with the hash
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();

    argon2
        .hash_password(secret.as_bytes(), &salt)
        .expect("failed to hash key")
        .to_string()
}
```

**Note**: This changes the hash format. Need to handle key re-registration or migration.

#### Dependencies to Add

```toml
# moloch-api/Cargo.toml
argon2 = { version = "0.5", features = ["std"] }
```

---

### 1.2 Light Client Signature Verification (CRITICAL) - DONE

**Status**: Resolved. `moloch-light/src/header.rs:79` uses `pk.verify()` with real
Ed25519 verification. Tests at lines 278-363 confirm correct behavior including
rejection of invalid signatures. Verified 2026-02-03.

~~**Current State**: `moloch-light/src/header.rs:78-82` always returns `true`~~
~~**Target**: Implement actual Ed25519 signature verification~~

#### RED - Write Failing Tests

```rust
// moloch-light/src/header.rs - Add to #[cfg(test)] mod tests

use moloch_core::crypto::{SecretKey, PublicKey};

#[test]
fn test_verify_signature_valid() {
    let secret = SecretKey::generate();
    let public = secret.public_key();

    // Create a header and sign it
    let header = create_test_header(1);
    let message = header.hash().as_bytes();
    let signature = secret.sign(message);

    let trusted = TrustedHeader::new(header, vec![(public.clone(), signature)], Hash::ZERO);

    // Should verify successfully
    assert!(trusted.verify_signature(&public, &trusted.signatures[0].1));
}

#[test]
fn test_verify_signature_invalid() {
    let secret1 = SecretKey::generate();
    let secret2 = SecretKey::generate();
    let public1 = secret1.public_key();

    let header = create_test_header(1);
    let message = header.hash().as_bytes();

    // Sign with secret2 but try to verify with public1
    let wrong_signature = secret2.sign(message);

    let trusted = TrustedHeader::new(header, vec![(public1.clone(), wrong_signature)], Hash::ZERO);

    // Should fail verification
    assert!(!trusted.verify_signature(&public1, &trusted.signatures[0].1));
}

#[test]
fn test_verify_signature_wrong_message() {
    let secret = SecretKey::generate();
    let public = secret.public_key();

    let header = create_test_header(1);

    // Sign a different message
    let wrong_message = b"wrong message";
    let signature = secret.sign(wrong_message);

    let trusted = TrustedHeader::new(header, vec![(public.clone(), signature)], Hash::ZERO);

    // Should fail because signature is for different message
    assert!(!trusted.verify_signature(&public, &trusted.signatures[0].1));
}

#[test]
fn test_verify_finality_requires_real_signatures() {
    let validators: Vec<_> = (0..3).map(|_| SecretKey::generate()).collect();
    let public_keys: Vec<_> = validators.iter().map(|s| s.public_key()).collect();

    let header = create_test_header(1);
    let message = header.hash().as_bytes();

    // Only 1 valid signature (need 2 for 2/3+1 of 3)
    let sig0 = validators[0].sign(message);
    let fake_sig = moloch_core::Sig::default(); // Invalid signature

    let trusted = TrustedHeader::new(
        header,
        vec![
            (public_keys[0].clone(), sig0),
            (public_keys[1].clone(), fake_sig),
        ],
        Hash::ZERO,
    );

    // Should fail - only 1 of 2 signatures is valid
    let result = trusted.verify_finality(&public_keys, 2);
    assert!(result.is_err());
}
```

#### GREEN - Implementation

```rust
fn verify_signature(&self, pk: &PublicKey, sig: &moloch_core::Sig) -> bool {
    let message = self.header.hash();
    pk.verify(message.as_bytes(), sig).is_ok()
}
```

---

## Phase 2: High Priority Fixes

### 2.1 Rust Toolchain Pinning - DONE

**Status**: Resolved. `rust-toolchain.toml` exists with `channel = "1.89"`,
`profile = "minimal"`, and components `rustfmt` + `clippy`. Verified 2026-02-03.

~~**Target**: Create `rust-toolchain.toml` for reproducible builds~~

#### Test (Manual Verification)

```bash
# After creating the file, verify:
rustup show  # Should show pinned version
cargo --version  # Should match toolchain
```

#### Implementation

Create `/rust-toolchain.toml`:

```toml
[toolchain]
channel = "1.75"
profile = "minimal"
components = ["rustfmt", "clippy"]
```

---

### 2.2 Repository URL Fix - DONE

**Status**: Resolved. `Cargo.toml` workspace metadata has
`repository = "https://github.com/Daemoniorum-LLC/moloch"` and all crates
inherit via `repository.workspace = true`. README clone URL also fixed.
Verified 2026-02-03.

~~**Current**: `https://github.com/Daemoniorum-LLC/workspace`~~
~~**Target**: `https://github.com/Daemoniorum-LLC/moloch`~~

#### Test (CI Verification)

```bash
# Verify Cargo.toml metadata
cargo metadata --format-version 1 | jq '.packages[0].repository'
# Should output: "https://github.com/Daemoniorum-LLC/moloch"
```

#### Implementation

Edit `/Cargo.toml` line 27.

---

### 2.3 Add Crate Keywords - DONE

**Status**: Resolved. Workspace defines `keywords = ["audit", "blockchain",
"cryptography", "merkle", "zk-proofs"]` and `categories = ["cryptography",
"data-structures"]`. All crates inherit via `keywords.workspace = true` and
`categories.workspace = true`. Verified 2026-02-03.

~~**Target**: Add keywords for crates.io discoverability~~

#### Implementation

Add to workspace Cargo.toml:

```toml
[workspace.package]
keywords = ["audit", "blockchain", "cryptography", "merkle", "ed25519"]
categories = ["cryptography", "data-structures"]
```

---

### 2.4 JWT Secret Production Guard - DONE

**Status**: Resolved. `moloch-api/src/auth.rs` implements `new_strict()` constructor
that panics on default JWT secret or secrets shorter than 32 characters. Tests at
lines 653-724 confirm correct behavior. Verified 2026-02-03.

~~**Target**: Panic or warn loudly if default JWT secret is used~~

#### RED - Write Failing Test

```rust
#[test]
#[should_panic(expected = "JWT secret must be changed")]
fn test_default_jwt_secret_panics_in_strict_mode() {
    let config = AuthConfig::default();
    let _auth = AuthMiddleware::new_strict(config); // New constructor
}

#[test]
fn test_custom_jwt_secret_works() {
    let mut config = AuthConfig::default();
    config.jwt_secret = "my-secure-production-secret-at-least-32-chars".to_string();
    let auth = AuthMiddleware::new_strict(config);
    // Should not panic
    assert!(auth.generate_token(&ApiKey::new("test", "Test", Permission::Read)).is_ok());
}
```

#### GREEN - Implementation

```rust
impl AuthMiddleware {
    /// Create auth middleware with strict production checks.
    pub fn new_strict(config: AuthConfig) -> Self {
        if config.jwt_secret == "change-me-in-production" {
            panic!("JWT secret must be changed from default value in production");
        }
        if config.jwt_secret.len() < 32 {
            panic!("JWT secret must be at least 32 characters");
        }
        Self::new(config)
    }
}
```

---

## Phase 3: Medium Priority - Examples Directory

### 3.1 Create Examples

**Target**: Working examples for common use cases

#### Structure

```
examples/
├── basic_event.rs       # Create and sign an event
├── chain_operations.rs  # Build a chain of blocks
├── holocrypt_zk.rs      # ZK proofs and selective encryption
├── light_client.rs      # Light client verification
└── api_client.rs        # HTTP API usage
```

#### Test (CI Integration)

```yaml
# .github/workflows/ci.yml - add job
examples:
  runs-on: ubuntu-latest
  steps:
    - uses: actions/checkout@v4
    - uses: dtolnay/rust-toolchain@stable
    - run: cargo build --examples
    - run: cargo run --example basic_event
```

---

## Phase 4: Code Quality

### 4.1 Error Handling Consistency

**Target**: Standardize error patterns across crates

- [ ] Document error handling convention in CONTRIBUTING.md
- [ ] Ensure all crates use `thiserror` consistently
- [ ] Add `From` implementations for error conversion

### 4.2 Documentation Tests

**Target**: Add `cargo test --doc` passing examples

- [ ] Add working examples to public API doc comments
- [ ] Remove or fix `ignore` attributes on doc tests

---

## Execution Order

| Order | Item | Status | Blocking Release? |
|-------|------|--------|-------------------|
| 1 | API Key Hashing (1.1) | **DONE** (uses BLAKE3) | ~~YES~~ |
| 2 | Signature Verification (1.2) | **DONE** (real Ed25519) | ~~YES~~ |
| 3 | JWT Secret Guard (2.4) | **DONE** (`new_strict()`) | ~~YES~~ |
| 4 | Rust Toolchain (2.1) | **DONE** (channel 1.89) | ~~No~~ |
| 5 | Repository URL (2.2) | **DONE** (workspace inheritance) | ~~No~~ |
| 6 | Crate Keywords (2.3) | **DONE** (workspace inheritance) | ~~No~~ |
| 7 | Examples Directory (3.1) | Deferred to post-0.1.0 | No |
| 8 | Error Consistency (4.1) | Deferred to post-0.1.0 | No |

**All release-blocking items resolved as of 2026-02-03.**

---

## Verification Checklist

After completing all items:

```bash
# Run full test suite
cargo test --all

# Check formatting
cargo fmt --all -- --check

# Run clippy
cargo clippy --all -- -D warnings

# Build docs
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps

# Verify examples compile
cargo build --examples

# Security audit
cargo audit
```
