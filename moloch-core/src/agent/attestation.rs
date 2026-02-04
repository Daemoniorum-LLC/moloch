//! Agent attestation types for agent identity verification.
//!
//! Agent attestation binds a cryptographic identity to a verifiable agent configuration.
//! This answers: "What exactly was running when this action was taken?"

use serde::{Deserialize, Serialize};
use std::time::Duration;

use crate::crypto::{hash, Hash, PublicKey, Sig};
use crate::error::{Error, Result};

/// Cryptographic attestation of agent state.
///
/// An attestation binds an agent's identity (public key) to its verifiable
/// configuration (code, config, prompt, tools). This enables verification that
/// an agent was in a known-good state when it took an action.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentAttestation {
    /// Agent's public key (identity).
    agent_id: PublicKey,

    /// Hash of agent's executable code or model weights.
    code_hash: Hash,

    /// Hash of agent's configuration.
    config_hash: Hash,

    /// Hash of system prompt / instructions.
    prompt_hash: Hash,

    /// Available tools at time of attestation.
    tools: Vec<ToolAttestation>,

    /// Runtime environment attestation.
    runtime: RuntimeAttestation,

    /// When this attestation was created (Unix timestamp ms).
    attested_at: i64,

    /// How long this attestation is valid (milliseconds).
    validity_period_ms: u64,

    /// Signature from attestation authority.
    authority_signature: Sig,

    /// The authority that signed this attestation.
    authority: PublicKey,
}

impl AgentAttestation {
    /// Create a new attestation builder.
    pub fn builder() -> AgentAttestationBuilder {
        AgentAttestationBuilder::new()
    }

    /// Get the agent's public key.
    pub fn agent_id(&self) -> &PublicKey {
        &self.agent_id
    }

    /// Get the code hash.
    pub fn code_hash(&self) -> &Hash {
        &self.code_hash
    }

    /// Get the config hash.
    pub fn config_hash(&self) -> &Hash {
        &self.config_hash
    }

    /// Get the prompt hash.
    pub fn prompt_hash(&self) -> &Hash {
        &self.prompt_hash
    }

    /// Get the attested tools.
    pub fn tools(&self) -> &[ToolAttestation] {
        &self.tools
    }

    /// Get the runtime attestation.
    pub fn runtime(&self) -> &RuntimeAttestation {
        &self.runtime
    }

    /// Get when the attestation was created.
    pub fn attested_at(&self) -> i64 {
        self.attested_at
    }

    /// Get the validity period.
    pub fn validity_period(&self) -> Duration {
        Duration::from_millis(self.validity_period_ms)
    }

    /// Get the authority signature.
    pub fn authority_signature(&self) -> &Sig {
        &self.authority_signature
    }

    /// Get the attestation authority.
    pub fn authority(&self) -> &PublicKey {
        &self.authority
    }

    /// Check if this attestation is valid at a given time.
    ///
    /// Returns true if:
    /// - `attested_at + validity_period > check_time`
    pub fn is_valid_at(&self, check_time: i64) -> bool {
        let expires_at = self
            .attested_at
            .saturating_add(self.validity_period_ms as i64);
        check_time < expires_at
    }

    /// Get when this attestation expires.
    pub fn expires_at(&self) -> i64 {
        self.attested_at
            .saturating_add(self.validity_period_ms as i64)
    }

    /// Compute the canonical bytes for signing/verification.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        // Include all fields except authority_signature
        let mut data = Vec::new();
        data.extend_from_slice(&self.agent_id.as_bytes());
        data.extend_from_slice(self.code_hash.as_bytes());
        data.extend_from_slice(self.config_hash.as_bytes());
        data.extend_from_slice(self.prompt_hash.as_bytes());
        for tool in &self.tools {
            data.extend_from_slice(tool.tool_id.as_bytes());
            data.extend_from_slice(tool.version.as_bytes());
            data.extend_from_slice(tool.implementation_hash.as_bytes());
        }
        data.extend_from_slice(self.runtime.runtime_id.as_bytes());
        data.extend_from_slice(self.runtime.runtime_hash.as_bytes());
        data.extend_from_slice(&self.attested_at.to_le_bytes());
        data.extend_from_slice(&self.validity_period_ms.to_le_bytes());
        data.extend_from_slice(&self.authority.as_bytes());
        data
    }

    /// Compute the hash of this attestation.
    pub fn hash(&self) -> Hash {
        hash(&self.canonical_bytes())
    }

    /// Verify the authority signature.
    pub fn verify_signature(&self) -> Result<()> {
        let bytes = self.canonical_bytes();
        self.authority
            .verify(&bytes, &self.authority_signature)
            .map_err(|_| Error::invalid_input("Attestation signature verification failed"))
    }

    /// Check if a tool is included in this attestation.
    pub fn has_tool(&self, tool_id: &str) -> bool {
        self.tools.iter().any(|t| t.tool_id == tool_id)
    }

    /// Get a specific tool attestation.
    pub fn get_tool(&self, tool_id: &str) -> Option<&ToolAttestation> {
        self.tools.iter().find(|t| t.tool_id == tool_id)
    }

    /// Validate attestation binding: the agent_id in the attestation must
    /// match the actor's public key (G-4.2, Rule 4.3.3).
    pub fn validate_binding(&self, actor_key: &PublicKey) -> Result<()> {
        if self.agent_id != *actor_key {
            return Err(Error::invalid_input(
                "attestation agent_id does not match event actor",
            ));
        }
        Ok(())
    }

    /// Validate tool consistency: the invoked tool must be listed in the
    /// agent's attestation (G-4.3, Rule 4.3.4, INV-ATTEST-3).
    pub fn validate_tool(&self, tool_id: &str) -> Result<()> {
        if !self.has_tool(tool_id) {
            return Err(Error::invalid_input(format!(
                "tool '{}' not found in agent attestation",
                tool_id
            )));
        }
        Ok(())
    }

    /// Full attestation validation at action time (Rule 4.3.2).
    ///
    /// Checks:
    /// - Signature validity
    /// - Temporal validity (not expired)
    /// - Binding to actor
    pub fn validate_for_action(&self, actor_key: &PublicKey, action_time: i64) -> Result<()> {
        // Check validity window
        if !self.is_valid_at(action_time) {
            return Err(Error::invalid_input("attestation has expired"));
        }

        // Check signature
        self.verify_signature()?;

        // Check binding
        self.validate_binding(actor_key)?;

        Ok(())
    }
}

/// Builder for AgentAttestation.
#[derive(Debug, Default)]
pub struct AgentAttestationBuilder {
    agent_id: Option<PublicKey>,
    code_hash: Option<Hash>,
    config_hash: Option<Hash>,
    prompt_hash: Option<Hash>,
    tools: Vec<ToolAttestation>,
    runtime: Option<RuntimeAttestation>,
    attested_at: Option<i64>,
    validity_period_ms: Option<u64>,
    authority: Option<PublicKey>,
}

impl AgentAttestationBuilder {
    /// Create a new builder.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the agent ID.
    pub fn agent_id(mut self, agent_id: PublicKey) -> Self {
        self.agent_id = Some(agent_id);
        self
    }

    /// Set the code hash.
    pub fn code_hash(mut self, hash: Hash) -> Self {
        self.code_hash = Some(hash);
        self
    }

    /// Set the config hash.
    pub fn config_hash(mut self, hash: Hash) -> Self {
        self.config_hash = Some(hash);
        self
    }

    /// Set the prompt hash.
    pub fn prompt_hash(mut self, hash: Hash) -> Self {
        self.prompt_hash = Some(hash);
        self
    }

    /// Add a tool attestation.
    pub fn tool(mut self, tool: ToolAttestation) -> Self {
        self.tools.push(tool);
        self
    }

    /// Set all tools.
    pub fn tools(mut self, tools: Vec<ToolAttestation>) -> Self {
        self.tools = tools;
        self
    }

    /// Set the runtime attestation.
    pub fn runtime(mut self, runtime: RuntimeAttestation) -> Self {
        self.runtime = Some(runtime);
        self
    }

    /// Set the attestation time.
    pub fn attested_at(mut self, timestamp: i64) -> Self {
        self.attested_at = Some(timestamp);
        self
    }

    /// Set the validity period.
    pub fn validity_period(mut self, duration: Duration) -> Self {
        self.validity_period_ms = Some(duration.as_millis() as u64);
        self
    }

    /// Set the authority.
    pub fn authority(mut self, authority: PublicKey) -> Self {
        self.authority = Some(authority);
        self
    }

    /// Sign and build the attestation.
    ///
    /// # Arguments
    /// * `authority_key` - The authority's secret key for signing
    ///
    /// # Errors
    /// Returns error if required fields are missing.
    pub fn sign(self, authority_key: &crate::crypto::SecretKey) -> Result<AgentAttestation> {
        let agent_id = self
            .agent_id
            .ok_or_else(|| Error::invalid_input("agent_id is required"))?;

        let code_hash = self
            .code_hash
            .ok_or_else(|| Error::invalid_input("code_hash is required"))?;

        // Validate code_hash is not empty (all zeros)
        if code_hash.as_bytes().iter().all(|&b| b == 0) {
            return Err(Error::invalid_input("code_hash cannot be empty"));
        }

        let config_hash = self
            .config_hash
            .ok_or_else(|| Error::invalid_input("config_hash is required"))?;

        let prompt_hash = self
            .prompt_hash
            .ok_or_else(|| Error::invalid_input("prompt_hash is required"))?;

        let runtime = self
            .runtime
            .ok_or_else(|| Error::invalid_input("runtime is required"))?;

        let attested_at = self
            .attested_at
            .unwrap_or_else(|| chrono::Utc::now().timestamp_millis());

        let validity_period_ms = self.validity_period_ms.unwrap_or(3600 * 1000); // 1 hour default

        if validity_period_ms == 0 {
            return Err(Error::invalid_input("validity_period must be positive"));
        }

        let authority = self.authority.unwrap_or_else(|| authority_key.public_key());

        // Create attestation without signature first
        let mut attestation = AgentAttestation {
            agent_id,
            code_hash,
            config_hash,
            prompt_hash,
            tools: self.tools,
            runtime,
            attested_at,
            validity_period_ms,
            authority_signature: Sig::empty(), // Placeholder
            authority,
        };

        // Sign the canonical bytes
        let canonical = attestation.canonical_bytes();
        attestation.authority_signature = authority_key.sign(&canonical);

        Ok(attestation)
    }
}

/// A required capability for a tool.
///
/// This is a simplified representation of capability requirements that a tool
/// needs to function. It matches the base types from `CapabilityKind`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum RequiredCapability {
    /// Read data from resources.
    Read,
    /// Write/modify data in resources.
    Write,
    /// Delete data from resources.
    Delete,
    /// Execute commands or code.
    Execute,
    /// Invoke a specific tool.
    InvokeTool { tool_id: String },
    /// Spawn child agents.
    SpawnAgent,
    /// Delegate capabilities to other agents.
    DelegateCapability,
    /// Send messages on a channel.
    SendMessage { channel: String },
    /// Receive messages from a channel.
    ReceiveMessage { channel: String },
    /// Spend currency (any amount).
    Spend { currency: String },
    /// Modify permissions.
    ModifyPermissions,
    /// View audit logs.
    ViewAuditLog,
    /// File system access.
    FileSystem,
    /// Network access.
    Network,
}

impl RequiredCapability {
    /// Create a read capability requirement.
    pub fn read() -> Self {
        Self::Read
    }

    /// Create a write capability requirement.
    pub fn write() -> Self {
        Self::Write
    }

    /// Create an execute capability requirement.
    pub fn execute() -> Self {
        Self::Execute
    }

    /// Create a tool invocation requirement.
    pub fn invoke_tool(tool_id: impl Into<String>) -> Self {
        Self::InvokeTool {
            tool_id: tool_id.into(),
        }
    }

    /// Create a file system access requirement.
    pub fn file_system() -> Self {
        Self::FileSystem
    }

    /// Create a network access requirement.
    pub fn network() -> Self {
        Self::Network
    }
}

impl std::fmt::Display for RequiredCapability {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RequiredCapability::Read => write!(f, "read"),
            RequiredCapability::Write => write!(f, "write"),
            RequiredCapability::Delete => write!(f, "delete"),
            RequiredCapability::Execute => write!(f, "execute"),
            RequiredCapability::InvokeTool { tool_id } => write!(f, "invoke_tool:{}", tool_id),
            RequiredCapability::SpawnAgent => write!(f, "spawn_agent"),
            RequiredCapability::DelegateCapability => write!(f, "delegate_capability"),
            RequiredCapability::SendMessage { channel } => write!(f, "send_message:{}", channel),
            RequiredCapability::ReceiveMessage { channel } => {
                write!(f, "receive_message:{}", channel)
            }
            RequiredCapability::Spend { currency } => write!(f, "spend:{}", currency),
            RequiredCapability::ModifyPermissions => write!(f, "modify_permissions"),
            RequiredCapability::ViewAuditLog => write!(f, "view_audit_log"),
            RequiredCapability::FileSystem => write!(f, "file_system"),
            RequiredCapability::Network => write!(f, "network"),
        }
    }
}

/// Attestation of a specific tool.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ToolAttestation {
    /// Tool identifier.
    pub tool_id: String,

    /// Tool version.
    pub version: String,

    /// Hash of tool implementation.
    pub implementation_hash: Hash,

    /// Tool's capability requirements.
    pub required_capabilities: Vec<RequiredCapability>,
}

impl ToolAttestation {
    /// Create a new tool attestation.
    pub fn new(
        tool_id: impl Into<String>,
        version: impl Into<String>,
        implementation_hash: Hash,
    ) -> Self {
        Self {
            tool_id: tool_id.into(),
            version: version.into(),
            implementation_hash,
            required_capabilities: Vec::new(),
        }
    }

    /// Add a required capability.
    pub fn with_capability(mut self, capability: RequiredCapability) -> Self {
        self.required_capabilities.push(capability);
        self
    }

    /// Add multiple required capabilities.
    pub fn with_capabilities(mut self, capabilities: Vec<RequiredCapability>) -> Self {
        self.required_capabilities = capabilities;
        self
    }

    /// Check if this tool requires a specific capability.
    pub fn requires(&self, capability: &RequiredCapability) -> bool {
        self.required_capabilities.contains(capability)
    }
}

/// Runtime environment attestation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuntimeAttestation {
    /// Runtime identifier (e.g., "claude-code-v1.2.3").
    pub runtime_id: String,

    /// Hash of runtime binary.
    pub runtime_hash: Hash,

    /// TEE attestation if available.
    pub tee_quote: Option<TeeQuote>,

    /// Platform measurements.
    pub platform_hash: Option<Hash>,
}

impl RuntimeAttestation {
    /// Create a new runtime attestation.
    pub fn new(runtime_id: impl Into<String>, runtime_hash: Hash) -> Self {
        Self {
            runtime_id: runtime_id.into(),
            runtime_hash,
            tee_quote: None,
            platform_hash: None,
        }
    }

    /// Add a TEE quote.
    pub fn with_tee(mut self, quote: TeeQuote) -> Self {
        self.tee_quote = Some(quote);
        self
    }

    /// Add a platform hash.
    pub fn with_platform_hash(mut self, hash: Hash) -> Self {
        self.platform_hash = Some(hash);
        self
    }
}

/// Trusted Execution Environment quote.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TeeQuote {
    /// TEE type.
    pub tee_type: TeeType,

    /// Raw attestation quote.
    pub quote: Vec<u8>,

    /// Measurement registers.
    pub measurements: Vec<Hash>,
}

impl TeeQuote {
    /// Create a new TEE quote.
    pub fn new(tee_type: TeeType, quote: Vec<u8>) -> Self {
        Self {
            tee_type,
            quote,
            measurements: Vec::new(),
        }
    }

    /// Add a measurement.
    pub fn with_measurement(mut self, hash: Hash) -> Self {
        self.measurements.push(hash);
        self
    }
}

/// Type of Trusted Execution Environment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TeeType {
    /// Intel SGX.
    IntelSgx,
    /// Intel TDX.
    IntelTdx,
    /// AMD SEV-SNP.
    AmdSevSnp,
    /// ARM CCA.
    ArmCca,
    /// Software-based (for testing only).
    Software,
}

/// Error types specific to attestation operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AttestationError {
    /// Attestation not found for agent.
    NotFound,
    /// Attestation has expired.
    Expired,
    /// Attestation has been revoked.
    Revoked,
    /// Attestation authority is not trusted.
    UntrustedAuthority,
    /// Signature verification failed.
    InvalidSignature,
    /// Agent ID mismatch.
    AgentMismatch,
    /// Tool not in attestation.
    ToolNotAttested(String),
}

impl std::fmt::Display for AttestationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AttestationError::NotFound => write!(f, "Attestation not found"),
            AttestationError::Expired => write!(f, "Attestation has expired"),
            AttestationError::Revoked => write!(f, "Attestation has been revoked"),
            AttestationError::UntrustedAuthority => write!(f, "Attestation authority not trusted"),
            AttestationError::InvalidSignature => write!(f, "Attestation signature invalid"),
            AttestationError::AgentMismatch => write!(f, "Agent ID does not match attestation"),
            AttestationError::ToolNotAttested(tool) => {
                write!(f, "Tool '{}' not in agent's attestation", tool)
            }
        }
    }
}

impl std::error::Error for AttestationError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{hash, SecretKey};

    fn test_runtime() -> RuntimeAttestation {
        RuntimeAttestation::new("test-runtime-v1.0.0", hash(b"runtime-binary"))
    }

    fn test_tool() -> ToolAttestation {
        ToolAttestation::new("read_file", "1.0.0", hash(b"read-file-impl"))
    }

    // === Construction Tests ===

    #[test]
    fn attestation_requires_code_hash() {
        let authority = SecretKey::generate();
        let agent = SecretKey::generate();

        let result = AgentAttestation::builder()
            .agent_id(agent.public_key())
            // Missing code_hash
            .config_hash(hash(b"config"))
            .prompt_hash(hash(b"prompt"))
            .runtime(test_runtime())
            .sign(&authority);

        assert!(result.is_err());
    }

    #[test]
    fn attestation_rejects_empty_code_hash() {
        let authority = SecretKey::generate();
        let agent = SecretKey::generate();

        let result = AgentAttestation::builder()
            .agent_id(agent.public_key())
            .code_hash(Hash::from_bytes([0u8; 32])) // Empty hash
            .config_hash(hash(b"config"))
            .prompt_hash(hash(b"prompt"))
            .runtime(test_runtime())
            .sign(&authority);

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("empty"));
    }

    #[test]
    fn attestation_requires_valid_signature() {
        let authority = SecretKey::generate();
        let agent = SecretKey::generate();

        let attestation = AgentAttestation::builder()
            .agent_id(agent.public_key())
            .code_hash(hash(b"code"))
            .config_hash(hash(b"config"))
            .prompt_hash(hash(b"prompt"))
            .runtime(test_runtime())
            .sign(&authority)
            .unwrap();

        // Verify with correct authority
        assert!(attestation.verify_signature().is_ok());

        // Tamper with attestation and verify fails
        let mut tampered = attestation.clone();
        tampered.attested_at += 1;
        assert!(tampered.verify_signature().is_err());
    }

    #[test]
    fn attestation_validity_period_must_be_positive() {
        let authority = SecretKey::generate();
        let agent = SecretKey::generate();

        let result = AgentAttestation::builder()
            .agent_id(agent.public_key())
            .code_hash(hash(b"code"))
            .config_hash(hash(b"config"))
            .prompt_hash(hash(b"prompt"))
            .runtime(test_runtime())
            .validity_period(Duration::from_secs(0)) // Zero duration
            .sign(&authority);

        assert!(result.is_err());
    }

    // === Validity Tests ===

    #[test]
    fn attestation_valid_within_validity_period() {
        let authority = SecretKey::generate();
        let agent = SecretKey::generate();
        let start = 1000000i64;

        let attestation = AgentAttestation::builder()
            .agent_id(agent.public_key())
            .code_hash(hash(b"code"))
            .config_hash(hash(b"config"))
            .prompt_hash(hash(b"prompt"))
            .runtime(test_runtime())
            .attested_at(start)
            .validity_period(Duration::from_secs(3600)) // 1 hour
            .sign(&authority)
            .unwrap();

        // Valid at start
        assert!(attestation.is_valid_at(start));

        // Valid 30 minutes later
        assert!(attestation.is_valid_at(start + 1800 * 1000));

        // Valid 59 minutes later
        assert!(attestation.is_valid_at(start + 3540 * 1000));
    }

    #[test]
    fn attestation_invalid_after_expiry() {
        let authority = SecretKey::generate();
        let agent = SecretKey::generate();
        let start = 1000000i64;

        let attestation = AgentAttestation::builder()
            .agent_id(agent.public_key())
            .code_hash(hash(b"code"))
            .config_hash(hash(b"config"))
            .prompt_hash(hash(b"prompt"))
            .runtime(test_runtime())
            .attested_at(start)
            .validity_period(Duration::from_secs(3600)) // 1 hour
            .sign(&authority)
            .unwrap();

        // Invalid at exactly expiry
        assert!(!attestation.is_valid_at(start + 3600 * 1000));

        // Invalid after expiry
        assert!(!attestation.is_valid_at(start + 3601 * 1000));
    }

    // === Tool Attestation Tests ===

    #[test]
    fn tool_attestation_includes_version() {
        let tool = ToolAttestation::new("bash", "5.1.0", hash(b"bash-impl"));
        assert_eq!(tool.version, "5.1.0");
    }

    #[test]
    fn tool_attestation_includes_implementation_hash() {
        let impl_hash = hash(b"tool-implementation");
        let tool = ToolAttestation::new("read_file", "1.0.0", impl_hash);
        assert_eq!(tool.implementation_hash, impl_hash);
    }

    #[test]
    fn tool_attestation_with_capabilities() {
        let tool = ToolAttestation::new("bash", "5.1.0", hash(b"bash-impl"))
            .with_capability(RequiredCapability::Execute)
            .with_capability(RequiredCapability::FileSystem);

        assert_eq!(tool.required_capabilities.len(), 2);
        assert!(tool.requires(&RequiredCapability::Execute));
        assert!(tool.requires(&RequiredCapability::FileSystem));
        assert!(!tool.requires(&RequiredCapability::Network));
    }

    #[test]
    fn attestation_has_tool_check() {
        let authority = SecretKey::generate();
        let agent = SecretKey::generate();

        let attestation = AgentAttestation::builder()
            .agent_id(agent.public_key())
            .code_hash(hash(b"code"))
            .config_hash(hash(b"config"))
            .prompt_hash(hash(b"prompt"))
            .runtime(test_runtime())
            .tool(test_tool())
            .tool(ToolAttestation::new("bash", "5.1", hash(b"bash")))
            .sign(&authority)
            .unwrap();

        assert!(attestation.has_tool("read_file"));
        assert!(attestation.has_tool("bash"));
        assert!(!attestation.has_tool("write_file"));
    }

    // === Runtime Attestation Tests ===

    #[test]
    fn runtime_attestation_with_tee() {
        let runtime = RuntimeAttestation::new("claude-v1", hash(b"runtime"))
            .with_tee(TeeQuote::new(TeeType::IntelSgx, vec![1, 2, 3, 4]));

        assert!(runtime.tee_quote.is_some());
        assert_eq!(runtime.tee_quote.unwrap().tee_type, TeeType::IntelSgx);
    }

    #[test]
    fn runtime_attestation_with_platform_hash() {
        let platform = hash(b"platform-measurements");
        let runtime =
            RuntimeAttestation::new("claude-v1", hash(b"runtime")).with_platform_hash(platform);

        assert_eq!(runtime.platform_hash, Some(platform));
    }

    // === Hash Tests ===

    #[test]
    fn attestation_hash_deterministic() {
        let authority = SecretKey::generate();
        let agent = SecretKey::generate();

        let attestation = AgentAttestation::builder()
            .agent_id(agent.public_key())
            .code_hash(hash(b"code"))
            .config_hash(hash(b"config"))
            .prompt_hash(hash(b"prompt"))
            .runtime(test_runtime())
            .attested_at(1000000)
            .sign(&authority)
            .unwrap();

        let h1 = attestation.hash();
        let h2 = attestation.hash();
        assert_eq!(h1, h2);
    }

    #[test]
    fn different_attestations_different_hash() {
        let authority = SecretKey::generate();
        let agent = SecretKey::generate();

        let attestation1 = AgentAttestation::builder()
            .agent_id(agent.public_key())
            .code_hash(hash(b"code1"))
            .config_hash(hash(b"config"))
            .prompt_hash(hash(b"prompt"))
            .runtime(test_runtime())
            .attested_at(1000000)
            .sign(&authority)
            .unwrap();

        let attestation2 = AgentAttestation::builder()
            .agent_id(agent.public_key())
            .code_hash(hash(b"code2")) // Different code
            .config_hash(hash(b"config"))
            .prompt_hash(hash(b"prompt"))
            .runtime(test_runtime())
            .attested_at(1000000)
            .sign(&authority)
            .unwrap();

        assert_ne!(attestation1.hash(), attestation2.hash());
    }

    // === Getter Tests ===

    #[test]
    fn attestation_getters_work() {
        let authority = SecretKey::generate();
        let agent = SecretKey::generate();
        let code = hash(b"code");
        let config = hash(b"config");
        let prompt = hash(b"prompt");
        let runtime = test_runtime();

        let attestation = AgentAttestation::builder()
            .agent_id(agent.public_key())
            .code_hash(code)
            .config_hash(config)
            .prompt_hash(prompt)
            .runtime(runtime.clone())
            .attested_at(1000000)
            .validity_period(Duration::from_secs(7200))
            .sign(&authority)
            .unwrap();

        assert_eq!(attestation.agent_id(), &agent.public_key());
        assert_eq!(attestation.code_hash(), &code);
        assert_eq!(attestation.config_hash(), &config);
        assert_eq!(attestation.prompt_hash(), &prompt);
        assert_eq!(attestation.runtime().runtime_id, runtime.runtime_id);
        assert_eq!(attestation.attested_at(), 1000000);
        assert_eq!(attestation.validity_period(), Duration::from_secs(7200));
        assert_eq!(attestation.authority(), &authority.public_key());
        assert_eq!(attestation.expires_at(), 1000000 + 7200 * 1000);
    }

    // === Attestation Binding Tests (G-4.2) ===

    #[test]
    fn validate_binding_passes_for_matching_agent() {
        let authority = SecretKey::generate();
        let agent = SecretKey::generate();

        let attestation = AgentAttestation::builder()
            .agent_id(agent.public_key())
            .code_hash(hash(b"code"))
            .config_hash(hash(b"config"))
            .prompt_hash(hash(b"prompt"))
            .runtime(test_runtime())
            .sign(&authority)
            .unwrap();

        assert!(attestation.validate_binding(&agent.public_key()).is_ok());
    }

    #[test]
    fn validate_binding_fails_for_different_agent() {
        let authority = SecretKey::generate();
        let agent = SecretKey::generate();
        let other = SecretKey::generate();

        let attestation = AgentAttestation::builder()
            .agent_id(agent.public_key())
            .code_hash(hash(b"code"))
            .config_hash(hash(b"config"))
            .prompt_hash(hash(b"prompt"))
            .runtime(test_runtime())
            .sign(&authority)
            .unwrap();

        let result = attestation.validate_binding(&other.public_key());
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("does not match"));
    }

    // === Tool Consistency Tests (G-4.3) ===

    #[test]
    fn validate_tool_passes_for_attested_tool() {
        let authority = SecretKey::generate();
        let agent = SecretKey::generate();

        let attestation = AgentAttestation::builder()
            .agent_id(agent.public_key())
            .code_hash(hash(b"code"))
            .config_hash(hash(b"config"))
            .prompt_hash(hash(b"prompt"))
            .runtime(test_runtime())
            .tool(test_tool())
            .sign(&authority)
            .unwrap();

        assert!(attestation.validate_tool("read_file").is_ok());
    }

    #[test]
    fn validate_tool_fails_for_unattested_tool() {
        let authority = SecretKey::generate();
        let agent = SecretKey::generate();

        let attestation = AgentAttestation::builder()
            .agent_id(agent.public_key())
            .code_hash(hash(b"code"))
            .config_hash(hash(b"config"))
            .prompt_hash(hash(b"prompt"))
            .runtime(test_runtime())
            .tool(test_tool())
            .sign(&authority)
            .unwrap();

        let result = attestation.validate_tool("execute_code");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("not found"));
    }

    // === Full Action Validation Tests ===

    #[test]
    fn validate_for_action_passes_when_valid() {
        let authority = SecretKey::generate();
        let agent = SecretKey::generate();

        let attestation = AgentAttestation::builder()
            .agent_id(agent.public_key())
            .code_hash(hash(b"code"))
            .config_hash(hash(b"config"))
            .prompt_hash(hash(b"prompt"))
            .runtime(test_runtime())
            .attested_at(1000)
            .validity_period(Duration::from_secs(3600))
            .sign(&authority)
            .unwrap();

        // Within validity window
        assert!(attestation
            .validate_for_action(&agent.public_key(), 2000)
            .is_ok());
    }

    #[test]
    fn validate_for_action_fails_when_expired() {
        let authority = SecretKey::generate();
        let agent = SecretKey::generate();

        let attestation = AgentAttestation::builder()
            .agent_id(agent.public_key())
            .code_hash(hash(b"code"))
            .config_hash(hash(b"config"))
            .prompt_hash(hash(b"prompt"))
            .runtime(test_runtime())
            .attested_at(1000)
            .validity_period(Duration::from_secs(1))
            .sign(&authority)
            .unwrap();

        // Past validity window (1000ms + 1000ms = 2000, checking at 3000)
        let result = attestation.validate_for_action(&agent.public_key(), 3000);
        assert!(result.is_err());
    }

    #[test]
    fn validate_for_action_fails_for_wrong_agent() {
        let authority = SecretKey::generate();
        let agent = SecretKey::generate();
        let other = SecretKey::generate();

        let attestation = AgentAttestation::builder()
            .agent_id(agent.public_key())
            .code_hash(hash(b"code"))
            .config_hash(hash(b"config"))
            .prompt_hash(hash(b"prompt"))
            .runtime(test_runtime())
            .attested_at(1000)
            .validity_period(Duration::from_secs(3600))
            .sign(&authority)
            .unwrap();

        let result = attestation.validate_for_action(&other.public_key(), 2000);
        assert!(result.is_err());
    }
}
