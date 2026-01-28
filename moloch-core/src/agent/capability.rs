//! Capability-based authorization for agents.
//!
//! The capability model defines what an agent is permitted to do. It answers:
//! "Was this action within the agent's authorized scope?"

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::Duration;

use crate::crypto::{hash, Hash, PublicKey, SecretKey, Sig};
use crate::error::{Error, Result};
use crate::event::{ResourceId, ResourceKind};

use super::principal::PrincipalId;

/// Unique capability identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CapabilityId(pub [u8; 16]);

impl CapabilityId {
    /// Generate a new random capability ID.
    pub fn generate() -> Self {
        use rand::RngCore;
        let mut bytes = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut bytes);
        Self(bytes)
    }

    /// Create from bytes.
    pub fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    /// Get the bytes.
    pub fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }

    /// Convert to hex string.
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    /// Parse from hex string.
    pub fn from_hex(s: &str) -> Result<Self> {
        let bytes = hex::decode(s).map_err(|_| Error::invalid_input("invalid hex"))?;
        if bytes.len() != 16 {
            return Err(Error::invalid_input("capability ID must be 16 bytes"));
        }
        let mut arr = [0u8; 16];
        arr.copy_from_slice(&bytes);
        Ok(Self(arr))
    }
}

impl std::fmt::Display for CapabilityId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

/// Categories of capabilities.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum CapabilityKind {
    // Data capabilities
    /// Read data from resources.
    Read,
    /// Write/modify data in resources.
    Write,
    /// Delete data from resources.
    Delete,

    // Execution capabilities
    /// Execute commands or code.
    Execute,

    // Tool capabilities
    /// Invoke a specific tool.
    InvokeTool { tool_id: String },

    // Agent capabilities
    /// Spawn child agents.
    SpawnAgent,
    /// Delegate capabilities to other agents.
    DelegateCapability,

    // Communication capabilities
    /// Send messages on a channel.
    SendMessage { channel: String },
    /// Receive messages from a channel.
    ReceiveMessage { channel: String },

    // Financial capabilities
    /// Spend currency up to a maximum amount.
    Spend { currency: String, max_amount: u64 },

    // Administrative capabilities
    /// Modify permissions.
    ModifyPermissions,
    /// View audit logs.
    ViewAuditLog,
}

impl CapabilityKind {
    /// Check if this kind matches an action kind.
    pub fn matches(&self, other: &CapabilityKind) -> bool {
        match (self, other) {
            (CapabilityKind::Read, CapabilityKind::Read) => true,
            (CapabilityKind::Write, CapabilityKind::Write) => true,
            (CapabilityKind::Delete, CapabilityKind::Delete) => true,
            (CapabilityKind::Execute, CapabilityKind::Execute) => true,
            (
                CapabilityKind::InvokeTool { tool_id: cap_tool },
                CapabilityKind::InvokeTool {
                    tool_id: action_tool,
                },
            ) => cap_tool == action_tool || cap_tool == "*",
            (CapabilityKind::SpawnAgent, CapabilityKind::SpawnAgent) => true,
            (CapabilityKind::DelegateCapability, CapabilityKind::DelegateCapability) => true,
            (
                CapabilityKind::SendMessage { channel: cap_ch },
                CapabilityKind::SendMessage { channel: action_ch },
            ) => cap_ch == action_ch || cap_ch == "*",
            (
                CapabilityKind::ReceiveMessage { channel: cap_ch },
                CapabilityKind::ReceiveMessage { channel: action_ch },
            ) => cap_ch == action_ch || cap_ch == "*",
            (
                CapabilityKind::Spend {
                    currency: cap_cur,
                    max_amount: cap_max,
                },
                CapabilityKind::Spend {
                    currency: action_cur,
                    max_amount: action_amount,
                },
            ) => cap_cur == action_cur && action_amount <= cap_max,
            (CapabilityKind::ModifyPermissions, CapabilityKind::ModifyPermissions) => true,
            (CapabilityKind::ViewAuditLog, CapabilityKind::ViewAuditLog) => true,
            _ => false,
        }
    }
}

/// Scope of resources a capability applies to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ResourceScope {
    /// Specific resource by ID.
    Specific { resource: String },

    /// Pattern match (e.g., "repo:org/*").
    Pattern { pattern: String },

    /// All resources of a kind.
    Kind { kind: ResourceKind },

    /// All resources (dangerous, requires explicit grant).
    All,
}

impl ResourceScope {
    /// Create a specific resource scope.
    pub fn specific(resource: impl Into<String>) -> Self {
        Self::Specific {
            resource: resource.into(),
        }
    }

    /// Create a pattern scope.
    pub fn pattern(pattern: impl Into<String>) -> Self {
        Self::Pattern {
            pattern: pattern.into(),
        }
    }

    /// Create a kind scope.
    pub fn kind(kind: ResourceKind) -> Self {
        Self::Kind { kind }
    }

    /// Create an all scope.
    pub fn all() -> Self {
        Self::All
    }

    /// Check if this scope matches a resource.
    pub fn matches(&self, resource: &ResourceId) -> bool {
        match self {
            ResourceScope::Specific { resource: r } => {
                // Match against the resource's string representation
                let resource_str = Self::resource_to_string(resource);
                &resource_str == r
            }
            ResourceScope::Pattern { pattern } => {
                let resource_str = Self::resource_to_string(resource);
                self.glob_match(pattern, &resource_str)
            }
            ResourceScope::Kind { kind } => resource.kind == *kind,
            ResourceScope::All => true,
        }
    }

    /// Convert a resource to a string for matching.
    fn resource_to_string(resource: &ResourceId) -> String {
        let kind_str = match resource.kind {
            ResourceKind::Repository => "repository",
            ResourceKind::Commit => "commit",
            ResourceKind::Branch => "branch",
            ResourceKind::Tag => "tag",
            ResourceKind::PullRequest => "pull_request",
            ResourceKind::Issue => "issue",
            ResourceKind::File => "file",
            ResourceKind::User => "user",
            ResourceKind::Organization => "organization",
            ResourceKind::Credential => "credential",
            ResourceKind::Config => "config",
            ResourceKind::Document => "document",
            ResourceKind::Other => "other",
        };
        format!("{}:{}", kind_str, resource.id)
    }

    /// Simple glob matching for patterns.
    fn glob_match(&self, pattern: &str, s: &str) -> bool {
        if pattern == "*" {
            return true;
        }

        // Simple glob: only supports trailing * for now
        if let Some(prefix) = pattern.strip_suffix('*') {
            s.starts_with(prefix)
        } else if let Some(suffix) = pattern.strip_prefix('*') {
            s.ends_with(suffix)
        } else {
            pattern == s
        }
    }
}

/// Rate limit configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RateLimit {
    /// Maximum requests per period.
    pub max_requests: u64,
    /// Period in milliseconds.
    pub period_ms: u64,
}

impl RateLimit {
    /// Create a new rate limit.
    pub fn new(max_requests: u64, period: Duration) -> Self {
        Self {
            max_requests,
            period_ms: period.as_millis() as u64,
        }
    }

    /// Get the period as a Duration.
    pub fn period(&self) -> Duration {
        Duration::from_millis(self.period_ms)
    }
}

/// Time of day (hours, minutes, seconds).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct TimeOfDay {
    pub hour: u8,
    pub minute: u8,
    pub second: u8,
}

impl TimeOfDay {
    /// Create a new time of day.
    pub fn new(hour: u8, minute: u8, second: u8) -> Self {
        Self {
            hour,
            minute,
            second,
        }
    }

    /// Get seconds since midnight.
    pub fn seconds_since_midnight(&self) -> u32 {
        (self.hour as u32) * 3600 + (self.minute as u32) * 60 + (self.second as u32)
    }
}

/// Day of week.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DayOfWeek {
    Monday,
    Tuesday,
    Wednesday,
    Thursday,
    Friday,
    Saturday,
    Sunday,
}

/// Time window constraint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TimeWindow {
    /// Start time of day.
    pub start: TimeOfDay,
    /// End time of day.
    pub end: TimeOfDay,
    /// Days when the window is active.
    pub days: Vec<DayOfWeek>,
    /// Timezone name (e.g., "UTC", "America/New_York").
    pub timezone: String,
}

impl TimeWindow {
    /// Create a weekday business hours window.
    pub fn weekday_business_hours() -> Self {
        Self {
            start: TimeOfDay::new(9, 0, 0),
            end: TimeOfDay::new(17, 0, 0),
            days: vec![
                DayOfWeek::Monday,
                DayOfWeek::Tuesday,
                DayOfWeek::Wednesday,
                DayOfWeek::Thursday,
                DayOfWeek::Friday,
            ],
            timezone: "UTC".to_string(),
        }
    }

    /// Check if a given timestamp is within this window.
    /// Note: This is a simplified implementation that ignores timezone.
    pub fn is_within(&self, _timestamp: i64) -> bool {
        // In a real implementation, we would:
        // 1. Convert timestamp to the specified timezone
        // 2. Check if the day of week is in our list
        // 3. Check if the time of day is between start and end
        // For now, return true as a placeholder
        true
    }
}

/// Constraints on capability usage.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CapabilityConstraints {
    /// Maximum invocations.
    pub max_uses: Option<u64>,

    /// Current usage count.
    pub current_uses: u64,

    /// Rate limit.
    pub rate_limit: Option<RateLimit>,

    /// Time windows when capability is valid.
    pub time_windows: Vec<TimeWindow>,

    /// Required approval for each use.
    pub requires_approval: bool,

    /// Approval timeout in milliseconds.
    pub approval_timeout_ms: Option<u64>,

    /// Custom constraints as key-value pairs.
    pub custom: HashMap<String, String>,
}

impl CapabilityConstraints {
    /// Create empty constraints.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set max uses.
    pub fn with_max_uses(mut self, max: u64) -> Self {
        self.max_uses = Some(max);
        self
    }

    /// Set rate limit.
    pub fn with_rate_limit(mut self, limit: RateLimit) -> Self {
        self.rate_limit = Some(limit);
        self
    }

    /// Add a time window.
    pub fn with_time_window(mut self, window: TimeWindow) -> Self {
        self.time_windows.push(window);
        self
    }

    /// Require approval for each use.
    pub fn with_requires_approval(mut self, timeout: Duration) -> Self {
        self.requires_approval = true;
        self.approval_timeout_ms = Some(timeout.as_millis() as u64);
        self
    }

    /// Add a custom constraint.
    pub fn with_custom(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.custom.insert(key.into(), value.into());
        self
    }

    /// Get approval timeout as Duration.
    pub fn approval_timeout(&self) -> Option<Duration> {
        self.approval_timeout_ms.map(Duration::from_millis)
    }

    /// Check if usage limit is reached.
    pub fn is_usage_limit_reached(&self) -> bool {
        match self.max_uses {
            Some(max) => self.current_uses >= max,
            None => false,
        }
    }

    /// Increment usage count. Returns error if limit reached.
    pub fn increment_usage(&mut self) -> Result<()> {
        if self.is_usage_limit_reached() {
            return Err(Error::invalid_input("Usage limit reached"));
        }
        self.current_uses += 1;
        Ok(())
    }
}

/// A specific permission granted to an agent.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Capability {
    /// Unique capability identifier.
    id: CapabilityId,

    /// What kind of capability this is.
    kind: CapabilityKind,

    /// Resource scope.
    scope: ResourceScope,

    /// Constraints on usage.
    constraints: CapabilityConstraints,

    /// Who granted this capability.
    grantor: PrincipalId,

    /// When this capability was granted (Unix timestamp ms).
    granted_at: i64,

    /// When this capability expires (Unix timestamp ms).
    expires_at: Option<i64>,

    /// Whether this capability can be delegated.
    delegatable: bool,

    /// Maximum delegation depth.
    max_delegation_depth: u32,

    /// Signature from grantor.
    signature: Sig,
}

impl Capability {
    /// Create a new capability builder.
    pub fn builder() -> CapabilityBuilder {
        CapabilityBuilder::new()
    }

    /// Get the capability ID.
    pub fn id(&self) -> CapabilityId {
        self.id
    }

    /// Get the capability kind.
    pub fn kind(&self) -> &CapabilityKind {
        &self.kind
    }

    /// Get the resource scope.
    pub fn scope(&self) -> &ResourceScope {
        &self.scope
    }

    /// Get the constraints.
    pub fn constraints(&self) -> &CapabilityConstraints {
        &self.constraints
    }

    /// Get mutable constraints (for usage tracking).
    pub fn constraints_mut(&mut self) -> &mut CapabilityConstraints {
        &mut self.constraints
    }

    /// Get the grantor.
    pub fn grantor(&self) -> &PrincipalId {
        &self.grantor
    }

    /// Get when this was granted.
    pub fn granted_at(&self) -> i64 {
        self.granted_at
    }

    /// Get when this expires.
    pub fn expires_at(&self) -> Option<i64> {
        self.expires_at
    }

    /// Check if this capability is delegatable.
    pub fn is_delegatable(&self) -> bool {
        self.delegatable
    }

    /// Get maximum delegation depth.
    pub fn max_delegation_depth(&self) -> u32 {
        self.max_delegation_depth
    }

    /// Get the signature.
    pub fn signature(&self) -> &Sig {
        &self.signature
    }

    /// Check if this capability is valid at a given time.
    pub fn is_valid_at(&self, timestamp: i64) -> bool {
        match self.expires_at {
            Some(exp) => timestamp < exp,
            None => true, // Never expires
        }
    }

    /// Check if this capability matches an action.
    pub fn matches(&self, action_kind: &CapabilityKind, resource: &ResourceId) -> bool {
        self.kind.matches(action_kind) && self.scope.matches(resource)
    }

    /// Compute the canonical bytes for signing/verification.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(&self.id.0);
        // Include kind, scope, constraints, etc.
        let kind_json = serde_json::to_vec(&self.kind).unwrap_or_default();
        data.extend_from_slice(&kind_json);
        let scope_json = serde_json::to_vec(&self.scope).unwrap_or_default();
        data.extend_from_slice(&scope_json);
        let grantor_json = serde_json::to_vec(&self.grantor).unwrap_or_default();
        data.extend_from_slice(&grantor_json);
        data.extend_from_slice(&self.granted_at.to_le_bytes());
        if let Some(exp) = self.expires_at {
            data.extend_from_slice(&exp.to_le_bytes());
        }
        data.push(if self.delegatable { 1 } else { 0 });
        data.extend_from_slice(&self.max_delegation_depth.to_le_bytes());
        data
    }

    /// Compute the hash of this capability.
    pub fn hash(&self) -> Hash {
        hash(&self.canonical_bytes())
    }
}

/// Builder for Capability.
#[derive(Debug, Default)]
pub struct CapabilityBuilder {
    id: Option<CapabilityId>,
    kind: Option<CapabilityKind>,
    scope: Option<ResourceScope>,
    constraints: CapabilityConstraints,
    grantor: Option<PrincipalId>,
    granted_at: Option<i64>,
    expires_at: Option<i64>,
    delegatable: bool,
    max_delegation_depth: u32,
}

impl CapabilityBuilder {
    /// Create a new builder.
    pub fn new() -> Self {
        Self {
            max_delegation_depth: 3, // Default
            ..Default::default()
        }
    }

    /// Set the capability ID.
    pub fn id(mut self, id: CapabilityId) -> Self {
        self.id = Some(id);
        self
    }

    /// Set the capability kind.
    pub fn kind(mut self, kind: CapabilityKind) -> Self {
        self.kind = Some(kind);
        self
    }

    /// Set the resource scope.
    pub fn scope(mut self, scope: ResourceScope) -> Self {
        self.scope = Some(scope);
        self
    }

    /// Set the constraints.
    pub fn constraints(mut self, constraints: CapabilityConstraints) -> Self {
        self.constraints = constraints;
        self
    }

    /// Set the grantor.
    pub fn grantor(mut self, grantor: PrincipalId) -> Self {
        self.grantor = Some(grantor);
        self
    }

    /// Set when this was granted.
    pub fn granted_at(mut self, timestamp: i64) -> Self {
        self.granted_at = Some(timestamp);
        self
    }

    /// Set when this expires.
    pub fn expires_at(mut self, timestamp: i64) -> Self {
        self.expires_at = Some(timestamp);
        self
    }

    /// Set expiry duration from now.
    pub fn expires_in(mut self, duration: Duration) -> Self {
        let now = chrono::Utc::now().timestamp_millis();
        self.expires_at = Some(now + duration.as_millis() as i64);
        self
    }

    /// Make this capability delegatable.
    pub fn delegatable(mut self, max_depth: u32) -> Self {
        self.delegatable = true;
        self.max_delegation_depth = max_depth;
        self
    }

    /// Sign and build the capability.
    pub fn sign(self, _grantor_key: &SecretKey) -> Result<Capability> {
        let id = self.id.unwrap_or_else(CapabilityId::generate);

        let kind = self
            .kind
            .ok_or_else(|| Error::invalid_input("kind is required"))?;

        let scope = self.scope.unwrap_or(ResourceScope::All);

        let grantor = self
            .grantor
            .ok_or_else(|| Error::invalid_input("grantor is required"))?;

        let granted_at = self
            .granted_at
            .unwrap_or_else(|| chrono::Utc::now().timestamp_millis());

        let mut capability = Capability {
            id,
            kind,
            scope,
            constraints: self.constraints,
            grantor,
            granted_at,
            expires_at: self.expires_at,
            delegatable: self.delegatable,
            max_delegation_depth: self.max_delegation_depth,
            signature: Sig::empty(),
        };

        // Sign the canonical bytes
        let canonical = capability.canonical_bytes();
        capability.signature = _grantor_key.sign(&canonical);

        Ok(capability)
    }
}

/// Result of a capability check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CapabilityCheck {
    /// Action is permitted.
    Permitted { capability_id: CapabilityId },
    /// Action is denied.
    Denied { reason: DenialReason },
    /// Action requires human approval.
    RequiresApproval {
        capability_id: CapabilityId,
        timeout: Duration,
    },
}

/// Reason for denying a capability.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DenialReason {
    /// No matching capability found.
    NoMatchingCapability,
    /// Capability has expired.
    Expired,
    /// Rate limit exceeded.
    RateLimitExceeded,
    /// Usage limit exceeded.
    UsageLimitExceeded,
    /// Outside allowed time window.
    OutsideTimeWindow,
    /// Resource not in scope.
    ScopeViolation,
    /// Delegation depth exceeded.
    DelegationDepthExceeded,
    /// Capability has been revoked.
    Revoked,
}

impl std::fmt::Display for DenialReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DenialReason::NoMatchingCapability => write!(f, "No matching capability found"),
            DenialReason::Expired => write!(f, "Capability has expired"),
            DenialReason::RateLimitExceeded => write!(f, "Rate limit exceeded"),
            DenialReason::UsageLimitExceeded => write!(f, "Usage limit exceeded"),
            DenialReason::OutsideTimeWindow => write!(f, "Outside allowed time window"),
            DenialReason::ScopeViolation => write!(f, "Resource not in capability scope"),
            DenialReason::DelegationDepthExceeded => write!(f, "Delegation depth exceeded"),
            DenialReason::Revoked => write!(f, "Capability has been revoked"),
        }
    }
}

/// Hash of a capability set.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CapabilitySetId(pub Hash);

/// A collection of capabilities granted to an agent.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapabilitySet {
    /// The capabilities in this set.
    capabilities: Vec<Capability>,

    /// The agent these capabilities are granted to.
    grantee: PublicKey,

    /// Parent capability set (for delegation chains).
    parent: Option<CapabilitySetId>,

    /// Current delegation depth.
    delegation_depth: u32,
}

impl CapabilitySet {
    /// Create a new empty capability set.
    pub fn new(grantee: PublicKey) -> Self {
        Self {
            capabilities: Vec::new(),
            grantee,
            parent: None,
            delegation_depth: 0,
        }
    }

    /// Create with capabilities.
    pub fn with_capabilities(grantee: PublicKey, capabilities: Vec<Capability>) -> Self {
        Self {
            capabilities,
            grantee,
            parent: None,
            delegation_depth: 0,
        }
    }

    /// Add a capability to the set.
    pub fn add(&mut self, capability: Capability) {
        self.capabilities.push(capability);
    }

    /// Get the grantee.
    pub fn grantee(&self) -> &PublicKey {
        &self.grantee
    }

    /// Get the capabilities.
    pub fn capabilities(&self) -> &[Capability] {
        &self.capabilities
    }

    /// Get the parent capability set ID.
    pub fn parent(&self) -> Option<CapabilitySetId> {
        self.parent
    }

    /// Get the delegation depth.
    pub fn delegation_depth(&self) -> u32 {
        self.delegation_depth
    }

    /// Compute the hash of this capability set.
    pub fn hash(&self) -> Hash {
        let mut data = Vec::new();
        data.extend_from_slice(&self.grantee.as_bytes());
        for cap in &self.capabilities {
            data.extend_from_slice(cap.hash().as_bytes());
        }
        hash(&data)
    }

    /// Get the capability set ID.
    pub fn id(&self) -> CapabilitySetId {
        CapabilitySetId(self.hash())
    }

    /// Check if an action is permitted.
    pub fn permits(
        &self,
        action_kind: &CapabilityKind,
        resource: &ResourceId,
        timestamp: i64,
    ) -> CapabilityCheck {
        for cap in &self.capabilities {
            // Check if capability matches the action
            if !cap.matches(action_kind, resource) {
                continue;
            }

            // Check expiry
            if !cap.is_valid_at(timestamp) {
                return CapabilityCheck::Denied {
                    reason: DenialReason::Expired,
                };
            }

            // Check usage limits
            if cap.constraints().is_usage_limit_reached() {
                return CapabilityCheck::Denied {
                    reason: DenialReason::UsageLimitExceeded,
                };
            }

            // Check time windows
            if !cap.constraints().time_windows.is_empty() {
                let in_window = cap
                    .constraints()
                    .time_windows
                    .iter()
                    .any(|w| w.is_within(timestamp));
                if !in_window {
                    return CapabilityCheck::Denied {
                        reason: DenialReason::OutsideTimeWindow,
                    };
                }
            }

            // Check if approval is required
            if cap.constraints().requires_approval {
                let timeout = cap
                    .constraints()
                    .approval_timeout()
                    .unwrap_or(Duration::from_secs(300));
                return CapabilityCheck::RequiresApproval {
                    capability_id: cap.id(),
                    timeout,
                };
            }

            // All checks passed
            return CapabilityCheck::Permitted {
                capability_id: cap.id(),
            };
        }

        // No matching capability found
        CapabilityCheck::Denied {
            reason: DenialReason::NoMatchingCapability,
        }
    }

    /// Find the capability that permits an action (if any).
    pub fn find_capability(
        &self,
        action_kind: &CapabilityKind,
        resource: &ResourceId,
    ) -> Option<&Capability> {
        self.capabilities
            .iter()
            .find(|cap| cap.matches(action_kind, resource))
    }

    /// Create a delegated subset of capabilities.
    pub fn delegate(
        &self,
        capability_ids: Vec<CapabilityId>,
        new_grantee: PublicKey,
    ) -> Result<CapabilitySet> {
        let mut delegated_caps = Vec::new();

        for id in capability_ids {
            let cap = self
                .capabilities
                .iter()
                .find(|c| c.id() == id)
                .ok_or_else(|| Error::invalid_input("Capability not found in set"))?;

            if !cap.is_delegatable() {
                return Err(Error::invalid_input("Capability is not delegatable"));
            }

            if self.delegation_depth + 1 > cap.max_delegation_depth() {
                return Err(Error::invalid_input("Delegation depth exceeded"));
            }

            delegated_caps.push(cap.clone());
        }

        Ok(CapabilitySet {
            capabilities: delegated_caps,
            grantee: new_grantee,
            parent: Some(self.id()),
            delegation_depth: self.delegation_depth + 1,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::SecretKey;

    fn test_grantor() -> PrincipalId {
        PrincipalId::user("test-user").unwrap()
    }

    fn test_resource(kind: &str, id: &str) -> ResourceId {
        let kind = match kind {
            "repo" | "repository" => ResourceKind::Repository,
            "file" => ResourceKind::File,
            "commit" => ResourceKind::Commit,
            "branch" => ResourceKind::Branch,
            _ => ResourceKind::Other,
        };
        ResourceId::new(kind, id)
    }

    // === CapabilityId Tests ===

    #[test]
    fn capability_id_generates_unique() {
        let id1 = CapabilityId::generate();
        let id2 = CapabilityId::generate();
        assert_ne!(id1, id2);
    }

    #[test]
    fn capability_id_hex_roundtrip() {
        let id = CapabilityId::generate();
        let hex = id.to_hex();
        let restored = CapabilityId::from_hex(&hex).unwrap();
        assert_eq!(id, restored);
    }

    // === ResourceScope Tests ===

    #[test]
    fn scope_specific_matches_exact_resource() {
        let scope = ResourceScope::specific("repository:org/project");
        assert!(scope.matches(&test_resource("repository", "org/project")));
        assert!(!scope.matches(&test_resource("repository", "org/other")));
    }

    #[test]
    fn scope_pattern_matches_glob() {
        let scope = ResourceScope::pattern("repository:org/*");
        assert!(scope.matches(&test_resource("repository", "org/project")));
        assert!(scope.matches(&test_resource("repository", "org/other")));
        assert!(!scope.matches(&test_resource("repository", "other/project")));
    }

    #[test]
    fn scope_kind_matches_all_of_kind() {
        let scope = ResourceScope::kind(ResourceKind::Repository);
        assert!(scope.matches(&test_resource("repository", "anything")));
        assert!(!scope.matches(&test_resource("file", "anything")));
    }

    #[test]
    fn scope_all_matches_everything() {
        let scope = ResourceScope::all();
        assert!(scope.matches(&test_resource("repository", "anything")));
        assert!(scope.matches(&test_resource("file", "anything")));
    }

    // === CapabilityConstraints Tests ===

    #[test]
    fn constraint_max_uses_enforced() {
        let mut constraints = CapabilityConstraints::new().with_max_uses(5);

        for _ in 0..5 {
            assert!(constraints.increment_usage().is_ok());
        }
        assert!(constraints.increment_usage().is_err());
    }

    #[test]
    fn constraint_unlimited_uses() {
        let mut constraints = CapabilityConstraints::new();

        for _ in 0..1000 {
            assert!(constraints.increment_usage().is_ok());
        }
    }

    // === CapabilityKind Tests ===

    #[test]
    fn capability_kind_matches_same() {
        assert!(CapabilityKind::Read.matches(&CapabilityKind::Read));
        assert!(CapabilityKind::Write.matches(&CapabilityKind::Write));
        assert!(CapabilityKind::Execute.matches(&CapabilityKind::Execute));
    }

    #[test]
    fn capability_kind_different_not_match() {
        assert!(!CapabilityKind::Read.matches(&CapabilityKind::Write));
        assert!(!CapabilityKind::Write.matches(&CapabilityKind::Execute));
    }

    #[test]
    fn capability_kind_tool_matches_specific() {
        let cap_kind = CapabilityKind::InvokeTool {
            tool_id: "bash".to_string(),
        };
        let action_kind = CapabilityKind::InvokeTool {
            tool_id: "bash".to_string(),
        };
        assert!(cap_kind.matches(&action_kind));

        let other_tool = CapabilityKind::InvokeTool {
            tool_id: "read_file".to_string(),
        };
        assert!(!cap_kind.matches(&other_tool));
    }

    #[test]
    fn capability_kind_tool_wildcard() {
        let cap_kind = CapabilityKind::InvokeTool {
            tool_id: "*".to_string(),
        };
        let action_kind = CapabilityKind::InvokeTool {
            tool_id: "bash".to_string(),
        };
        assert!(cap_kind.matches(&action_kind));
    }

    #[test]
    fn capability_kind_spend_checks_amount() {
        let cap_kind = CapabilityKind::Spend {
            currency: "USD".to_string(),
            max_amount: 100,
        };
        let action_ok = CapabilityKind::Spend {
            currency: "USD".to_string(),
            max_amount: 50,
        };
        let action_too_much = CapabilityKind::Spend {
            currency: "USD".to_string(),
            max_amount: 150,
        };

        assert!(cap_kind.matches(&action_ok));
        assert!(!cap_kind.matches(&action_too_much));
    }

    // === Capability Tests ===

    #[test]
    fn capability_created_successfully() {
        let grantor_key = SecretKey::generate();
        let cap = Capability::builder()
            .kind(CapabilityKind::Read)
            .scope(ResourceScope::all())
            .grantor(test_grantor())
            .sign(&grantor_key)
            .unwrap();

        assert_eq!(cap.kind(), &CapabilityKind::Read);
        assert_eq!(cap.scope(), &ResourceScope::all());
    }

    #[test]
    fn capability_expiry_checked() {
        let grantor_key = SecretKey::generate();
        let now = chrono::Utc::now().timestamp_millis();

        let cap = Capability::builder()
            .kind(CapabilityKind::Read)
            .scope(ResourceScope::all())
            .grantor(test_grantor())
            .granted_at(now)
            .expires_at(now + 3600 * 1000)
            .sign(&grantor_key)
            .unwrap();

        assert!(cap.is_valid_at(now));
        assert!(cap.is_valid_at(now + 1800 * 1000));
        assert!(!cap.is_valid_at(now + 3600 * 1000));
    }

    #[test]
    fn capability_matches_action() {
        let grantor_key = SecretKey::generate();
        let cap = Capability::builder()
            .kind(CapabilityKind::Read)
            .scope(ResourceScope::kind(ResourceKind::Repository))
            .grantor(test_grantor())
            .sign(&grantor_key)
            .unwrap();

        assert!(cap.matches(&CapabilityKind::Read, &test_resource("repository", "test")));
        assert!(!cap.matches(&CapabilityKind::Write, &test_resource("repository", "test")));
        assert!(!cap.matches(&CapabilityKind::Read, &test_resource("file", "test")));
    }

    // === CapabilitySet Tests ===

    #[test]
    fn capability_set_permits_matching() {
        let grantor_key = SecretKey::generate();
        let agent_key = SecretKey::generate();

        let cap = Capability::builder()
            .kind(CapabilityKind::Read)
            .scope(ResourceScope::all())
            .grantor(test_grantor())
            .sign(&grantor_key)
            .unwrap();

        let set = CapabilitySet::with_capabilities(agent_key.public_key(), vec![cap]);
        let now = chrono::Utc::now().timestamp_millis();

        let check = set.permits(
            &CapabilityKind::Read,
            &test_resource("repository", "test"),
            now,
        );

        assert!(matches!(check, CapabilityCheck::Permitted { .. }));
    }

    #[test]
    fn capability_set_denies_no_matching() {
        let grantor_key = SecretKey::generate();
        let agent_key = SecretKey::generate();

        let cap = Capability::builder()
            .kind(CapabilityKind::Read)
            .scope(ResourceScope::all())
            .grantor(test_grantor())
            .sign(&grantor_key)
            .unwrap();

        let set = CapabilitySet::with_capabilities(agent_key.public_key(), vec![cap]);
        let now = chrono::Utc::now().timestamp_millis();

        let check = set.permits(
            &CapabilityKind::Write,
            &test_resource("repository", "test"),
            now,
        );

        assert!(matches!(
            check,
            CapabilityCheck::Denied {
                reason: DenialReason::NoMatchingCapability
            }
        ));
    }

    #[test]
    fn capability_set_requires_approval() {
        let grantor_key = SecretKey::generate();
        let agent_key = SecretKey::generate();

        let cap = Capability::builder()
            .kind(CapabilityKind::Write)
            .scope(ResourceScope::all())
            .grantor(test_grantor())
            .constraints(
                CapabilityConstraints::new().with_requires_approval(Duration::from_secs(300)),
            )
            .sign(&grantor_key)
            .unwrap();

        let set = CapabilitySet::with_capabilities(agent_key.public_key(), vec![cap]);
        let now = chrono::Utc::now().timestamp_millis();

        let check = set.permits(
            &CapabilityKind::Write,
            &test_resource("repository", "test"),
            now,
        );

        assert!(matches!(check, CapabilityCheck::RequiresApproval { .. }));
    }

    #[test]
    fn capability_set_denies_expired() {
        let grantor_key = SecretKey::generate();
        let agent_key = SecretKey::generate();
        let now = chrono::Utc::now().timestamp_millis();

        let cap = Capability::builder()
            .kind(CapabilityKind::Read)
            .scope(ResourceScope::all())
            .grantor(test_grantor())
            .granted_at(now - 7200 * 1000)
            .expires_at(now - 3600 * 1000) // Expired 1 hour ago
            .sign(&grantor_key)
            .unwrap();

        let set = CapabilitySet::with_capabilities(agent_key.public_key(), vec![cap]);

        let check = set.permits(
            &CapabilityKind::Read,
            &test_resource("repository", "test"),
            now,
        );

        assert!(matches!(
            check,
            CapabilityCheck::Denied {
                reason: DenialReason::Expired
            }
        ));
    }

    #[test]
    fn capability_set_delegation() {
        let grantor_key = SecretKey::generate();
        let agent1_key = SecretKey::generate();
        let agent2_key = SecretKey::generate();

        let cap = Capability::builder()
            .kind(CapabilityKind::Read)
            .scope(ResourceScope::all())
            .grantor(test_grantor())
            .delegatable(3)
            .sign(&grantor_key)
            .unwrap();

        let cap_id = cap.id();
        let set = CapabilitySet::with_capabilities(agent1_key.public_key(), vec![cap]);

        let delegated = set.delegate(vec![cap_id], agent2_key.public_key()).unwrap();

        assert_eq!(delegated.grantee(), &agent2_key.public_key());
        assert_eq!(delegated.delegation_depth(), 1);
        assert_eq!(delegated.capabilities().len(), 1);
    }

    #[test]
    fn capability_set_delegation_depth_enforced() {
        let grantor_key = SecretKey::generate();
        let agent1_key = SecretKey::generate();
        let agent2_key = SecretKey::generate();
        let agent3_key = SecretKey::generate();

        // Capability with max delegation depth of 1
        let cap = Capability::builder()
            .kind(CapabilityKind::Read)
            .scope(ResourceScope::all())
            .grantor(test_grantor())
            .delegatable(1)
            .sign(&grantor_key)
            .unwrap();

        let cap_id = cap.id();
        let set1 = CapabilitySet::with_capabilities(agent1_key.public_key(), vec![cap]);

        // First delegation succeeds
        let set2 = set1.delegate(vec![cap_id], agent2_key.public_key()).unwrap();

        // Second delegation should fail
        let result = set2.delegate(vec![cap_id], agent3_key.public_key());
        assert!(result.is_err());
    }

    #[test]
    fn capability_set_non_delegatable_rejected() {
        let grantor_key = SecretKey::generate();
        let agent1_key = SecretKey::generate();
        let agent2_key = SecretKey::generate();

        // Non-delegatable capability
        let cap = Capability::builder()
            .kind(CapabilityKind::Read)
            .scope(ResourceScope::all())
            .grantor(test_grantor())
            .sign(&grantor_key)
            .unwrap();

        let cap_id = cap.id();
        let set = CapabilitySet::with_capabilities(agent1_key.public_key(), vec![cap]);

        let result = set.delegate(vec![cap_id], agent2_key.public_key());
        assert!(result.is_err());
    }

    #[test]
    fn capability_set_hash_deterministic() {
        let grantor_key = SecretKey::generate();
        let agent_key = SecretKey::generate();

        let cap = Capability::builder()
            .id(CapabilityId::from_bytes([1u8; 16]))
            .kind(CapabilityKind::Read)
            .scope(ResourceScope::all())
            .grantor(test_grantor())
            .granted_at(1000000)
            .sign(&grantor_key)
            .unwrap();

        let set = CapabilitySet::with_capabilities(agent_key.public_key(), vec![cap]);

        let h1 = set.hash();
        let h2 = set.hash();
        assert_eq!(h1, h2);
    }
}
