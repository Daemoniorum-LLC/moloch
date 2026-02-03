//! Session types for agent accountability.
//!
//! A session is a bounded context for agent operations. Every agent action
//! occurs within a session, which defines:
//!
//! - The principal who initiated the session
//! - Maximum duration and depth limits
//! - Session-level capability constraints

use serde::{Deserialize, Serialize};
use std::fmt;
use std::time::Duration;

use crate::crypto::{hash, Hash};
use crate::error::{Error, Result};

use super::principal::PrincipalId;

/// Unique session identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SessionId(pub [u8; 16]);

impl SessionId {
    /// Create a new random session ID.
    pub fn random() -> Self {
        use rand::Rng;
        let mut bytes = [0u8; 16];
        rand::thread_rng().fill(&mut bytes);
        Self(bytes)
    }

    /// Create from bytes.
    pub fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    /// Get the raw bytes.
    pub fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }

    /// Convert to hex string.
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    /// Parse from hex string.
    pub fn from_hex(s: &str) -> Result<Self> {
        let bytes = hex::decode(s).map_err(|e| Error::invalid_input(e.to_string()))?;
        if bytes.len() != 16 {
            return Err(Error::invalid_input(format!(
                "SessionId must be 16 bytes, got {}",
                bytes.len()
            )));
        }
        let mut arr = [0u8; 16];
        arr.copy_from_slice(&bytes);
        Ok(Self(arr))
    }
}

impl fmt::Display for SessionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", &self.to_hex()[..8]) // Short display
    }
}

/// A bounded context for agent operations.
///
/// Sessions provide:
/// - Traceability: All events link to a session
/// - Time bounds: Sessions expire after max_duration
/// - Depth limits: Prevents runaway agent spawning
/// - Scope: Session-level capability constraints
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    /// Unique session identifier.
    id: SessionId,

    /// Human principal who initiated the session.
    principal: PrincipalId,

    /// When the session started (Unix timestamp ms).
    started_at: i64,

    /// When the session ended (None if active).
    ended_at: Option<i64>,

    /// Maximum session duration.
    max_duration: Duration,

    /// Maximum causal depth permitted.
    max_depth: u32,

    /// Human-readable session purpose.
    purpose: String,

    /// Total events in this session.
    event_count: u64,

    /// Total actions taken in this session.
    action_count: u64,
}

impl Session {
    /// Default maximum depth for causal chains.
    pub const DEFAULT_MAX_DEPTH: u32 = 10;

    /// Default maximum session duration (1 hour).
    pub const DEFAULT_MAX_DURATION: Duration = Duration::from_secs(3600);

    /// Create a new session builder.
    pub fn builder() -> SessionBuilder {
        SessionBuilder::new()
    }

    /// Get the session ID.
    pub fn id(&self) -> SessionId {
        self.id
    }

    /// Get the principal who initiated this session.
    pub fn principal(&self) -> &PrincipalId {
        &self.principal
    }

    /// Get when the session started.
    pub fn started_at(&self) -> i64 {
        self.started_at
    }

    /// Get when the session ended, if it has.
    pub fn ended_at(&self) -> Option<i64> {
        self.ended_at
    }

    /// Get the maximum allowed duration.
    pub fn max_duration(&self) -> Duration {
        self.max_duration
    }

    /// Get the maximum allowed causal depth.
    pub fn max_depth(&self) -> u32 {
        self.max_depth
    }

    /// Get the session purpose.
    pub fn purpose(&self) -> &str {
        &self.purpose
    }

    /// Check if the session is still active (not ended).
    pub fn is_active(&self) -> bool {
        self.ended_at.is_none()
    }

    /// Check if the session has expired based on max_duration.
    pub fn is_expired(&self, current_time: i64) -> bool {
        let elapsed_ms = current_time.saturating_sub(self.started_at);
        let max_ms = self.max_duration.as_millis() as i64;
        elapsed_ms > max_ms
    }

    /// Get remaining duration before expiry.
    ///
    /// Returns None if already expired.
    pub fn remaining_duration(&self, current_time: i64) -> Option<Duration> {
        let elapsed_ms = current_time.saturating_sub(self.started_at);
        let max_ms = self.max_duration.as_millis() as i64;
        if elapsed_ms >= max_ms {
            None
        } else {
            Some(Duration::from_millis((max_ms - elapsed_ms) as u64))
        }
    }

    /// End the session.
    ///
    /// # Errors
    /// Returns error if session is already ended.
    pub fn end(&mut self, current_time: i64, reason: SessionEndReason) -> Result<SessionSummary> {
        if self.ended_at.is_some() {
            return Err(Error::invalid_input("Session already ended"));
        }

        self.ended_at = Some(current_time);

        Ok(SessionSummary {
            session_id: self.id,
            reason,
            duration: Duration::from_millis((current_time - self.started_at) as u64),
            event_count: self.event_count,
            action_count: self.action_count,
        })
    }

    /// Record an event in this session.
    pub fn record_event(&mut self) {
        self.event_count += 1;
    }

    /// Record an action in this session.
    pub fn record_action(&mut self) {
        self.action_count += 1;
    }

    /// Compute a unique hash for this session.
    pub fn hash(&self) -> Hash {
        let mut data = Vec::new();
        data.extend_from_slice(&self.id.0);
        data.extend_from_slice(self.principal.id().as_bytes());
        data.extend_from_slice(&self.started_at.to_le_bytes());
        hash(&data)
    }
}

/// Builder for creating sessions.
#[derive(Debug, Default)]
pub struct SessionBuilder {
    id: Option<SessionId>,
    principal: Option<PrincipalId>,
    started_at: Option<i64>,
    max_duration: Option<Duration>,
    max_depth: Option<u32>,
    purpose: Option<String>,
}

impl SessionBuilder {
    /// Create a new session builder.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the session ID (random if not specified).
    pub fn id(mut self, id: SessionId) -> Self {
        self.id = Some(id);
        self
    }

    /// Set the principal who initiated the session.
    pub fn principal(mut self, principal: PrincipalId) -> Self {
        self.principal = Some(principal);
        self
    }

    /// Set the start time (current time if not specified).
    pub fn started_at(mut self, timestamp: i64) -> Self {
        self.started_at = Some(timestamp);
        self
    }

    /// Set the maximum duration.
    pub fn max_duration(mut self, duration: Duration) -> Self {
        self.max_duration = Some(duration);
        self
    }

    /// Set the maximum causal depth.
    pub fn max_depth(mut self, depth: u32) -> Self {
        self.max_depth = Some(depth);
        self
    }

    /// Set the session purpose.
    pub fn purpose(mut self, purpose: impl Into<String>) -> Self {
        self.purpose = Some(purpose.into());
        self
    }

    /// Build the session.
    ///
    /// # Errors
    /// Returns error if principal is not set.
    pub fn build(self) -> Result<Session> {
        let principal = self
            .principal
            .ok_or_else(|| Error::invalid_input("Session requires a principal"))?;

        let started_at = self
            .started_at
            .unwrap_or_else(|| chrono::Utc::now().timestamp_millis());

        Ok(Session {
            id: self.id.unwrap_or_else(SessionId::random),
            principal,
            started_at,
            ended_at: None,
            max_duration: self.max_duration.unwrap_or(Session::DEFAULT_MAX_DURATION),
            max_depth: self.max_depth.unwrap_or(Session::DEFAULT_MAX_DEPTH),
            purpose: self.purpose.unwrap_or_default(),
            event_count: 0,
            action_count: 0,
        })
    }
}

/// Reason for session ending.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "reason")]
pub enum SessionEndReason {
    /// Session completed normally.
    Completed,

    /// Session timed out.
    Timeout,

    /// User terminated the session.
    UserTerminated,

    /// Session terminated due to error.
    ErrorTerminated {
        /// Error description.
        error: String,
    },

    /// Session terminated by emergency action.
    EmergencyTerminated {
        /// ID of the emergency event.
        emergency_id: String,
    },
}

/// Summary of a completed session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionSummary {
    /// Session ID.
    pub session_id: SessionId,

    /// Reason the session ended.
    pub reason: SessionEndReason,

    /// Total session duration.
    pub duration: Duration,

    /// Total events recorded.
    pub event_count: u64,

    /// Total actions taken.
    pub action_count: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_principal() -> PrincipalId {
        PrincipalId::user("alice").unwrap()
    }

    fn now_ms() -> i64 {
        chrono::Utc::now().timestamp_millis()
    }

    // === SessionId Tests ===

    #[test]
    fn session_id_generates_unique() {
        let id1 = SessionId::random();
        let id2 = SessionId::random();
        assert_ne!(id1, id2);
    }

    #[test]
    fn session_id_hex_roundtrip() {
        let id = SessionId::random();
        let hex = id.to_hex();
        let parsed = SessionId::from_hex(&hex).unwrap();
        assert_eq!(id, parsed);
    }

    #[test]
    fn session_id_from_bytes() {
        let bytes = [1u8; 16];
        let id = SessionId::from_bytes(bytes);
        assert_eq!(id.as_bytes(), &bytes);
    }

    // === Session Lifecycle Tests ===

    #[test]
    fn session_requires_principal() {
        let result = Session::builder().build();
        assert!(result.is_err());
    }

    #[test]
    fn session_created_with_defaults() {
        let session = Session::builder()
            .principal(test_principal())
            .build()
            .unwrap();

        assert!(session.is_active());
        assert_eq!(session.max_depth(), Session::DEFAULT_MAX_DEPTH);
        assert_eq!(session.max_duration(), Session::DEFAULT_MAX_DURATION);
    }

    #[test]
    fn session_tracks_started_at() {
        let before = now_ms();
        let session = Session::builder()
            .principal(test_principal())
            .build()
            .unwrap();
        let after = now_ms();

        assert!(session.started_at() >= before);
        assert!(session.started_at() <= after);
    }

    #[test]
    fn session_ended_at_none_when_active() {
        let session = Session::builder()
            .principal(test_principal())
            .build()
            .unwrap();

        assert!(session.ended_at().is_none());
        assert!(session.is_active());
    }

    #[test]
    fn session_end_sets_ended_at() {
        let mut session = Session::builder()
            .principal(test_principal())
            .build()
            .unwrap();

        let end_time = now_ms() + 1000;
        let summary = session.end(end_time, SessionEndReason::Completed).unwrap();

        assert!(!session.is_active());
        assert_eq!(session.ended_at(), Some(end_time));
        assert!(matches!(summary.reason, SessionEndReason::Completed));
    }

    #[test]
    fn session_cannot_end_twice() {
        let mut session = Session::builder()
            .principal(test_principal())
            .build()
            .unwrap();

        session.end(now_ms(), SessionEndReason::Completed).unwrap();
        let result = session.end(now_ms(), SessionEndReason::Completed);

        assert!(result.is_err());
    }

    // === Duration Tests ===

    #[test]
    fn session_is_expired_after_max_duration() {
        let start = now_ms();
        let session = Session::builder()
            .principal(test_principal())
            .started_at(start)
            .max_duration(Duration::from_secs(60))
            .build()
            .unwrap();

        // Not expired immediately
        assert!(!session.is_expired(start));

        // Not expired at 59 seconds
        assert!(!session.is_expired(start + 59_000));

        // Expired at 61 seconds
        assert!(session.is_expired(start + 61_000));
    }

    #[test]
    fn session_remaining_duration_decreases() {
        let start = now_ms();
        let session = Session::builder()
            .principal(test_principal())
            .started_at(start)
            .max_duration(Duration::from_secs(60))
            .build()
            .unwrap();

        let remaining1 = session.remaining_duration(start).unwrap();
        let remaining2 = session.remaining_duration(start + 10_000).unwrap();

        assert!(remaining2 < remaining1);
    }

    #[test]
    fn session_remaining_duration_none_when_expired() {
        let start = now_ms();
        let session = Session::builder()
            .principal(test_principal())
            .started_at(start)
            .max_duration(Duration::from_secs(60))
            .build()
            .unwrap();

        let remaining = session.remaining_duration(start + 70_000);
        assert!(remaining.is_none());
    }

    // === Depth and Purpose Tests ===

    #[test]
    fn session_max_depth_configurable() {
        let session = Session::builder()
            .principal(test_principal())
            .max_depth(5)
            .build()
            .unwrap();

        assert_eq!(session.max_depth(), 5);
    }

    #[test]
    fn session_purpose_recorded() {
        let session = Session::builder()
            .principal(test_principal())
            .purpose("Code review task")
            .build()
            .unwrap();

        assert_eq!(session.purpose(), "Code review task");
    }

    // === Event Counting Tests ===

    #[test]
    fn session_counts_events() {
        let mut session = Session::builder()
            .principal(test_principal())
            .build()
            .unwrap();

        session.record_event();
        session.record_event();
        session.record_action();

        let summary = session.end(now_ms(), SessionEndReason::Completed).unwrap();
        assert_eq!(summary.event_count, 2);
        assert_eq!(summary.action_count, 1);
    }

    // === Hash Tests ===

    #[test]
    fn same_session_same_hash() {
        let id = SessionId::random();
        let principal = test_principal();
        let started = now_ms();

        let s1 = Session::builder()
            .id(id)
            .principal(principal.clone())
            .started_at(started)
            .build()
            .unwrap();

        let s2 = Session::builder()
            .id(id)
            .principal(principal)
            .started_at(started)
            .build()
            .unwrap();

        assert_eq!(s1.hash(), s2.hash());
    }

    #[test]
    fn different_sessions_different_hash() {
        let s1 = Session::builder()
            .principal(test_principal())
            .build()
            .unwrap();

        let s2 = Session::builder()
            .principal(test_principal())
            .build()
            .unwrap();

        // Different IDs (random) means different hashes
        assert_ne!(s1.hash(), s2.hash());
    }
}
