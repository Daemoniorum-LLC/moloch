//! Millisecond-precision UTC timestamp type.
//!
//! Provides a type-safe wrapper around raw `i64` millisecond timestamps,
//! preventing confusion between seconds and milliseconds, and ensuring
//! timestamp values are always in the correct unit.
//!
//! See Section 3.2.2 of the Agent Accountability specification.

use serde::{Deserialize, Serialize};
use std::time::Duration;

/// Millisecond-precision UTC timestamp.
///
/// Wraps a raw `i64` representing milliseconds since the Unix epoch.
/// All agent module timestamps should use this type for consistency
/// and type safety.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Timestamp(i64);

impl Timestamp {
    /// Create a timestamp representing the current time.
    pub fn now() -> Self {
        Self(chrono::Utc::now().timestamp_millis())
    }

    /// Create a timestamp from raw milliseconds since Unix epoch.
    pub fn from_millis(ms: i64) -> Self {
        Self(ms)
    }

    /// Get the raw milliseconds since Unix epoch.
    pub fn as_millis(&self) -> i64 {
        self.0
    }

    /// Get the elapsed duration since this timestamp.
    ///
    /// Returns `Duration::ZERO` if the timestamp is in the future.
    pub fn elapsed(&self) -> Duration {
        let now = chrono::Utc::now().timestamp_millis();
        Duration::from_millis((now - self.0).max(0) as u64)
    }

    /// Check if this timestamp is expired given a time-to-live duration.
    ///
    /// Returns `true` if `elapsed() > ttl`.
    pub fn is_expired(&self, ttl: Duration) -> bool {
        self.elapsed() > ttl
    }
}

impl std::fmt::Display for Timestamp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}ms", self.0)
    }
}

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
        std::thread::sleep(Duration::from_millis(2));
        let t2 = Timestamp::now();
        assert!(t2 > t1);
    }

    #[test]
    fn timestamp_elapsed_since() {
        let t1 = Timestamp::now();
        std::thread::sleep(Duration::from_millis(10));
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
        let ts = Timestamp::from_millis(chrono::Utc::now().timestamp_millis() - 5000);
        let ttl = Duration::from_secs(3);
        assert!(ts.is_expired(ttl));
    }

    #[test]
    fn timestamp_is_not_expired_within_duration() {
        let ts = Timestamp::now();
        let ttl = Duration::from_secs(3600);
        assert!(!ts.is_expired(ttl));
    }
}
