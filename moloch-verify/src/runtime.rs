//! Runtime invariant checking and monitoring.

use std::collections::VecDeque;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use crate::invariants::InvariantViolation;
use crate::ChainState;

/// Result of a runtime check.
#[derive(Debug, Clone)]
pub enum CheckResult {
    /// Check passed.
    Passed,
    /// Check failed.
    Failed(InvariantViolation),
    /// Check was skipped.
    Skipped,
}

impl CheckResult {
    /// Check if passed.
    pub fn is_ok(&self) -> bool {
        matches!(self, Self::Passed)
    }
}

/// A runtime check that can be executed.
pub trait RuntimeCheck<S> {
    /// Name of the check.
    fn name(&self) -> &str;

    /// Execute the check.
    fn execute(&self, state: &S) -> CheckResult;

    /// Priority (higher = more important).
    fn priority(&self) -> u8 {
        50
    }
}

/// Pre-condition check.
pub struct PreCondition<F> {
    name: String,
    check: F,
}

impl<F> PreCondition<F> {
    /// Create a new pre-condition.
    pub fn new(name: impl Into<String>, check: F) -> Self {
        Self {
            name: name.into(),
            check,
        }
    }
}

impl<S, F> RuntimeCheck<S> for PreCondition<F>
where
    F: Fn(&S) -> bool,
{
    fn name(&self) -> &str {
        &self.name
    }

    fn execute(&self, state: &S) -> CheckResult {
        if (self.check)(state) {
            CheckResult::Passed
        } else {
            CheckResult::Failed(InvariantViolation::new(
                &self.name,
                "pre-condition not satisfied",
            ))
        }
    }

    fn priority(&self) -> u8 {
        100 // Pre-conditions are high priority
    }
}

/// Post-condition check.
pub struct PostCondition<F> {
    name: String,
    check: F,
}

impl<F> PostCondition<F> {
    /// Create a new post-condition.
    pub fn new(name: impl Into<String>, check: F) -> Self {
        Self {
            name: name.into(),
            check,
        }
    }
}

impl<S, F> RuntimeCheck<S> for PostCondition<F>
where
    F: Fn(&S) -> bool,
{
    fn name(&self) -> &str {
        &self.name
    }

    fn execute(&self, state: &S) -> CheckResult {
        if (self.check)(state) {
            CheckResult::Passed
        } else {
            CheckResult::Failed(InvariantViolation::new(
                &self.name,
                "post-condition not satisfied",
            ))
        }
    }

    fn priority(&self) -> u8 {
        90 // Post-conditions are high priority
    }
}

/// Record of a check execution.
#[derive(Debug, Clone)]
pub struct CheckRecord {
    /// Check name.
    pub name: String,
    /// Result.
    pub result: CheckResult,
    /// Execution time.
    pub duration: Duration,
    /// Timestamp.
    pub timestamp: Instant,
}

/// Monitor configuration.
#[derive(Debug, Clone)]
pub struct MonitorConfig {
    /// Maximum history entries.
    pub max_history: usize,
    /// Check interval.
    pub check_interval: Duration,
    /// Stop on first failure.
    pub stop_on_failure: bool,
}

impl Default for MonitorConfig {
    fn default() -> Self {
        Self {
            max_history: 1000,
            check_interval: Duration::from_secs(1),
            stop_on_failure: false,
        }
    }
}

/// Runtime monitor for continuous verification.
pub struct RuntimeMonitor<S> {
    /// Configuration.
    config: MonitorConfig,
    /// Registered checks.
    checks: Vec<Box<dyn RuntimeCheck<S> + Send + Sync>>,
    /// Execution history.
    history: Arc<RwLock<VecDeque<CheckRecord>>>,
    /// Failure count.
    failures: Arc<RwLock<usize>>,
}

impl<S: ChainState> RuntimeMonitor<S> {
    /// Create a new monitor with default config.
    pub fn new() -> Self {
        Self::with_config(MonitorConfig::default())
    }

    /// Create with custom configuration.
    pub fn with_config(config: MonitorConfig) -> Self {
        Self {
            config,
            checks: Vec::new(),
            history: Arc::new(RwLock::new(VecDeque::new())),
            failures: Arc::new(RwLock::new(0)),
        }
    }

    /// Add a check to the monitor.
    pub fn add_check(&mut self, check: impl RuntimeCheck<S> + Send + Sync + 'static) {
        self.checks.push(Box::new(check));
        // Sort by priority (higher first)
        self.checks.sort_by_key(|b| std::cmp::Reverse(b.priority()));
    }

    /// Run all checks against a state.
    pub fn check_state(&self, state: &S) -> Vec<CheckRecord> {
        let mut records = Vec::new();

        for check in &self.checks {
            let start = Instant::now();
            let result = check.execute(state);
            let duration = start.elapsed();

            let record = CheckRecord {
                name: check.name().to_string(),
                result: result.clone(),
                duration,
                timestamp: start,
            };

            // Update failure count
            if matches!(result, CheckResult::Failed(_)) {
                *self.failures.write().unwrap() += 1;
            }

            records.push(record.clone());

            // Add to history
            let mut history = self.history.write().unwrap();
            history.push_back(record);
            while history.len() > self.config.max_history {
                history.pop_front();
            }

            // Stop on failure if configured
            if self.config.stop_on_failure && matches!(result, CheckResult::Failed(_)) {
                break;
            }
        }

        records
    }

    /// Get total failure count.
    pub fn failure_count(&self) -> usize {
        *self.failures.read().unwrap()
    }

    /// Get recent history.
    pub fn recent_history(&self, count: usize) -> Vec<CheckRecord> {
        self.history
            .read()
            .unwrap()
            .iter()
            .rev()
            .take(count)
            .cloned()
            .collect()
    }

    /// Clear history.
    pub fn clear_history(&self) {
        self.history.write().unwrap().clear();
        *self.failures.write().unwrap() = 0;
    }
}

impl<S: ChainState> Default for RuntimeMonitor<S> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use moloch_core::{BlockHash, Hash};

    struct MockState {
        height: u64,
        events: u64,
    }

    impl ChainState for MockState {
        fn height(&self) -> u64 {
            self.height
        }

        fn block_hash(&self) -> BlockHash {
            BlockHash(Hash::ZERO)
        }

        fn mmr_root(&self) -> Hash {
            Hash::ZERO
        }

        fn event_count(&self) -> u64 {
            self.events
        }
    }

    #[test]
    fn test_precondition() {
        let check = PreCondition::new("height_positive", |s: &MockState| s.height > 0);

        let good_state = MockState {
            height: 10,
            events: 100,
        };
        assert!(check.execute(&good_state).is_ok());

        let bad_state = MockState {
            height: 0,
            events: 0,
        };
        assert!(!check.execute(&bad_state).is_ok());
    }

    #[test]
    fn test_runtime_monitor() {
        let mut monitor = RuntimeMonitor::<MockState>::new();

        monitor.add_check(PreCondition::new("height_check", |s: &MockState| {
            s.height > 0
        }));
        monitor.add_check(PostCondition::new("events_check", |s: &MockState| {
            s.events > 0
        }));

        let state = MockState {
            height: 10,
            events: 100,
        };
        let records = monitor.check_state(&state);

        assert_eq!(records.len(), 2);
        assert!(records.iter().all(|r| r.result.is_ok()));
        assert_eq!(monitor.failure_count(), 0);
    }

    #[test]
    fn test_monitor_failure_tracking() {
        let mut monitor = RuntimeMonitor::<MockState>::new();
        monitor.add_check(PreCondition::new("must_fail", |_: &MockState| false));

        let state = MockState {
            height: 10,
            events: 100,
        };
        monitor.check_state(&state);

        assert_eq!(monitor.failure_count(), 1);
    }
}
