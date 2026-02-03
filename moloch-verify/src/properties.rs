//! Property-based testing for chain operations.

use std::fmt::Debug;

/// Result of a property test.
#[derive(Debug, Clone)]
pub enum PropertyResult {
    /// Property holds.
    Passed,
    /// Property failed with counterexample.
    Failed {
        /// Counterexample description.
        counterexample: String,
        /// Number of tests before failure.
        tests_run: usize,
    },
    /// Property testing was skipped.
    Skipped {
        /// Reason for skipping.
        reason: String,
    },
}

impl PropertyResult {
    /// Check if the property passed.
    pub fn is_passed(&self) -> bool {
        matches!(self, Self::Passed)
    }

    /// Check if the property failed.
    pub fn is_failed(&self) -> bool {
        matches!(self, Self::Failed { .. })
    }
}

/// A property that should hold for all inputs.
pub trait Property<I> {
    /// Name of the property.
    fn name(&self) -> &str;

    /// Check if the property holds for an input.
    fn check(&self, input: &I) -> bool;

    /// Describe a failing input for debugging.
    fn describe_failure(&self, input: &I) -> String;
}

/// Property test runner.
pub struct PropertyTest<I, G> {
    /// Property to test.
    property: Box<dyn Property<I>>,
    /// Input generator.
    generator: G,
    /// Maximum iterations.
    max_iterations: usize,
    /// Seed for reproducibility.
    seed: u64,
}

impl<I, G> PropertyTest<I, G>
where
    G: Iterator<Item = I>,
    I: Debug,
{
    /// Create a new property test.
    pub fn new(property: impl Property<I> + 'static, generator: G) -> Self {
        Self {
            property: Box::new(property),
            generator,
            max_iterations: 100,
            seed: 0,
        }
    }

    /// Set maximum iterations.
    pub fn with_iterations(mut self, n: usize) -> Self {
        self.max_iterations = n;
        self
    }

    /// Set seed for reproducibility.
    pub fn with_seed(mut self, seed: u64) -> Self {
        self.seed = seed;
        self
    }

    /// Run the property test.
    pub fn run(self) -> PropertyResult {
        for (i, input) in self.generator.take(self.max_iterations).enumerate() {
            if !self.property.check(&input) {
                return PropertyResult::Failed {
                    counterexample: self.property.describe_failure(&input),
                    tests_run: i + 1,
                };
            }
        }
        PropertyResult::Passed
    }
}

/// Built-in property: append-only semantics.
pub struct AppendOnlyProperty;

impl Property<(Vec<u8>, Vec<u8>)> for AppendOnlyProperty {
    fn name(&self) -> &str {
        "append_only"
    }

    fn check(&self, (before, after): &(Vec<u8>, Vec<u8>)) -> bool {
        // After must start with before (append-only)
        after.starts_with(before)
    }

    fn describe_failure(&self, (before, after): &(Vec<u8>, Vec<u8>)) -> String {
        format!(
            "append-only violated: before={} bytes, after={} bytes, prefix mismatch",
            before.len(),
            after.len()
        )
    }
}

/// Built-in property: idempotent operations.
pub struct IdempotentProperty<F> {
    /// Operation to test.
    operation: F,
}

impl<F, I, O> Property<I> for IdempotentProperty<F>
where
    F: Fn(&I) -> O,
    O: PartialEq + Debug,
    I: Clone + Debug,
{
    fn name(&self) -> &str {
        "idempotent"
    }

    fn check(&self, input: &I) -> bool {
        let first = (self.operation)(input);
        let second = (self.operation)(input);
        first == second
    }

    fn describe_failure(&self, input: &I) -> String {
        format!("idempotent violated for input: {:?}", input)
    }
}

/// Built-in property: commutative operations.
pub struct CommutativeProperty<F> {
    /// Binary operation to test.
    operation: F,
}

impl<F, I, O> Property<(I, I)> for CommutativeProperty<F>
where
    F: Fn(&I, &I) -> O,
    O: PartialEq + Debug,
    I: Clone + Debug,
{
    fn name(&self) -> &str {
        "commutative"
    }

    fn check(&self, (a, b): &(I, I)) -> bool {
        let ab = (self.operation)(a, b);
        let ba = (self.operation)(b, a);
        ab == ba
    }

    fn describe_failure(&self, (a, b): &(I, I)) -> String {
        format!("commutative violated for: ({:?}, {:?})", a, b)
    }
}

/// Built-in property: associative operations.
pub struct AssociativeProperty<F> {
    /// Binary operation to test.
    operation: F,
}

impl<F, I> Property<(I, I, I)> for AssociativeProperty<F>
where
    F: Fn(&I, &I) -> I,
    I: PartialEq + Debug + Clone,
{
    fn name(&self) -> &str {
        "associative"
    }

    fn check(&self, (a, b, c): &(I, I, I)) -> bool {
        let ab = (self.operation)(a, b);
        let ab_c = (self.operation)(&ab, c);

        let bc = (self.operation)(b, c);
        let a_bc = (self.operation)(a, &bc);

        ab_c == a_bc
    }

    fn describe_failure(&self, (a, b, c): &(I, I, I)) -> String {
        format!("associative violated for: ({:?}, {:?}, {:?})", a, b, c)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_append_only_property() {
        let prop = AppendOnlyProperty;

        // Valid append
        assert!(prop.check(&(vec![1, 2, 3], vec![1, 2, 3, 4, 5])));

        // Invalid: data removed
        assert!(!prop.check(&(vec![1, 2, 3], vec![1, 2])));

        // Invalid: data modified
        assert!(!prop.check(&(vec![1, 2, 3], vec![1, 9, 3, 4])));
    }

    #[test]
    fn test_property_test_runner() {
        let inputs = vec![
            (vec![1u8], vec![1u8, 2]),
            (vec![1u8, 2], vec![1u8, 2, 3]),
            (vec![], vec![1u8]),
        ];

        let result = PropertyTest::new(AppendOnlyProperty, inputs.into_iter())
            .with_iterations(10)
            .run();

        assert!(result.is_passed());
    }

    #[test]
    fn test_property_failure() {
        let inputs = vec![
            (vec![1u8, 2, 3], vec![1u8, 2]), // This violates append-only
        ];

        let result = PropertyTest::new(AppendOnlyProperty, inputs.into_iter()).run();

        assert!(result.is_failed());
    }
}
