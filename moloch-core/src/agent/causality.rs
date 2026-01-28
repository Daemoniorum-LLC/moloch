//! Causal context types for agent accountability.
//!
//! The causal context links every agent event to its predecessors and ultimately
//! to a human principal. This enables answering "why did this happen?" and
//! "who authorized this?" for any agent action.

use serde::{Deserialize, Serialize};
use std::fmt;

use crate::crypto::Hash;
use crate::error::{Error, Result};
use crate::event::EventId;

use super::principal::PrincipalId;
use super::session::SessionId;

/// Context linking an event to its causal predecessors.
///
/// Every agent-initiated event MUST include a CausalContext that:
/// - Links to the parent event that triggered this action
/// - Links to the root event (human request) that started the chain
/// - Identifies the session and principal
///
/// # Invariants
///
/// - INV-CAUSAL-1: If parent_event_id is Some(p), then p.sequence < self.sequence
/// - INV-CAUSAL-2: root_event_id always points to an event with depth = 0
/// - INV-CAUSAL-3: depth <= session.max_depth
/// - INV-CAUSAL-4: Exactly one event per session has depth = 0
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CausalContext {
    /// The event that directly triggered this action.
    /// None only for session-initiating events (depth = 0).
    parent_event_id: Option<EventId>,

    /// The originating human request that started this causal chain.
    /// MUST always be present for agent actions.
    root_event_id: EventId,

    /// Session identifier for grouping related events.
    session_id: SessionId,

    /// The human principal ultimately responsible.
    principal: PrincipalId,

    /// Depth in the causal chain (0 = human-initiated).
    depth: u32,

    /// Monotonic sequence within session.
    sequence: u64,

    /// Optional cross-session reference for linked operations.
    cross_session_ref: Option<CrossSessionReference>,
}

impl CausalContext {
    /// Create a builder for constructing a CausalContext.
    pub fn builder() -> CausalContextBuilder {
        CausalContextBuilder::new()
    }

    /// Create a root context (depth 0) for a human-initiated event.
    ///
    /// This is the starting point of any causal chain.
    pub fn root(
        event_id: EventId,
        session_id: SessionId,
        principal: PrincipalId,
    ) -> Self {
        Self {
            parent_event_id: None,
            root_event_id: event_id,
            session_id,
            principal,
            depth: 0,
            sequence: 0,
            cross_session_ref: None,
        }
    }

    /// Create a child context from this context.
    ///
    /// # Arguments
    /// * `parent_event_id` - The event ID of the parent (this context's event)
    /// * `sequence` - The sequence number for the new event (must be > self.sequence)
    ///
    /// # Errors
    /// Returns error if sequence is not greater than parent's sequence.
    pub fn child(&self, parent_event_id: EventId, sequence: u64) -> Result<Self> {
        if sequence <= self.sequence {
            return Err(Error::invalid_input(format!(
                "Child sequence {} must be greater than parent sequence {}",
                sequence, self.sequence
            )));
        }

        Ok(Self {
            parent_event_id: Some(parent_event_id),
            root_event_id: self.root_event_id,
            session_id: self.session_id,
            principal: self.principal.clone(),
            depth: self.depth + 1,
            sequence,
            cross_session_ref: None,
        })
    }

    /// Get the parent event ID.
    pub fn parent_event_id(&self) -> Option<&EventId> {
        self.parent_event_id.as_ref()
    }

    /// Get the root event ID.
    pub fn root_event_id(&self) -> &EventId {
        &self.root_event_id
    }

    /// Get the session ID.
    pub fn session_id(&self) -> SessionId {
        self.session_id
    }

    /// Get the principal.
    pub fn principal(&self) -> &PrincipalId {
        &self.principal
    }

    /// Get the depth in the causal chain.
    pub fn depth(&self) -> u32 {
        self.depth
    }

    /// Get the sequence number within the session.
    pub fn sequence(&self) -> u64 {
        self.sequence
    }

    /// Get the cross-session reference, if any.
    pub fn cross_session_ref(&self) -> Option<&CrossSessionReference> {
        self.cross_session_ref.as_ref()
    }

    /// Check if this is a root event (depth = 0).
    pub fn is_root(&self) -> bool {
        self.depth == 0
    }

    /// Validate this context against constraints.
    ///
    /// # Arguments
    /// * `max_depth` - Maximum allowed depth (typically from session)
    ///
    /// # Errors
    /// Returns error if validation fails.
    pub fn validate(&self, max_depth: u32) -> Result<()> {
        // INV-CAUSAL-3: depth <= max_depth
        if self.depth > max_depth {
            return Err(Error::invalid_input(format!(
                "Causal depth {} exceeds maximum {}",
                self.depth, max_depth
            )));
        }

        // Depth 0 must have no parent
        if self.depth == 0 && self.parent_event_id.is_some() {
            return Err(Error::invalid_input(
                "Root event (depth=0) must not have a parent",
            ));
        }

        // Depth > 0 must have parent
        if self.depth > 0 && self.parent_event_id.is_none() {
            return Err(Error::invalid_input(
                "Non-root event (depth>0) must have a parent",
            ));
        }

        // Root event ID must equal self event ID for depth 0
        // (This can only be fully validated with the actual event ID)

        Ok(())
    }

    /// Validate this context against a parent context.
    ///
    /// Ensures INV-CAUSAL-1 and INV-CAUSAL-2 hold.
    pub fn validate_against_parent(&self, parent: &CausalContext) -> Result<()> {
        // INV-CAUSAL-1: parent.sequence < self.sequence
        if parent.sequence >= self.sequence {
            return Err(Error::invalid_input(format!(
                "Parent sequence {} must be less than child sequence {}",
                parent.sequence, self.sequence
            )));
        }

        // Parent depth must be exactly one less
        if parent.depth + 1 != self.depth {
            return Err(Error::invalid_input(format!(
                "Parent depth {} + 1 must equal child depth {}",
                parent.depth, self.depth
            )));
        }

        // Root event ID must match
        if parent.root_event_id != self.root_event_id {
            return Err(Error::invalid_input(
                "Root event ID must match parent's root event ID",
            ));
        }

        // Session must match (unless cross-session)
        if self.cross_session_ref.is_none() && parent.session_id != self.session_id {
            return Err(Error::invalid_input(
                "Session ID must match parent's session ID (or use cross-session reference)",
            ));
        }

        // Principal must match
        if parent.principal != self.principal {
            return Err(Error::invalid_input(
                "Principal must match parent's principal",
            ));
        }

        Ok(())
    }
}

impl fmt::Display for CausalContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "CausalContext(session={}, depth={}, seq={})",
            self.session_id, self.depth, self.sequence
        )
    }
}

/// Builder for constructing CausalContext.
#[derive(Debug, Default)]
pub struct CausalContextBuilder {
    parent_event_id: Option<EventId>,
    root_event_id: Option<EventId>,
    session_id: Option<SessionId>,
    principal: Option<PrincipalId>,
    depth: Option<u32>,
    sequence: Option<u64>,
    cross_session_ref: Option<CrossSessionReference>,
}

impl CausalContextBuilder {
    /// Create a new builder.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the parent event ID.
    pub fn parent_event_id(mut self, id: EventId) -> Self {
        self.parent_event_id = Some(id);
        self
    }

    /// Set the root event ID.
    pub fn root_event_id(mut self, id: EventId) -> Self {
        self.root_event_id = Some(id);
        self
    }

    /// Set the session ID.
    pub fn session_id(mut self, id: SessionId) -> Self {
        self.session_id = Some(id);
        self
    }

    /// Set the principal.
    pub fn principal(mut self, principal: PrincipalId) -> Self {
        self.principal = Some(principal);
        self
    }

    /// Set the depth.
    pub fn depth(mut self, depth: u32) -> Self {
        self.depth = Some(depth);
        self
    }

    /// Set the sequence.
    pub fn sequence(mut self, sequence: u64) -> Self {
        self.sequence = Some(sequence);
        self
    }

    /// Set a cross-session reference.
    pub fn cross_session_ref(mut self, reference: CrossSessionReference) -> Self {
        self.cross_session_ref = Some(reference);
        self
    }

    /// Build the CausalContext.
    ///
    /// # Errors
    /// Returns error if required fields are missing.
    pub fn build(self) -> Result<CausalContext> {
        let root_event_id = self
            .root_event_id
            .ok_or_else(|| Error::invalid_input("root_event_id is required"))?;

        let session_id = self
            .session_id
            .ok_or_else(|| Error::invalid_input("session_id is required"))?;

        let principal = self
            .principal
            .ok_or_else(|| Error::invalid_input("principal is required"))?;

        let depth = self.depth.unwrap_or(0);
        let sequence = self.sequence.unwrap_or(0);

        // Validate consistency
        if depth == 0 && self.parent_event_id.is_some() {
            return Err(Error::invalid_input(
                "Root context (depth=0) must not have parent_event_id",
            ));
        }

        if depth > 0 && self.parent_event_id.is_none() {
            return Err(Error::invalid_input(
                "Non-root context (depth>0) requires parent_event_id",
            ));
        }

        Ok(CausalContext {
            parent_event_id: self.parent_event_id,
            root_event_id,
            session_id,
            principal,
            depth,
            sequence,
            cross_session_ref: self.cross_session_ref,
        })
    }
}

/// Reference to an event in a different session.
///
/// Used when an action in one session is causally related to
/// an event in another session (e.g., follow-up tasks).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CrossSessionReference {
    /// The session being referenced.
    pub source_session_id: SessionId,

    /// The event being referenced.
    pub source_event_id: EventId,

    /// Reason for the cross-session reference.
    pub reason: String,

    /// Hash of the referenced event for integrity.
    pub source_event_hash: Hash,
}

impl CrossSessionReference {
    /// Create a new cross-session reference.
    pub fn new(
        source_session_id: SessionId,
        source_event_id: EventId,
        reason: impl Into<String>,
        source_event_hash: Hash,
    ) -> Self {
        Self {
            source_session_id,
            source_event_id,
            reason: reason.into(),
            source_event_hash,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::hash;

    fn test_event_id() -> EventId {
        EventId(hash(b"test-event"))
    }

    fn test_session_id() -> SessionId {
        SessionId::random()
    }

    fn test_principal() -> PrincipalId {
        PrincipalId::user("alice").unwrap()
    }

    // === Construction Tests ===

    #[test]
    fn causal_context_root_created_successfully() {
        let event_id = test_event_id();
        let session_id = test_session_id();
        let principal = test_principal();

        let ctx = CausalContext::root(event_id, session_id, principal.clone());

        assert!(ctx.is_root());
        assert_eq!(ctx.depth(), 0);
        assert_eq!(ctx.sequence(), 0);
        assert!(ctx.parent_event_id().is_none());
        assert_eq!(ctx.root_event_id(), &event_id);
        assert_eq!(ctx.principal(), &principal);
    }

    #[test]
    fn causal_context_requires_session_id() {
        let result = CausalContext::builder()
            .root_event_id(test_event_id())
            .principal(test_principal())
            .build();

        assert!(result.is_err());
    }

    #[test]
    fn causal_context_requires_principal() {
        let result = CausalContext::builder()
            .root_event_id(test_event_id())
            .session_id(test_session_id())
            .build();

        assert!(result.is_err());
    }

    #[test]
    fn causal_context_depth_zero_has_no_parent() {
        let ctx = CausalContext::builder()
            .root_event_id(test_event_id())
            .session_id(test_session_id())
            .principal(test_principal())
            .depth(0)
            .build()
            .unwrap();

        assert!(ctx.parent_event_id().is_none());
        assert!(ctx.is_root());
    }

    #[test]
    fn causal_context_depth_zero_with_parent_rejected() {
        let result = CausalContext::builder()
            .root_event_id(test_event_id())
            .session_id(test_session_id())
            .principal(test_principal())
            .depth(0)
            .parent_event_id(test_event_id())
            .build();

        assert!(result.is_err());
    }

    #[test]
    fn causal_context_depth_nonzero_requires_parent() {
        let result = CausalContext::builder()
            .root_event_id(test_event_id())
            .session_id(test_session_id())
            .principal(test_principal())
            .depth(1)
            .build();

        assert!(result.is_err());
    }

    #[test]
    fn causal_context_depth_nonzero_with_parent_succeeds() {
        let ctx = CausalContext::builder()
            .root_event_id(test_event_id())
            .session_id(test_session_id())
            .principal(test_principal())
            .depth(1)
            .sequence(1)
            .parent_event_id(test_event_id())
            .build()
            .unwrap();

        assert!(!ctx.is_root());
        assert_eq!(ctx.depth(), 1);
    }

    // === Child Creation Tests ===

    #[test]
    fn child_context_created_successfully() {
        let root = CausalContext::root(
            test_event_id(),
            test_session_id(),
            test_principal(),
        );

        let parent_id = test_event_id();
        let child = root.child(parent_id, 1).unwrap();

        assert_eq!(child.depth(), 1);
        assert_eq!(child.sequence(), 1);
        assert_eq!(child.parent_event_id(), Some(&parent_id));
        assert_eq!(child.root_event_id(), root.root_event_id());
    }

    #[test]
    fn child_sequence_must_exceed_parent() {
        let root = CausalContext::root(
            test_event_id(),
            test_session_id(),
            test_principal(),
        );

        // Same sequence should fail
        let result = root.child(test_event_id(), 0);
        assert!(result.is_err());

        // Greater sequence should succeed
        let result = root.child(test_event_id(), 1);
        assert!(result.is_ok());
    }

    // === Validation Tests ===

    #[test]
    fn validate_rejects_depth_exceeding_max() {
        let ctx = CausalContext::builder()
            .root_event_id(test_event_id())
            .session_id(test_session_id())
            .principal(test_principal())
            .depth(5)
            .sequence(5)
            .parent_event_id(test_event_id())
            .build()
            .unwrap();

        // Depth 5 exceeds max of 3
        let result = ctx.validate(3);
        assert!(result.is_err());

        // Depth 5 within max of 10
        let result = ctx.validate(10);
        assert!(result.is_ok());
    }

    #[test]
    fn validate_against_parent_checks_sequence() {
        let parent = CausalContext::root(
            test_event_id(),
            test_session_id(),
            test_principal(),
        );

        let child = parent.child(test_event_id(), 1).unwrap();

        // Valid: parent.sequence < child.sequence
        assert!(child.validate_against_parent(&parent).is_ok());

        // Create invalid child with lower sequence
        let invalid_child = CausalContext::builder()
            .root_event_id(parent.root_event_id)
            .session_id(parent.session_id)
            .principal(parent.principal.clone())
            .depth(1)
            .sequence(0) // Same as parent!
            .parent_event_id(test_event_id())
            .build()
            .unwrap();

        assert!(invalid_child.validate_against_parent(&parent).is_err());
    }

    #[test]
    fn validate_against_parent_checks_depth() {
        let parent = CausalContext::root(
            test_event_id(),
            test_session_id(),
            test_principal(),
        );

        // Correct child depth
        let valid_child = parent.child(test_event_id(), 1).unwrap();
        assert!(valid_child.validate_against_parent(&parent).is_ok());

        // Wrong depth (skipped a level)
        let invalid_child = CausalContext::builder()
            .root_event_id(parent.root_event_id)
            .session_id(parent.session_id)
            .principal(parent.principal.clone())
            .depth(2) // Should be 1
            .sequence(1)
            .parent_event_id(test_event_id())
            .build()
            .unwrap();

        assert!(invalid_child.validate_against_parent(&parent).is_err());
    }

    #[test]
    fn validate_accepts_cross_session_reference() {
        let source_session = test_session_id();
        let target_session = test_session_id();
        let event_id = test_event_id();

        let cross_ref = CrossSessionReference::new(
            source_session,
            event_id,
            "Follow-up task",
            hash(b"event-data"),
        );

        let ctx = CausalContext::builder()
            .root_event_id(event_id)
            .session_id(target_session)
            .principal(test_principal())
            .depth(1)
            .sequence(1)
            .parent_event_id(event_id)
            .cross_session_ref(cross_ref)
            .build()
            .unwrap();

        assert!(ctx.cross_session_ref().is_some());
    }

    // === Display Tests ===

    #[test]
    fn display_format_correct() {
        let ctx = CausalContext::root(
            test_event_id(),
            test_session_id(),
            test_principal(),
        );

        let display = format!("{}", ctx);
        assert!(display.contains("CausalContext"));
        assert!(display.contains("depth=0"));
        assert!(display.contains("seq=0"));
    }
}
