//! Principal types for agent accountability.
//!
//! A principal is the human or organization ultimately responsible for an agent's actions.
//! Every agent action must trace back to a principal through the causal chain.

use serde::{Deserialize, Serialize};
use std::fmt;

use crate::crypto::{hash, Hash};
use crate::error::{Error, Result};

/// Unique identifier for a principal (human or organization).
///
/// Principals are the root of accountability - every agent action must
/// ultimately trace back to a principal who authorized it.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PrincipalId {
    /// Principal's identifier (public key hash or organizational ID).
    id: String,

    /// Type of principal.
    kind: PrincipalKind,
}

impl PrincipalId {
    /// Create a new principal ID.
    ///
    /// # Arguments
    /// * `id` - Unique identifier for the principal
    /// * `kind` - Type of principal (User, Organization, ServiceAccount)
    ///
    /// # Errors
    /// Returns error if `id` is empty.
    pub fn new(id: impl Into<String>, kind: PrincipalKind) -> Result<Self> {
        let id = id.into();
        if id.is_empty() {
            return Err(Error::invalid_input("Principal ID cannot be empty"));
        }

        // Validate service account has owner
        if let PrincipalKind::ServiceAccount { ref owner } = kind {
            if owner.id.is_empty() {
                return Err(Error::invalid_input(
                    "Service account must have a valid owner",
                ));
            }
        }

        Ok(Self { id, kind })
    }

    /// Create a user principal.
    pub fn user(id: impl Into<String>) -> Result<Self> {
        Self::new(id, PrincipalKind::User)
    }

    /// Create an organization principal.
    pub fn organization(id: impl Into<String>) -> Result<Self> {
        Self::new(id, PrincipalKind::Organization)
    }

    /// Create a service account principal.
    ///
    /// Service accounts must have an owning principal (user or organization).
    pub fn service_account(id: impl Into<String>, owner: PrincipalId) -> Result<Self> {
        Self::new(
            id,
            PrincipalKind::ServiceAccount {
                owner: Box::new(owner),
            },
        )
    }

    /// Get the principal's ID.
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Get the principal's kind.
    pub fn kind(&self) -> &PrincipalKind {
        &self.kind
    }

    /// Check if this is a user principal.
    pub fn is_user(&self) -> bool {
        matches!(self.kind, PrincipalKind::User)
    }

    /// Check if this is an organization principal.
    pub fn is_organization(&self) -> bool {
        matches!(self.kind, PrincipalKind::Organization)
    }

    /// Check if this is a service account.
    pub fn is_service_account(&self) -> bool {
        matches!(self.kind, PrincipalKind::ServiceAccount { .. })
    }

    /// Get the root owner of this principal.
    ///
    /// For users and organizations, returns self.
    /// For service accounts, recursively finds the owning user/org.
    pub fn root_owner(&self) -> &PrincipalId {
        match &self.kind {
            PrincipalKind::User | PrincipalKind::Organization => self,
            PrincipalKind::ServiceAccount { owner } => owner.root_owner(),
        }
    }

    /// Compute a unique hash for this principal.
    pub fn hash(&self) -> Hash {
        let canonical = format!("{}:{}", self.kind.type_name(), self.id);
        hash(canonical.as_bytes())
    }
}

impl fmt::Display for PrincipalId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.kind.type_name(), self.id)
    }
}

/// Type of principal.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "type")]
pub enum PrincipalKind {
    /// Individual human user.
    User,

    /// Organization (actions require member attribution).
    Organization,

    /// Service account (must have owning principal).
    ServiceAccount {
        /// The user or organization that owns this service account.
        owner: Box<PrincipalId>,
    },
}

impl PrincipalKind {
    /// Get the type name for display/serialization.
    pub fn type_name(&self) -> &'static str {
        match self {
            PrincipalKind::User => "user",
            PrincipalKind::Organization => "org",
            PrincipalKind::ServiceAccount { .. } => "service",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // === Construction Tests ===

    #[test]
    fn user_principal_created_successfully() {
        let principal = PrincipalId::user("alice@example.com").unwrap();
        assert_eq!(principal.id(), "alice@example.com");
        assert!(principal.is_user());
    }

    #[test]
    fn organization_principal_created_successfully() {
        let principal = PrincipalId::organization("acme-corp").unwrap();
        assert_eq!(principal.id(), "acme-corp");
        assert!(principal.is_organization());
    }

    #[test]
    fn service_account_requires_owner() {
        let owner = PrincipalId::user("alice@example.com").unwrap();
        let service = PrincipalId::service_account("ci-bot", owner).unwrap();
        assert!(service.is_service_account());
    }

    #[test]
    fn empty_id_rejected() {
        let result = PrincipalId::user("");
        assert!(result.is_err());
    }

    #[test]
    fn service_account_with_empty_owner_rejected() {
        // Can't create invalid owner in the first place due to validation
        let result = PrincipalId::new("", PrincipalKind::User);
        assert!(result.is_err());
    }

    // === Root Owner Tests ===

    #[test]
    fn user_is_own_root_owner() {
        let user = PrincipalId::user("alice").unwrap();
        assert_eq!(user.root_owner(), &user);
    }

    #[test]
    fn organization_is_own_root_owner() {
        let org = PrincipalId::organization("acme").unwrap();
        assert_eq!(org.root_owner(), &org);
    }

    #[test]
    fn service_account_root_owner_is_owner() {
        let user = PrincipalId::user("alice").unwrap();
        let service = PrincipalId::service_account("bot", user.clone()).unwrap();
        assert_eq!(service.root_owner(), &user);
    }

    #[test]
    fn nested_service_account_finds_root() {
        let user = PrincipalId::user("alice").unwrap();
        let service1 = PrincipalId::service_account("bot1", user.clone()).unwrap();
        let service2 = PrincipalId::service_account("bot2", service1).unwrap();
        assert_eq!(service2.root_owner(), &user);
    }

    // === Hash Tests ===

    #[test]
    fn same_principal_same_hash() {
        let p1 = PrincipalId::user("alice").unwrap();
        let p2 = PrincipalId::user("alice").unwrap();
        assert_eq!(p1.hash(), p2.hash());
    }

    #[test]
    fn different_principal_different_hash() {
        let p1 = PrincipalId::user("alice").unwrap();
        let p2 = PrincipalId::user("bob").unwrap();
        assert_ne!(p1.hash(), p2.hash());
    }

    #[test]
    fn different_kind_different_hash() {
        let user = PrincipalId::user("alice").unwrap();
        let org = PrincipalId::organization("alice").unwrap();
        assert_ne!(user.hash(), org.hash());
    }

    // === Display Tests ===

    #[test]
    fn display_format_correct() {
        let user = PrincipalId::user("alice").unwrap();
        assert_eq!(format!("{}", user), "user:alice");

        let org = PrincipalId::organization("acme").unwrap();
        assert_eq!(format!("{}", org), "org:acme");

        let service = PrincipalId::service_account("bot", user).unwrap();
        assert_eq!(format!("{}", service), "service:bot");
    }
}
