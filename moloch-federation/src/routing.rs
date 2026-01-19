//! Routing for cross-chain messages.

use std::collections::{HashMap, HashSet};
use std::sync::RwLock;

use serde::{Deserialize, Serialize};

/// Routing policy for cross-chain messages.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RoutingPolicy {
    /// Direct routing only.
    Direct,
    /// Allow routing through intermediate chains.
    MultiHop,
    /// Prefer direct, fall back to multi-hop.
    PreferDirect,
}

impl Default for RoutingPolicy {
    fn default() -> Self {
        Self::PreferDirect
    }
}

/// Route to a chain.
#[derive(Debug, Clone)]
pub struct Route {
    /// Target chain ID.
    pub target: String,
    /// Intermediate hops (empty for direct).
    pub hops: Vec<String>,
    /// Estimated latency in milliseconds.
    pub latency_ms: u64,
    /// Route health (0-100).
    pub health: u8,
}

impl Route {
    /// Create a direct route.
    pub fn direct(target: String) -> Self {
        Self {
            target,
            hops: vec![],
            latency_ms: 0,
            health: 100,
        }
    }

    /// Check if this is a direct route.
    pub fn is_direct(&self) -> bool {
        self.hops.is_empty()
    }

    /// Get hop count (0 for direct).
    pub fn hop_count(&self) -> usize {
        self.hops.len()
    }
}

/// Routing table for federation.
pub struct RouteTable {
    /// Known chains.
    chains: RwLock<HashSet<String>>,
    /// Routes indexed by target chain.
    routes: RwLock<HashMap<String, Vec<Route>>>,
    /// Routing policy.
    policy: RoutingPolicy,
}

impl RouteTable {
    /// Create a new empty routing table.
    pub fn new() -> Self {
        Self {
            chains: RwLock::new(HashSet::new()),
            routes: RwLock::new(HashMap::new()),
            policy: RoutingPolicy::default(),
        }
    }

    /// Create with a specific policy.
    pub fn with_policy(policy: RoutingPolicy) -> Self {
        Self {
            chains: RwLock::new(HashSet::new()),
            routes: RwLock::new(HashMap::new()),
            policy,
        }
    }

    /// Add a chain to the routing table.
    pub fn add_chain(&self, chain_id: &str) {
        let mut chains = self.chains.write().unwrap();
        chains.insert(chain_id.to_string());

        // Add direct route
        let route = Route::direct(chain_id.to_string());
        let mut routes = self.routes.write().unwrap();
        routes.entry(chain_id.to_string()).or_default().push(route);
    }

    /// Remove a chain from the routing table.
    pub fn remove_chain(&self, chain_id: &str) {
        let mut chains = self.chains.write().unwrap();
        chains.remove(chain_id);

        let mut routes = self.routes.write().unwrap();
        routes.remove(chain_id);

        // Remove from other routes' hops
        for routes in routes.values_mut() {
            routes.retain(|r| !r.hops.contains(&chain_id.to_string()));
        }
    }

    /// Get best route to a chain.
    pub fn best_route(&self, target: &str) -> Option<Route> {
        let routes = self.routes.read().unwrap();
        let target_routes = routes.get(target)?;

        match self.policy {
            RoutingPolicy::Direct => {
                target_routes.iter().find(|r| r.is_direct()).cloned()
            }
            RoutingPolicy::MultiHop => {
                // Return route with best health
                target_routes.iter()
                    .max_by_key(|r| r.health)
                    .cloned()
            }
            RoutingPolicy::PreferDirect => {
                // Prefer direct, fall back to best health
                target_routes.iter()
                    .find(|r| r.is_direct())
                    .or_else(|| target_routes.iter().max_by_key(|r| r.health))
                    .cloned()
            }
        }
    }

    /// Get all routes to a chain.
    pub fn routes_to(&self, target: &str) -> Vec<Route> {
        self.routes.read().unwrap()
            .get(target)
            .cloned()
            .unwrap_or_default()
    }

    /// Add a route.
    pub fn add_route(&self, route: Route) {
        let mut routes = self.routes.write().unwrap();
        routes.entry(route.target.clone()).or_default().push(route);
    }

    /// Update route health.
    pub fn update_health(&self, target: &str, hop_count: usize, health: u8) {
        let mut routes = self.routes.write().unwrap();
        if let Some(target_routes) = routes.get_mut(target) {
            if let Some(route) = target_routes.iter_mut().find(|r| r.hop_count() == hop_count) {
                route.health = health;
            }
        }
    }

    /// Check if a chain is reachable.
    pub fn is_reachable(&self, target: &str) -> bool {
        let routes = self.routes.read().unwrap();
        routes.get(target)
            .map(|r| r.iter().any(|route| route.health > 0))
            .unwrap_or(false)
    }

    /// Get all known chains.
    pub fn known_chains(&self) -> Vec<String> {
        self.chains.read().unwrap().iter().cloned().collect()
    }
}

impl Default for RouteTable {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_route_table() {
        let table = RouteTable::new();

        table.add_chain("chain-a");
        table.add_chain("chain-b");

        assert!(table.is_reachable("chain-a"));
        assert!(table.is_reachable("chain-b"));
        assert!(!table.is_reachable("chain-c"));
    }

    #[test]
    fn test_best_route() {
        let table = RouteTable::new();
        table.add_chain("chain-a");

        let route = table.best_route("chain-a").unwrap();
        assert!(route.is_direct());
        assert_eq!(route.health, 100);
    }

    #[test]
    fn test_routing_policy() {
        let table = RouteTable::with_policy(RoutingPolicy::Direct);
        table.add_chain("chain-a");

        // Add a multi-hop route with better health
        table.add_route(Route {
            target: "chain-a".to_string(),
            hops: vec!["chain-b".to_string()],
            latency_ms: 100,
            health: 100,
        });

        // With Direct policy, should still get direct route
        let route = table.best_route("chain-a").unwrap();
        assert!(route.is_direct());
    }
}
