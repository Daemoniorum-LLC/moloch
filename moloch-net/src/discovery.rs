//! Peer discovery for Moloch network.
//!
//! Supports multiple discovery methods:
//! - Static peer list (configuration)
//! - DNS-based discovery
//! - Peer exchange protocol
//!
//! Also provides peer scoring for connection quality.

use std::collections::{HashMap, HashSet};
use std::net::{SocketAddr, ToSocketAddrs};
use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;
use tracing::{debug, error, info, trace, warn};

use crate::protocol::PeerId;
use crate::transport::ConnectionPool;
use moloch_core::crypto::PublicKey;

/// Information about a known peer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerInfo {
    /// Peer identifier.
    pub id: PeerId,
    /// Known addresses for this peer.
    pub addresses: Vec<SocketAddr>,
    /// Peer state.
    pub state: PeerState,
    /// Peer score (quality metric).
    pub score: PeerScore,
    /// When the peer was first seen.
    pub first_seen: DateTime<Utc>,
    /// When the peer was last seen.
    pub last_seen: Option<DateTime<Utc>>,
    /// Number of successful connections.
    pub connection_successes: u32,
    /// Number of failed connection attempts.
    pub connection_failures: u32,
    /// How we discovered this peer.
    pub source: DiscoverySource,
    /// Additional metadata.
    pub metadata: PeerMetadata,
}

impl PeerInfo {
    /// Create a new peer info.
    pub fn new(id: PeerId, addresses: Vec<SocketAddr>, source: DiscoverySource) -> Self {
        Self {
            id,
            addresses,
            state: PeerState::Unknown,
            score: PeerScore::default(),
            first_seen: Utc::now(),
            last_seen: None,
            connection_successes: 0,
            connection_failures: 0,
            source,
            metadata: PeerMetadata::default(),
        }
    }

    /// Record a successful connection.
    pub fn record_success(&mut self) {
        self.connection_successes += 1;
        self.last_seen = Some(Utc::now());
        self.state = PeerState::Connected;
        self.score.connection_success();
    }

    /// Record a failed connection attempt.
    pub fn record_failure(&mut self) {
        self.connection_failures += 1;
        self.score.connection_failure();
        if self.connection_failures > 5 && self.connection_successes == 0 {
            self.state = PeerState::Banned;
        }
    }

    /// Get success rate as a percentage.
    pub fn success_rate(&self) -> f64 {
        let total = self.connection_successes + self.connection_failures;
        if total == 0 {
            return 0.0;
        }
        (self.connection_successes as f64 / total as f64) * 100.0
    }

    /// Check if the peer should be tried for connection.
    pub fn should_connect(&self) -> bool {
        matches!(
            self.state,
            PeerState::Unknown | PeerState::Disconnected | PeerState::Known
        ) && !self.score.is_banned()
    }
}

/// State of a peer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PeerState {
    /// Peer state is unknown.
    Unknown,
    /// Peer is known but not connected.
    Known,
    /// Currently attempting to connect.
    Connecting,
    /// Connected and active.
    Connected,
    /// Disconnected (was connected before).
    Disconnected,
    /// Peer has been banned.
    Banned,
}

impl std::fmt::Display for PeerState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PeerState::Unknown => write!(f, "unknown"),
            PeerState::Known => write!(f, "known"),
            PeerState::Connecting => write!(f, "connecting"),
            PeerState::Connected => write!(f, "connected"),
            PeerState::Disconnected => write!(f, "disconnected"),
            PeerState::Banned => write!(f, "banned"),
        }
    }
}

/// Peer quality score.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerScore {
    /// Overall score (0-1000).
    pub value: u32,
    /// Latency score component.
    pub latency_score: u32,
    /// Reliability score component.
    pub reliability_score: u32,
    /// Behavior score component (misbehavior penalties).
    pub behavior_score: u32,
    /// Average latency in milliseconds.
    pub avg_latency_ms: Option<u64>,
    /// When the score was last updated.
    pub last_updated: DateTime<Utc>,
}

impl Default for PeerScore {
    fn default() -> Self {
        Self {
            value: 500, // Start at neutral
            latency_score: 500,
            reliability_score: 500,
            behavior_score: 500,
            avg_latency_ms: None,
            last_updated: Utc::now(),
        }
    }
}

impl PeerScore {
    /// Maximum score value.
    pub const MAX_SCORE: u32 = 1000;

    /// Minimum score before banning.
    pub const BAN_THRESHOLD: u32 = 50;

    /// Score for a good peer.
    pub const GOOD_THRESHOLD: u32 = 700;

    /// Calculate overall score from components.
    pub fn calculate(&mut self) {
        // Weighted average: latency 30%, reliability 40%, behavior 30%
        self.value =
            (self.latency_score * 30 + self.reliability_score * 40 + self.behavior_score * 30)
                / 100;
        self.value = self.value.min(Self::MAX_SCORE);
        self.last_updated = Utc::now();
    }

    /// Record successful connection.
    pub fn connection_success(&mut self) {
        self.reliability_score = (self.reliability_score + 50).min(Self::MAX_SCORE);
        self.calculate();
    }

    /// Record failed connection.
    pub fn connection_failure(&mut self) {
        self.reliability_score = self.reliability_score.saturating_sub(100);
        self.calculate();
    }

    /// Update latency measurement.
    pub fn update_latency(&mut self, latency_ms: u64) {
        // Exponential moving average
        self.avg_latency_ms = Some(match self.avg_latency_ms {
            Some(avg) => (avg * 7 + latency_ms * 3) / 10,
            None => latency_ms,
        });

        // Score based on latency (lower is better) - 0-1000 scale
        self.latency_score = if latency_ms < 50 {
            1000
        } else if latency_ms < 100 {
            900
        } else if latency_ms < 200 {
            700
        } else if latency_ms < 500 {
            500
        } else if latency_ms < 1000 {
            300
        } else {
            100
        };

        self.calculate();
    }

    /// Record misbehavior (protocol violation, etc.).
    pub fn record_misbehavior(&mut self, severity: u32) {
        self.behavior_score = self.behavior_score.saturating_sub(severity);
        self.calculate();
    }

    /// Check if peer should be banned.
    pub fn is_banned(&self) -> bool {
        self.value < Self::BAN_THRESHOLD
    }

    /// Check if peer is considered good.
    pub fn is_good(&self) -> bool {
        self.value >= Self::GOOD_THRESHOLD
    }
}

/// How a peer was discovered.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DiscoverySource {
    /// From static configuration.
    Static,
    /// From DNS discovery.
    Dns,
    /// From peer exchange.
    PeerExchange,
    /// From incoming connection.
    Incoming,
    /// Manually added.
    Manual,
}

impl std::fmt::Display for DiscoverySource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DiscoverySource::Static => write!(f, "static"),
            DiscoverySource::Dns => write!(f, "dns"),
            DiscoverySource::PeerExchange => write!(f, "peer_exchange"),
            DiscoverySource::Incoming => write!(f, "incoming"),
            DiscoverySource::Manual => write!(f, "manual"),
        }
    }
}

/// Additional peer metadata.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PeerMetadata {
    /// Chain height (if known).
    pub height: Option<u64>,
    /// Protocol version (if known).
    pub protocol_version: Option<String>,
    /// Node software version (if known).
    pub node_version: Option<String>,
    /// Is the peer syncing?
    pub syncing: Option<bool>,
    /// Custom tags.
    pub tags: Vec<String>,
}

/// Configuration for peer discovery.
#[derive(Debug, Clone)]
pub struct DiscoveryConfig {
    /// Static peer list.
    pub static_peers: Vec<String>,
    /// DNS seeds for discovery.
    pub dns_seeds: Vec<String>,
    /// Enable peer exchange.
    pub enable_peer_exchange: bool,
    /// Maximum number of peers to track.
    pub max_peers: usize,
    /// How often to refresh DNS.
    pub dns_refresh_interval: Duration,
    /// How often to exchange peers.
    pub peer_exchange_interval: Duration,
    /// Minimum number of connections to maintain.
    pub min_connections: usize,
    /// Target number of connections.
    pub target_connections: usize,
    /// Maximum number of connections.
    pub max_connections: usize,
}

impl Default for DiscoveryConfig {
    fn default() -> Self {
        Self {
            static_peers: Vec::new(),
            dns_seeds: Vec::new(),
            enable_peer_exchange: true,
            max_peers: 1000,
            dns_refresh_interval: Duration::from_secs(3600), // 1 hour
            peer_exchange_interval: Duration::from_secs(300), // 5 minutes
            min_connections: 3,
            target_connections: 10,
            max_connections: 50,
        }
    }
}

/// Peer discovery service.
#[derive(Debug)]
pub struct PeerDiscovery {
    /// Configuration.
    config: DiscoveryConfig,
    /// Known peers by ID.
    peers_by_id: RwLock<HashMap<PeerId, PeerInfo>>,
    /// Known peers by address.
    peers_by_addr: RwLock<HashMap<SocketAddr, PeerId>>,
    /// Banned peers.
    banned: RwLock<HashSet<PeerId>>,
}

impl PeerDiscovery {
    /// Create a new peer discovery service.
    pub fn new(config: DiscoveryConfig) -> Self {
        Self {
            config,
            peers_by_id: RwLock::new(HashMap::new()),
            peers_by_addr: RwLock::new(HashMap::new()),
            banned: RwLock::new(HashSet::new()),
        }
    }

    /// Get the configuration.
    pub fn config(&self) -> &DiscoveryConfig {
        &self.config
    }

    /// Add a peer from static configuration.
    pub async fn add_static_peer(&self, addr: SocketAddr, id: Option<PeerId>) -> Option<PeerId> {
        // If we don't have an ID, we can't add yet (will get ID on connection)
        let peer_id = id?;

        let mut peers = self.peers_by_id.write().await;
        let mut by_addr = self.peers_by_addr.write().await;

        if peers.len() >= self.config.max_peers {
            return None;
        }

        if peers.contains_key(&peer_id) {
            // Update addresses
            if let Some(info) = peers.get_mut(&peer_id) {
                if !info.addresses.contains(&addr) {
                    info.addresses.push(addr);
                }
            }
        } else {
            let info = PeerInfo::new(peer_id.clone(), vec![addr], DiscoverySource::Static);
            peers.insert(peer_id.clone(), info);
        }

        by_addr.insert(addr, peer_id.clone());
        Some(peer_id)
    }

    /// Add a peer from incoming connection.
    pub async fn add_incoming_peer(&self, addr: SocketAddr, id: PeerId) -> bool {
        let mut peers = self.peers_by_id.write().await;
        let mut by_addr = self.peers_by_addr.write().await;
        let banned = self.banned.read().await;

        if banned.contains(&id) {
            return false;
        }

        if peers.len() >= self.config.max_peers {
            return false;
        }

        if let Some(info) = peers.get_mut(&id) {
            if !info.addresses.contains(&addr) {
                info.addresses.push(addr);
            }
            info.record_success();
        } else {
            let mut info = PeerInfo::new(id.clone(), vec![addr], DiscoverySource::Incoming);
            info.record_success();
            peers.insert(id.clone(), info);
        }

        by_addr.insert(addr, id);
        true
    }

    /// Add peers from peer exchange.
    pub async fn add_exchanged_peers(&self, peers_info: Vec<(PeerId, Vec<SocketAddr>)>) -> usize {
        let mut peers = self.peers_by_id.write().await;
        let mut by_addr = self.peers_by_addr.write().await;
        let banned = self.banned.read().await;

        let mut added = 0;

        for (id, addrs) in peers_info {
            if banned.contains(&id) {
                continue;
            }

            if peers.len() >= self.config.max_peers {
                break;
            }

            if let Some(info) = peers.get_mut(&id) {
                for addr in &addrs {
                    if !info.addresses.contains(addr) {
                        info.addresses.push(*addr);
                    }
                }
            } else {
                let info = PeerInfo::new(id.clone(), addrs.clone(), DiscoverySource::PeerExchange);
                peers.insert(id.clone(), info);
                added += 1;

                for addr in addrs {
                    by_addr.insert(addr, id.clone());
                }
            }
        }

        added
    }

    /// Discover peers from DNS.
    pub async fn discover_dns(&self) -> Vec<SocketAddr> {
        let mut discovered = Vec::new();

        for seed in &self.config.dns_seeds {
            match self.resolve_dns(seed).await {
                Ok(addrs) => {
                    debug!("Resolved {} to {} addresses", seed, addrs.len());
                    discovered.extend(addrs);
                }
                Err(e) => {
                    warn!("Failed to resolve DNS seed {}: {}", seed, e);
                }
            }
        }

        discovered
    }

    /// Resolve a DNS seed to addresses.
    async fn resolve_dns(&self, host: &str) -> Result<Vec<SocketAddr>, std::io::Error> {
        // Tokio's async DNS resolution
        let addrs: Vec<SocketAddr> = tokio::net::lookup_host(host).await?.collect();
        Ok(addrs)
    }

    /// Get peer info by ID.
    pub async fn get_peer(&self, id: &PeerId) -> Option<PeerInfo> {
        self.peers_by_id.read().await.get(id).cloned()
    }

    /// Get peer info by address.
    pub async fn get_peer_by_addr(&self, addr: &SocketAddr) -> Option<PeerInfo> {
        let by_addr = self.peers_by_addr.read().await;
        let id = by_addr.get(addr)?;
        self.peers_by_id.read().await.get(id).cloned()
    }

    /// Get all known peers.
    pub async fn all_peers(&self) -> Vec<PeerInfo> {
        self.peers_by_id.read().await.values().cloned().collect()
    }

    /// Get peers in a specific state.
    pub async fn peers_in_state(&self, state: PeerState) -> Vec<PeerInfo> {
        self.peers_by_id
            .read()
            .await
            .values()
            .filter(|p| p.state == state)
            .cloned()
            .collect()
    }

    /// Get peers suitable for connection attempts.
    pub async fn peers_to_connect(&self, limit: usize) -> Vec<PeerInfo> {
        let peers = self.peers_by_id.read().await;
        let banned = self.banned.read().await;

        let mut candidates: Vec<_> = peers
            .values()
            .filter(|p| p.should_connect() && !banned.contains(&p.id))
            .cloned()
            .collect();

        // Sort by score (highest first)
        candidates.sort_by(|a, b| b.score.value.cmp(&a.score.value));

        candidates.into_iter().take(limit).collect()
    }

    /// Get the best peers for a specific purpose.
    pub async fn best_peers(&self, count: usize) -> Vec<PeerInfo> {
        let peers = self.peers_by_id.read().await;

        let mut connected: Vec<_> = peers
            .values()
            .filter(|p| p.state == PeerState::Connected)
            .cloned()
            .collect();

        connected.sort_by(|a, b| b.score.value.cmp(&a.score.value));
        connected.into_iter().take(count).collect()
    }

    /// Update peer state.
    pub async fn update_state(&self, id: &PeerId, state: PeerState) {
        if let Some(peer) = self.peers_by_id.write().await.get_mut(id) {
            peer.state = state;
            if state == PeerState::Connected {
                peer.last_seen = Some(Utc::now());
            }
        }
    }

    /// Record connection success.
    pub async fn record_success(&self, id: &PeerId) {
        if let Some(peer) = self.peers_by_id.write().await.get_mut(id) {
            peer.record_success();
        }
    }

    /// Record connection failure.
    pub async fn record_failure(&self, id: &PeerId) {
        let mut peers = self.peers_by_id.write().await;
        let mut banned = self.banned.write().await;

        if let Some(peer) = peers.get_mut(id) {
            peer.record_failure();
            if peer.state == PeerState::Banned || peer.score.is_banned() {
                banned.insert(id.clone());
            }
        }
    }

    /// Update peer latency.
    pub async fn update_latency(&self, id: &PeerId, latency_ms: u64) {
        if let Some(peer) = self.peers_by_id.write().await.get_mut(id) {
            peer.score.update_latency(latency_ms);
        }
    }

    /// Update peer metadata.
    pub async fn update_metadata(&self, id: &PeerId, metadata: PeerMetadata) {
        if let Some(peer) = self.peers_by_id.write().await.get_mut(id) {
            peer.metadata = metadata;
        }
    }

    /// Ban a peer.
    pub async fn ban_peer(&self, id: &PeerId, reason: &str) {
        info!("Banning peer {}: {}", id, reason);

        let mut peers = self.peers_by_id.write().await;
        let mut banned = self.banned.write().await;

        if let Some(peer) = peers.get_mut(id) {
            peer.state = PeerState::Banned;
            peer.score.behavior_score = 0;
            peer.score.calculate();
        }

        banned.insert(id.clone());
    }

    /// Unban a peer.
    pub async fn unban_peer(&self, id: &PeerId) {
        let mut peers = self.peers_by_id.write().await;
        let mut banned = self.banned.write().await;

        if let Some(peer) = peers.get_mut(id) {
            peer.state = PeerState::Unknown;
            peer.score = PeerScore::default();
        }

        banned.remove(id);
    }

    /// Check if a peer is banned.
    pub async fn is_banned(&self, id: &PeerId) -> bool {
        self.banned.read().await.contains(id)
    }

    /// Remove a peer.
    pub async fn remove_peer(&self, id: &PeerId) -> Option<PeerInfo> {
        let mut peers = self.peers_by_id.write().await;
        let mut by_addr = self.peers_by_addr.write().await;

        if let Some(info) = peers.remove(id) {
            for addr in &info.addresses {
                by_addr.remove(addr);
            }
            Some(info)
        } else {
            None
        }
    }

    /// Get peer count.
    pub async fn peer_count(&self) -> usize {
        self.peers_by_id.read().await.len()
    }

    /// Get connected peer count.
    pub async fn connected_count(&self) -> usize {
        self.peers_by_id
            .read()
            .await
            .values()
            .filter(|p| p.state == PeerState::Connected)
            .count()
    }

    /// Get peers for exchange (to share with other nodes).
    pub async fn peers_for_exchange(&self, limit: usize) -> Vec<(PeerId, Vec<SocketAddr>)> {
        let peers = self.peers_by_id.read().await;

        let mut good_peers: Vec<_> = peers
            .values()
            .filter(|p| p.score.is_good() && !p.addresses.is_empty())
            .cloned()
            .collect();

        good_peers.sort_by(|a, b| b.score.value.cmp(&a.score.value));

        good_peers
            .into_iter()
            .take(limit)
            .map(|p| (p.id, p.addresses))
            .collect()
    }

    /// Clean up stale peers.
    pub async fn cleanup_stale(&self, max_age: Duration) {
        let mut peers = self.peers_by_id.write().await;
        let mut by_addr = self.peers_by_addr.write().await;

        let now = Utc::now();
        let max_age_ms = max_age.as_millis() as i64;

        let stale: Vec<PeerId> = peers
            .iter()
            .filter(|(_, p)| {
                // Keep static peers
                if p.source == DiscoverySource::Static {
                    return false;
                }
                // Keep connected peers
                if p.state == PeerState::Connected {
                    return false;
                }
                // Check if stale
                match p.last_seen {
                    Some(last) => (now - last).num_milliseconds() > max_age_ms,
                    None => (now - p.first_seen).num_milliseconds() > max_age_ms,
                }
            })
            .map(|(id, _)| id.clone())
            .collect();

        for id in stale {
            if let Some(info) = peers.remove(&id) {
                for addr in &info.addresses {
                    by_addr.remove(addr);
                }
            }
        }
    }

    /// Get discovery statistics.
    pub async fn stats(&self) -> DiscoveryStats {
        let peers = self.peers_by_id.read().await;
        let banned = self.banned.read().await;

        DiscoveryStats {
            total_peers: peers.len(),
            connected_peers: peers
                .values()
                .filter(|p| p.state == PeerState::Connected)
                .count(),
            known_peers: peers
                .values()
                .filter(|p| p.state == PeerState::Known)
                .count(),
            disconnected_peers: peers
                .values()
                .filter(|p| p.state == PeerState::Disconnected)
                .count(),
            banned_peers: banned.len(),
            good_peers: peers.values().filter(|p| p.score.is_good()).count(),
            static_peers: peers
                .values()
                .filter(|p| p.source == DiscoverySource::Static)
                .count(),
            dns_peers: peers
                .values()
                .filter(|p| p.source == DiscoverySource::Dns)
                .count(),
            exchanged_peers: peers
                .values()
                .filter(|p| p.source == DiscoverySource::PeerExchange)
                .count(),
        }
    }
}

/// Discovery statistics.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DiscoveryStats {
    /// Total known peers.
    pub total_peers: usize,
    /// Currently connected peers.
    pub connected_peers: usize,
    /// Known but not connected.
    pub known_peers: usize,
    /// Previously connected but now disconnected.
    pub disconnected_peers: usize,
    /// Banned peers.
    pub banned_peers: usize,
    /// Peers with good scores.
    pub good_peers: usize,
    /// Peers from static config.
    pub static_peers: usize,
    /// Peers from DNS discovery.
    pub dns_peers: usize,
    /// Peers from peer exchange.
    pub exchanged_peers: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use moloch_core::crypto::SecretKey;

    fn test_peer_id() -> PeerId {
        PeerId::new(SecretKey::generate().public_key())
    }

    fn test_addr(port: u16) -> SocketAddr {
        format!("127.0.0.1:{}", port).parse().unwrap()
    }

    #[test]
    fn test_peer_score_default() {
        let score = PeerScore::default();
        assert_eq!(score.value, 500);
        assert!(!score.is_banned());
        assert!(!score.is_good());
    }

    #[test]
    fn test_peer_score_connection_success() {
        let mut score = PeerScore::default();
        for _ in 0..20 {
            score.connection_success();
        }
        assert!(score.is_good());
    }

    #[test]
    fn test_peer_score_connection_failure() {
        let mut score = PeerScore::default();
        // Reduce reliability to 0
        for _ in 0..10 {
            score.connection_failure();
        }
        // Also add misbehavior to further reduce score
        score.record_misbehavior(500);
        // And simulate bad latency
        score.update_latency(2000);
        // Now the score should be below ban threshold
        assert!(score.is_banned());
    }

    #[test]
    fn test_peer_score_latency() {
        let mut score = PeerScore::default();

        // Good latency
        score.update_latency(30);
        assert_eq!(score.latency_score, 1000);

        // Bad latency
        score.update_latency(2000);
        assert_eq!(score.latency_score, 100);
    }

    #[test]
    fn test_peer_info_success_rate() {
        let mut info = PeerInfo::new(
            test_peer_id(),
            vec![test_addr(8000)],
            DiscoverySource::Static,
        );

        info.record_success();
        info.record_success();
        info.record_failure();

        assert!((info.success_rate() - 66.666).abs() < 0.1);
    }

    #[test]
    fn test_peer_state_display() {
        assert_eq!(format!("{}", PeerState::Connected), "connected");
        assert_eq!(format!("{}", PeerState::Banned), "banned");
    }

    #[test]
    fn test_discovery_source_display() {
        assert_eq!(format!("{}", DiscoverySource::Static), "static");
        assert_eq!(
            format!("{}", DiscoverySource::PeerExchange),
            "peer_exchange"
        );
    }

    #[tokio::test]
    async fn test_peer_discovery_add_remove() {
        let config = DiscoveryConfig::default();
        let discovery = PeerDiscovery::new(config);

        let peer_id = test_peer_id();
        let addr = test_addr(8000);

        // Add static peer
        discovery.add_static_peer(addr, Some(peer_id.clone())).await;

        // Check it exists
        let info = discovery.get_peer(&peer_id).await;
        assert!(info.is_some());
        assert_eq!(info.unwrap().source, DiscoverySource::Static);

        // Remove peer
        let removed = discovery.remove_peer(&peer_id).await;
        assert!(removed.is_some());

        // Check it's gone
        assert!(discovery.get_peer(&peer_id).await.is_none());
    }

    #[tokio::test]
    async fn test_peer_discovery_incoming() {
        let config = DiscoveryConfig::default();
        let discovery = PeerDiscovery::new(config);

        let peer_id = test_peer_id();
        let addr = test_addr(8000);

        // Add incoming peer
        let added = discovery.add_incoming_peer(addr, peer_id.clone()).await;
        assert!(added);

        // Check state is connected
        let info = discovery.get_peer(&peer_id).await.unwrap();
        assert_eq!(info.state, PeerState::Connected);
        assert_eq!(info.connection_successes, 1);
    }

    #[tokio::test]
    async fn test_peer_discovery_ban() {
        let config = DiscoveryConfig::default();
        let discovery = PeerDiscovery::new(config);

        let peer_id = test_peer_id();
        let addr = test_addr(8000);

        discovery.add_static_peer(addr, Some(peer_id.clone())).await;

        // Ban peer
        discovery.ban_peer(&peer_id, "test reason").await;

        // Check it's banned
        assert!(discovery.is_banned(&peer_id).await);
        let info = discovery.get_peer(&peer_id).await.unwrap();
        assert_eq!(info.state, PeerState::Banned);

        // Unban
        discovery.unban_peer(&peer_id).await;
        assert!(!discovery.is_banned(&peer_id).await);
    }

    #[tokio::test]
    async fn test_peer_discovery_max_peers() {
        let mut config = DiscoveryConfig::default();
        config.max_peers = 5;
        let discovery = PeerDiscovery::new(config);

        // Add 5 peers
        for i in 0..5 {
            let peer_id = test_peer_id();
            discovery
                .add_incoming_peer(test_addr(8000 + i), peer_id)
                .await;
        }

        // 6th should fail
        let peer_id = test_peer_id();
        let added = discovery.add_incoming_peer(test_addr(9000), peer_id).await;
        assert!(!added);
    }

    #[tokio::test]
    async fn test_peer_discovery_peer_exchange() {
        let config = DiscoveryConfig::default();
        let discovery = PeerDiscovery::new(config);

        let peers = vec![
            (test_peer_id(), vec![test_addr(8000)]),
            (test_peer_id(), vec![test_addr(8001), test_addr(8002)]),
        ];

        let added = discovery.add_exchanged_peers(peers).await;
        assert_eq!(added, 2);
        assert_eq!(discovery.peer_count().await, 2);
    }

    #[tokio::test]
    async fn test_peer_discovery_update_state() {
        let config = DiscoveryConfig::default();
        let discovery = PeerDiscovery::new(config);

        let peer_id = test_peer_id();
        discovery
            .add_static_peer(test_addr(8000), Some(peer_id.clone()))
            .await;

        discovery
            .update_state(&peer_id, PeerState::Connecting)
            .await;
        let info = discovery.get_peer(&peer_id).await.unwrap();
        assert_eq!(info.state, PeerState::Connecting);
    }

    #[tokio::test]
    async fn test_peer_discovery_latency() {
        let config = DiscoveryConfig::default();
        let discovery = PeerDiscovery::new(config);

        let peer_id = test_peer_id();
        discovery
            .add_static_peer(test_addr(8000), Some(peer_id.clone()))
            .await;

        discovery.update_latency(&peer_id, 50).await;
        let info = discovery.get_peer(&peer_id).await.unwrap();
        assert_eq!(info.score.avg_latency_ms, Some(50));
    }

    #[tokio::test]
    async fn test_peer_discovery_stats() {
        let config = DiscoveryConfig::default();
        let discovery = PeerDiscovery::new(config);

        let peer1 = test_peer_id();
        let peer2 = test_peer_id();

        discovery
            .add_static_peer(test_addr(8000), Some(peer1.clone()))
            .await;
        discovery
            .add_incoming_peer(test_addr(8001), peer2.clone())
            .await;

        let stats = discovery.stats().await;
        assert_eq!(stats.total_peers, 2);
        assert_eq!(stats.connected_peers, 1);
        assert_eq!(stats.static_peers, 1);
    }

    #[tokio::test]
    async fn test_peer_discovery_peers_to_connect() {
        let config = DiscoveryConfig::default();
        let discovery = PeerDiscovery::new(config);

        let peer1 = test_peer_id();
        let peer2 = test_peer_id();

        discovery
            .add_static_peer(test_addr(8000), Some(peer1.clone()))
            .await;
        discovery
            .add_static_peer(test_addr(8001), Some(peer2.clone()))
            .await;

        // Update one peer's score
        {
            let mut peers = discovery.peers_by_id.write().await;
            if let Some(p) = peers.get_mut(&peer1) {
                for _ in 0..10 {
                    p.score.connection_success();
                }
            }
        }

        let candidates = discovery.peers_to_connect(5).await;
        assert_eq!(candidates.len(), 2);
        // Higher score should be first
        assert_eq!(candidates[0].id, peer1);
    }

    #[tokio::test]
    async fn test_peer_discovery_banned_not_connected() {
        let config = DiscoveryConfig::default();
        let discovery = PeerDiscovery::new(config);

        let peer_id = test_peer_id();
        discovery
            .add_static_peer(test_addr(8000), Some(peer_id.clone()))
            .await;
        discovery.ban_peer(&peer_id, "test").await;

        // Banned peer shouldn't be in connect candidates
        let candidates = discovery.peers_to_connect(5).await;
        assert!(candidates.is_empty());

        // Should reject incoming from banned
        let added = discovery.add_incoming_peer(test_addr(8001), peer_id).await;
        assert!(!added);
    }
}
