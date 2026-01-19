//! Chain synchronization protocol for Moloch.
//!
//! Supports multiple sync modes:
//! - Fast sync: Download blocks and verify MMR
//! - Snap sync: Download state snapshot
//! - Catch-up sync: Fill gaps in the chain
//! - Warp sync: Skip to a recent checkpoint
//!
//! The sync manager coordinates with peers to efficiently sync the chain.

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tokio::sync::{mpsc, oneshot, RwLock};
use tracing::{debug, error, info, trace, warn};

use crate::discovery::PeerInfo;
use crate::protocol::{
    generate_message_id, BlocksMessage, GetBlocksMessage, GetHeadersMessage, GetSnapshotMessage,
    HeadersMessage, Message, MessageId, PeerId, SnapshotMessage,
};
use moloch_core::block::{Block, BlockHash, BlockHeader};
use moloch_core::crypto::Hash;

/// Synchronization mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SyncMode {
    /// Full sync from genesis.
    Full,
    /// Fast sync: download blocks and verify MMR proofs.
    Fast,
    /// Snap sync: download recent state snapshot.
    Snap,
    /// Catch-up: fill gaps and stay current.
    CatchUp,
    /// Warp sync: skip to recent checkpoint.
    Warp,
}

impl Default for SyncMode {
    fn default() -> Self {
        SyncMode::Fast
    }
}

impl std::fmt::Display for SyncMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SyncMode::Full => write!(f, "full"),
            SyncMode::Fast => write!(f, "fast"),
            SyncMode::Snap => write!(f, "snap"),
            SyncMode::CatchUp => write!(f, "catch-up"),
            SyncMode::Warp => write!(f, "warp"),
        }
    }
}

/// Current sync status.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncStatus {
    /// Current sync mode.
    pub mode: SyncMode,
    /// Current sync state.
    pub state: SyncState,
    /// Local chain height.
    pub local_height: Option<u64>,
    /// Target chain height (highest seen).
    pub target_height: Option<u64>,
    /// Blocks per second (recent rate).
    pub blocks_per_second: f64,
    /// Estimated time to sync.
    pub eta_seconds: Option<u64>,
    /// Number of peers syncing with.
    pub sync_peers: usize,
    /// When sync started.
    pub started_at: Option<DateTime<Utc>>,
    /// Progress percentage.
    pub progress: f64,
}

impl Default for SyncStatus {
    fn default() -> Self {
        Self {
            mode: SyncMode::default(),
            state: SyncState::Idle,
            local_height: None,
            target_height: None,
            blocks_per_second: 0.0,
            eta_seconds: None,
            sync_peers: 0,
            started_at: None,
            progress: 0.0,
        }
    }
}

impl SyncStatus {
    /// Check if sync is in progress.
    pub fn is_syncing(&self) -> bool {
        matches!(
            self.state,
            SyncState::Downloading | SyncState::Verifying | SyncState::Applying
        )
    }

    /// Check if sync is complete.
    pub fn is_synced(&self) -> bool {
        self.state == SyncState::Synced
    }

    /// Calculate progress percentage.
    pub fn calculate_progress(&mut self) {
        match (self.local_height, self.target_height) {
            (Some(local), Some(target)) if target > 0 => {
                self.progress = (local as f64 / target as f64) * 100.0;
            }
            _ => self.progress = 0.0,
        }
    }
}

/// State of the sync process.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SyncState {
    /// Not syncing.
    Idle,
    /// Finding peers.
    FindingPeers,
    /// Downloading headers.
    DownloadingHeaders,
    /// Downloading blocks.
    Downloading,
    /// Verifying downloaded data.
    Verifying,
    /// Applying blocks to chain.
    Applying,
    /// Fully synced.
    Synced,
    /// Sync failed.
    Failed,
    /// Sync paused.
    Paused,
}

impl std::fmt::Display for SyncState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SyncState::Idle => write!(f, "idle"),
            SyncState::FindingPeers => write!(f, "finding_peers"),
            SyncState::DownloadingHeaders => write!(f, "downloading_headers"),
            SyncState::Downloading => write!(f, "downloading"),
            SyncState::Verifying => write!(f, "verifying"),
            SyncState::Applying => write!(f, "applying"),
            SyncState::Synced => write!(f, "synced"),
            SyncState::Failed => write!(f, "failed"),
            SyncState::Paused => write!(f, "paused"),
        }
    }
}

/// Configuration for sync manager.
#[derive(Debug, Clone)]
pub struct SyncConfig {
    /// Sync mode to use.
    pub mode: SyncMode,
    /// Maximum blocks per request.
    pub batch_size: u32,
    /// Maximum concurrent requests.
    pub max_concurrent_requests: usize,
    /// Request timeout.
    pub request_timeout: Duration,
    /// Maximum retries per request.
    pub max_retries: u32,
    /// Minimum peers required to sync.
    pub min_peers: usize,
    /// How far behind before starting sync.
    pub sync_threshold: u64,
    /// Checkpoint to sync to (for warp sync).
    pub checkpoint: Option<Checkpoint>,
    /// Enable header-first sync.
    pub header_first: bool,
}

impl Default for SyncConfig {
    fn default() -> Self {
        Self {
            mode: SyncMode::Fast,
            batch_size: 100,
            max_concurrent_requests: 4,
            request_timeout: Duration::from_secs(30),
            max_retries: 3,
            min_peers: 1,
            sync_threshold: 10,
            checkpoint: None,
            header_first: true,
        }
    }
}

/// A sync checkpoint (trusted state).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Checkpoint {
    /// Block height.
    pub height: u64,
    /// Block hash at this height.
    pub hash: BlockHash,
    /// MMR root at this height.
    pub mmr_root: Hash,
    /// When this checkpoint was created.
    pub created_at: DateTime<Utc>,
}

/// A pending sync request.
#[derive(Debug)]
struct PendingRequest {
    /// Request ID.
    id: MessageId,
    /// Peer the request was sent to.
    peer: PeerId,
    /// Request type.
    kind: RequestKind,
    /// When the request was sent.
    sent_at: Instant,
    /// Retry count.
    retries: u32,
}

/// Type of sync request.
#[derive(Debug, Clone)]
enum RequestKind {
    Headers { start: u64, count: u32 },
    Blocks { start: u64, count: u32 },
    Snapshot { height: Option<u64> },
}

/// A block range being synced.
#[derive(Debug, Clone)]
struct SyncRange {
    /// Start height (inclusive).
    start: u64,
    /// End height (exclusive).
    end: u64,
    /// Peer assigned to this range.
    peer: Option<PeerId>,
    /// Request ID if in progress.
    request_id: Option<MessageId>,
    /// Number of retries.
    retries: u32,
}

/// Sync manager coordinates chain synchronization.
#[derive(Debug)]
pub struct SyncManager {
    /// Configuration.
    config: SyncConfig,
    /// Current status.
    status: RwLock<SyncStatus>,
    /// Pending requests.
    pending_requests: RwLock<HashMap<MessageId, PendingRequest>>,
    /// Ranges being synced.
    sync_ranges: RwLock<VecDeque<SyncRange>>,
    /// Downloaded blocks (waiting to be applied).
    block_buffer: RwLock<HashMap<u64, Block>>,
    /// Downloaded headers (for header-first sync).
    header_buffer: RwLock<HashMap<u64, BlockHeader>>,
    /// Peers and their reported heights.
    peer_heights: RwLock<HashMap<PeerId, u64>>,
    /// Blocks successfully synced.
    synced_count: std::sync::atomic::AtomicU64,
    /// Sync start time (for rate calculation).
    sync_start: RwLock<Option<Instant>>,
}

impl SyncManager {
    /// Create a new sync manager.
    pub fn new(config: SyncConfig) -> Self {
        Self {
            config,
            status: RwLock::new(SyncStatus::default()),
            pending_requests: RwLock::new(HashMap::new()),
            sync_ranges: RwLock::new(VecDeque::new()),
            block_buffer: RwLock::new(HashMap::new()),
            header_buffer: RwLock::new(HashMap::new()),
            peer_heights: RwLock::new(HashMap::new()),
            synced_count: std::sync::atomic::AtomicU64::new(0),
            sync_start: RwLock::new(None),
        }
    }

    /// Get the configuration.
    pub fn config(&self) -> &SyncConfig {
        &self.config
    }

    /// Get the current sync status.
    pub async fn status(&self) -> SyncStatus {
        let mut status = self.status.read().await.clone();
        status.calculate_progress();
        self.update_rate(&mut status).await;
        status
    }

    /// Update sync rate statistics.
    async fn update_rate(&self, status: &mut SyncStatus) {
        let sync_start = self.sync_start.read().await;
        if let Some(start) = *sync_start {
            let elapsed = start.elapsed().as_secs_f64();
            if elapsed > 0.0 {
                let synced = self.synced_count.load(std::sync::atomic::Ordering::Relaxed);
                status.blocks_per_second = synced as f64 / elapsed;

                // Calculate ETA
                if let (Some(local), Some(target)) = (status.local_height, status.target_height) {
                    if status.blocks_per_second > 0.0 && target > local {
                        let remaining = target - local;
                        status.eta_seconds = Some((remaining as f64 / status.blocks_per_second) as u64);
                    }
                }
            }
        }
    }

    /// Check if we need to sync.
    pub async fn needs_sync(&self, local_height: Option<u64>) -> bool {
        let peer_heights = self.peer_heights.read().await;

        if peer_heights.is_empty() {
            return false;
        }

        let max_peer_height = peer_heights.values().copied().max().unwrap_or(0);
        let local = local_height.unwrap_or(0);

        max_peer_height > local + self.config.sync_threshold
    }

    /// Update a peer's reported height.
    pub async fn update_peer_height(&self, peer: PeerId, height: u64) {
        let mut heights = self.peer_heights.write().await;
        heights.insert(peer, height);

        // Update target height
        let max_height = heights.values().copied().max().unwrap_or(0);
        let mut status = self.status.write().await;
        status.target_height = Some(max_height);
    }

    /// Remove a peer (on disconnect).
    pub async fn remove_peer(&self, peer: &PeerId) {
        self.peer_heights.write().await.remove(peer);

        // Cancel pending requests from this peer
        let mut pending = self.pending_requests.write().await;
        let to_remove: Vec<_> = pending
            .iter()
            .filter(|(_, req)| &req.peer == peer)
            .map(|(id, _)| *id)
            .collect();

        for id in to_remove {
            pending.remove(&id);
        }

        // Mark ranges assigned to this peer as unassigned
        let mut ranges = self.sync_ranges.write().await;
        for range in ranges.iter_mut() {
            if range.peer.as_ref() == Some(peer) {
                range.peer = None;
                range.request_id = None;
            }
        }
    }

    /// Start syncing from a specific height.
    pub async fn start_sync(&self, from_height: u64, to_height: u64) {
        info!("Starting sync from {} to {}", from_height, to_height);

        let mut status = self.status.write().await;
        status.state = SyncState::Downloading;
        status.local_height = Some(from_height);
        status.target_height = Some(to_height);
        status.started_at = Some(Utc::now());
        drop(status);

        // Create sync ranges
        let mut ranges = self.sync_ranges.write().await;
        ranges.clear();

        let batch_size = self.config.batch_size as u64;
        let mut start = from_height;

        while start < to_height {
            let end = (start + batch_size).min(to_height);
            ranges.push_back(SyncRange {
                start,
                end,
                peer: None,
                request_id: None,
                retries: 0,
            });
            start = end;
        }

        *self.sync_start.write().await = Some(Instant::now());
        self.synced_count
            .store(0, std::sync::atomic::Ordering::SeqCst);
    }

    /// Pause syncing.
    pub async fn pause_sync(&self) {
        let mut status = self.status.write().await;
        if status.is_syncing() {
            status.state = SyncState::Paused;
        }
    }

    /// Resume syncing.
    pub async fn resume_sync(&self) {
        let mut status = self.status.write().await;
        if status.state == SyncState::Paused {
            status.state = SyncState::Downloading;
        }
    }

    /// Get the next sync request to send.
    ///
    /// Returns (peer_id, message) if there's work to do.
    pub async fn next_request(&self, available_peers: &[PeerInfo]) -> Option<(PeerId, Message)> {
        let status = self.status.read().await;
        if !status.is_syncing() {
            return None;
        }
        drop(status);

        // Check if we're at max concurrent requests
        let pending = self.pending_requests.read().await;
        if pending.len() >= self.config.max_concurrent_requests {
            return None;
        }
        drop(pending);

        // Find a range that needs work
        let mut ranges = self.sync_ranges.write().await;

        for range in ranges.iter_mut() {
            if range.peer.is_some() {
                continue; // Already assigned
            }

            // Find a peer that has this range
            let heights = self.peer_heights.read().await;
            let suitable_peer = available_peers.iter().find(|p| {
                heights
                    .get(&p.id)
                    .map(|h| *h >= range.end)
                    .unwrap_or(false)
            });

            if let Some(peer) = suitable_peer {
                let message_id = generate_message_id();

                let message = if self.config.header_first {
                    Message::GetHeaders(GetHeadersMessage {
                        id: message_id,
                        start_height: range.start,
                        count: (range.end - range.start) as u32,
                    })
                } else {
                    Message::GetBlocks(GetBlocksMessage {
                        id: message_id,
                        start_height: range.start,
                        count: (range.end - range.start) as u32,
                    })
                };

                range.peer = Some(peer.id.clone());
                range.request_id = Some(message_id);

                // Track pending request
                let mut pending = self.pending_requests.write().await;
                pending.insert(
                    message_id,
                    PendingRequest {
                        id: message_id,
                        peer: peer.id.clone(),
                        kind: if self.config.header_first {
                            RequestKind::Headers {
                                start: range.start,
                                count: (range.end - range.start) as u32,
                            }
                        } else {
                            RequestKind::Blocks {
                                start: range.start,
                                count: (range.end - range.start) as u32,
                            }
                        },
                        sent_at: Instant::now(),
                        retries: range.retries,
                    },
                );

                return Some((peer.id.clone(), message));
            }
        }

        None
    }

    /// Handle a received blocks response.
    pub async fn handle_blocks(&self, response: BlocksMessage) -> Result<Vec<Block>, SyncError> {
        // Remove from pending
        let mut pending = self.pending_requests.write().await;
        let request = pending.remove(&response.request_id);
        drop(pending);

        if request.is_none() {
            return Err(SyncError::UnexpectedResponse(response.request_id));
        }

        // Store blocks in buffer
        let mut buffer = self.block_buffer.write().await;
        let mut received = Vec::new();

        for block in response.blocks {
            let height = block.header.height;
            buffer.insert(height, block.clone());
            received.push(block);
        }

        // Update synced count
        self.synced_count.fetch_add(
            received.len() as u64,
            std::sync::atomic::Ordering::SeqCst,
        );

        Ok(received)
    }

    /// Handle a received headers response.
    pub async fn handle_headers(&self, response: HeadersMessage) -> Result<Vec<BlockHeader>, SyncError> {
        // Remove from pending
        let mut pending = self.pending_requests.write().await;
        let request = pending.remove(&response.request_id);
        drop(pending);

        if request.is_none() {
            return Err(SyncError::UnexpectedResponse(response.request_id));
        }

        // Store headers in buffer
        let mut buffer = self.header_buffer.write().await;
        let mut received = Vec::new();

        for header in response.headers {
            let height = header.height;
            buffer.insert(height, header.clone());
            received.push(header);
        }

        Ok(received)
    }

    /// Handle a received snapshot response.
    pub async fn handle_snapshot(&self, response: SnapshotMessage) -> Result<(), SyncError> {
        let mut pending = self.pending_requests.write().await;
        let request = pending.remove(&response.request_id);
        drop(pending);

        if request.is_none() {
            return Err(SyncError::UnexpectedResponse(response.request_id));
        }

        // Update local height to snapshot height
        let mut status = self.status.write().await;
        status.local_height = Some(response.height);

        info!(
            "Received snapshot at height {} with {} events",
            response.height, response.event_count
        );

        Ok(())
    }

    /// Get blocks ready to apply (in order).
    pub async fn get_ready_blocks(&self, current_height: u64) -> Vec<Block> {
        let mut buffer = self.block_buffer.write().await;
        let mut ready = Vec::new();

        let mut next_height = current_height + 1;
        while let Some(block) = buffer.remove(&next_height) {
            ready.push(block);
            next_height += 1;
        }

        ready
    }

    /// Mark a range as complete.
    pub async fn complete_range(&self, start: u64, end: u64) {
        let mut ranges = self.sync_ranges.write().await;
        ranges.retain(|r| !(r.start == start && r.end == end));

        // Check if all ranges are complete
        if ranges.is_empty() {
            drop(ranges);
            let mut status = self.status.write().await;
            status.state = SyncState::Synced;
            info!("Sync complete");
        }
    }

    /// Handle a request timeout.
    pub async fn handle_timeout(&self, request_id: MessageId) {
        let mut pending = self.pending_requests.write().await;

        if let Some(request) = pending.remove(&request_id) {
            warn!("Request {} to {} timed out", request_id, request.peer);

            // Mark the range as unassigned for retry
            let mut ranges = self.sync_ranges.write().await;
            for range in ranges.iter_mut() {
                if range.request_id == Some(request_id) {
                    range.peer = None;
                    range.request_id = None;
                    range.retries += 1;

                    if range.retries > self.config.max_retries {
                        warn!("Range {}-{} exceeded max retries", range.start, range.end);
                    }
                    break;
                }
            }
        }
    }

    /// Get timed out requests.
    pub async fn get_timed_out_requests(&self) -> Vec<MessageId> {
        let pending = self.pending_requests.read().await;
        let now = Instant::now();

        pending
            .iter()
            .filter(|(_, req)| now.duration_since(req.sent_at) > self.config.request_timeout)
            .map(|(id, _)| *id)
            .collect()
    }

    /// Request a snapshot from a peer.
    pub fn create_snapshot_request(&self, height: Option<u64>) -> (MessageId, Message) {
        let id = generate_message_id();
        let msg = Message::GetSnapshot(GetSnapshotMessage { id, height });
        (id, msg)
    }

    /// Request blocks from a peer.
    pub fn create_blocks_request(&self, start: u64, count: u32) -> (MessageId, Message) {
        let id = generate_message_id();
        let msg = Message::GetBlocks(GetBlocksMessage {
            id,
            start_height: start,
            count,
        });
        (id, msg)
    }

    /// Request headers from a peer.
    pub fn create_headers_request(&self, start: u64, count: u32) -> (MessageId, Message) {
        let id = generate_message_id();
        let msg = Message::GetHeaders(GetHeadersMessage {
            id,
            start_height: start,
            count,
        });
        (id, msg)
    }

    /// Get sync statistics.
    pub async fn stats(&self) -> SyncStats {
        let status = self.status.read().await;
        let pending = self.pending_requests.read().await;
        let ranges = self.sync_ranges.read().await;
        let block_buffer = self.block_buffer.read().await;
        let header_buffer = self.header_buffer.read().await;
        let peer_heights = self.peer_heights.read().await;

        SyncStats {
            state: status.state,
            mode: status.mode,
            local_height: status.local_height,
            target_height: status.target_height,
            pending_requests: pending.len(),
            remaining_ranges: ranges.len(),
            buffered_blocks: block_buffer.len(),
            buffered_headers: header_buffer.len(),
            known_peers: peer_heights.len(),
            blocks_synced: self.synced_count.load(std::sync::atomic::Ordering::Relaxed),
            blocks_per_second: status.blocks_per_second,
        }
    }
}

/// Sync statistics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncStats {
    /// Current sync state.
    pub state: SyncState,
    /// Sync mode.
    pub mode: SyncMode,
    /// Local chain height.
    pub local_height: Option<u64>,
    /// Target chain height.
    pub target_height: Option<u64>,
    /// Number of pending requests.
    pub pending_requests: usize,
    /// Number of remaining ranges to sync.
    pub remaining_ranges: usize,
    /// Number of buffered blocks.
    pub buffered_blocks: usize,
    /// Number of buffered headers.
    pub buffered_headers: usize,
    /// Number of known peer heights.
    pub known_peers: usize,
    /// Total blocks synced.
    pub blocks_synced: u64,
    /// Blocks per second.
    pub blocks_per_second: f64,
}

/// Sync errors.
#[derive(Debug, thiserror::Error)]
pub enum SyncError {
    #[error("unexpected response for request {0}")]
    UnexpectedResponse(MessageId),

    #[error("request timed out: {0}")]
    Timeout(MessageId),

    #[error("not enough peers: have {have}, need {need}")]
    NotEnoughPeers { have: usize, need: usize },

    #[error("invalid block at height {0}")]
    InvalidBlock(u64),

    #[error("chain mismatch at height {0}")]
    ChainMismatch(u64),

    #[error("sync cancelled")]
    Cancelled,

    #[error("peer error: {0}")]
    PeerError(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use moloch_core::crypto::SecretKey;

    fn test_peer_id() -> PeerId {
        crate::protocol::PeerId::new(SecretKey::generate().public_key())
    }

    fn test_peer_info(height: u64) -> PeerInfo {
        use crate::discovery::{DiscoverySource, PeerScore, PeerState, PeerMetadata};

        PeerInfo {
            id: test_peer_id(),
            addresses: vec!["127.0.0.1:8000".parse().unwrap()],
            state: PeerState::Connected,
            score: PeerScore::default(),
            first_seen: Utc::now(),
            last_seen: Some(Utc::now()),
            connection_successes: 1,
            connection_failures: 0,
            source: DiscoverySource::Static,
            metadata: PeerMetadata {
                height: Some(height),
                ..Default::default()
            },
        }
    }

    #[test]
    fn test_sync_mode_display() {
        assert_eq!(format!("{}", SyncMode::Fast), "fast");
        assert_eq!(format!("{}", SyncMode::Snap), "snap");
    }

    #[test]
    fn test_sync_state_display() {
        assert_eq!(format!("{}", SyncState::Downloading), "downloading");
        assert_eq!(format!("{}", SyncState::Synced), "synced");
    }

    #[test]
    fn test_sync_status_default() {
        let status = SyncStatus::default();
        assert!(!status.is_syncing());
        assert!(!status.is_synced());
        assert_eq!(status.progress, 0.0);
    }

    #[test]
    fn test_sync_status_progress() {
        let mut status = SyncStatus {
            local_height: Some(50),
            target_height: Some(100),
            ..Default::default()
        };

        status.calculate_progress();
        assert_eq!(status.progress, 50.0);
    }

    #[tokio::test]
    async fn test_sync_manager_creation() {
        let config = SyncConfig::default();
        let manager = SyncManager::new(config);

        let status = manager.status().await;
        assert_eq!(status.state, SyncState::Idle);
    }

    #[tokio::test]
    async fn test_sync_manager_peer_heights() {
        let config = SyncConfig::default();
        let manager = SyncManager::new(config);

        let peer1 = test_peer_id();
        let peer2 = test_peer_id();

        manager.update_peer_height(peer1.clone(), 100).await;
        manager.update_peer_height(peer2.clone(), 200).await;

        let status = manager.status().await;
        assert_eq!(status.target_height, Some(200));

        // Remove peer
        manager.remove_peer(&peer2).await;
        let status = manager.status().await;
        assert_eq!(status.target_height, Some(200)); // Still 200 (target doesn't decrease automatically)
    }

    #[tokio::test]
    async fn test_sync_manager_needs_sync() {
        let mut config = SyncConfig::default();
        config.sync_threshold = 10;
        let manager = SyncManager::new(config);

        // No peers = no sync needed
        assert!(!manager.needs_sync(Some(50)).await);

        // Add peer with higher height
        let peer = test_peer_id();
        manager.update_peer_height(peer, 100).await;

        // Should sync (100 - 50 > 10)
        assert!(manager.needs_sync(Some(50)).await);

        // Shouldn't sync if close
        assert!(!manager.needs_sync(Some(95)).await);
    }

    #[tokio::test]
    async fn test_sync_manager_start_sync() {
        let config = SyncConfig::default();
        let manager = SyncManager::new(config);

        manager.start_sync(0, 1000).await;

        let status = manager.status().await;
        assert_eq!(status.state, SyncState::Downloading);
        assert_eq!(status.local_height, Some(0));
        assert_eq!(status.target_height, Some(1000));

        // Check ranges were created
        let ranges = manager.sync_ranges.read().await;
        assert!(!ranges.is_empty());
    }

    #[tokio::test]
    async fn test_sync_manager_pause_resume() {
        let config = SyncConfig::default();
        let manager = SyncManager::new(config);

        manager.start_sync(0, 100).await;

        // Pause
        manager.pause_sync().await;
        let status = manager.status().await;
        assert_eq!(status.state, SyncState::Paused);

        // Resume
        manager.resume_sync().await;
        let status = manager.status().await;
        assert_eq!(status.state, SyncState::Downloading);
    }

    #[tokio::test]
    async fn test_sync_manager_next_request() {
        let config = SyncConfig::default();
        let manager = SyncManager::new(config);

        // No sync started = no request
        let request = manager.next_request(&[]).await;
        assert!(request.is_none());

        // Start sync
        manager.start_sync(0, 100).await;

        // No available peers = no request
        let request = manager.next_request(&[]).await;
        assert!(request.is_none());

        // With a suitable peer
        let peer = test_peer_info(100);
        manager.update_peer_height(peer.id.clone(), 100).await;

        let request = manager.next_request(&[peer]).await;
        assert!(request.is_some());
    }

    #[tokio::test]
    async fn test_sync_manager_handle_blocks() {
        let config = SyncConfig::default();
        let manager = SyncManager::new(config);

        // Handle unexpected response
        let response = BlocksMessage {
            request_id: 999,
            blocks: vec![],
            has_more: false,
        };
        let result = manager.handle_blocks(response).await;
        assert!(matches!(result, Err(SyncError::UnexpectedResponse(999))));
    }

    #[tokio::test]
    async fn test_sync_manager_create_requests() {
        let config = SyncConfig::default();
        let manager = SyncManager::new(config);

        let (id1, msg1) = manager.create_blocks_request(0, 100);
        assert!(matches!(msg1, Message::GetBlocks(_)));

        let (id2, msg2) = manager.create_headers_request(100, 50);
        assert!(matches!(msg2, Message::GetHeaders(_)));

        let (id3, msg3) = manager.create_snapshot_request(Some(500));
        assert!(matches!(msg3, Message::GetSnapshot(_)));

        // IDs should be unique
        assert_ne!(id1, id2);
        assert_ne!(id2, id3);
    }

    #[tokio::test]
    async fn test_sync_manager_stats() {
        let config = SyncConfig::default();
        let manager = SyncManager::new(config);

        manager.start_sync(0, 100).await;

        let stats = manager.stats().await;
        assert_eq!(stats.state, SyncState::Downloading);
        assert!(stats.remaining_ranges > 0);
        assert_eq!(stats.buffered_blocks, 0);
    }

    #[tokio::test]
    async fn test_sync_manager_timeout() {
        let config = SyncConfig::default();
        let manager = SyncManager::new(config);

        // Add a fake pending request
        let request_id = generate_message_id();
        {
            let mut pending = manager.pending_requests.write().await;
            pending.insert(
                request_id,
                PendingRequest {
                    id: request_id,
                    peer: test_peer_id(),
                    kind: RequestKind::Blocks { start: 0, count: 100 },
                    sent_at: Instant::now() - Duration::from_secs(60),
                    retries: 0,
                },
            );
        }

        // Should detect timeout
        let timed_out = manager.get_timed_out_requests().await;
        assert_eq!(timed_out.len(), 1);
        assert_eq!(timed_out[0], request_id);

        // Handle timeout
        manager.handle_timeout(request_id).await;
        let pending = manager.pending_requests.read().await;
        assert!(!pending.contains_key(&request_id));
    }

    #[tokio::test]
    async fn test_sync_manager_complete_range() {
        let config = SyncConfig::default();
        let manager = SyncManager::new(config);

        manager.start_sync(0, 100).await;

        let initial_count = manager.sync_ranges.read().await.len();
        assert!(initial_count > 0);

        // Complete the first range
        manager.complete_range(0, 100).await;

        let status = manager.status().await;
        assert_eq!(status.state, SyncState::Synced);
    }

    #[test]
    fn test_checkpoint() {
        let checkpoint = Checkpoint {
            height: 1000,
            hash: moloch_core::block::BlockHash(moloch_core::crypto::hash(b"block")),
            mmr_root: moloch_core::crypto::hash(b"mmr"),
            created_at: Utc::now(),
        };

        assert_eq!(checkpoint.height, 1000);
    }
}
