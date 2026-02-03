//! Header synchronization for light clients.
//!
//! Light clients sync only block headers, not full blocks.
//! This allows verification with minimal bandwidth and storage.

use std::time::Duration;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;

use crate::checkpoint::TrustedCheckpoint;
use crate::errors::Result;
use crate::header::{HeaderChain, TrustedHeader};

/// Sync engine configuration.
#[derive(Debug, Clone)]
pub struct SyncConfig {
    /// Maximum headers to request per batch.
    pub batch_size: usize,
    /// Timeout for sync requests.
    pub request_timeout: Duration,
    /// Maximum concurrent requests.
    pub max_concurrent: usize,
    /// Interval between sync attempts.
    pub sync_interval: Duration,
}

impl Default for SyncConfig {
    fn default() -> Self {
        Self {
            batch_size: 100,
            request_timeout: Duration::from_secs(10),
            max_concurrent: 4,
            sync_interval: Duration::from_secs(1),
        }
    }
}

/// Current sync status.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SyncStatus {
    /// Not started.
    Idle,
    /// Syncing from checkpoint.
    SyncingFromCheckpoint {
        /// Checkpoint height.
        checkpoint: u64,
        /// Current height.
        current: u64,
        /// Target height.
        target: u64,
    },
    /// Syncing headers.
    Syncing {
        /// Current synced height.
        current: u64,
        /// Target height.
        target: u64,
    },
    /// Fully synced.
    Synced {
        /// Current height.
        height: u64,
    },
    /// Sync error.
    Error {
        /// Error message.
        message: String,
    },
}

impl SyncStatus {
    /// Check if synced.
    pub fn is_synced(&self) -> bool {
        matches!(self, SyncStatus::Synced { .. })
    }

    /// Get sync progress as percentage.
    pub fn progress(&self) -> f64 {
        match self {
            SyncStatus::Idle => 0.0,
            SyncStatus::SyncingFromCheckpoint {
                checkpoint,
                current,
                target,
            } => {
                if *target <= *checkpoint {
                    100.0
                } else {
                    ((current - checkpoint) as f64 / (target - checkpoint) as f64) * 100.0
                }
            }
            SyncStatus::Syncing { current, target } => {
                if *target == 0 {
                    100.0
                } else {
                    (*current as f64 / *target as f64) * 100.0
                }
            }
            SyncStatus::Synced { .. } => 100.0,
            SyncStatus::Error { .. } => 0.0,
        }
    }
}

/// Detailed sync progress information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncProgress {
    /// Current status.
    pub status: SyncStatus,
    /// Headers synced per second.
    pub headers_per_second: f64,
    /// Estimated time remaining.
    pub eta_seconds: Option<u64>,
    /// Total bytes downloaded.
    pub bytes_downloaded: u64,
    /// Number of peers connected.
    pub peer_count: usize,
}

/// Provider of headers for syncing.
#[async_trait]
pub trait HeaderProvider: Send + Sync {
    /// Get the current chain tip height.
    async fn tip_height(&self) -> Result<u64>;

    /// Get headers in a range.
    async fn get_headers(&self, start: u64, count: usize) -> Result<Vec<TrustedHeader>>;

    /// Get a single header.
    async fn get_header(&self, height: u64) -> Result<Option<TrustedHeader>>;
}

/// Header sync engine.
pub struct SyncEngine<P: HeaderProvider> {
    /// Configuration.
    config: SyncConfig,
    /// Header provider (network or local).
    provider: P,
    /// Header chain being built.
    chain: HeaderChain,
    /// Current status.
    status: SyncStatus,
    /// Status update channel.
    status_tx: Option<mpsc::Sender<SyncStatus>>,
}

impl<P: HeaderProvider> SyncEngine<P> {
    /// Create a new sync engine.
    pub fn new(config: SyncConfig, provider: P, checkpoint: TrustedCheckpoint) -> Self {
        let chain = HeaderChain::new(checkpoint.header, checkpoint.validators);
        Self {
            config,
            provider,
            chain,
            status: SyncStatus::Idle,
            status_tx: None,
        }
    }

    /// Set status update channel.
    pub fn with_status_channel(mut self, tx: mpsc::Sender<SyncStatus>) -> Self {
        self.status_tx = Some(tx);
        self
    }

    /// Get current sync status.
    pub fn status(&self) -> &SyncStatus {
        &self.status
    }

    /// Get the header chain.
    pub fn chain(&self) -> &HeaderChain {
        &self.chain
    }

    /// Get current synced height.
    pub fn height(&self) -> u64 {
        self.chain.height()
    }

    /// Perform a sync cycle.
    pub async fn sync(&mut self) -> Result<()> {
        // Get current tip from provider
        let target = self.provider.tip_height().await?;
        let current = self.chain.height();

        if current >= target {
            self.update_status(SyncStatus::Synced { height: current });
            return Ok(());
        }

        self.update_status(SyncStatus::Syncing { current, target });

        // Sync in batches
        let mut height = current + 1;
        while height <= target {
            let count = self.config.batch_size.min((target - height + 1) as usize);
            let headers = self.provider.get_headers(height, count).await?;

            if headers.is_empty() {
                break;
            }

            for header in headers {
                self.chain.add_header(header)?;
                height += 1;
            }

            self.update_status(SyncStatus::Syncing {
                current: height - 1,
                target,
            });
        }

        self.update_status(SyncStatus::Synced {
            height: self.chain.height(),
        });
        Ok(())
    }

    /// Run continuous sync loop.
    pub async fn run(&mut self) -> Result<()> {
        loop {
            if let Err(e) = self.sync().await {
                self.update_status(SyncStatus::Error {
                    message: e.to_string(),
                });
            }

            if self.status.is_synced() {
                tokio::time::sleep(self.config.sync_interval).await;
            }
        }
    }

    fn update_status(&mut self, status: SyncStatus) {
        self.status = status.clone();
        if let Some(ref tx) = self.status_tx {
            let _ = tx.try_send(status);
        }
    }
}

/// Mock header provider for testing.
#[cfg(test)]
pub struct MockHeaderProvider {
    headers: Vec<TrustedHeader>,
}

#[cfg(test)]
#[allow(missing_docs)]
impl MockHeaderProvider {
    /// Create a new mock provider with the given headers.
    pub fn new(headers: Vec<TrustedHeader>) -> Self {
        Self { headers }
    }
}

#[cfg(test)]
#[async_trait]
impl HeaderProvider for MockHeaderProvider {
    async fn tip_height(&self) -> Result<u64> {
        Ok(self.headers.last().map(|h| h.height()).unwrap_or(0))
    }

    async fn get_headers(&self, start: u64, count: usize) -> Result<Vec<TrustedHeader>> {
        Ok(self
            .headers
            .iter()
            .filter(|h| h.height() >= start)
            .take(count)
            .cloned()
            .collect())
    }

    async fn get_header(&self, height: u64) -> Result<Option<TrustedHeader>> {
        Ok(self.headers.iter().find(|h| h.height() == height).cloned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sync_progress() {
        let status = SyncStatus::Syncing {
            current: 500,
            target: 1000,
        };
        assert!((status.progress() - 50.0).abs() < 0.01);

        let status = SyncStatus::Synced { height: 1000 };
        assert!(status.is_synced());
        assert!((status.progress() - 100.0).abs() < 0.01);
    }

    #[test]
    fn test_sync_config_default() {
        let config = SyncConfig::default();
        assert_eq!(config.batch_size, 100);
        assert_eq!(config.max_concurrent, 4);
    }
}
