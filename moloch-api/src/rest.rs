//! REST API endpoints for Moloch.
//!
//! Endpoints:
//! - POST /v1/events - Submit event
//! - GET /v1/events/{id} - Get event by ID
//! - GET /v1/events?actor=X - Query events
//! - GET /v1/blocks/{height} - Get block
//! - GET /v1/blocks/latest - Get head
//! - GET /v1/proofs/inclusion - Get inclusion proof
//! - GET /v1/proofs/consistency - Get consistency proof
//! - GET /v1/status - Node status

use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tracing::{debug, error, info};

use moloch_core::block::{Block, BlockHash, BlockHeader};
use moloch_core::crypto::Hash;
use moloch_core::event::{ActorId, AuditEvent, EventType, ResourceId};

use crate::server::ApiState;

/// REST API error response.
#[derive(Debug, thiserror::Error)]
pub enum ApiError {
    #[error("not found: {0}")]
    NotFound(String),

    #[error("bad request: {0}")]
    BadRequest(String),

    #[error("internal error: {0}")]
    Internal(String),

    #[error("service unavailable")]
    Unavailable,
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let status = match &self {
            ApiError::NotFound(_) => StatusCode::NOT_FOUND,
            ApiError::BadRequest(_) => StatusCode::BAD_REQUEST,
            ApiError::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
            ApiError::Unavailable => StatusCode::SERVICE_UNAVAILABLE,
        };

        let body = serde_json::json!({
            "error": self.to_string(),
            "code": status.as_u16(),
        });

        (status, Json(body)).into_response()
    }
}

// ============================================================================
// Events API
// ============================================================================

/// Request to submit a new event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubmitEventRequest {
    /// The event to submit (already signed).
    pub event: AuditEvent,
}

/// Response for event submission.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubmitEventResponse {
    /// ID of the submitted event.
    pub id: String,
    /// Whether the event was accepted.
    pub accepted: bool,
    /// Message (e.g., error reason).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

/// Query parameters for listing events.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventsQuery {
    /// Filter by actor ID.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub actor: Option<String>,
    /// Filter by resource ID.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resource: Option<String>,
    /// Filter by event type.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub event_type: Option<String>,
    /// Start time (inclusive).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub from: Option<DateTime<Utc>>,
    /// End time (exclusive).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub to: Option<DateTime<Utc>>,
    /// Maximum number of results.
    #[serde(default = "default_limit")]
    pub limit: usize,
    /// Offset for pagination.
    #[serde(default)]
    pub offset: usize,
}

impl Default for EventsQuery {
    fn default() -> Self {
        Self {
            actor: None,
            resource: None,
            event_type: None,
            from: None,
            to: None,
            limit: 100,
            offset: 0,
        }
    }
}

fn default_limit() -> usize {
    100
}

/// Response for event listing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventsResponse {
    /// List of events.
    pub events: Vec<EventInfo>,
    /// Total count (if available).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub total: Option<usize>,
    /// Whether there are more results.
    pub has_more: bool,
}

/// Event information for API responses.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventInfo {
    /// Event ID (hash).
    pub id: String,
    /// Event type.
    pub event_type: String,
    /// Actor ID.
    pub actor: String,
    /// Resource ID.
    pub resource: String,
    /// Timestamp.
    #[serde(with = "chrono::serde::ts_milliseconds")]
    pub timestamp: DateTime<Utc>,
    /// Block height (if included).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub block_height: Option<u64>,
}

impl From<&AuditEvent> for EventInfo {
    fn from(event: &AuditEvent) -> Self {
        Self {
            id: event.id().as_hash().to_hex(),
            event_type: format!("{:?}", event.event_type),
            actor: format!("{:?}", event.actor),
            resource: format!("{:?}", event.resource),
            timestamp: event.event_time,
            block_height: None,
        }
    }
}

/// Events API handlers.
pub struct EventsApi;

impl EventsApi {
    /// Create router for events endpoints.
    pub fn router() -> Router<Arc<ApiState>> {
        Router::new()
            .route("/", post(Self::submit_event).get(Self::list_events))
            .route("/{id}", get(Self::get_event))
    }

    /// POST /v1/events - Submit a new event.
    async fn submit_event(
        State(state): State<Arc<ApiState>>,
        Json(request): Json<SubmitEventRequest>,
    ) -> Result<Json<SubmitEventResponse>, ApiError> {
        let event = request.event;
        let id = event.id().as_hash().to_hex();

        info!("Submitting event: {}", id);

        // Add to mempool
        match state.submit_event(event).await {
            Ok(()) => Ok(Json(SubmitEventResponse {
                id,
                accepted: true,
                message: None,
            })),
            Err(e) => Ok(Json(SubmitEventResponse {
                id,
                accepted: false,
                message: Some(e.to_string()),
            })),
        }
    }

    /// GET /v1/events/{id} - Get event by ID.
    async fn get_event(
        State(state): State<Arc<ApiState>>,
        Path(id): Path<String>,
    ) -> Result<Json<EventInfo>, ApiError> {
        let hash = Hash::from_hex(&id)
            .map_err(|_| ApiError::BadRequest("invalid event ID".to_string()))?;

        let event = state
            .get_event(&hash)
            .await
            .ok_or_else(|| ApiError::NotFound(format!("event {} not found", id)))?;

        Ok(Json(EventInfo::from(&event)))
    }

    /// GET /v1/events?... - List/query events.
    async fn list_events(
        State(state): State<Arc<ApiState>>,
        Query(query): Query<EventsQuery>,
    ) -> Result<Json<EventsResponse>, ApiError> {
        let events = state
            .query_events(&query)
            .await
            .map_err(|e| ApiError::Internal(e.to_string()))?;

        let has_more = events.len() >= query.limit;
        let event_infos: Vec<_> = events.iter().map(EventInfo::from).collect();

        Ok(Json(EventsResponse {
            events: event_infos,
            total: None,
            has_more,
        }))
    }
}

// ============================================================================
// Blocks API
// ============================================================================

/// Block information for API responses.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockInfo {
    /// Block height.
    pub height: u64,
    /// Block hash.
    pub hash: String,
    /// Parent block hash.
    pub parent: String,
    /// Number of events in the block.
    pub events_count: usize,
    /// Merkle root of events.
    pub events_root: String,
    /// MMR root.
    pub mmr_root: String,
    /// Timestamp.
    #[serde(with = "chrono::serde::ts_milliseconds")]
    pub timestamp: DateTime<Utc>,
    /// Sealer (validator) ID.
    pub sealer: String,
}

impl From<&Block> for BlockInfo {
    fn from(block: &Block) -> Self {
        Self {
            height: block.header.height,
            hash: block.hash().as_hash().to_hex(),
            parent: block.header.parent.as_hash().to_hex(),
            events_count: block.header.events_count as usize,
            events_root: block.header.events_root.to_hex(),
            mmr_root: block.header.mmr_root.to_hex(),
            timestamp: block.header.timestamp,
            sealer: format!("{:?}", block.header.sealer),
        }
    }
}

/// Blocks API handlers.
pub struct BlocksApi;

impl BlocksApi {
    /// Create router for blocks endpoints.
    pub fn router() -> Router<Arc<ApiState>> {
        Router::new()
            .route("/latest", get(Self::get_latest))
            .route("/{height}", get(Self::get_by_height))
    }

    /// GET /v1/blocks/latest - Get the latest block.
    async fn get_latest(State(state): State<Arc<ApiState>>) -> Result<Json<BlockInfo>, ApiError> {
        let block = state
            .get_latest_block()
            .await
            .ok_or_else(|| ApiError::NotFound("no blocks yet".to_string()))?;

        Ok(Json(BlockInfo::from(&block)))
    }

    /// GET /v1/blocks/{height} - Get block by height.
    async fn get_by_height(
        State(state): State<Arc<ApiState>>,
        Path(height): Path<u64>,
    ) -> Result<Json<BlockInfo>, ApiError> {
        let block = state
            .get_block(height)
            .await
            .ok_or_else(|| ApiError::NotFound(format!("block {} not found", height)))?;

        Ok(Json(BlockInfo::from(&block)))
    }
}

// ============================================================================
// Proofs API
// ============================================================================

/// Query parameters for inclusion proof.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InclusionProofQuery {
    /// Event ID to prove.
    pub event_id: String,
}

/// Inclusion proof response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InclusionProofResponse {
    /// Event ID.
    pub event_id: String,
    /// Block height containing the event.
    pub block_height: u64,
    /// Block hash.
    pub block_hash: String,
    /// Merkle proof (list of sibling hashes).
    pub proof: Vec<String>,
    /// Event index in block.
    pub index: usize,
}

/// Query parameters for consistency proof.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsistencyProofQuery {
    /// Old tree size (height).
    pub from_height: u64,
    /// New tree size (height).
    pub to_height: u64,
}

/// Consistency proof response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsistencyProofResponse {
    /// From height.
    pub from_height: u64,
    /// To height.
    pub to_height: u64,
    /// MMR root at from_height.
    pub from_root: String,
    /// MMR root at to_height.
    pub to_root: String,
    /// Proof hashes.
    pub proof: Vec<String>,
}

/// Proofs API handlers.
pub struct ProofsApi;

impl ProofsApi {
    /// Create router for proofs endpoints.
    pub fn router() -> Router<Arc<ApiState>> {
        Router::new()
            .route("/inclusion", get(Self::inclusion_proof))
            .route("/consistency", get(Self::consistency_proof))
    }

    /// GET /v1/proofs/inclusion?event_id=X - Get inclusion proof.
    async fn inclusion_proof(
        State(state): State<Arc<ApiState>>,
        Query(query): Query<InclusionProofQuery>,
    ) -> Result<Json<InclusionProofResponse>, ApiError> {
        let hash = Hash::from_hex(&query.event_id)
            .map_err(|_| ApiError::BadRequest("invalid event ID".to_string()))?;

        let proof = state
            .get_inclusion_proof(&hash)
            .await
            .ok_or_else(|| ApiError::NotFound(format!("event {} not found", query.event_id)))?;

        Ok(Json(proof))
    }

    /// GET /v1/proofs/consistency?from_height=X&to_height=Y - Get consistency proof.
    async fn consistency_proof(
        State(state): State<Arc<ApiState>>,
        Query(query): Query<ConsistencyProofQuery>,
    ) -> Result<Json<ConsistencyProofResponse>, ApiError> {
        if query.from_height >= query.to_height {
            return Err(ApiError::BadRequest(
                "from_height must be less than to_height".to_string(),
            ));
        }

        let proof = state
            .get_consistency_proof(query.from_height, query.to_height)
            .await
            .ok_or_else(|| ApiError::NotFound("heights not found".to_string()))?;

        Ok(Json(proof))
    }
}

// ============================================================================
// Status API
// ============================================================================

/// Node status response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatusResponse {
    /// Node version.
    pub version: String,
    /// Chain ID.
    pub chain_id: String,
    /// Current block height.
    pub height: u64,
    /// Latest block hash.
    pub latest_block: Option<String>,
    /// Whether the node is syncing.
    pub syncing: bool,
    /// Number of connected peers.
    pub peer_count: usize,
    /// Number of pending events in mempool.
    pub pending_events: usize,
    /// Node uptime in seconds.
    pub uptime_seconds: u64,
}

/// Status API handlers.
pub struct StatusApi;

impl StatusApi {
    /// Create router for status endpoints.
    pub fn router() -> Router<Arc<ApiState>> {
        Router::new().route("/", get(Self::get_status))
    }

    /// GET /v1/status - Get node status.
    async fn get_status(
        State(state): State<Arc<ApiState>>,
    ) -> Result<Json<StatusResponse>, ApiError> {
        let status = state.get_status().await;
        Ok(Json(status))
    }
}

// ============================================================================
// Combined Router
// ============================================================================

/// Create the complete REST API router.
pub fn create_router() -> Router<Arc<ApiState>> {
    Router::new()
        .nest("/v1/events", EventsApi::router())
        .nest("/v1/blocks", BlocksApi::router())
        .nest("/v1/proofs", ProofsApi::router())
        .nest("/v1/status", StatusApi::router())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_events_query_defaults() {
        let query = EventsQuery::default();
        assert_eq!(query.limit, 100);
        assert_eq!(query.offset, 0);
    }

    #[test]
    fn test_api_error_status_codes() {
        let not_found = ApiError::NotFound("test".to_string());
        let bad_request = ApiError::BadRequest("test".to_string());
        let internal = ApiError::Internal("test".to_string());
        let unavailable = ApiError::Unavailable;

        // Check that they convert to responses without panicking
        let _ = not_found.into_response();
        let _ = bad_request.into_response();
        let _ = internal.into_response();
        let _ = unavailable.into_response();
    }

    #[test]
    fn test_submit_event_response() {
        let response = SubmitEventResponse {
            id: "abc123".to_string(),
            accepted: true,
            message: None,
        };

        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("abc123"));
        assert!(json.contains("true"));
    }

    #[test]
    fn test_block_info_serialization() {
        let info = BlockInfo {
            height: 100,
            hash: "abc".to_string(),
            parent: "def".to_string(),
            events_count: 50,
            events_root: "123".to_string(),
            mmr_root: "456".to_string(),
            timestamp: Utc::now(),
            sealer: "validator-1".to_string(),
        };

        let json = serde_json::to_string(&info).unwrap();
        assert!(json.contains("100"));
        assert!(json.contains("50"));
    }

    #[test]
    fn test_status_response() {
        let status = StatusResponse {
            version: "0.1.0".to_string(),
            chain_id: "moloch-test".to_string(),
            height: 1000,
            latest_block: Some("abc".to_string()),
            syncing: false,
            peer_count: 5,
            pending_events: 10,
            uptime_seconds: 3600,
        };

        let json = serde_json::to_string(&status).unwrap();
        assert!(json.contains("moloch-test"));
        assert!(json.contains("1000"));
    }
}
