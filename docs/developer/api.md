# Moloch API Reference

REST and WebSocket API for interacting with the Moloch audit chain.

## Base URL

```
http://localhost:8080/v1
```

## Authentication

### API Key

```bash
curl -H "X-API-Key: your-api-key" https://api.example.com/v1/events
```

### JWT Token

```bash
curl -H "Authorization: Bearer <token>" https://api.example.com/v1/events
```

## REST Endpoints

### Events

#### Submit Event

```http
POST /v1/events
Content-Type: application/json

{
  "event_type": "push",
  "actor": {
    "id": "user:alice@example.com",
    "kind": "user"
  },
  "resource": {
    "id": "repo:my-org/my-repo",
    "kind": "repository"
  },
  "outcome": "success",
  "metadata": {
    "branch": "main",
    "commits": 5
  }
}
```

Response:
```json
{
  "id": "evt_abc123...",
  "timestamp_ms": 1705123456789,
  "block_height": null
}
```

#### Get Event

```http
GET /v1/events/{event_id}
```

Response:
```json
{
  "id": "evt_abc123...",
  "timestamp_ms": 1705123456789,
  "event_type": "push",
  "actor": { ... },
  "resource": { ... },
  "outcome": "success",
  "metadata": { ... },
  "block_height": 1234
}
```

#### Query Events

```http
GET /v1/events?actor=user:alice&resource=repo:my-org/*&limit=100
```

Query parameters:
| Parameter | Description |
|-----------|-------------|
| `actor` | Filter by actor ID |
| `resource` | Filter by resource ID (supports wildcards) |
| `event_type` | Filter by event type |
| `from` | Start timestamp (unix ms) |
| `to` | End timestamp (unix ms) |
| `limit` | Max results (default 100, max 1000) |
| `offset` | Pagination offset |

### Blocks

#### Get Block

```http
GET /v1/blocks/{height}
```

#### Get Latest Block

```http
GET /v1/blocks/latest
```

Response:
```json
{
  "height": 1234,
  "parent_hash": "abc123...",
  "events_root": "def456...",
  "sealer_id": "validator:node1",
  "event_count": 50,
  "timestamp_ms": 1705123456789
}
```

### Proofs

#### Get Inclusion Proof

```http
GET /v1/proofs/inclusion?event_id={event_id}
```

Response:
```json
{
  "event_id": "evt_abc123...",
  "block_height": 1234,
  "mmr_proof": {
    "leaf_index": 5678,
    "siblings": ["hash1", "hash2", ...],
    "root": "root_hash"
  }
}
```

#### Get Consistency Proof

```http
GET /v1/proofs/consistency?from={height}&to={height}
```

### Status

#### Node Status

```http
GET /v1/status
```

Response:
```json
{
  "chain_id": "moloch-mainnet",
  "head_height": 1234,
  "head_hash": "abc123...",
  "peer_count": 5,
  "syncing": false,
  "version": "0.1.0"
}
```

## WebSocket API

### Connect

```javascript
const ws = new WebSocket('ws://localhost:8080/v1/ws');

ws.onopen = () => {
  // Subscribe to events
  ws.send(JSON.stringify({
    type: 'subscribe',
    channel: 'events',
    filter: {
      actor: 'user:alice@example.com'
    }
  }));
};
```

### Channels

#### Events Channel

Subscribe to new events:

```json
{
  "type": "subscribe",
  "channel": "events",
  "filter": {
    "actor": "user:*",
    "event_type": "push"
  }
}
```

Messages:
```json
{
  "type": "event",
  "data": {
    "id": "evt_abc123...",
    "event_type": "push",
    ...
  }
}
```

#### Blocks Channel

Subscribe to new blocks:

```json
{
  "type": "subscribe",
  "channel": "blocks"
}
```

Messages:
```json
{
  "type": "block",
  "data": {
    "height": 1235,
    "event_count": 42,
    ...
  }
}
```

### Unsubscribe

```json
{
  "type": "unsubscribe",
  "channel": "events"
}
```

## Error Responses

All errors follow this format:

```json
{
  "error": {
    "code": "INVALID_EVENT",
    "message": "Event signature verification failed",
    "details": {
      "field": "signature"
    }
  }
}
```

### Error Codes

| Code | HTTP Status | Description |
|------|-------------|-------------|
| `INVALID_REQUEST` | 400 | Malformed request body |
| `INVALID_EVENT` | 400 | Event validation failed |
| `NOT_FOUND` | 404 | Resource not found |
| `RATE_LIMITED` | 429 | Too many requests |
| `INTERNAL_ERROR` | 500 | Server error |

## Rate Limits

| Tier | Requests/min | WebSocket connections |
|------|--------------|----------------------|
| Free | 60 | 1 |
| Standard | 600 | 5 |
| Enterprise | 6000 | 50 |

Rate limit headers:
```http
X-RateLimit-Limit: 600
X-RateLimit-Remaining: 599
X-RateLimit-Reset: 1705123500
```

## SDK Examples

### Rust

```rust
use moloch_client::Client;

let client = Client::new("http://localhost:8080")
    .api_key("your-api-key");

// Submit event
let event_id = client.submit_event(&event).await?;

// Query events
let events = client.query()
    .actor("user:alice")
    .event_type("push")
    .limit(100)
    .execute()
    .await?;

// Get proof
let proof = client.get_inclusion_proof(&event_id).await?;
```

### Python

```python
from moloch import Client

client = Client("http://localhost:8080", api_key="your-api-key")

# Submit event
event_id = client.submit_event(
    event_type="push",
    actor={"id": "user:alice", "kind": "user"},
    resource={"id": "repo:my-org/my-repo", "kind": "repository"},
    outcome="success"
)

# Query events
events = client.query_events(actor="user:alice", limit=100)
```
