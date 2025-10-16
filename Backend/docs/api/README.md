# Jarvis Coding REST API Documentation

## Overview

The Jarvis Coding REST API provides programmatic access to the security event generation platform, enabling automated event generation, parser validation, and scenario execution.

**Base URL**: `https://api.jarvis-coding.io/api/v1` (Production)  
**Base URL**: `http://localhost:8000/api/v1` (Development)

## 🚀 Quick Start

### Authentication

```bash
# Get API token
curl -X POST https://api.jarvis-coding.io/api/v1/auth/token \
  -H "Content-Type: application/json" \
  -d '{"username": "your-username", "password": "your-password"}'

# Use token in requests
curl -H "Authorization: Bearer YOUR_TOKEN" \
  https://api.jarvis-coding.io/api/v1/generators
```

### Generate Events

```bash
# Generate 10 CrowdStrike Falcon events
curl -X POST https://api.jarvis-coding.io/api/v1/generators/crowdstrike_falcon/execute \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"count": 10, "format": "json"}'
```

## 📚 API References

- [Generators API](generators-api.md) - Event generation endpoints
- [Parsers API](parsers-api.md) - Parser management endpoints
- [Scenarios API](scenarios-api.md) - Attack scenario endpoints
- [Validation API](validation-api.md) - Field validation endpoints (Phase 3)
- [Authentication API](auth-api.md) - Authentication and authorization

## 🔑 Authentication

The API uses JWT (JSON Web Token) authentication:

1. **Get Token**: POST to `/auth/token` with credentials
2. **Use Token**: Include in `Authorization: Bearer TOKEN` header
3. **Refresh Token**: POST to `/auth/refresh` before expiration

## 📊 Response Format

### Success Response

```json
{
  "success": true,
  "data": {
    // Response data
  },
  "metadata": {
    "timestamp": "2025-01-29T10:30:00Z",
    "request_id": "req_123abc",
    "execution_time_ms": 145
  }
}
```

### Error Response

```json
{
  "success": false,
  "error": {
    "code": "GENERATOR_NOT_FOUND",
    "message": "Generator 'invalid_generator' not found",
    "details": {
      "available_generators": ["crowdstrike_falcon", "..."]
    }
  },
  "metadata": {
    "timestamp": "2025-01-29T10:30:00Z",
    "request_id": "req_123abc"
  }
}
```

## 🎯 Common Use Cases

### 1. Generate Events for Testing

```python
import requests

# Generate events
response = requests.post(
    "https://api.jarvis-coding.io/api/v1/generators/aws_cloudtrail/execute",
    headers={"Authorization": f"Bearer {token}"},
    json={"count": 50, "format": "json"}
)

events = response.json()["data"]["events"]
```

### 2. Validate Parser Compatibility

```python
# Check if generator works with parser
response = requests.post(
    "https://api.jarvis-coding.io/api/v1/validation/check",
    headers={"Authorization": f"Bearer {token}"},
    json={
        "generator_id": "crowdstrike_falcon",
        "parser_id": "marketplace-crowdstrike-latest"
    }
)

compatibility = response.json()["data"]["compatibility_score"]
```

### 3. Execute Attack Scenario

```python
# Run phishing attack scenario
response = requests.post(
    "https://api.jarvis-coding.io/api/v1/scenarios/phishing_attack/execute",
    headers={"Authorization": f"Bearer {token}"},
    json={"speed": "realtime"}
)

scenario_id = response.json()["data"]["execution_id"]
```

## 🔒 Rate Limiting

- **Default**: 100 requests per minute
- **Authenticated**: 1000 requests per minute
- **Enterprise**: Custom limits

Rate limit headers:
- `X-RateLimit-Limit`: Maximum requests
- `X-RateLimit-Remaining`: Requests remaining
- `X-RateLimit-Reset`: Reset timestamp

## 📡 WebSocket Events

Real-time event streaming via WebSocket:

```javascript
const ws = new WebSocket('wss://api.jarvis-coding.io/api/v1/events');

ws.on('message', (data) => {
  const event = JSON.parse(data);
  console.log('New event:', event);
});

// Subscribe to specific generators
ws.send(JSON.stringify({
  action: 'subscribe',
  generators: ['crowdstrike_falcon', 'aws_cloudtrail']
}));
```

## 🏷️ HTTP Status Codes

| Code | Description |
|------|-------------|
| 200 | Success |
| 201 | Created |
| 204 | No Content |
| 400 | Bad Request |
| 401 | Unauthorized |
| 403 | Forbidden |
| 404 | Not Found |
| 429 | Too Many Requests |
| 500 | Internal Server Error |
| 503 | Service Unavailable |

## 🔍 Pagination

List endpoints support pagination:

```bash
GET /api/v1/generators?page=2&per_page=20
```

Response includes:
```json
{
  "data": [...],
  "pagination": {
    "page": 2,
    "per_page": 20,
    "total": 106,
    "total_pages": 6
  }
}
```

## 🔧 SDK Support

### Python SDK

```python
from jarvis_coding import JarvisClient

client = JarvisClient(api_key="your-api-key")

# Generate events
events = client.generators.execute(
    "crowdstrike_falcon",
    count=10
)

# Run scenario
result = client.scenarios.run("phishing_attack")
```

### JavaScript SDK

```javascript
import { JarvisClient } from '@jarvis-coding/sdk';

const client = new JarvisClient({ apiKey: 'your-api-key' });

// Generate events
const events = await client.generators.execute('crowdstrike_falcon', {
  count: 10,
  format: 'json'
});
```

## 📝 API Changelog

### Version 2.0.0 (Current)
- Initial REST API release
- 100+ generator endpoints
- WebSocket support
- JWT authentication

### Version 2.1.0 (Planned)
- Field validation endpoints
- Batch operations
- Webhook support

## 🤝 Support

- **Documentation**: [docs.jarvis-coding.io](https://docs.jarvis-coding.io)
- **Issues**: [GitHub Issues](https://github.com/natesmalley/jarvis_coding/issues)
- **API Status**: [status.jarvis-coding.io](https://status.jarvis-coding.io)

## Next Steps

1. [Get API credentials](auth-api.md)
2. [Explore generator endpoints](generators-api.md)
3. [Test parser compatibility](parsers-api.md)
4. [Run attack scenarios](scenarios-api.md)