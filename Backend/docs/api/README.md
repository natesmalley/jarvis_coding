# Jarvis Coding REST API Documentation

## Overview

The Jarvis Coding REST API provides programmatic access to the security event generation platform, enabling automated event generation, parser validation, and scenario execution.

**Base URL**: `https://api.jarvis-coding.io/api/v1` (Production)  
**Base URL**: `http://localhost:8000/api/v1` (Development)

## 🚀 Quick Start

### Authentication

The API uses simple API key authentication. Include your API key in requests:

```bash
# Using header (recommended)
curl -H "X-API-Key: YOUR_API_KEY" \
  http://localhost:8000/api/v1/generators

# Using query parameter
curl "http://localhost:8000/api/v1/generators?api_key=YOUR_API_KEY"
```

For local development, you can disable authentication:
```bash
export DISABLE_AUTH=true
python start_api.py
```

**Important Security Notes:**
- Never commit API keys or HEC tokens to version control
- Use environment variables or secure secret management
- Rotate tokens regularly
- Keep tokens in `.env` files (which should be in `.gitignore`)

### Generate Events

```bash
# Generate 10 CrowdStrike Falcon events
curl -X POST http://localhost:8000/api/v1/generators/crowdstrike_falcon/execute \
  -H "X-API-Key: YOUR_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"count": 10}'
```

## 📚 API References

- [Generators API](generators-api.md) - Event generation endpoints
- [Parsers API](parsers-api.md) - Parser management endpoints
- [Scenarios API](scenarios-api.md) - Attack scenario endpoints
- [Validation API](validation-api.md) - Field validation endpoints (Phase 3)
- [Authentication API](auth-api.md) - Authentication and authorization

## 🔑 Authentication

The API uses simple API key authentication with role-based access control:

1. **API Key Types**:
   - **Admin**: Full access to all endpoints
   - **Write**: Can execute generators and scenarios
   - **Read-Only**: Can view generators and parsers only

2. **Using API Keys**:
   - Include in `X-API-Key` header (recommended)
   - Or pass as `api_key` query parameter

3. **Configuration**:
   - Set keys in environment variables: `API_KEYS_ADMIN`, `API_KEYS_WRITE`, `API_KEYS_READ_ONLY`
   - Multiple keys per role supported (comma-separated)
   - Disable auth for development with `DISABLE_AUTH=true`

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

## 🔐 HEC Token Configuration

To send events to SentinelOne, configure your HEC token:

```bash
# Set HEC token (example format - use your actual token)
export S1_HEC_TOKEN="your-40-character-token-here"

# Set API URL for your SentinelOne instance
export S1_API_URL="https://usea1-purple.sentinelone.net"

# Optional: Configure batching
export S1_HEC_BATCH=true
export S1_HEC_BATCH_MAX_BYTES=1048576
export S1_HEC_BATCH_FLUSH_MS=500
```

**Token Format:**
- Typically 40+ characters
- Alphanumeric with special characters
- Example format: `0Z1Fy0tyI53ipwHRnnbFS0ecWaNa1Nt_dG6/HNc/qsEQ-`
- Store securely in `.env` file or secret manager

## 🎯 Common Use Cases

### 1. Generate Events for Testing

```python
import requests

# Generate events
response = requests.post(
    "http://localhost:8000/api/v1/generators/aws_cloudtrail/execute",
    headers={"X-API-Key": api_key},
    json={"count": 50}
)

if response.status_code == 200:
    events = response.json()["data"]["events"]
```

### 2. List Available Parsers

```python
# Get available parsers
response = requests.get(
    "http://localhost:8000/api/v1/parsers",
    headers={"X-API-Key": api_key}
)

if response.status_code == 200:
    parsers = response.json()["data"]["parsers"]
    print(f"Found {len(parsers)} parsers")
```

### 3. Execute Attack Scenario

```python
# Get available scenarios
response = requests.get(
    "http://localhost:8000/api/v1/scenarios",
    headers={"X-API-Key": api_key}
)

if response.status_code == 200:
    scenarios = response.json()["data"]["scenarios"]
    # Execute a specific scenario
    response = requests.post(
        f"http://localhost:8000/api/v1/scenarios/{scenarios[0]['id']}/execute",
        headers={"X-API-Key": api_key}
    )
```

## 🔒 Rate Limiting

- **Default**: 100 requests per minute
- **Authenticated**: 1000 requests per minute
- **Enterprise**: Custom limits

Rate limit headers:
- `X-RateLimit-Limit`: Maximum requests
- `X-RateLimit-Remaining`: Requests remaining
- `X-RateLimit-Reset`: Reset timestamp

## 📡 Available Endpoints

### Core Endpoints
- `GET /api/v1/health` - Health check (no auth required)
- `GET /api/v1/generators` - List all generators
- `POST /api/v1/generators/{id}/execute` - Execute a generator
- `GET /api/v1/parsers` - List all parsers
- `GET /api/v1/scenarios` - List available scenarios
- `POST /api/v1/scenarios/{id}/execute` - Execute a scenario

### Documentation
- `GET /api/v1/docs` - Swagger UI documentation
- `GET /api/v1/redoc` - ReDoc documentation

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

### Python Example

```python
import requests

class JarvisAPI:
    def __init__(self, base_url="http://localhost:8000", api_key=None):
        self.base_url = base_url
        self.headers = {"X-API-Key": api_key} if api_key else {}
    
    def list_generators(self):
        return requests.get(
            f"{self.base_url}/api/v1/generators",
            headers=self.headers
        ).json()
    
    def execute_generator(self, generator_id, count=10):
        return requests.post(
            f"{self.base_url}/api/v1/generators/{generator_id}/execute",
            headers=self.headers,
            json={"count": count}
        ).json()

# Usage
api = JarvisAPI(api_key="your-api-key")
generators = api.list_generators()
events = api.execute_generator("crowdstrike_falcon", count=5)
```

## 📝 API Status

### Current Features (v2.0.0)
- ✅ 114 generator endpoints available
- ✅ 119 parsers available
- ✅ Simple API key authentication
- ✅ Role-based access control (Admin/Write/Read-Only)
- ✅ Health monitoring endpoint
- ✅ Swagger UI documentation
- ✅ Scenario execution support

### In Development
- 🔄 Field validation system
- 🔄 Batch operations
- 🔄 WebSocket streaming
- 🔄 Advanced parser management

## 🤝 Support

- **Documentation**: [docs.jarvis-coding.io](https://docs.jarvis-coding.io)
- **Issues**: [GitHub Issues](https://github.com/natesmalley/jarvis_coding/issues)
- **API Status**: [status.jarvis-coding.io](https://status.jarvis-coding.io)

## Next Steps

1. [Get API credentials](auth-api.md)
2. [Explore generator endpoints](generators-api.md)
3. [Test parser compatibility](parsers-api.md)
4. [Run attack scenarios](scenarios-api.md)