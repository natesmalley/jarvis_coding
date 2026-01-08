# Jarvis Frontend & Backend – Docker Quickstart

This repository contains two services:
- Backend API (FastAPI) under `Backend/api/`
- Frontend UI (Flask) under `Frontend/`

A root-level `docker-compose.yml` builds and runs both services together.

## Prerequisites
- Docker Desktop (or Docker Engine) installed
- Docker Compose v2 (bundled with recent Docker Desktop)
- Terminal access

If you're new to Docker, think of images as "apps" you build, and containers as the running "instances" of those apps.

## Project Structure
- `Backend/api/Dockerfile`: Builds the API image
- `Frontend/Dockerfile`: Builds the UI image
- `docker-compose.yml`: Orchestrates API and UI
- `.env`: Environment variables loaded by Compose

---

## Quick Start

### 1. Create Environment File
First time setup - copy the example template to create your `.env` file:
```bash
cp .env.example .env
```

Or if you prefer the simplified version:
```bash
cp ".env copy" .env
```

The default configuration has authentication disabled for easy local development (`DISABLE_AUTH=true`). This is perfect for getting started!

**Note**: See the [Detailed Configuration](#detailed-configuration) section below for complete environment variable documentation.

### 2. Start Services
Build and start both services:
```bash
docker compose up -d --build
```
- **API**: http://localhost:8000
- **Frontend UI**: http://localhost:9001
- **API Docs**: http://localhost:8000/api/v1/docs

### 3. Stop Services
```bash
docker compose down
```

---

## Step-by-Step (Beginner Friendly)
1. Build images (compiles dependencies and copies code):
```bash
docker compose build
```
2. Start containers:
```bash
docker compose up -d
```
3. Verify they are running:
```bash
docker ps
```
4. Check logs (live streaming):
```bash
docker logs -f jarvis-api
# in a second terminal
docker logs -f jarvis-frontend
```
5. Test endpoints:
```bash
# API root
curl http://localhost:8000
# API health
curl http://localhost:8000/api/v1/health
# Open the UI in your browser
open http://localhost:9001
```

---

## Configuration (.env)

The `.env` file controls both services. Use the comprehensive `.env.example` template:
```bash
cp .env.example .env
```

### Quick Configuration Overview

#### Local Development (Default)
```bash
DISABLE_AUTH=true
SECRET_KEY=dev-key
LOG_LEVEL=debug
```
Perfect for testing and development. No SentinelOne integration required.

#### Production with SentinelOne
```bash
DISABLE_AUTH=false
SECRET_KEY=<generate-secure-key>
JARVIS_WRITE_KEYS=<your-sentinelone-write-hec-token>
S1_HEC_TOKEN=<your-sentinelone-write-hec-token>
S1_HEC_URL=https://ingest.REGION.sentinelone.net/api/v1/cloud_connect/events
S1_HEC_AUTH_SCHEME=Bearer
BACKEND_API_KEY=<same-as-jarvis-write-key>
```

### Applying Configuration Changes
After editing `.env`, restart containers:
```bash
docker compose down && docker compose up -d
```

---

## Detailed Configuration

For complete documentation of all environment variables, see [.env.example](.env.example).

### Core Environment Variables

#### Authentication & Security

| Variable | Description | Required | Default |
|----------|-------------|----------|---------|
| `DISABLE_AUTH` | Disable authentication for local dev | No | `false` |
| `SECRET_KEY` | Encryption key for JWT/sessions | **Yes** (prod) | `change-me-in-production` |
| `JARVIS_ADMIN_KEYS` | Admin API keys (comma-separated) | No | - |
| `JARVIS_WRITE_KEYS` | Write-access AI SIEM API keys | **Yes** (prod) | - |
| `JARVIS_READ_KEYS` | Read-only AI SIEM API keys | No | - |
| `BACKEND_API_KEY` | Frontend→Backend API key | **Yes** (prod) | - |

**Generate secure keys**:
```bash
# For SECRET_KEY
python -c "import secrets; print(secrets.token_urlsafe(32))"

```

#### SentinelOne Integration

##### HEC (HTTP Event Collector) - For Sending Events

| Variable | Description | Required | Example |
|----------|-------------|----------|---------|
| `S1_HEC_TOKEN` | HEC token for **sending/writing** events to SentinelOne | No | `xxxxxxxx-xxxx-xxxx...` |
| `S1_HEC_URL` | HEC endpoint URL | No | `https://ingest.REGION.sentinelone.net/api/v1/cloud_connect/events` |
| `S1_HEC_AUTH_SCHEME` | Auth scheme: `Splunk` or `Bearer` (use `Bearer` for Cloud Connect) | No | `Bearer` |
| `S1_HEC_BATCH` | Enable batch mode | No | `true` |
| `S1_HEC_BATCH_MAX_BYTES` | Max batch size in bytes | No | `1048576` |
| `S1_HEC_BATCH_FLUSH_MS` | Batch flush interval (ms) | No | `500` |
| `S1_HEC_VERIFY` | Verify SSL certificates | No | `true` |
| `S1_HEC_DEBUG` | Debug level (0-2) | No | `0` |

**Where to get tokens**:
- **HEC Token**: SentinelOne Console → Policy & Settings → API Keys → Log Access Keys (New Write Key for **sending** events)


#### Keyring (Frontend Credential Storage)

| Variable | Description | Default |
|----------|-------------|---------|
| `KEYRING_CRYPTFILE_PASSWORD` | Keyring encryption password | `change-this-strong-password` |
| `KEYRING_CRYPTFILE_PATH` | Keyring file path | `/app/Frontend/.keyring.cfg` |
| `PYTHON_KEYRING_BACKEND` | Keyring backend type | `keyrings.alt.file.EncryptedKeyring` |

---

## Parser Configuration

### Parser Mappings File

Parser mappings are configured in `Backend/event_generators/shared/parser_mappings.json`. This file defines two types of mappings:

**1. `marketplace_to_product`** - Maps SentinelOne marketplace parser names to internal product generators:
```json
{
  "marketplace-awscloudtrail-latest": "aws_cloudtrail",
  "marketplace-fortinetfortigate-latest": "fortinet_fortigate"
}
```

**2. `product_to_parser`** - Maps internal product names to SentinelOne parser names:
```json
{
  "aws_cloudtrail": "marketplace-awscloudtrail-latest",
  "fortinet_fortigate": "fortinet_fortigate_candidate_logs-latest"
}
```

### Updating Parser Mappings

To add or update parser mappings:

1. Edit `Backend/event_generators/shared/parser_mappings.json`
2. Add your mapping in both sections if needed
3. Restart containers:
   ```bash
   docker compose restart
   ```

**Example - Adding a new AWS parser:**
```json
{
  "marketplace_to_product": {
    "marketplace-awss3-latest": "aws_s3"
  },
  "product_to_parser": {
    "aws_s3": "marketplace-awss3-latest"
  }
}
```

---

## Common Commands
- Rebuild everything after Dockerfile changes:
```bash
docker compose build --no-cache && docker compose up -d
```
- Rebuild just the API:
```bash
docker compose build api && docker compose up -d
```
- Rebuild just the Frontend:
```bash
docker compose build frontend && docker compose up -d
```
- Tail logs:
```bash
docker logs -f jarvis-api
```

## Troubleshooting

### "Missing API key" or "API key required" errors
**Symptom**: Frontend shows "Failed to save destination" with 403 errors about missing API key.

**Root Cause**: `.env` file not created or `DISABLE_AUTH` not set to `true`.

**Solution**:
```bash
cp .env.example .env
# Edit .env and set:
# DISABLE_AUTH=true
docker compose down && docker compose up -d
```

### "Failed to send events to SentinelOne"
**Symptom**: Events not appearing in SentinelOne console.

**Root Causes**:
1. Missing or invalid `S1_HEC_TOKEN`
2. Incorrect `S1_HEC_URL`
3. SSL certificate issues

**Solutions**:
```bash
# 1. Verify your HEC token in .env
S1_HEC_TOKEN=<your-actual-token>

# 2. Verify your instance URL format (no /raw suffix for Cloud Connect)
S1_HEC_URL=https://ingest.REGION.sentinelone.net/api/v1/cloud_connect/events
S1_HEC_AUTH_SCHEME=Bearer

# 3. If SSL issues, temporarily disable verification (dev only!)
S1_HEC_VERIFY=false

# 4. Enable debug logging
S1_HEC_DEBUG=2

# Restart and check logs
docker compose down && docker compose up -d
docker logs -f jarvis-api
```

### "Environment variable not loaded"
**Symptom**: Application doesn't use values from `.env` file or warnings about unset variables.

**Root Cause**: Docker Compose not reading `.env` file or variables not defined.

**Solutions**:
```bash
# 1. Ensure .env is in the same directory as docker-compose.yml
ls -la .env

# 2. Variables can be empty (optional ones have defaults in docker-compose.yml)
# For example, S1_SDL_API_TOKEN can be left empty if not needed
S1_SDL_API_TOKEN=

# 3. Restart containers (down + up, not just restart)
docker compose down
docker compose up -d

# 4. Verify environment variables are loaded
docker exec jarvis-api env | grep S1_HEC_TOKEN
```

### "port already in use"
**Symptom**: `Error: bind: address already in use`.

**Solution**:
```bash
# Find process using port 8000
lsof -i :8000

# Stop the process or change port in docker-compose.yml
# Change: "8000:8000" to "8080:8000"
```

#### API keeps restarting with missing modules
**Symptom**: Container restarts continuously with `ModuleNotFoundError`.

**Solution**:
```bash
docker compose build api --no-cache && docker compose up -d
```

#### API health is failing with missing `/event_generators` or `/parsers`
**Symptom**: Health check fails, missing directories.

**Solution**:
```bash
# Ensure symlinks exist
ls -la Backend/api/event_generators
ls -la Backend/api/parsers

# Rebuild with no cache
docker compose build --no-cache
docker compose up -d
```

#### Frontend can't reach backend
**Symptom**: Frontend shows "API connection failed".

**Root Cause**: Incorrect `API_BASE_URL` configuration.

**Solution**:
```bash
# In .env, set for Docker:
API_BASE_URL=http://api:8000

# For local development without Docker:
API_BASE_URL=http://localhost:8000

# Restart
docker compose down && docker compose up -d
```

#### CORS errors in browser
**Symptom**: Browser console shows CORS policy errors.

**Solution**:
```bash
# Add your frontend URL to .env
BACKEND_CORS_ORIGINS=http://localhost:3000,https://yourdomain.com

# Restart
docker compose down && docker compose up -d
```

### Debugging Tips

#### Enable Debug Logging
```bash
# In .env
LOG_LEVEL=debug
S1_HEC_DEBUG=2

# Restart and watch logs
docker compose down && docker compose up -d
docker logs -f jarvis-api
```

#### Check Environment Variables
```bash
# View all env vars in API container
docker exec jarvis-api env

# Check specific variable
docker exec jarvis-api env | grep S1_HEC_TOKEN
```

#### View Container Logs
```bash
# Real-time logs
docker logs -f jarvis-api
docker logs -f jarvis-frontend

# Last 100 lines
docker logs --tail 100 jarvis-api

# Logs since specific time
docker logs --since 10m jarvis-api
```

---

## Development Tips
- Live code mounting is enabled for the UI and backend content in Compose (read-only) to keep container images small and consistent. Rebuild images when you change Dockerfiles or dependencies.
- Use `docker compose down` to stop and clean up containers and network.

## Clean Up
Stop and remove containers, and the compose network:
```bash
docker compose down
```
Optionally remove images:
```bash
docker rmi jarvis_frontend-api jarvis_frontend-frontend
```
