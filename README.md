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

## Quick Start

### 1. Create Environment File
First time setup - copy the template to create your `.env` file:
```bash
cp ".env copy" .env
```

The default configuration has authentication disabled for easy local development (`DISABLE_AUTH=true`). This is perfect for getting started!

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

## Configuration (.env)

The `.env` file controls both services. Copy from `.env copy` if you haven't already:
```bash
cp ".env copy" .env
```

### Authentication Settings
By default, authentication is **disabled** for local development:
- `DISABLE_AUTH=true` - No API keys required (recommended for local dev)
- `BACKEND_API_KEY` - Not needed when auth is disabled

For production, enable authentication:
```bash
DISABLE_AUTH=false
API_KEYS_ADMIN=your-secure-admin-key
BACKEND_API_KEY=your-secure-admin-key  # Frontend uses this to talk to backend
```

### Other Key Variables
- **HEC Batching** (used by UI when sending to HEC):
  - `S1_HEC_BATCH=true`
  - `S1_HEC_BATCH_MAX_BYTES=1048576`
  - `S1_HEC_BATCH_FLUSH_MS=500`
  - `S1_HEC_DEBUG=0`
- **Secret Key**: `SECRET_KEY` - Change for production deployments

### Applying Configuration Changes
After editing `.env`, restart containers:
```bash
docker compose down && docker compose up -d
```

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

**Solution**: Create the `.env` file with `DISABLE_AUTH=true`:
```bash
cp ".env copy" .env
docker compose down && docker compose up -d
```

### "port already in use"
Another process is using that port. The UI maps `9001:8000`. Either stop the other app or change the left number in `docker-compose.yml`.

### API keeps restarting with missing modules
Rebuild the API image: 
```bash
docker compose build api --no-cache && docker compose up -d
```

### API health is failing with missing `/event_generators` or `/parsers`
The image includes symlinks for these paths; ensure you rebuilt after recent changes.

### Frontend can’t reach backend
Inside containers, the UI uses `API_BASE_URL=http://api:8000`. From your host, use `http://localhost:8000` for the API and `http://localhost:9001` for the UI.

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
