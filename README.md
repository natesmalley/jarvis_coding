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

## One-Command Quick Start
This builds the images (the first time) and starts both services in the background.
```bash
# From the repository root
docker compose up -d --build
```
- API: http://localhost:8000
- Frontend UI: http://localhost:9001

To stop everything:
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
Compose automatically loads environment variables from the root `.env` file. Safe defaults are already provided. You can edit `.env` to change behavior.

Key variables:
- `DISABLE_AUTH=true` for local development convenience
- `BACKEND_API_KEY` (optional) if auth is enabled
- HEC batching (used by the UI when sending to HEC via `hec_sender.py`):
  - `S1_HEC_BATCH=true`
  - `S1_HEC_BATCH_MAX_BYTES=1048576`
  - `S1_HEC_BATCH_FLUSH_MS=500`
  - `S1_HEC_DEBUG=0`

After changing `.env`, restart containers to apply:
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
- "port already in use":
  - Another process is using that port. The UI maps `9001:8000`. Either stop the other app or change the left number in `docker-compose.yml`.
- API keeps restarting with missing modules:
  - Rebuild the API image: `docker compose build api --no-cache && docker compose up -d`
- API health is failing with missing `/event_generators` or `/parsers`:
  - The image includes symlinks for these paths; ensure you rebuilt after recent changes.
- Frontend can’t reach backend:
  - Inside containers, the UI uses `API_BASE_URL=http://api:8000`. From your host, use `http://localhost:8000` for the API and `http://localhost:9001` for the UI.

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
