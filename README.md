# Jarvis Tech Summit 2025 - Microservices Platform

A scalable, containerized platform for delivering personalized Jarvis instances to multiple concurrent users. Built for Tech Summit 2025 to support 150+ simultaneous users with isolated environments.

## Table of Contents
- [Architecture Overview](#architecture-overview)
- [Prerequisites](#prerequisites)
- [Complete Setup Guide](#complete-setup-guide)
- [User Experience](#user-experience)
- [Admin Console Guide](#admin-console-guide)
- [Configuration](#configuration)
- [Troubleshooting](#troubleshooting)
- [Maintenance](#maintenance)
- [Production Deployment](#production-deployment)

## Architecture Overview

The platform consists of four main components:

1. **Session Manager** - Orchestrates user sessions and container lifecycle
2. **Admin Panel** - Manages configuration and monitors active sessions  
3. **Landing Page** - User entry point with automatic session provisioning
4. **Jarvis Instances** - Isolated frontend/backend container pairs per user

### System Flow

```
User → Landing Page → Session Manager → Docker Orchestration
                            ↓
                     Redis (Session State)
                            ↓
                     Isolated Containers (Frontend + Backend)
                            ↓
                     Shared Storage (Named Volumes)
```

### Network Architecture

- **Shared Network**: All containers use `jarvis-network` to avoid Docker subnet exhaustion
- **Port Allocation**: Dynamic port allocation (10000-20000 range) managed by Redis
- **Service Discovery**: Containers communicate via Docker DNS names

### Storage Architecture

- **Named Volumes**: Each session gets a persistent named volume (`jarvis-{session_id}-data`)
- **Shared Data**: Frontend and backend containers share the same data volume for persistence
- **Volume Mounts**:
  - Backend: `/app/data` (SQLite database, uploads)
  - Frontend: `/app/shared-data` (access to shared resources)
  - Event Generators: Read-only mount from host (`/Backend/event_generators`)
  - Parsers: Read-only mount from host (`/Backend/parsers`)
- **Persistence**: Destinations and configurations persist across container restarts

## Prerequisites

- Docker Engine 20.10+ with Docker Compose
- 8GB RAM minimum (16GB recommended for 150 users)
- Available ports:
  - Port 80 (Landing page/NGINX)
  - Port 9001 (Session Manager)
  - Port 6379 (Redis)
  - Ports 10000-20000 (Dynamic container allocation)
- Unix socket access to Docker daemon (`/var/run/docker.sock`)

## Complete Setup Guide

### Step 1: Clone Repository and Prepare Environment

```bash
# Clone the repository
git clone <repository-url>
cd jarvis_coding

# Create Docker network (required for shared network architecture)
docker network create jarvis-network
```

### Step 2: Build Production Images

```bash
# Build backend with user permissions fix (CRITICAL: includes jarvis user creation)
docker build -f backend-prod.Dockerfile -t jarvis-backend-prod:latest .

# Build frontend production image (includes DELETE endpoint fix)
docker build -f frontend-prod.Dockerfile -t jarvis-frontend:prod .

# Build session manager
cd session-manager
docker build -t session-manager:latest .
cd ..
```

### Step 3: Start Core Infrastructure

```bash
# Start Redis (required for session state)
docker run -d --name redis \
  -p 6379:6379 \
  --network jarvis-network \
  redis:alpine

# Start Session Manager with correct backend image
docker run -d --name session-manager \
  -p 9001:9000 \
  -e REDIS_HOST=host.docker.internal \
  -e BACKEND_IMAGE=jarvis-backend-prod:latest \
  -v /var/run/docker.sock:/var/run/docker.sock \
  --network bridge \
  session-manager:latest

# Start Landing Page
docker run -d --name jarvis-landing \
  -p 80:80 \
  -v $(pwd)/landing:/usr/share/nginx/html:ro \
  --network jarvis-network \
  nginx:alpine
```

### Step 4: Configure NGINX Routing (Optional)

If you want path-based routing for sessions:

```bash
# Copy NGINX config
cp nginx-simple.conf /tmp/nginx.conf

# Start NGINX with routing
docker run -d --name jarvis-nginx \
  -p 8080:80 \
  -v /tmp/nginx.conf:/etc/nginx/nginx.conf:ro \
  --network jarvis-network \
  nginx:alpine
```

### Step 5: Verify Installation

```bash
# Check all services are running
docker ps | grep -E "redis|session-manager|jarvis-landing"

# Test Session Manager health
curl http://localhost:9001/api/health

# Expected output:
# {
#   "status": "healthy",
#   "timestamp": "...",
#   "active_sessions": 0,
#   "max_sessions": 150
# }
```

## User Experience

### For End Users

1. **Access Landing Page**: Navigate to http://localhost
2. **Launch Instance**: Click "Launch Your Jarvis Instance" button
3. **Automatic Setup**: 
   - Unique session ID generated
   - Session token stored in browser localStorage
   - Frontend and backend containers created
4. **Use Jarvis**: 
   - Log generator interface loads automatically
   - Select security products and scenarios
   - Generate and send logs to configured destinations
5. **Session Persistence**: 
   - Sessions last 24 hours by default
   - Automatic reconnection on page refresh
   - Token persists across browser sessions

### Session URLs

Each user receives personalized URLs:
- Frontend: `http://localhost:{dynamic_port}/`
- Backend API: `http://localhost:{dynamic_port}/api/v1/`
- Session ID: Visible in localStorage as `jarvis_session_token`

## Admin Console Guide

### Accessing the Admin Panel

1. **URL**: http://localhost/admin
2. **Credentials**:
   - Username: `admin`
   - Password: `techsummit2025`

### Admin Panel Features

#### 1. Dashboard Overview
- **Active Sessions Count**: Real-time count of running sessions
- **Resource Usage**: CPU and memory consumption
- **System Health**: Service status indicators

#### 2. Session Management

**List All Sessions** (`GET /api/admin/sessions/active`)
```json
{
  "total": 15,
  "sessions": [
    {
      "session_id": "user123-a24fd782",
      "user_id": "user123",
      "status": "active",
      "created_at": "2025-11-16T10:00:00Z",
      "expires_at": "2025-11-17T10:00:00Z",
      "containers": {
        "frontend": "running",
        "backend": "running"
      }
    }
  ],
  "max_sessions": 150
}
```

**Terminate Session** (`DELETE /api/admin/sessions/{session_id}`)
- Immediately stops frontend and backend containers
- Releases allocated ports
- Clears session from Redis

**Extend Session** (`POST /api/admin/sessions/{session_id}/extend`)
```bash
curl -X POST http://localhost:9001/api/admin/sessions/{session_id}/extend \
  -u admin:techsummit2025 \
  -H "Content-Type: application/json" \
  -d '{"hours": 12}'
```

#### 3. Configuration Management

**Global Settings** (`PUT /api/admin/config`)
```json
{
  "max_sessions": 150,
  "max_sessions_per_user": 3,
  "session_ttl_hours": 24,
  "features": {
    "log_generation": true,
    "destinations": true,
    "scenarios": ["all"],
    "products": ["sentinelone"]
  }
}
```

**Per-Session Configuration** (`POST /api/admin/sessions/{session_id}/config`)
```json
{
  "features": {
    "log_generation": true,
    "max_events": 1000,
    "allowed_products": ["sentinelone"],
    "rate_limit": 100
  }
}
```

#### 4. Maintenance Operations

**Cleanup Expired Sessions** (`POST /api/admin/sessions/cleanup`)
```bash
curl -X POST http://localhost:9001/api/admin/sessions/cleanup \
  -u admin:techsummit2025
```

**Health Check All Services**
```bash
# Check Session Manager
curl http://localhost:9001/api/health

# Check Redis
docker exec redis redis-cli PING

# Check Active Containers
docker ps --filter "label=managed_by=jarvis_session_manager"
```

### Admin API Endpoints

| Endpoint | Method | Description | Auth Required |
|----------|--------|-------------|---------------|
| `/api/admin/login` | POST | Admin login | No |
| `/api/admin/config` | GET | Get global config | Yes |
| `/api/admin/config` | PUT | Update global config | Yes |
| `/api/admin/sessions/active` | GET | List all active sessions | Yes |
| `/api/admin/sessions/{id}` | GET | Get session details | Yes |
| `/api/admin/sessions/{id}` | DELETE | Terminate session | Yes |
| `/api/admin/sessions/{id}/config` | POST | Update session config | Yes |
| `/api/admin/sessions/{id}/extend` | POST | Extend session TTL | Yes |
| `/api/admin/sessions/cleanup` | POST | Clean expired sessions | Yes |

## Configuration

### Environment Variables

#### Session Manager
```bash
# Redis Connection
REDIS_HOST=redis              # Redis hostname
REDIS_PORT=6379               # Redis port
REDIS_DB=0                    # Redis database number

# Docker Configuration
BACKEND_IMAGE=jarvis-backend-prod:latest  # Backend container image
FRONTEND_IMAGE=jarvis-frontend:prod       # Frontend container image

# Session Limits
MAX_TOTAL_SESSIONS=150        # Maximum concurrent sessions
MAX_SESSIONS_PER_USER=5       # Max sessions per user ID
SESSION_TTL_HOURS=24          # Session lifetime in hours

# Port Allocation
PORT_RANGE_START=10000        # Start of port range
PORT_RANGE_END=20000          # End of port range
```

#### Backend Containers
```bash
# Authentication
DISABLE_AUTH=true             # Disable auth for Tech Summit
API_KEY=<generated>           # Auto-generated per session

# Session Info
SESSION_ID=<unique_id>        # Unique session identifier
USER_ID=<user_id>            # User identifier

# Logging
LOG_LEVEL=info               # Log verbosity
```

#### Frontend Containers
```bash
# API Connection
API_BASE_URL=http://jarvis-{session_id}-backend:8000
SESSION_API_KEY=<generated>   # Matches backend API key

# Server Config
SERVER_MODE=gunicorn         # Production server
WORKERS=2                    # Gunicorn workers
PORT=8000                    # Internal port
```

### Configuration Files

#### Session Manager Config
Location: `/session-manager/app/core/config.py`

```python
# Key settings to adjust:
max_total_sessions: int = 150
session_ttl_hours: int = 24
port_range_start: int = 10000
port_range_end: int = 20000
backend_cpu_limit: str = "1.5"
backend_memory_limit: str = "2G"
frontend_cpu_limit: str = "0.5"
frontend_memory_limit: str = "1G"
```

#### Admin Panel Config
Location: `/session-manager/app/routers/admin.py`

```python
# Change admin credentials
ADMIN_USERNAME = os.environ.get("ADMIN_USERNAME", "<ASK_NATE>")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "<ASK_NATE>")
```

## Key Architecture Decisions & Fixes

### Resolved Issues During Development

1. **Docker Network Subnet Exhaustion (27 session limit)**
   - **Problem**: Creating per-session networks exhausted Docker's subnet pool
   - **Solution**: Implemented shared network architecture (`jarvis-network`)
   - **Result**: Can now scale to 150+ sessions

2. **Backend Container User Permissions**
   - **Problem**: entrypoint.sh expected `jarvis:jarvis` user but Dockerfile didn't create it
   - **Solution**: Added user creation and `gosu` installation in backend-prod.Dockerfile
   - **Result**: Backend containers start successfully

3. **Destination Persistence**
   - **Problem**: Destinations weren't persisting between container restarts
   - **Solution**: Added named volumes (`jarvis-{session_id}-data`) shared between frontend/backend
   - **Result**: SQLite database and configurations persist

4. **Frontend DELETE Endpoint**
   - **Problem**: Destination deletion returning 405 Method Not Allowed
   - **Solution**: Rebuilt frontend image with proper DELETE route registration
   - **Result**: Full CRUD operations for destinations work

5. **Volume Mounts for Event Generators**
   - **Problem**: Frontend couldn't access event generators and parsers
   - **Solution**: Mount host Backend directory as read-only volume in both containers
   - **Result**: All products and scenarios accessible in dropdowns

## Troubleshooting

### Common Issues and Solutions

#### 1. Backend Container Fails: "invalid user: jarvis:jarvis"

**Issue**: Backend Dockerfile missing user creation
**Solution**: Ensure you're using `jarvis-backend-prod:latest` image built from updated Dockerfile:

```dockerfile
# Create jarvis user (required in Dockerfile)
RUN useradd -m -u 1000 jarvis && \
    mkdir -p /app/data && \
    chown -R jarvis:jarvis /app
```

#### 2. Session Creation Returns 502 Error

**Issue**: Backend container not starting properly
**Solution**: 
```bash
# Check backend logs
docker logs jarvis-{session_id}-backend

# Verify image is correct
docker ps | grep backend | awk '{print $2}'
# Should show: jarvis-backend-prod:latest

# Restart session manager with correct image
docker restart session-manager
```

#### 3. Docker Network Subnet Exhaustion (>27 sessions fail)

**Issue**: Per-session networks exhaust Docker subnets
**Solution**: Platform now uses shared network architecture:
```bash
# Verify shared network exists
docker network ls | grep jarvis-network

# If missing, create it
docker network create jarvis-network
```

#### 4. Port Allocation Failures

**Issue**: Ports already in use or exhausted
**Solution**:
```bash
# Check allocated ports in Redis
docker exec redis redis-cli SMEMBERS allocated_ports

# Clear port allocations if needed
docker exec redis redis-cli DEL allocated_ports

# Restart session manager
docker restart session-manager
```

#### 5. Frontend Can't Connect to Backend

**Issue**: Container network connectivity
**Solution**:
```bash
# Verify both containers on same network
docker inspect {frontend_container} | grep NetworkMode
docker inspect {backend_container} | grep NetworkMode

# Test connectivity
docker exec {frontend_container} ping {backend_container}
```

#### 6. Session Manager Can't Access Docker

**Issue**: Docker socket permissions
**Solution**:
```bash
# Ensure socket is mounted
docker inspect session-manager | grep -A 2 Mounts

# Should show:
# "/var/run/docker.sock:/var/run/docker.sock"
```

#### 7. Admin Panel 404 Errors

**Issue**: Router not properly imported
**Solution**: Verify `/session-manager/app/routers/__init__.py` exists and main.py includes:
```python
from .routers import admin
app.include_router(admin.router, prefix="/api/admin", tags=["admin"])
```

### Debug Commands

```bash
# View all Jarvis containers
docker ps -a --filter "label=managed_by=jarvis_session_manager"

# Check session manager logs
docker logs session-manager --tail 50

# Monitor Redis keys
docker exec redis redis-cli --scan --pattern "session:*"

# Check port allocations
docker exec redis redis-cli SMEMBERS allocated_ports | wc -l

# View container resource usage
docker stats --no-stream $(docker ps -q --filter "label=managed_by=jarvis_session_manager")

# Test session creation
curl -X POST http://localhost:9001/api/sessions \
  -H "Content-Type: application/json" \
  -d '{"user_id": "test-user", "metadata": {}}'
```

## Maintenance

### Daily Operations

```bash
# Morning health check
curl http://localhost:9001/api/health

# Review overnight sessions
curl http://localhost:9001/api/admin/sessions/active \
  -u admin:techsummit2025 | jq '.total'

# Clean expired sessions
curl -X POST http://localhost:9001/api/admin/sessions/cleanup \
  -u admin:techsummit2025
```

### Before Tech Summit Event

```bash
# 1. Clear all test sessions
docker ps -q --filter "label=managed_by=jarvis_session_manager" | xargs docker rm -f

# 2. Reset Redis
docker exec redis redis-cli FLUSHALL

# 3. Restart core services
docker restart redis session-manager

# 4. Pre-warm Docker images on all nodes
docker pull jarvis-backend-prod:latest
docker pull jarvis-frontend:prod

# 5. Test session creation
for i in {1..5}; do
  curl -X POST http://localhost:9001/api/sessions \
    -H "Content-Type: application/json" \
    -d "{\"user_id\": \"test-$i\", \"metadata\": {}}"
done

# 6. Verify all test sessions running
docker ps --filter "label=managed_by=jarvis_session_manager" | wc -l
```

### During Event Monitoring

```bash
# Real-time session count
watch -n 5 'docker ps -q --filter "label=managed_by=jarvis_session_manager" | wc -l'

# Monitor resource usage
docker stats --no-stream

# Check for failed containers
docker ps -a --filter "status=exited" --filter "label=managed_by=jarvis_session_manager"

# View session manager performance
docker logs session-manager --tail 100 -f | grep -E "Created session|Failed|Error"
```

### Post-Event Cleanup

```bash
# 1. Export session data (optional)
docker exec redis redis-cli --rdb /data/backup.rdb SAVE

# 2. Stop all user sessions
docker ps -q --filter "label=managed_by=jarvis_session_manager" | xargs docker stop

# 3. Remove all user containers  
docker ps -aq --filter "label=managed_by=jarvis_session_manager" | xargs docker rm

# 4. Clear Redis data
docker exec redis redis-cli FLUSHALL

# 5. Reset port allocations
docker restart session-manager
```

## Production Deployment

### Scaling Considerations

#### For 150 Concurrent Users

**Resource Requirements**:
- **RAM**: 16GB minimum (100MB per session pair)
- **CPU**: 8+ cores recommended
- **Disk**: 50GB for container layers and logs
- **Network**: 100Mbps+ for smooth operation

**Docker Daemon Tuning**:
```bash
# /etc/docker/daemon.json
{
  "max-concurrent-downloads": 10,
  "max-concurrent-uploads": 10,
  "log-driver": "json-file",
  "log-opts": {
    "max-size": "10m",
    "max-file": "3"
  },
  "storage-driver": "overlay2",
  "storage-opts": [
    "overlay2.override_kernel_check=true"
  ]
}
```

### Security Hardening

1. **Change Default Passwords**:
```bash
export ADMIN_USERNAME=techsummit_admin
export ADMIN_PASSWORD=$(openssl rand -base64 32)
```

2. **Enable HTTPS**:
```nginx
server {
    listen 443 ssl;
    ssl_certificate /etc/nginx/ssl/cert.pem;
    ssl_certificate_key /etc/nginx/ssl/key.pem;
    # ... rest of config
}
```

3. **Implement Rate Limiting**:
```python
# In session-manager/app/main.py
from slowapi import Limiter
limiter = Limiter(key_func=lambda: request.client.host)
app.add_middleware(limiter.middleware)
```

4. **Network Isolation**:
```bash
# Create internal network for backends
docker network create jarvis-backend --internal

# Create DMZ network for frontends  
docker network create jarvis-frontend
```

### High Availability Setup

For production, consider:

1. **Redis Persistence**:
```bash
docker run -d --name redis \
  -v redis-data:/data \
  redis:alpine redis-server --appendonly yes
```

2. **Session Manager Replicas**:
```yaml
# docker-compose.ha.yml
services:
  session-manager:
    image: session-manager:latest
    deploy:
      replicas: 3
      restart_policy:
        condition: any
```

3. **Load Balancer** (HAProxy/NGINX):
```nginx
upstream session_managers {
    server session-manager-1:9000;
    server session-manager-2:9000;
    server session-manager-3:9000;
}
```

### Monitoring Integration

#### Prometheus Metrics
```yaml
# prometheus.yml
scrape_configs:
  - job_name: 'session-manager'
    static_configs:
      - targets: ['session-manager:9090']
```

#### Grafana Dashboard
Import dashboard JSON from `/monitoring/grafana-dashboard.json` for:
- Active sessions gauge
- Container creation rate
- Resource usage per session
- Error rate monitoring

### Backup and Recovery

```bash
# Backup script (run daily)
#!/bin/bash
DATE=$(date +%Y%m%d)
mkdir -p /backups/$DATE

# Backup Redis
docker exec redis redis-cli SAVE
docker cp redis:/data/dump.rdb /backups/$DATE/

# Backup configurations
tar -czf /backups/$DATE/configs.tar.gz \
  session-manager/app/core/config.py \
  docker-compose.*.yml \
  nginx*.conf

# Backup container images
docker save -o /backups/$DATE/images.tar \
  jarvis-backend-prod:latest \
  jarvis-frontend:prod \
  session-manager:latest
```

## Support and Debugging

### Logging Locations

- **Session Manager**: `docker logs session-manager`
- **Redis**: `docker logs redis`
- **User Containers**: `docker logs jarvis-{session_id}-{component}`
- **NGINX**: `docker logs jarvis-nginx`

### Key Files to Check

```bash
# Session Manager
/session-manager/app/core/config.py          # Configuration
/session-manager/app/services/docker_manager.py  # Container orchestration
/session-manager/app/routers/admin.py        # Admin endpoints

# Docker Images
/backend-prod.Dockerfile                     # Backend container definition
/frontend-prod.Dockerfile                    # Frontend container definition
/session-manager/Dockerfile                  # Session manager build

# Landing Page
/landing/index.html                          # User entry point
/landing/app.js                             # Session creation logic

# Configuration
/nginx-simple.conf                           # NGINX routing
/docker-compose.tech-summit.yml             # Service orchestration
```

### Emergency Procedures

**All Sessions Failed**:
```bash
# 1. Stop everything
docker stop $(docker ps -q)

# 2. Clean up
docker system prune -f

# 3. Restart core services only
docker start redis
docker start session-manager

# 4. Test with single session
curl -X POST http://localhost:9001/api/sessions \
  -H "Content-Type: application/json" \
  -d '{"user_id": "emergency-test"}'
```

**Out of Resources**:
```bash
# Free up space
docker system prune -a -f --volumes

# Reduce session limits
docker exec session-manager sh -c \
  'echo "MAX_TOTAL_SESSIONS=50" >> /app/.env'
docker restart session-manager
```

## License

Proprietary - Tech Summit 2025. All rights reserved.