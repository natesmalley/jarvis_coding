#!/bin/bash
# Update HELIOS frontend/backend images from latest main branch
# Run this script on the server to pull latest main code and rebuild container images
# Usage: ./update-images.sh [--restart-sessions]

set -e

REPO_DIR="$(cd "$(dirname "$0")" && pwd)"
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo "================================================"
echo "HELIOS Image Update Script"
echo "================================================"
echo ""

cd "$REPO_DIR"
CURRENT_BRANCH=$(git branch --show-current)
echo -e "Repo: $REPO_DIR"
echo -e "Current branch: $CURRENT_BRANCH"

# Step 1: Fetch and checkout main, build images
echo ""
echo -e "${YELLOW}Step 1: Fetching latest main branch...${NC}"
git fetch origin main
git stash 2>/dev/null || true

# Save current branch to return to
git checkout main
git reset --hard origin/main
MAIN_COMMIT=$(git log --oneline -1)
echo -e "${GREEN}Main branch at: $MAIN_COMMIT${NC}"

# Step 2: Build frontend and backend images from main
echo ""
echo -e "${YELLOW}Step 2: Building frontend image...${NC}"
docker build -f Frontend/Dockerfile -t jarvis-frontend:latest . 2>&1 | tail -3
echo -e "${GREEN}Frontend image built${NC}"

echo ""
echo -e "${YELLOW}Step 3: Building backend image...${NC}"
docker build -f Backend/api/Dockerfile -t jarvis-backend:latest . 2>&1 | tail -3
echo -e "${GREEN}Backend image built${NC}"

# Step 3: Return to original branch
echo ""
echo -e "${YELLOW}Step 4: Returning to $CURRENT_BRANCH branch...${NC}"
git checkout "$CURRENT_BRANCH"
git stash pop 2>/dev/null || true

# Step 4: Rebuild session manager from current branch
if [ -d "session-manager" ]; then
    echo ""
    echo -e "${YELLOW}Step 5: Building session manager...${NC}"
    cd session-manager
    docker build -t session-manager:latest . 2>&1 | tail -3
    cd "$REPO_DIR"
    echo -e "${GREEN}Session manager built${NC}"
fi

# Step 5: Restart infrastructure containers
echo ""
echo -e "${YELLOW}Step 6: Restarting infrastructure...${NC}"

# Restart session manager with correct config
docker stop jarvis-session-manager 2>/dev/null || true
docker rm jarvis-session-manager 2>/dev/null || true
docker run -d --name jarvis-session-manager \
  --network jarvis-shared \
  --restart unless-stopped \
  -p 9000:9000 \
  -e REDIS_HOST=jarvis-redis \
  -e REDIS_PORT=6379 \
  -e BACKEND_IMAGE=jarvis-backend:latest \
  -e FRONTEND_IMAGE=jarvis-frontend:latest \
  -e MAX_TOTAL_SESSIONS=100 \
  -e SESSION_TTL_HOURS=24 \
  -e PORT_RANGE_START=10000 \
  -e PORT_RANGE_END=20000 \
  -e LOG_LEVEL=info \
  -v /var/run/docker.sock:/var/run/docker.sock \
  session-manager:latest > /dev/null
echo -e "${GREEN}Session manager restarted${NC}"

# Restart Docker nginx on port 8080 (host nginx handles 80/443 with SSL)
docker stop jarvis-nginx 2>/dev/null || true
docker rm jarvis-nginx 2>/dev/null || true
docker run -d --name jarvis-nginx \
  --network jarvis-shared \
  --restart unless-stopped \
  -p 8080:80 \
  -v "$REPO_DIR/landing":/usr/share/nginx/html:ro \
  -v "$REPO_DIR/admin-panel":/usr/share/nginx/admin:ro \
  -v "$REPO_DIR/nginx-production.conf":/etc/nginx/nginx.conf:ro \
  nginx:alpine > /dev/null
echo -e "${GREEN}Docker nginx restarted on port 8080${NC}"

# Step 6: Optionally clear sessions so they pick up new images
if [ "$1" == "--restart-sessions" ]; then
    echo ""
    echo -e "${YELLOW}Step 7: Clearing all active sessions...${NC}"

    # Kill existing session containers
    docker ps -q --filter label=managed_by=session_manager | xargs -r -P 20 docker stop -t 2 2>/dev/null || true
    docker ps -aq --filter label=managed_by=session_manager | xargs -r docker rm -f 2>/dev/null || true
    docker exec jarvis-redis redis-cli FLUSHALL > /dev/null 2>&1

    # Restart session manager to clear cached state
    docker restart jarvis-session-manager > /dev/null
    echo -e "${GREEN}All sessions cleared${NC}"
fi

# Step 7: Clean up old images and volumes
echo ""
echo -e "${YELLOW}Cleaning up...${NC}"
docker image prune -f 2>&1 | tail -1
docker volume prune -f 2>&1 | tail -1

# Health check
echo ""
echo -e "${YELLOW}Verifying...${NC}"
sleep 3
HEALTH=$(curl -s http://localhost:9000/api/health 2>/dev/null)
LANDING=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:8080/ 2>/dev/null)
echo -e "Session Manager: $HEALTH"
echo -e "Landing Page:    HTTP $LANDING"

# Summary
echo ""
echo -e "${GREEN}================================================${NC}"
echo -e "${GREEN}Update Complete${NC}"
echo -e "${GREEN}================================================${NC}"
echo ""
echo "Images built from main branch commit: $MAIN_COMMIT"
echo ""
docker images --format "table {{.Repository}}\t{{.Tag}}\t{{.CreatedSince}}" | grep -E "jarvis|session|REPO"
echo ""
echo "New sessions will use the updated images."
if [ "$1" != "--restart-sessions" ]; then
    echo "Existing sessions still use the old images."
    echo "Run with --restart-sessions to clear all sessions and restart."
fi
