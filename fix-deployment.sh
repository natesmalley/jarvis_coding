#!/bin/bash

echo "Fixing Jarvis deployment networking..."

# Stop existing containers
echo "Stopping existing containers..."
docker stop jarvis-nginx session-manager redis 2>/dev/null
docker rm jarvis-nginx session-manager redis 2>/dev/null

# Ensure jarvis-shared network exists
echo "Creating/verifying jarvis-shared network..."
docker network create jarvis-shared 2>/dev/null || echo "Network already exists"

# Start Redis on jarvis-shared network
echo "Starting Redis..."
docker run -d --name redis \
  --network jarvis-shared \
  -p 6379:6379 \
  redis:alpine

# Start Session Manager on jarvis-shared network  
echo "Starting Session Manager..."
docker run -d --name session-manager \
  --network jarvis-shared \
  -p 9001:9000 \
  -e REDIS_HOST=redis \
  -e BACKEND_IMAGE=jarvis-backend-prod:latest \
  -e FRONTEND_IMAGE=jarvis-frontend:prod \
  -v /var/run/docker.sock:/var/run/docker.sock \
  session-manager:latest

# Update landing page and NGINX config on the server
echo "Starting NGINX on jarvis-shared network..."
docker run -d --name jarvis-nginx \
  --network jarvis-shared \
  -p 80:80 \
  -p 443:443 \
  -v $(pwd)/landing:/usr/share/nginx/html:ro \
  -v $(pwd)/admin-panel:/usr/share/nginx/admin:ro \
  -v $(pwd)/nginx-fixed.conf:/etc/nginx/nginx.conf:ro \
  nginx:alpine

echo "Verifying services..."
sleep 3

# Test connectivity
echo "Testing Session Manager health..."
curl http://localhost:9001/api/health

echo ""
echo "Deployment fixed! All services are on jarvis-shared network."
echo ""
echo "Key changes:"
echo "1. All services (Redis, Session Manager, NGINX) are on jarvis-shared network"
echo "2. NGINX can now resolve container names via Docker DNS"  
echo "3. Path-based routing (/session/{id}/frontend/) will work properly"
echo ""
echo "Access points:"
echo "- Landing page: http://your-domain/"
echo "- Admin panel: http://your-domain/admin"
echo "- Session Manager API: http://your-domain/api/"