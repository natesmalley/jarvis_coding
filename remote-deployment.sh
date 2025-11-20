#!/bin/bash

echo "Deploying Jarvis for remote server (port 9001 setup)..."

# Stop existing containers
echo "Stopping existing containers..."
sudo docker stop jarvis-nginx 2>/dev/null
sudo docker rm jarvis-nginx 2>/dev/null

# Session Manager should already be running on port 9001
# We need to move it to a different port (9002) and use NGINX on 9001

echo "Reconfiguring services..."

# Stop session manager to free up port 9001
sudo docker stop session-manager 2>/dev/null
sudo docker rm session-manager 2>/dev/null

# Ensure jarvis-shared network exists
sudo docker network create jarvis-shared 2>/dev/null || echo "Network already exists"

# Restart Session Manager on port 9002 (internal port stays 9000)
echo "Starting Session Manager on port 9002..."
sudo docker run -d --name session-manager \
  --network jarvis-shared \
  -p 9002:9000 \
  -e REDIS_HOST=redis \
  -e BACKEND_IMAGE=jarvis-backend-prod:latest \
  -e FRONTEND_IMAGE=jarvis-frontend:prod \
  -v /var/run/docker.sock:/var/run/docker.sock \
  session-manager:latest

# Start NGINX on port 9001 (this will be the main entry point)
echo "Starting NGINX on port 9001..."
sudo docker run -d --name jarvis-nginx \
  --network jarvis-shared \
  -p 9001:9001 \
  -v $(pwd)/landing:/usr/share/nginx/html:ro \
  -v $(pwd)/admin-panel:/usr/share/nginx/admin:ro \
  -v $(pwd)/nginx-port-9001.conf:/etc/nginx/nginx.conf:ro \
  nginx:alpine

echo ""
echo "Deployment complete!"
echo ""
echo "Services running:"
echo "- NGINX (main entry): port 9001"
echo "- Session Manager API: port 9002 (internal, accessed via NGINX /api)"
echo "- Redis: port 6379"
echo ""
echo "Access the application at:"
echo "- http://185.64.247.212:9001/ (Landing page)"
echo "- http://185.64.247.212:9001/admin (Admin panel)"
echo "- http://185.64.247.212:9001/api/health (API health check)"