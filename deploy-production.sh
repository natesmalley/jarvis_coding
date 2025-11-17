#!/bin/bash

# Production Deployment Script for Jarvis Tech Summit 2025
# Usage: ./deploy-production.sh

set -e

echo "🚀 Jarvis Production Deployment Script"
echo "======================================"

# Check if running as root (recommended for production)
if [ "$EUID" -eq 0 ]; then 
   echo "✅ Running as root"
else
   echo "⚠️  Warning: Not running as root. Some operations may fail."
fi

# Check for .env.production file
if [ ! -f .env.production ]; then
    echo "❌ Error: .env.production file not found!"
    echo "Please copy .env.production.template to .env.production and configure it."
    exit 1
fi

# Load environment variables
source .env.production

echo "📋 Configuration:"
echo "  - Domain: ${DOMAIN_NAME:-not set}"
echo "  - HTTP Port: ${HTTP_PORT:-80}"
echo "  - Max Sessions: ${MAX_TOTAL_SESSIONS:-150}"
echo "  - Workspace: ${WORKSPACE_PATH:-./}"

# Step 1: Build Images
echo ""
echo "🔨 Step 1: Building Docker Images..."
echo "-------------------------------------"

echo "Building backend image..."
docker build -f backend-prod.Dockerfile -t jarvis-backend-prod:latest .

echo "Building frontend image..."
docker build -f frontend-prod.Dockerfile -t jarvis-frontend:prod .

echo "Building session manager..."
cd session-manager
docker build -t session-manager:latest .
cd ..

# Step 2: Create Network
echo ""
echo "🌐 Step 2: Setting up Docker Network..."
echo "----------------------------------------"

# Check if network exists
if docker network ls | grep -q jarvis-shared; then
    echo "Network jarvis-shared already exists"
else
    echo "Creating jarvis-shared network..."
    docker network create jarvis-shared
fi

# Step 3: Stop existing containers (if any)
echo ""
echo "🛑 Step 3: Stopping Existing Services..."
echo "-----------------------------------------"

docker-compose -f docker-compose.production.yml down || true

# Step 4: Start services
echo ""
echo "🚀 Step 4: Starting Services..."
echo "--------------------------------"

docker-compose -f docker-compose.production.yml up -d

# Step 5: Wait for services to be ready
echo ""
echo "⏳ Step 5: Waiting for Services..."
echo "-----------------------------------"

echo -n "Waiting for Redis..."
until docker exec jarvis-redis redis-cli ping &>/dev/null; do
    echo -n "."
    sleep 1
done
echo " ✅"

echo -n "Waiting for Session Manager..."
for i in {1..30}; do
    if curl -s http://localhost:9000/api/health &>/dev/null; then
        echo " ✅"
        break
    fi
    echo -n "."
    sleep 1
done

echo -n "Waiting for NGINX..."
for i in {1..10}; do
    if curl -s http://localhost:${HTTP_PORT:-80}/health &>/dev/null; then
        echo " ✅"
        break
    fi
    echo -n "."
    sleep 1
done

# Step 6: Verify deployment
echo ""
echo "🔍 Step 6: Verifying Deployment..."
echo "-----------------------------------"

# Check all services are running
SERVICES_OK=true

if docker ps | grep -q jarvis-redis; then
    echo "✅ Redis is running"
else
    echo "❌ Redis is not running"
    SERVICES_OK=false
fi

if docker ps | grep -q jarvis-session-manager; then
    echo "✅ Session Manager is running"
else
    echo "❌ Session Manager is not running"
    SERVICES_OK=false
fi

if docker ps | grep -q jarvis-nginx; then
    echo "✅ NGINX is running"
else
    echo "❌ NGINX is not running"
    SERVICES_OK=false
fi

# Test API endpoint
echo ""
echo "Testing API health endpoint..."
HEALTH_RESPONSE=$(curl -s http://localhost:9000/api/health | jq -r '.status' 2>/dev/null || echo "failed")
if [ "$HEALTH_RESPONSE" = "healthy" ]; then
    echo "✅ API is healthy"
else
    echo "❌ API health check failed"
    SERVICES_OK=false
fi

# Final status
echo ""
echo "======================================"
if [ "$SERVICES_OK" = true ]; then
    echo "✅ Deployment Successful!"
    echo ""
    echo "Access Points:"
    echo "  - Landing Page: http://${DOMAIN_NAME:-localhost}/"
    echo "  - Admin Panel: http://${DOMAIN_NAME:-localhost}/admin"
    echo "  - API Health: http://${DOMAIN_NAME:-localhost}:9000/api/health"
    echo ""
    echo "Default Admin Credentials:"
    echo "  - Username: ${ADMIN_USERNAME:-admin}"
    echo "  - Password: (as configured in .env.production)"
else
    echo "❌ Deployment Failed!"
    echo "Check the logs with: docker-compose -f docker-compose.production.yml logs"
    exit 1
fi

echo ""
echo "🎯 Next Steps:"
echo "1. Configure your firewall to allow ports ${HTTP_PORT:-80} and ${HTTPS_PORT:-443}"
echo "2. Set up SSL certificates for HTTPS (recommended)"
echo "3. Configure DNS to point ${DOMAIN_NAME:-your-domain} to this server"
echo "4. Monitor logs: docker-compose -f docker-compose.production.yml logs -f"
echo ""
echo "======================================"