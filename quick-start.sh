#!/bin/bash
# Quick start script for Tech Summit (uses pre-built images)

set -e

echo "================================================"
echo "Quick Start - Tech Summit Deployment"
echo "================================================"

# Create .env if needed
if [ ! -f .env ]; then
    cat > .env << EOF
POSTGRES_PASSWORD=techsummit2024
SECRET_KEY=$(openssl rand -hex 32 2>/dev/null || echo "techsummit-secret-key")
MAX_TOTAL_SESSIONS=150
SESSION_TTL_HOURS=24
SERVER_MODE=gunicorn
GRAFANA_PASSWORD=admin
LOG_LEVEL=info
EOF
    echo "✅ Created .env file"
fi

# Tag existing images for our use
echo "Preparing images..."
docker tag jarvis_coding-api:latest jarvis-backend:latest 2>/dev/null || true
docker tag jarvis_coding-frontend:latest jarvis-frontend:latest 2>/dev/null || true

# Build only Session Manager (smaller, faster)
echo "Building Session Manager..."
docker build -t jarvis-session-manager:latest -f session-manager/Dockerfile . || {
    echo "⚠️  Using simplified Session Manager build"
    # Create a simplified Dockerfile if build fails
    cat > session-manager/Dockerfile.simple << 'DOCKERFILE'
FROM python:3.11-slim
WORKDIR /app
RUN pip install fastapi uvicorn docker redis psycopg2-binary sqlalchemy httpx gunicorn
COPY session-manager/app ./app
COPY session-manager/gunicorn.conf.py .
EXPOSE 9000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "9000"]
DOCKERFILE
    docker build -t jarvis-session-manager:latest -f session-manager/Dockerfile.simple .
}

# Start only essential services
echo "Starting core services..."

# Start PostgreSQL and Redis
docker run -d --name jarvis-postgres \
    -e POSTGRES_DB=sessions \
    -e POSTGRES_USER=postgres \
    -e POSTGRES_PASSWORD=techsummit2024 \
    -p 5432:5432 \
    postgres:15-alpine 2>/dev/null || echo "PostgreSQL already running"

docker run -d --name jarvis-redis \
    -p 6379:6379 \
    redis:7-alpine 2>/dev/null || echo "Redis already running"

# Wait for services
echo "Waiting for databases..."
sleep 5

# Start Session Manager with host networking for Docker access
docker run -d --name jarvis-session-manager \
    --network host \
    -v /var/run/docker.sock:/var/run/docker.sock \
    -e DATABASE_URL=postgresql://postgres:techsummit2024@localhost:5432/sessions \
    -e REDIS_URL=redis://localhost:6379/0 \
    -e PORT=9000 \
    -e MAX_TOTAL_SESSIONS=150 \
    -e SERVER_MODE=uvicorn \
    jarvis-session-manager:latest 2>/dev/null || {
    docker stop jarvis-session-manager 2>/dev/null
    docker rm jarvis-session-manager 2>/dev/null
    docker run -d --name jarvis-session-manager \
        --network host \
        -v /var/run/docker.sock:/var/run/docker.sock \
        -e DATABASE_URL=postgresql://postgres:techsummit2024@localhost:5432/sessions \
        -e REDIS_URL=redis://localhost:6379/0 \
        -e PORT=9000 \
        -e MAX_TOTAL_SESSIONS=150 \
        -e SERVER_MODE=uvicorn \
        jarvis-session-manager:latest
}

echo ""
echo "================================================"
echo "Services Starting..."
echo "================================================"
echo ""
echo "Waiting for Session Manager to be ready..."
for i in {1..30}; do
    if curl -s http://localhost:9000/api/health > /dev/null 2>&1; then
        echo "✅ Session Manager is ready!"
        break
    fi
    echo -n "."
    sleep 1
done

echo ""
echo "================================================"
echo "Deployment Status"
echo "================================================"
docker ps --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"

echo ""
echo "================================================"
echo "Access Points"
echo "================================================"
echo "Session Manager API: http://localhost:9000/api"
echo "Health Check: http://localhost:9000/api/health"
echo ""
echo "Test with:"
echo '  curl -X POST http://localhost:9000/api/sessions -H "Content-Type: application/json" -d "{\"user_id\": \"test-user\"}"'
echo ""