#!/bin/bash
# Deployment script for Tech Summit

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo "================================================"
echo "Tech Summit Deployment Script"
echo "Target: 150 Concurrent Users"
echo "================================================"

# Function to check prerequisites
check_prerequisites() {
    echo -e "\n${YELLOW}Checking prerequisites...${NC}"
    
    # Check Docker
    if ! command -v docker &> /dev/null; then
        echo -e "${RED}❌ Docker is not installed${NC}"
        exit 1
    fi
    echo -e "${GREEN}✅ Docker found: $(docker --version)${NC}"
    
    # Check Docker Compose
    if ! command -v docker-compose &> /dev/null; then
        if ! docker compose version &> /dev/null; then
            echo -e "${RED}❌ Docker Compose is not installed${NC}"
            exit 1
        fi
        COMPOSE_CMD="docker compose"
    else
        COMPOSE_CMD="docker-compose"
    fi
    echo -e "${GREEN}✅ Docker Compose found${NC}"
    
    # Check available resources
    echo -e "\n${YELLOW}System Resources:${NC}"
    if [[ "$OSTYPE" == "darwin"* ]]; then
        echo "CPU Cores: $(sysctl -n hw.ncpu)"
        echo "Total Memory: $(( $(sysctl -n hw.memsize) / 1073741824 )) GB"
    else
        echo "CPU Cores: $(nproc)"
        echo "Total Memory: $(free -h | awk '/^Mem:/ {print $2}')"
    fi
}

# Function to create .env file
create_env_file() {
    if [ ! -f .env ]; then
        echo -e "\n${YELLOW}Creating .env file...${NC}"
        cat > .env << EOF
# Database
POSTGRES_PASSWORD=techsummit2024

# Session Manager
SECRET_KEY=$(openssl rand -hex 32 2>/dev/null || echo "change-me-in-production")
MAX_TOTAL_SESSIONS=150
SESSION_TTL_HOURS=24

# Server Mode
SERVER_MODE=gunicorn

# Monitoring
GRAFANA_PASSWORD=admin

# Logging
LOG_LEVEL=info
EOF
        echo -e "${GREEN}✅ .env file created${NC}"
    else
        echo -e "${GREEN}✅ .env file already exists${NC}"
    fi
}

# Function to build images
build_images() {
    echo -e "\n${YELLOW}Building Docker images...${NC}"
    
    # Build Backend
    echo -e "${BLUE}Building Backend image...${NC}"
    docker build -t jarvis-backend:latest -f Backend/api/Dockerfile . || {
        echo -e "${RED}❌ Failed to build Backend image${NC}"
        exit 1
    }
    echo -e "${GREEN}✅ Backend image built${NC}"
    
    # Build Frontend  
    echo -e "${BLUE}Building Frontend image...${NC}"
    docker build -t jarvis-frontend:latest -f Frontend/Dockerfile . || {
        echo -e "${RED}❌ Failed to build Frontend image${NC}"
        exit 1
    }
    echo -e "${GREEN}✅ Frontend image built${NC}"
    
    # Build Session Manager
    echo -e "${BLUE}Building Session Manager image...${NC}"
    docker build -t jarvis-session-manager:latest -f session-manager/Dockerfile . || {
        echo -e "${RED}❌ Failed to build Session Manager image${NC}"
        exit 1
    }
    echo -e "${GREEN}✅ Session Manager image built${NC}"
}

# Function to start services
start_services() {
    echo -e "\n${YELLOW}Starting services...${NC}"
    
    # Stop any existing services
    echo "Stopping any existing services..."
    $COMPOSE_CMD -f docker-compose.tech-summit.yml down 2>/dev/null || true
    
    # Start core services
    echo -e "${BLUE}Starting core services...${NC}"
    $COMPOSE_CMD -f docker-compose.tech-summit.yml up -d postgres redis
    
    # Wait for PostgreSQL to be ready
    echo "Waiting for PostgreSQL to be ready..."
    sleep 5
    until docker exec jarvis-postgres pg_isready -U postgres 2>/dev/null; do
        echo -n "."
        sleep 1
    done
    echo -e "\n${GREEN}✅ PostgreSQL is ready${NC}"
    
    # Start Session Manager
    echo -e "${BLUE}Starting Session Manager...${NC}"
    $COMPOSE_CMD -f docker-compose.tech-summit.yml up -d session-manager
    
    # Start NGINX
    echo -e "${BLUE}Starting NGINX...${NC}"
    $COMPOSE_CMD -f docker-compose.tech-summit.yml up -d nginx
    
    # Start monitoring (optional)
    echo -e "${BLUE}Starting monitoring services...${NC}"
    $COMPOSE_CMD -f docker-compose.tech-summit.yml up -d prometheus grafana 2>/dev/null || {
        echo -e "${YELLOW}⚠️  Monitoring services are optional${NC}"
    }
    
    # Optional: Start shared frontend
    if [ "$1" == "--with-shared-frontend" ]; then
        echo -e "${BLUE}Starting shared frontend...${NC}"
        $COMPOSE_CMD -f docker-compose.tech-summit.yml \
                     -f docker-compose.tech-summit-shared.yml up -d shared-frontend
    fi
    
    echo -e "${GREEN}✅ All services started${NC}"
}

# Function to verify deployment
verify_deployment() {
    echo -e "\n${YELLOW}Verifying deployment...${NC}"
    
    # Check running containers
    echo "Running containers:"
    docker ps --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"
    
    # Test Session Manager health
    echo -e "\n${YELLOW}Testing Session Manager health...${NC}"
    for i in {1..10}; do
        if curl -s http://localhost/api/health > /dev/null 2>&1; then
            echo -e "${GREEN}✅ Session Manager is healthy${NC}"
            curl -s http://localhost/api/health | python3 -m json.tool
            break
        else
            if [ $i -eq 10 ]; then
                echo -e "${RED}❌ Session Manager health check failed${NC}"
                exit 1
            fi
            echo "Waiting for Session Manager to be ready..."
            sleep 2
        fi
    done
    
    # Create a test session
    echo -e "\n${YELLOW}Creating test session...${NC}"
    RESPONSE=$(curl -s -X POST http://localhost/api/sessions \
        -H "Content-Type: application/json" \
        -d '{"user_id": "deployment_test"}')
    
    if echo "$RESPONSE" | grep -q "session_id"; then
        echo -e "${GREEN}✅ Test session created successfully${NC}"
        SESSION_ID=$(echo "$RESPONSE" | python3 -c "import sys, json; print(json.load(sys.stdin)['session_id'])")
        echo "Session ID: $SESSION_ID"
        
        # Clean up test session
        sleep 2
        curl -s -X DELETE "http://localhost/api/sessions/$SESSION_ID"
        echo -e "${GREEN}✅ Test session cleaned up${NC}"
    else
        echo -e "${RED}❌ Failed to create test session${NC}"
        echo "$RESPONSE"
    fi
}

# Function to show status
show_status() {
    echo -e "\n${GREEN}================================================${NC}"
    echo -e "${GREEN}Deployment Complete!${NC}"
    echo -e "${GREEN}================================================${NC}"
    echo ""
    echo "Access Points:"
    echo "  - Session Manager API: http://localhost/api"
    echo "  - Health Check: http://localhost/health"
    echo "  - Prometheus: http://localhost:9090"
    echo "  - Grafana: http://localhost:3000 (admin/admin)"
    
    if [ "$1" == "--with-shared-frontend" ]; then
        echo "  - Shared Frontend: http://localhost:8080"
    fi
    
    echo ""
    echo "Quick Commands:"
    echo "  - View logs: $COMPOSE_CMD -f docker-compose.tech-summit.yml logs -f"
    echo "  - Stop services: $COMPOSE_CMD -f docker-compose.tech-summit.yml down"
    echo "  - Run tests: ./run_tests.sh"
    echo ""
}

# Main execution
main() {
    echo -e "${BLUE}Starting deployment at $(date)${NC}"
    
    # Parse arguments
    SKIP_BUILD=false
    WITH_SHARED_FRONTEND=""
    
    for arg in "$@"; do
        case $arg in
            --skip-build)
                SKIP_BUILD=true
                ;;
            --with-shared-frontend)
                WITH_SHARED_FRONTEND="--with-shared-frontend"
                ;;
            --help)
                echo "Usage: $0 [OPTIONS]"
                echo "Options:"
                echo "  --skip-build          Skip building Docker images"
                echo "  --with-shared-frontend  Deploy with shared frontend instance"
                echo "  --help                Show this help message"
                exit 0
                ;;
        esac
    done
    
    # Run deployment steps
    check_prerequisites
    create_env_file
    
    if [ "$SKIP_BUILD" = false ]; then
        build_images
    else
        echo -e "${YELLOW}Skipping image build (--skip-build flag)${NC}"
    fi
    
    start_services $WITH_SHARED_FRONTEND
    verify_deployment
    show_status $WITH_SHARED_FRONTEND
    
    echo -e "${GREEN}Deployment completed at $(date)${NC}"
}

# Run main function
main "$@"