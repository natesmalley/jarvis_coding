# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

HELIOS (HEC-enabled Event Log Inject & Orchestration System) is a security event generation and parser validation platform consisting of:
- **Backend API**: FastAPI service for generating security events and managing parsers
- **Frontend UI**: Flask-based web interface for event generation and management
- **Event Generators**: 100+ Python generators for various security vendors
- **Parser System**: JSON-based parser configurations for SentinelOne AI SIEM

## Essential Commands

### Local Development

```bash
# Setup virtual environment
python3 -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# Install dependencies
pip install -r Backend/api/requirements.txt
pip install -r Backend/event_generators/shared/requirements.txt
pip install -r Frontend/requirements.txt

# Run Backend API (from Backend/api directory)
cd Backend/api
DISABLE_AUTH=true python start_api.py  # Runs on http://localhost:8000

# Run Frontend UI (from Frontend directory)  
cd Frontend
API_BASE_URL=http://localhost:8000 python log_generator_ui.py  # Runs on http://localhost:9001

# Run tests
cd Backend/api
pytest tests/

# Code formatting and linting
black Backend/api
flake8 Backend/api
mypy Backend/api/app
```

### Docker Development (Recommended)

```bash
# Create environment file (first time only)
cp ".env copy" .env

# Build and start both services
docker compose up -d --build

# View logs
docker logs -f jarvis-api
docker logs -f jarvis-frontend

# Stop services
docker compose down

# Rebuild after changes
docker compose build --no-cache && docker compose up -d
```

### Testing and Validation

```bash
# Send test events to HEC
cd Backend/event_generators/shared
export S1_HEC_TOKEN="Your-SDL-WRITE-TOKEN"
python hec_sender.py --product crowdstrike_falcon --count 5

# Validate parser-generator alignment
cd Backend/scenarios
python parser_generator_audit.py

# Run enterprise attack scenario
python enterprise_attack_scenario.py
```

## Architecture and Code Structure

### Backend API (`Backend/api/`)

The FastAPI backend follows a clean architecture pattern:

- **`app/main.py`**: Application entry point with FastAPI initialization and middleware configuration
- **`app/core/`**: Core configuration, authentication, and settings
  - `config.py`: Application settings using pydantic-settings
  - `simple_auth.py`: API key authentication implementation
- **`app/routers/`**: API endpoint definitions (generators, parsers, scenarios, health, etc.)
- **`app/services/`**: Business logic layer
  - `generator_service.py`: Event generation logic
  - `parser_service.py`: Parser management
  - `scenario_service.py`: Attack scenario orchestration
- **`app/models/`**: Pydantic models for request/response validation
- **`app/utils/`**: Helper utilities (logging, encryption, API key generation)

**Key patterns**:
- Dependency injection for authentication
- Async/await for I/O operations
- Pydantic models for validation
- Service layer for business logic separation

### Event Generators (`Backend/event_generators/`)

Organized by security category:
- Each generator is self-contained (<200 lines)
- Uses only Python standard library (except hec_sender.py)
- Naming convention: `<vendor>_<product>.py`
- Exports `<product>_log()` function returning event dictionary

**Generator categories**:
- `cloud_infrastructure/`: AWS, GCP, Azure events
- `network_security/`: Firewall, IDS/IPS, network devices
- `endpoint_security/`: EDR, endpoint protection
- `identity_access/`: IAM, authentication, SSO
- `email_security/`: Email security gateways
- `web_security/`: WAF, proxy, CDN
- `infrastructure/`: Backup, CI/CD, IT management

### Parser System (`Backend/parsers/`)

- **Structure**: `<vendor>_<product>-latest/` directories
- **Contents**: JSON parser configuration + metadata.yaml
- **Standards**: OCSF 1.1.0 compliant field mapping
- **Integration**: Dynamic sourcetype mapping via HEC sender

### Frontend UI (`Frontend/`)

Flask-based web interface:
- **`log_generator_ui.py`**: Main Flask application
- **`templates/`**: Jinja2 HTML templates
- **`static/`**: JavaScript and CSS assets
- Token management via browser localStorage

## Environment Configuration

### Required Environment Variables

```bash
# Authentication (default: disabled for dev)
DISABLE_AUTH=true  # Set to false for production
API_KEYS_ADMIN=your-secure-admin-key
BACKEND_API_KEY=your-secure-admin-key

# HEC Configuration
S1_HEC_TOKEN=Your-SDL-WRITE-TOKEN
S1_API_URL=https://usea1-purple.sentinelone.net
S1_HEC_BATCH=true
S1_HEC_BATCH_MAX_BYTES=1048576
S1_HEC_BATCH_FLUSH_MS=500

# Application
SECRET_KEY=your-secret-key
DATABASE_URL=sqlite+aiosqlite:///./data/jarvis.db
```

## Adding New Features

### New Event Generator
1. Create file in appropriate category: `Backend/event_generators/<category>/<vendor>_<product>.py`
2. Implement `<product>_log()` function
3. Update `PROD_MAP` and `SOURCETYPE_MAP` in `hec_sender.py`
4. Test with corresponding parser

### New API Endpoint
1. Create router in `Backend/api/app/routers/`
2. Add service logic in `Backend/api/app/services/`
3. Define models in `Backend/api/app/models/`
4. Register router in `app/main.py`

### New Parser
1. Create directory: `Backend/parsers/community/<vendor>_<product>-latest/`
2. Add JSON parser configuration
3. Include metadata.yaml with parser details
4. Follow OCSF schema standards

## Testing Strategy

- **Unit tests**: Use pytest for API endpoints and services
- **Integration tests**: Validate generator-parser compatibility
- **End-to-end tests**: HEC ingestion and SDL API validation
- **Coverage**: Aim for 80%+ coverage on critical paths

## Common Issues and Solutions

### API Authentication Errors
- Ensure `.env` has `DISABLE_AUTH=true` for local development
- For production, set proper API keys in environment

### Port Conflicts
- API default: 8000
- Frontend default: 9001 (local) or 9002 (Docker)
- Change in docker-compose.yml if needed

### Module Import Errors
- Rebuild Docker images after dependency changes
- Ensure virtual environment is activated for local development

### Parser Not Found
- Verify parser exists in `Backend/parsers/` directory
- Check naming convention matches expectations

## Security Considerations

- Never commit tokens or API keys
- Use `.env` files (in .gitignore)
- Validate all user inputs
- Follow OCSF standards for parser compatibility
- Use role-based API access in production