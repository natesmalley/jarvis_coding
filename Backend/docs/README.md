# Backend Documentation

## Overview

The Backend provides the core functionality for the Jarvis Coding security event generation platform:
- **Event Generators**: 100+ security event generators for various vendors
- **Parser System**: JSON-based parsers for field extraction
- **REST API**: FastAPI-based service for programmatic access
- **Scenarios**: Attack scenario orchestration and testing

## 📚 Available Documentation

### Getting Started
- **[Backend README](../README.md)** - Main backend documentation with setup instructions
- **[API Documentation](api/README.md)** - REST API reference and examples
- **[Main Project README](../../README.md)** - Overall project overview

### Key Components

#### Event Generators
Located in `Backend/event_generators/`:
- **114 generators** across 6 categories
- Categories: cloud_infrastructure, network_security, endpoint_security, identity_access, email_security, web_security, infrastructure
- Each generator is a standalone Python script
- Shared utilities in `event_generators/shared/`

#### Parsers
Located in `Backend/parsers/`:
- **119 community parsers** in `parsers/community/`
- JSON-based configuration files
- Each parser in its own directory with metadata.yaml

#### API Service
Located in `Backend/api/`:
- FastAPI application with modular routers
- Authentication with API keys (optional)
- Swagger docs at `/api/v1/docs`
- Database support for persistence

#### Scenarios
Located in `Backend/scenarios/`:
- Attack scenario orchestration
- Enterprise attack scenarios
- HEC sender integration
- Parser-generator validation tools

## 🚀 Quick Start

### Using Docker (Recommended)

```bash
# From repository root
cp ".env copy" .env
docker-compose up --build

# Access services:
# API: http://localhost:8000
# Frontend: http://localhost:9002
# API Docs: http://localhost:8000/api/v1/docs
```

### Local Development

```bash
# Setup Python environment
python3 -m venv .venv
source .venv/bin/activate

# Install dependencies
pip install -r Backend/api/requirements.txt
pip install -r Backend/event_generators/shared/requirements.txt

# Run API server
cd Backend/api
DISABLE_AUTH=true python start_api.py

# Test with curl
curl http://localhost:8000/api/v1/health
curl http://localhost:8000/api/v1/generators
```

## 🔧 Configuration

### Environment Variables

Create a `.env` file in the repository root:

```bash
# Authentication (optional for dev)
DISABLE_AUTH=true

# SentinelOne Integration
S1_HEC_TOKEN=your-token-here
S1_API_URL=https://usea1-purple.sentinelone.net

# API Keys (if DISABLE_AUTH=false)
API_KEYS_ADMIN=your-admin-key
API_KEYS_WRITE=your-write-key
API_KEYS_READ_ONLY=your-readonly-key
```

## 📊 Testing Event Generation

### Generate Events via API

```bash
# List available generators
curl http://localhost:8000/api/v1/generators

# Execute a generator
curl -X POST http://localhost:8000/api/v1/generators/aws_waf/execute \
  -H "Content-Type: application/json" \
  -d '{"count": 5, "format": "json"}'
```

### Send Events to SentinelOne

```bash
# Configure HEC token
export S1_HEC_TOKEN="your-token-here"

# Send events
cd Backend/event_generators/shared
python hec_sender.py --product aws_waf --count 10
```

### Run Attack Scenarios

```bash
cd Backend/scenarios

# Run enterprise attack scenario
python enterprise_attack_scenario.py

# Send scenario events
python enterprise_scenario_sender.py --product cisco_duo --count 5
```

## 📁 Project Structure

```
Backend/
├── api/                    # FastAPI REST API
│   ├── app/               # Application code
│   ├── data/              # SQLite database
│   └── start_api.py       # API entry point
├── event_generators/       # Event generation modules
│   ├── cloud_infrastructure/
│   ├── network_security/
│   ├── endpoint_security/
│   ├── identity_access/
│   ├── email_security/
│   ├── web_security/
│   ├── infrastructure/
│   └── shared/            # Shared utilities & HEC sender
├── parsers/               # Parser configurations
│   └── community/         # Community parsers
├── scenarios/             # Attack scenarios
│   ├── configs/           # Scenario configurations
│   └── *.py              # Scenario scripts
└── docs/                  # This documentation
    └── api/              # API-specific docs
```

## 🧪 Validation Tools

### Parser-Generator Validation

```bash
cd Backend/scenarios

# Audit parser-generator alignment
python parser_generator_audit.py

# Validate scenario format
python format_validator.py

# Test enterprise scenario
python enterprise_scenario_validator.py
```

## 🔑 API Authentication

The API supports three authentication modes:

1. **Development (No Auth)**:
   ```bash
   DISABLE_AUTH=true python start_api.py
   ```

2. **API Key Authentication**:
   ```bash
   # Header authentication
   curl -H "X-API-Key: your-key" http://localhost:8000/api/v1/generators
   
   # Query parameter
   curl "http://localhost:8000/api/v1/generators?api_key=your-key"
   ```

3. **Role-Based Access**:
   - **Admin**: Full access
   - **Write**: Execute generators and scenarios
   - **Read-Only**: View only

## 📈 Current Status

- **Generators**: 114 available and functional
- **Parsers**: 119 community parsers
- **API Endpoints**: Health, generators, parsers, scenarios
- **Documentation**: Swagger UI at `/api/v1/docs`

## 🤝 Contributing

1. **Generator Development**: Add new generators to appropriate category directory
2. **Parser Development**: Create JSON parser configurations
3. **API Enhancement**: Extend routers and services
4. **Documentation**: Keep docs in sync with implementation

## 📝 Notes

- This documentation reflects the actual current state of the Backend
- Many planned features are in development (WebSockets, advanced validation, etc.)
- Use environment variables for sensitive configuration
- Docker deployment is recommended for production

## 🔗 Related Documentation

- [API Reference](api/README.md) - Detailed API documentation
- [Main Project README](../../README.md) - Overall project documentation
- [Frontend Documentation](../../Frontend/README.md) - UI documentation

For additional help, check the main project repository or open an issue.