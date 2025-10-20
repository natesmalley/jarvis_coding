# Jarvis Coding REST API

## 🚀 Quick Start

### Install Dependencies

```bash
# Create virtual environment
python3 -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

### Run the API Server

```bash
# Start the server
python start_api.py

# Or use uvicorn directly
uvicorn app.main:app --reload
```

The API will be available at:
- API: http://localhost:8000
- Documentation: http://localhost:8000/api/v1/docs
- ReDoc: http://localhost:8000/api/v1/redoc

## 🔐 Authentication

The API supports simple token-based authentication with role-based access control.

### Authentication Methods

**Header-based (Recommended):**
```bash
curl -H "X-API-Key: your-api-key" http://localhost:8000/api/v1/generators
```

**Query parameter:**
```bash
curl "http://localhost:8000/api/v1/generators?api_key=your-api-key"
```

### User Roles

- **Admin**: Full access to all endpoints and key management
- **Write**: Can execute generators and test parsers  
- **Read-Only**: Can view generators, parsers, and run validation

### Managing API Keys

Generate and manage API keys using the built-in utility:

```bash
# Create a new API key
python app/utils/api_key_generator.py create --name "production-admin" --role admin --rate-limit 1000

# List all keys  
python app/utils/api_key_generator.py list

# Revoke a key
python app/utils/api_key_generator.py revoke abc123def456

# Generate environment variable format
python app/utils/api_key_generator.py env
```

### Development Mode

For development, you can disable authentication entirely:

```bash
export DISABLE_AUTH=true
python start_api.py
```

⚠️ **Never disable authentication in production!**

## 📡 API Endpoints

### Health Check (No Authentication Required)
```bash
curl http://localhost:8000/api/v1/health
```

### List Generators (Read Access Required)
```bash
curl -H "X-API-Key: your-api-key" http://localhost:8000/api/v1/generators
```

### Execute Generator (Write Access Required)
```bash
curl -X POST http://localhost:8000/api/v1/generators/crowdstrike_falcon/execute \
  -H "Content-Type: application/json" \
  -H "X-API-Key: your-api-key" \
  -d '{"count": 5, "format": "json"}'
```

### Get Generator Details (Read Access Required)
```bash
curl -H "X-API-Key: your-api-key" http://localhost:8000/api/v1/generators/crowdstrike_falcon
```

## 🏗️ Project Structure

```
api/
├── app/
│   ├── core/           # Core configuration
│   ├── models/         # Pydantic models
│   ├── routers/        # API endpoints
│   ├── services/       # Business logic
│   └── utils/          # Utilities
├── tests/              # API tests
├── requirements.txt    # Dependencies
├── start_api.py        # Startup script
└── README.md          # This file
```

## 🔑 Environment Variables

Create a `.env` file in the `api` directory using the provided template:

```bash
cp .env.example .env
```

### Authentication Configuration

```env
# Authentication settings
DISABLE_AUTH=false
API_KEYS_ADMIN=your-admin-key-here
API_KEYS_READ_ONLY=your-readonly-key-here  
API_KEYS_WRITE=your-write-key-here

# Security
SECRET_KEY=your-secret-key-change-in-production
```

### Full Configuration Example

```env
# Authentication (Required for Production)
DISABLE_AUTH=false
API_KEYS_ADMIN=jarvis_admin_abcd1234efgh5678ijkl9012mnop3456qrst7890
API_KEYS_READ_ONLY=jarvis_readonly_uvwx1234yzab5678cdef9012ghij3456klmn7890
API_KEYS_WRITE=jarvis_write_opqr1234stuv5678wxyz9012abcd3456efgh7890

# API Settings
SECRET_KEY=your-very-long-and-secure-secret-key-generate-with-openssl-rand-hex-32
DATABASE_URL=sqlite+aiosqlite:///./jarvis_coding.db

# SentinelOne Integration
S1_HEC_TOKEN=your-hec-token
S1_SDL_API_TOKEN=your-sdl-token

# CORS (comma-separated origins)
BACKEND_CORS_ORIGINS=http://localhost:3000,http://localhost:8080
```

### Production Security Checklist

- ✅ Set `DISABLE_AUTH=false`
- ✅ Generate secure API keys (40+ characters)
- ✅ Use a strong `SECRET_KEY` (32+ bytes)
- ✅ Configure appropriate CORS origins
- ✅ Use HTTPS in production
- ✅ Set up proper rate limiting

## 📊 API Features

### Current Features (v2.0.0)
- ✅ List all 100+ generators
- ✅ Execute generators with custom parameters
- ✅ Get generator details and schemas
- ✅ Batch execution support
- ✅ **Token-based authentication**
- ✅ **Role-based access control (Admin/Write/Read-Only)**
- ✅ **Rate limiting per API key**
- ✅ **Development mode (no-auth support)**
- ✅ Health monitoring
- ✅ OpenAPI documentation
- ✅ CORS support

### In Development
- 🔄 Parser management endpoints
- 🔄 Field validation system
- 🔄 Database persistence
- 🔄 WebSocket support
- 🔄 API key audit logging

## 🧪 Testing

```bash
# Run tests
pytest tests/

# With coverage
pytest tests/ --cov=app --cov-report=html
```

## 🐳 Docker Support

```bash
# Build image
docker build -t jarvis-api .

# Run container
docker run -p 8000:8000 jarvis-api
```

## 📚 API Documentation

Interactive API documentation is available at:
- **Swagger UI**: http://localhost:8000/api/v1/docs
- **ReDoc**: http://localhost:8000/api/v1/redoc

## 🤝 Contributing

See the main [Contributing Guide](../docs/development/contributing.md) for details.

## 📝 License

Part of the Jarvis Coding Security Event Generation Platform.