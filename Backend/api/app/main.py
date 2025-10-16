"""
Jarvis Coding API - Main Application
Security Event Generation Platform
"""
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from contextlib import asynccontextmanager
from pydantic import ValidationError
import logging
import sys
import uuid
from pathlib import Path

# Add parent directories to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from app.core.config import settings
from app.routers import generators, parsers, validation, health, scenarios, export, metrics, search, categories, destinations
from app.utils.logging import setup_logging
from app.core.simple_auth import validate_api_keys_config

# Setup logging
setup_logging()
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Manage application lifecycle"""
    # Startup
    logger.info(f"Starting {settings.PROJECT_NAME} v{settings.PROJECT_VERSION}")
    logger.info(f"Generators path: {settings.GENERATORS_PATH}")
    logger.info(f"Parsers path: {settings.PARSERS_PATH}")
    
    # Initialize and validate authentication
    auth_config = validate_api_keys_config()
    
    yield
    
    # Shutdown
    logger.info("Shutting down API server")


# Create FastAPI application
app = FastAPI(
    title=settings.PROJECT_NAME,
    description=settings.PROJECT_DESCRIPTION,
    version=settings.PROJECT_VERSION,
    openapi_url=f"{settings.API_V1_STR}/openapi.json",
    docs_url=f"{settings.API_V1_STR}/docs",
    redoc_url=f"{settings.API_V1_STR}/redoc",
    lifespan=lifespan
)

# Configure CORS
if settings.BACKEND_CORS_ORIGINS:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=[str(origin) for origin in settings.BACKEND_CORS_ORIGINS],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
else:
    # Development mode - allow all origins
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

# Exception handlers
@app.exception_handler(ValidationError)
async def validation_exception_handler(request: Request, exc: ValidationError):
    return JSONResponse(
        status_code=422,
        content={
            "success": False,
            "error": {
                "code": "VALIDATION_ERROR",
                "message": "Request validation failed",
                "details": exc.errors()
            }
        }
    )

@app.exception_handler(422)
async def unprocessable_entity_handler(request: Request, exc):
    return JSONResponse(
        status_code=422,
        content={
            "success": False,
            "error": {
                "code": "UNPROCESSABLE_ENTITY",
                "message": "The request was well-formed but contains semantic errors"
            }
        }
    )

@app.exception_handler(404)
async def not_found_handler(request: Request, exc):
    return JSONResponse(
        status_code=404,
        content={
            "success": False,
            "error": {
                "code": "NOT_FOUND",
                "message": f"Path {request.url.path} not found"
            }
        }
    )

@app.exception_handler(500)
async def internal_error_handler(request: Request, exc):
    logger.error(f"Internal server error: {exc}")
    return JSONResponse(
        status_code=500,
        content={
            "success": False,
            "error": {
                "code": "INTERNAL_ERROR",
                "message": "An internal server error occurred"
            }
        }
    )

@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    logger.error(f"Unhandled exception: {exc}", exc_info=True)
    
    return JSONResponse(
        status_code=500,
        content={
            "success": False,
            "error": {
                "code": "INTERNAL_SERVER_ERROR",
                "message": "An unexpected error occurred",
                "request_id": str(uuid.uuid4())  # For tracking
            }
        }
    )

# Root endpoint
@app.get("/")
async def root():
    """Root endpoint"""
    return {
        "name": settings.PROJECT_NAME,
        "version": settings.PROJECT_VERSION,
        "description": settings.PROJECT_DESCRIPTION,
        "docs": f"{settings.API_V1_STR}/docs",
        "health": f"{settings.API_V1_STR}/health",
        "authentication": {
            "enabled": not settings.DISABLE_AUTH,
            "methods": ["X-API-Key header", "api_key query parameter"] if not settings.DISABLE_AUTH else ["disabled"]
        }
    }

# Include routers
app.include_router(
    health.router,
    prefix=f"{settings.API_V1_STR}/health",
    tags=["health"]
)

app.include_router(
    generators.router,
    prefix=f"{settings.API_V1_STR}/generators",
    tags=["generators"]
)

app.include_router(
    parsers.router,
    prefix=f"{settings.API_V1_STR}/parsers",
    tags=["parsers"]
)

app.include_router(
    validation.router,
    prefix=f"{settings.API_V1_STR}/validation",
    tags=["validation"]
)

app.include_router(
    scenarios.router,
    prefix=f"{settings.API_V1_STR}/scenarios",
    tags=["scenarios"]
)

app.include_router(
    export.router,
    prefix=f"{settings.API_V1_STR}/export",
    tags=["export"]
)

app.include_router(
    metrics.router,
    prefix=f"{settings.API_V1_STR}/metrics",
    tags=["metrics"]
)

app.include_router(
    search.router,
    prefix=f"{settings.API_V1_STR}/search",
    tags=["search"]
)

app.include_router(
    categories.router,
    prefix=f"{settings.API_V1_STR}/categories",
    tags=["categories"]
)

app.include_router(
    destinations.router,
    prefix=f"{settings.API_V1_STR}/destinations",
    tags=["destinations"]
)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "app.main:app",
        host=settings.HOST,
        port=settings.PORT,
        reload=settings.RELOAD,
        log_level=settings.LOG_LEVEL
    )