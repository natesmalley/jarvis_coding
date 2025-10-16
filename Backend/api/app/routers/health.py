"""
Health check endpoints
"""
from fastapi import APIRouter, HTTPException
from datetime import datetime, timezone
import time
import os
from pathlib import Path

from app.models.responses import HealthStatus
from app.core.config import settings

router = APIRouter()

# Track server start time
SERVER_START_TIME = time.time()


@router.get("", response_model=HealthStatus)
async def health_check():
    """Health check endpoint"""
    try:
        # Count available generators
        generators_count = 0
        if settings.GENERATORS_PATH.exists():
            for category_dir in settings.GENERATORS_PATH.iterdir():
                if category_dir.is_dir() and not category_dir.name.startswith('_'):
                    generators_count += len(list(category_dir.glob("*.py")))
        
        # Count available parsers
        parsers_count = 0
        if settings.PARSERS_PATH.exists():
            community_path = settings.PARSERS_PATH / "community"
            if community_path.exists():
                parsers_count = len(list(community_path.iterdir()))
        
        # Check database (simplified for now)
        database_connected = True  # Will implement proper check with SQLAlchemy
        
        return HealthStatus(
            status="healthy",
            version=settings.PROJECT_VERSION,
            uptime_seconds=time.time() - SERVER_START_TIME,
            generators_available=generators_count,
            parsers_available=parsers_count,
            database_connected=database_connected,
            timestamp=datetime.now(timezone.utc)
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Health check failed: {str(e)}")


@router.get("/ready")
async def readiness_check():
    """Readiness check for container orchestration"""
    # Check if critical paths exist
    if not settings.GENERATORS_PATH.exists():
        return {"ready": False, "reason": "Generators path not found"}
    
    if not settings.PARSERS_PATH.exists():
        return {"ready": False, "reason": "Parsers path not found"}
    
    return {"ready": True, "status": "Service ready to accept requests"}


@router.get("/live")
async def liveness_check():
    """Liveness check for container orchestration"""
    return {"alive": True, "timestamp": datetime.now(timezone.utc).isoformat()}