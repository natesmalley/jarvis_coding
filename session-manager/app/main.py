"""Main FastAPI application for Session Manager"""
from fastapi import FastAPI, HTTPException, Depends, status, Header
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from contextlib import asynccontextmanager
import logging
import asyncio
from datetime import datetime, timedelta
import uuid
import redis
from typing import Optional
import os

from .core.config import settings
from .models.session import (
    SessionCreate, SessionResponse, SessionHealth,
    SessionStatus, SessionListResponse
)
from .services.docker_manager import DockerManager
from .services.port_allocator import PortAllocator
from .routers import admin

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Global instances
docker_manager: Optional[DockerManager] = None
port_allocator: Optional[PortAllocator] = None
redis_client: Optional[redis.Redis] = None
cleanup_task = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Manage application lifecycle"""
    global docker_manager, port_allocator, redis_client, cleanup_task
    
    # Startup
    logger.info("Starting Session Manager...")
    
    # Initialize services
    redis_client = redis.from_url(settings.redis_url, decode_responses=True)
    docker_manager = DockerManager()
    port_allocator = PortAllocator(redis_client)
    
    # Start background cleanup task
    cleanup_task = asyncio.create_task(cleanup_expired_sessions())
    
    logger.info("Session Manager started successfully")
    
    yield
    
    # Shutdown
    logger.info("Shutting down Session Manager...")
    
    if cleanup_task:
        cleanup_task.cancel()
        try:
            await cleanup_task
        except asyncio.CancelledError:
            pass
    
    if redis_client:
        redis_client.close()
    
    logger.info("Session Manager shutdown complete")


# Create FastAPI app
app = FastAPI(
    title=settings.api_title,
    version=settings.api_version,
    lifespan=lifespan
)

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=settings.cors_credentials,
    allow_methods=settings.cors_methods,
    allow_headers=settings.cors_headers,
)

# Include admin router for management
app.include_router(admin.router, prefix="/api/admin", tags=["admin"])


async def cleanup_expired_sessions():
    """Background task to cleanup expired sessions"""
    while True:
        try:
            await asyncio.sleep(settings.session_cleanup_interval_minutes * 60)
            logger.info("Running session cleanup...")
            docker_manager.cleanup_expired_sessions()
            port_allocator.cleanup_orphaned_ports()
        except Exception as e:
            logger.error(f"Error in cleanup task: {e}")


def get_active_sessions_count() -> int:
    """Get count of active sessions"""
    try:
        sessions = docker_manager.list_sessions()
        return len([s for s in sessions if any(
            c['status'] == 'running' for c in s.get('containers', [])
        )])
    except:
        return 0


@app.get("/api/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "active_sessions": get_active_sessions_count(),
        "max_sessions": settings.max_total_sessions
    }


@app.post("/api/sessions", response_model=SessionResponse)
async def create_session(request: SessionCreate):
    """Create a new user session"""
    
    # Check session limits
    active_count = get_active_sessions_count()
    if active_count >= settings.max_total_sessions:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"Maximum number of sessions ({settings.max_total_sessions}) reached"
        )
    
    # Check user session limit
    user_sessions = [s for s in docker_manager.list_sessions() 
                     if s['user_id'] == request.user_id]
    if len(user_sessions) >= settings.max_sessions_per_user:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"User has reached maximum sessions ({settings.max_sessions_per_user})"
        )
    
    # Generate session ID
    session_id = f"{request.user_id}-{uuid.uuid4().hex[:8]}"
    
    try:
        # Allocate ports
        backend_port = port_allocator.allocate_port()
        frontend_port = port_allocator.allocate_port()
        
        # Get features from admin config
        from .routers.admin import admin_config
        features = admin_config.features if hasattr(admin_config, 'features') else {}
        
        # Create containers
        container_info = docker_manager.create_session_containers(
            session_id=session_id,
            user_id=request.user_id,
            backend_port=backend_port,
            frontend_port=frontend_port,
            features=features
        )
        
        # Create response
        now = datetime.utcnow()
        expires_at = now + timedelta(hours=settings.session_ttl_hours)
        
        response = SessionResponse(
            id=str(uuid.uuid4()),
            session_id=session_id,
            user_id=request.user_id,
            status=SessionStatus.ACTIVE,
            frontend_url=container_info['frontend_url'],
            backend_url=container_info['backend_url'],
            frontend_container_id=container_info['frontend_container_id'],
            backend_container_id=container_info['backend_container_id'],
            created_at=now,
            expires_at=expires_at,
            metadata=request.metadata or {}
        )
        
        # Store session info in Redis
        session_key = f"session:{session_id}"
        redis_client.hset(session_key, mapping={
            "user_id": request.user_id,
            "frontend_port": frontend_port,
            "backend_port": backend_port,
            "created_at": now.isoformat(),
            "expires_at": expires_at.isoformat(),
            "api_key": container_info['api_key']
        })
        redis_client.expire(session_key, settings.session_ttl_hours * 3600)
        
        logger.info(f"Created session {session_id} for user {request.user_id}")
        return response
        
    except Exception as e:
        logger.error(f"Failed to create session: {e}")
        # Cleanup on failure
        if 'backend_port' in locals():
            port_allocator.release_port(backend_port)
        if 'frontend_port' in locals():
            port_allocator.release_port(frontend_port)
        docker_manager.cleanup_session(session_id)
        
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to create session: {str(e)}"
        )


@app.get("/api/sessions/{session_id}", response_model=SessionResponse)
async def get_session(session_id: str):
    """Get information about a specific session"""
    
    # Get session info from Redis
    session_key = f"session:{session_id}"
    session_data = redis_client.hgetall(session_key)
    
    if not session_data:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Session {session_id} not found"
        )
    
    # Check container health
    health = docker_manager.get_session_health(session_id)
    
    # Determine status
    if health['frontend_healthy'] and health['backend_healthy']:
        status = SessionStatus.ACTIVE
    elif not health['frontend_healthy'] and not health['backend_healthy']:
        status = SessionStatus.STOPPED
    else:
        status = SessionStatus.FAILED
    
    return SessionResponse(
        id=str(uuid.uuid4()),
        session_id=session_id,
        user_id=session_data.get('user_id'),
        status=status,
        frontend_url=f"http://localhost:{session_data.get('frontend_port')}",
        backend_url=f"http://localhost:{session_data.get('backend_port')}",
        frontend_container_id="",
        backend_container_id="",
        created_at=datetime.fromisoformat(session_data.get('created_at')),
        expires_at=datetime.fromisoformat(session_data.get('expires_at')),
        metadata={}
    )


@app.delete("/api/sessions/{session_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_session(session_id: str):
    """Terminate a session"""
    
    # Get session info from Redis
    session_key = f"session:{session_id}"
    session_data = redis_client.hgetall(session_key)
    
    if not session_data:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Session {session_id} not found"
        )
    
    try:
        # Stop containers
        docker_manager.stop_session(session_id)
        
        # Release ports
        frontend_port = int(session_data.get('frontend_port', 0))
        backend_port = int(session_data.get('backend_port', 0))
        
        if frontend_port:
            port_allocator.release_port(frontend_port)
        if backend_port:
            port_allocator.release_port(backend_port)
        
        # Remove from Redis
        redis_client.delete(session_key)
        
        logger.info(f"Terminated session {session_id}")
        
    except Exception as e:
        logger.error(f"Failed to terminate session {session_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to terminate session: {str(e)}"
        )


@app.get("/api/sessions/{session_id}/health", response_model=SessionHealth)
async def get_session_health(session_id: str):
    """Get health status of a session"""
    
    # Check if session exists
    session_key = f"session:{session_id}"
    if not redis_client.exists(session_key):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Session {session_id} not found"
        )
    
    health = docker_manager.get_session_health(session_id)
    
    return SessionHealth(
        session_id=session_id,
        frontend_healthy=health['frontend_healthy'],
        backend_healthy=health['backend_healthy'],
        last_check=datetime.utcnow()
    )


@app.get("/api/sessions", response_model=SessionListResponse)
async def list_sessions(
    user_id: Optional[str] = None,
    page: int = 1,
    per_page: int = 20
):
    """List all active sessions"""
    
    sessions = docker_manager.list_sessions()
    
    # Filter by user if specified
    if user_id:
        sessions = [s for s in sessions if s['user_id'] == user_id]
    
    # Calculate pagination
    total = len(sessions)
    start = (page - 1) * per_page
    end = start + per_page
    
    # Convert to response format
    session_responses = []
    for session in sessions[start:end]:
        # Get additional info from Redis
        session_key = f"session:{session['session_id']}"
        session_data = redis_client.hgetall(session_key)
        
        if session_data:
            session_responses.append(SessionResponse(
                id=str(uuid.uuid4()),
                session_id=session['session_id'],
                user_id=session['user_id'],
                status=SessionStatus.ACTIVE if any(
                    c['status'] == 'running' for c in session.get('containers', [])
                ) else SessionStatus.STOPPED,
                frontend_url=f"http://localhost:{session_data.get('frontend_port')}",
                backend_url=f"http://localhost:{session_data.get('backend_port')}",
                frontend_container_id="",
                backend_container_id="",
                created_at=datetime.fromisoformat(session_data.get('created_at')),
                expires_at=datetime.fromisoformat(session_data.get('expires_at', session['expires_at'])),
                metadata={}
            ))
    
    active_count = sum(1 for s in session_responses if s.status == SessionStatus.ACTIVE)
    
    return SessionListResponse(
        sessions=session_responses,
        total=total,
        active=active_count,
        page=page,
        per_page=per_page
    )


@app.post("/api/sessions/{session_id}/extend")
async def extend_session(session_id: str, hours: int = 12):
    """Extend a session's TTL"""
    
    # Validate hours
    if hours < 1 or hours > 24:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Extension hours must be between 1 and 24"
        )
    
    # Get session info from Redis
    session_key = f"session:{session_id}"
    session_data = redis_client.hgetall(session_key)
    
    if not session_data:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Session {session_id} not found"
        )
    
    # Update expiration
    current_expires = datetime.fromisoformat(session_data.get('expires_at'))
    new_expires = current_expires + timedelta(hours=hours)
    
    # Update Redis
    redis_client.hset(session_key, 'expires_at', new_expires.isoformat())
    redis_client.expire(session_key, int((new_expires - datetime.utcnow()).total_seconds()))
    
    # Update container labels
    containers = docker_manager.client.containers.list(
        filters={'label': f'session_id={session_id}'}
    )
    
    for container in containers:
        # Docker doesn't support updating labels on running containers
        # We'd need to recreate them, so just log for now
        logger.info(f"Extended session {session_id} by {hours} hours")
    
    return {
        "session_id": session_id,
        "new_expires_at": new_expires.isoformat(),
        "extended_by_hours": hours
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host=settings.host, port=settings.port)