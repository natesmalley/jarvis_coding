"""Admin API endpoints"""
from fastapi import APIRouter, HTTPException, Depends, status
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from typing import Dict, List
import secrets
import hashlib
import json
import os
from datetime import datetime

from ..models.admin import AdminLogin, AdminConfig, SessionConfig, AdminResponse
from ..models.session import SessionListResponse
from ..core.config import settings
from ..services.docker_manager import DockerManager
from ..services.port_allocator import PortAllocator

router = APIRouter()
security = HTTPBasic()

# Default admin credentials (should be changed in production)
ADMIN_USERNAME = os.environ.get("ADMIN_USERNAME", "admin")
ADMIN_PASSWORD_HASH = hashlib.sha256(
    os.environ.get("ADMIN_PASSWORD", "techsummit2025").encode()
).hexdigest()

# In-memory storage for configs (in production, use Redis or database)
admin_config = AdminConfig()
session_configs: Dict[str, SessionConfig] = {}


def verify_admin(credentials: HTTPBasicCredentials = Depends(security)):
    """Verify admin credentials"""
    username_correct = secrets.compare_digest(credentials.username, ADMIN_USERNAME)
    password_hash = hashlib.sha256(credentials.password.encode()).hexdigest()
    password_correct = secrets.compare_digest(password_hash, ADMIN_PASSWORD_HASH)
    
    if not (username_correct and password_correct):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
            headers={"WWW-Authenticate": "Basic"},
        )
    return credentials.username


@router.post("/login")
async def admin_login(login: AdminLogin):
    """Admin login endpoint"""
    password_hash = hashlib.sha256(login.password.encode()).hexdigest()
    
    if login.username == ADMIN_USERNAME and password_hash == ADMIN_PASSWORD_HASH:
        return AdminResponse(
            success=True,
            message="Login successful",
            data={"username": login.username}
        )
    
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid credentials"
    )


@router.get("/config", response_model=AdminConfig)
async def get_config(admin: str = Depends(verify_admin)):
    """Get current admin configuration"""
    return admin_config


@router.put("/config", response_model=AdminResponse)
async def update_config(
    config: AdminConfig,
    admin: str = Depends(verify_admin)
):
    """Update admin configuration"""
    global admin_config
    
    config.updated_at = datetime.utcnow()
    config.updated_by = admin
    admin_config = config
    
    # Save to file for persistence
    config_file = "/app/data/admin_config.json"
    os.makedirs(os.path.dirname(config_file), exist_ok=True)
    
    with open(config_file, "w") as f:
        json.dump(config.dict(), f, default=str, indent=2)
    
    return AdminResponse(
        success=True,
        message="Configuration updated successfully",
        data=config.dict()
    )


@router.get("/sessions/active")
async def get_active_sessions(admin: str = Depends(verify_admin)):
    """Get all active sessions with details"""
    docker_manager = DockerManager()
    sessions = docker_manager.list_sessions()
    
    # Add configuration info for each session
    for session in sessions:
        session_id = session.get("session_id")
        if session_id in session_configs:
            session["config"] = session_configs[session_id].dict()
        else:
            session["config"] = {"features": admin_config.features}
    
    return {
        "total": len(sessions),
        "sessions": sessions,
        "max_sessions": admin_config.max_sessions
    }


@router.post("/sessions/{session_id}/config", response_model=AdminResponse)
async def update_session_config(
    session_id: str,
    config: SessionConfig,
    admin: str = Depends(verify_admin)
):
    """Update configuration for a specific session"""
    session_configs[session_id] = config
    
    # Notify the frontend container about config changes
    docker_manager = DockerManager()
    containers = docker_manager.client.containers.list(
        filters={"label": f"session_id={session_id}"}
    )
    
    for container in containers:
        if "frontend" in container.name:
            # Write config to container
            config_json = json.dumps(config.dict(), default=str)
            container.exec_run(
                f"echo '{config_json}' > /app/session_config.json"
            )
    
    return AdminResponse(
        success=True,
        message=f"Session {session_id} configuration updated",
        data=config.dict()
    )


@router.delete("/sessions/{session_id}")
async def terminate_session(
    session_id: str,
    admin: str = Depends(verify_admin)
):
    """Terminate a specific session"""
    docker_manager = DockerManager()
    
    try:
        docker_manager.stop_session(session_id)
        
        # Clean up config
        if session_id in session_configs:
            del session_configs[session_id]
        
        return AdminResponse(
            success=True,
            message=f"Session {session_id} terminated successfully"
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to terminate session: {str(e)}"
        )


@router.post("/sessions/cleanup")
async def cleanup_sessions(admin: str = Depends(verify_admin)):
    """Clean up expired sessions"""
    docker_manager = DockerManager()
    
    try:
        cleaned = docker_manager.cleanup_expired_sessions()
        
        return AdminResponse(
            success=True,
            message=f"Cleaned up {cleaned} expired sessions"
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Cleanup failed: {str(e)}"
        )


# Load saved config on startup
config_file = "/app/data/admin_config.json"
if os.path.exists(config_file):
    with open(config_file, "r") as f:
        saved_config = json.load(f)
        admin_config = AdminConfig(**saved_config)