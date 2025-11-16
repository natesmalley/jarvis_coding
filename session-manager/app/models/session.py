"""Session data models"""
from pydantic import BaseModel, Field
from datetime import datetime
from typing import Optional, Dict, Any
from enum import Enum
import uuid


class SessionStatus(str, Enum):
    """Session status enumeration"""
    CREATING = "creating"
    ACTIVE = "active"
    STOPPING = "stopping"
    STOPPED = "stopped"
    FAILED = "failed"


class SessionCreate(BaseModel):
    """Request model for creating a session"""
    user_id: str = Field(..., description="User ID requesting the session")
    metadata: Optional[Dict[str, Any]] = Field(default={}, description="Optional metadata")


class SessionResponse(BaseModel):
    """Response model for session information"""
    id: str = Field(..., description="Unique session ID")
    session_id: str = Field(..., description="Session identifier")
    user_id: str = Field(..., description="User ID owning the session")
    status: SessionStatus = Field(..., description="Current session status")
    frontend_url: Optional[str] = Field(None, description="Frontend URL")
    backend_url: Optional[str] = Field(None, description="Backend URL")
    frontend_container_id: Optional[str] = Field(None, description="Frontend container ID")
    backend_container_id: Optional[str] = Field(None, description="Backend container ID")
    created_at: datetime = Field(..., description="Session creation time")
    expires_at: datetime = Field(..., description="Session expiration time")
    last_activity: Optional[datetime] = Field(None, description="Last activity timestamp")
    metadata: Dict[str, Any] = Field(default={}, description="Session metadata")


class SessionHealth(BaseModel):
    """Health check response for a session"""
    session_id: str
    frontend_healthy: bool
    backend_healthy: bool
    last_check: datetime


class SessionMetrics(BaseModel):
    """Metrics for a session"""
    session_id: str
    cpu_usage: float
    memory_usage: float
    request_count: int
    error_count: int
    uptime_seconds: float


class SessionListResponse(BaseModel):
    """Response model for listing sessions"""
    sessions: list[SessionResponse]
    total: int
    active: int
    page: int = 1
    per_page: int = 20