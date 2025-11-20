"""Admin models for session management"""
from pydantic import BaseModel, Field
from typing import Optional, Dict, Any
from datetime import datetime


class AdminLogin(BaseModel):
    """Admin login credentials"""
    username: str
    password: str


class AdminConfig(BaseModel):
    """Admin configuration settings"""
    landing_port: int = Field(default=80, ge=1, le=65535)
    max_sessions: int = Field(default=150, ge=1, le=500)
    session_ttl_hours: int = Field(default=24, ge=1, le=168)
    
    # Feature toggles
    features: Dict[str, Any] = Field(default_factory=lambda: {
        "generators": True,
        "scenarios": True, 
        "destinations": True,
        "uploads": True,
        "export": True,
        "continuous_mode": True,
        "products": ["sentinelone"]  # Only SentinelOne for Tech Summit
    })
    
    # Security settings
    auth_enabled: bool = True
    require_api_key: bool = False
    
    updated_at: Optional[datetime] = None
    updated_by: Optional[str] = None


class SessionConfig(BaseModel):
    """Per-session configuration override"""
    session_id: str
    features: Dict[str, Any]
    created_at: datetime = Field(default_factory=datetime.utcnow)
    
    
class AdminResponse(BaseModel):
    """Admin API response"""
    success: bool
    message: Optional[str] = None
    data: Optional[Any] = None