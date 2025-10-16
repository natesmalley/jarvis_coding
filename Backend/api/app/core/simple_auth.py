"""
Simple token-based authentication for containerized deployment
Designed for simplicity and security without JWT complexity
"""
import os
import secrets
import time
from typing import Optional, Dict, Tuple, Set
from collections import defaultdict
from datetime import datetime, timedelta

from fastapi import HTTPException, Security, Depends, Request
from fastapi.security import APIKeyHeader, APIKeyQuery
from starlette.status import HTTP_403_FORBIDDEN, HTTP_429_TOO_MANY_REQUESTS
import logging

logger = logging.getLogger(__name__)

# Authentication configuration from environment
DISABLE_AUTH = os.getenv("DISABLE_AUTH", "false").lower() == "true"
DEFAULT_API_KEY = os.getenv("JARVIS_API_KEY", "development-key-change-in-production")

# Role-based API keys from environment
ADMIN_KEYS = set(filter(None, os.getenv("JARVIS_ADMIN_KEYS", DEFAULT_API_KEY).split(",")))
WRITE_KEYS = set(filter(None, os.getenv("JARVIS_WRITE_KEYS", "").split(",")))
READ_KEYS = set(filter(None, os.getenv("JARVIS_READ_KEYS", "").split(",")))

# API key authentication methods
API_KEY_NAME = "X-API-Key"
api_key_header = APIKeyHeader(name=API_KEY_NAME, auto_error=False)
api_key_query = APIKeyQuery(name="api_key", auto_error=False)

# Roles
class Role:
    ADMIN = "admin"
    WRITE = "write"
    READ_ONLY = "read_only"
    
    @classmethod
    def all_roles(cls):
        return [cls.ADMIN, cls.WRITE, cls.READ_ONLY]
    
    @classmethod
    def can_write(cls, role: str) -> bool:
        return role in [cls.ADMIN, cls.WRITE]
    
    @classmethod
    def can_read(cls, role: str) -> bool:
        return True  # All roles can read


class RateLimiter:
    """Simple in-memory rate limiter for API keys"""
    
    def __init__(self):
        self.requests: Dict[str, list] = defaultdict(list)
        self.limits = {
            Role.ADMIN: int(os.getenv("RATE_LIMIT_ADMIN", "1000")),
            Role.WRITE: int(os.getenv("RATE_LIMIT_WRITE", "500")),
            Role.READ_ONLY: int(os.getenv("RATE_LIMIT_READ", "100")),
        }
        self.window_minutes = int(os.getenv("RATE_LIMIT_WINDOW_MINUTES", "1"))
    
    def check_rate_limit(self, api_key: str, role: str) -> Tuple[bool, Optional[int]]:
        """
        Check if request is within rate limit
        Returns: (allowed, remaining_requests)
        """
        now = time.time()
        window_start = now - (self.window_minutes * 60)
        
        # Clean old requests
        self.requests[api_key] = [
            req_time for req_time in self.requests[api_key] 
            if req_time > window_start
        ]
        
        limit = self.limits.get(role, 100)
        current_count = len(self.requests[api_key])
        
        if current_count >= limit:
            return False, 0
        
        self.requests[api_key].append(now)
        return True, limit - current_count - 1
    
    def reset(self, api_key: Optional[str] = None):
        """Reset rate limit tracking"""
        if api_key:
            self.requests[api_key] = []
        else:
            self.requests.clear()


# Global rate limiter instance
rate_limiter = RateLimiter()


def get_key_role(api_key: str) -> Optional[str]:
    """Determine the role for a given API key"""
    if api_key in ADMIN_KEYS:
        return Role.ADMIN
    elif api_key in WRITE_KEYS:
        return Role.WRITE
    elif api_key in READ_KEYS:
        return Role.READ_ONLY
    return None


async def get_api_key(
    request: Request,
    api_key_from_header: Optional[str] = Security(api_key_header),
    api_key_from_query: Optional[str] = Security(api_key_query),
) -> Tuple[str, str]:
    """
    Validate API key and return key with role
    Returns: (api_key, role)
    """
    # Skip auth if disabled (development mode)
    if DISABLE_AUTH:
        logger.debug("Authentication disabled - development mode")
        return "dev-mode", Role.ADMIN
    
    # Get API key from header or query
    api_key = api_key_from_header or api_key_from_query
    
    if not api_key:
        logger.warning(f"Missing API key from {request.client.host}")
        raise HTTPException(
            status_code=HTTP_403_FORBIDDEN,
            detail="API key required. Provide via X-API-Key header or api_key query parameter"
        )
    
    # Validate API key and get role
    role = get_key_role(api_key)
    
    if not role:
        # Log first 8 chars of invalid key for debugging
        key_prefix = api_key[:8] if len(api_key) > 8 else "short-key"
        logger.warning(f"Invalid API key from {request.client.host}: {key_prefix}...")
        raise HTTPException(
            status_code=HTTP_403_FORBIDDEN,
            detail="Invalid API key"
        )
    
    # Check rate limit
    allowed, remaining = rate_limiter.check_rate_limit(api_key, role)
    
    if not allowed:
        logger.warning(f"Rate limit exceeded for {role} key from {request.client.host}")
        raise HTTPException(
            status_code=HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Rate limit exceeded. Try again in {rate_limiter.window_minutes} minute(s)",
            headers={"X-RateLimit-Remaining": "0"}
        )
    
    # Add rate limit info to response headers
    if hasattr(request, "state"):
        request.state.rate_limit_remaining = remaining
    
    logger.debug(f"Authenticated {role} from {request.client.host}")
    return api_key, role


async def require_read_access(
    auth_info: Tuple[str, str] = Depends(get_api_key)
) -> str:
    """Require at least read access to the endpoint"""
    _, role = auth_info
    
    if not Role.can_read(role):
        raise HTTPException(
            status_code=HTTP_403_FORBIDDEN,
            detail="Insufficient permissions for this operation"
        )
    
    return role


async def require_write_access(
    auth_info: Tuple[str, str] = Depends(get_api_key)
) -> str:
    """Require write access to the endpoint"""
    _, role = auth_info
    
    if not Role.can_write(role):
        raise HTTPException(
            status_code=HTTP_403_FORBIDDEN,
            detail="Write access required for this operation"
        )
    
    return role


async def require_admin_access(
    auth_info: Tuple[str, str] = Depends(get_api_key)
) -> str:
    """Require admin access to the endpoint"""
    _, role = auth_info
    
    if role != Role.ADMIN:
        raise HTTPException(
            status_code=HTTP_403_FORBIDDEN,
            detail="Admin access required for this operation"
        )
    
    return role


def generate_api_key(length: int = 40) -> str:
    """
    Generate a secure random API key
    Default 40 characters for good entropy
    """
    return secrets.token_urlsafe(length)[:length]


def validate_api_keys_config() -> Dict[str, any]:
    """
    Validate API keys configuration on startup
    Returns configuration summary
    """
    config = {
        "auth_enabled": not DISABLE_AUTH,
        "admin_keys_count": len(ADMIN_KEYS),
        "write_keys_count": len(WRITE_KEYS),
        "read_keys_count": len(READ_KEYS),
        "total_keys": len(ADMIN_KEYS | WRITE_KEYS | READ_KEYS),
        "rate_limits": rate_limiter.limits,
        "rate_window_minutes": rate_limiter.window_minutes
    }
    
    if DISABLE_AUTH:
        logger.warning("⚠️  Authentication is DISABLED - not for production use!")
    else:
        logger.info(f"🔐 Authentication enabled with {config['total_keys']} API keys")
        logger.info(f"   Admin keys: {config['admin_keys_count']}")
        logger.info(f"   Write keys: {config['write_keys_count']}")
        logger.info(f"   Read keys: {config['read_keys_count']}")
    
    return config


# Optional: API key info endpoint (admin only)
async def get_current_key_info(
    auth_info: Tuple[str, str] = Depends(get_api_key)
) -> Dict[str, str]:
    """Get information about the current API key"""
    api_key, role = auth_info
    
    # Don't return the actual key, just metadata
    return {
        "role": role,
        "key_prefix": api_key[:8] if len(api_key) > 8 else "dev",
        "rate_limit": rate_limiter.limits.get(role, 0),
        "rate_window_minutes": rate_limiter.window_minutes
    }