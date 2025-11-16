"""Configuration settings for Session Manager"""
from pydantic_settings import BaseSettings
from typing import Optional, List
import secrets


class Settings(BaseSettings):
    """Application settings"""
    
    # API Configuration
    api_title: str = "Jarvis Session Manager"
    api_version: str = "1.0.0"
    api_prefix: str = "/api"
    
    # Server Configuration
    host: str = "0.0.0.0"
    port: int = 9000
    workers: int = 4
    
    # Security
    secret_key: str = secrets.token_urlsafe(32)
    algorithm: str = "HS256"
    access_token_expire_minutes: int = 1440  # 24 hours
    
    # Database Configuration
    database_url: str = "postgresql://postgres:password@postgres:5432/sessions"
    database_pool_size: int = 20
    database_max_overflow: int = 40
    
    # Redis Configuration
    redis_host: str = "redis"
    redis_port: int = 6379
    redis_db: int = 0
    
    @property
    def redis_url(self) -> str:
        """Build Redis URL from components"""
        import os
        host = os.getenv("REDIS_HOST", self.redis_host)
        port = os.getenv("REDIS_PORT", str(self.redis_port))
        db = os.getenv("REDIS_DB", str(self.redis_db))
        return f"redis://{host}:{port}/{db}"
    redis_pool_size: int = 10
    
    # Docker Configuration
    docker_socket: str = "unix:///var/run/docker.sock"
    docker_network_prefix: str = "jarvis"
    
    # Session Configuration
    session_ttl_hours: int = 24
    max_sessions_per_user: int = 5
    max_total_sessions: int = 150  # For Tech Summit
    session_cleanup_interval_minutes: int = 5
    
    # Port Allocation
    port_range_start: int = 10000
    port_range_end: int = 20000
    
    # Container Resources (per session)
    backend_cpu_limit: str = "1.5"
    backend_memory_limit: str = "2G"
    frontend_cpu_limit: str = "0.5"
    frontend_memory_limit: str = "1G"
    
    # Container Images
    backend_image: str = "jarvis-backend-prod:latest"
    frontend_image: str = "jarvis-frontend:prod"
    
    # Monitoring
    enable_metrics: bool = True
    metrics_port: int = 9090
    
    # CORS
    cors_origins: List[str] = ["*"]
    cors_credentials: bool = True
    cors_methods: List[str] = ["*"]
    cors_headers: List[str] = ["*"]
    
    class Config:
        env_file = ".env"
        case_sensitive = False


# Create settings instance
settings = Settings()