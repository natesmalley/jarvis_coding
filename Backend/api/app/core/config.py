"""
Core configuration for Jarvis Coding API
"""
from typing import List, Optional
from pydantic_settings import BaseSettings
from pydantic import AnyHttpUrl, field_validator
import os
from pathlib import Path

# Get the project root directory
PROJECT_ROOT = Path(__file__).parent.parent.parent.parent
GENERATORS_PATH = PROJECT_ROOT / "event_generators"
PARSERS_PATH = PROJECT_ROOT / "parsers"
SCENARIOS_PATH = PROJECT_ROOT / "scenarios"


class Settings(BaseSettings):
    """Application settings"""
    
    # API Settings
    API_V1_STR: str = "/api/v1"
    PROJECT_NAME: str = "Jarvis Coding API"
    PROJECT_VERSION: str = "2.0.0"
    PROJECT_DESCRIPTION: str = "Security Event Generation Platform API"
    
    # Server Settings
    HOST: str = "0.0.0.0"
    PORT: int = int(os.getenv("PORT", "9001"))  # Changed default to 9001 to avoid conflicts
    RELOAD: bool = True
    LOG_LEVEL: str = "info"
    
    # Security
    SECRET_KEY: str = os.getenv("SECRET_KEY", "your-secret-key-change-in-production")
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7
    
    # CORS
    BACKEND_CORS_ORIGINS: List[AnyHttpUrl] = []
    
    @field_validator("BACKEND_CORS_ORIGINS", mode="before")
    @classmethod
    def assemble_cors_origins(cls, v: str | List[str]) -> List[str] | str:
        if isinstance(v, str) and not v.startswith("["):
            return [i.strip() for i in v.split(",")]
        elif isinstance(v, (list, str)):
            return v
        raise ValueError(v)
    
    # Database
    DATABASE_URL: Optional[str] = os.getenv(
        "DATABASE_URL", 
        "sqlite+aiosqlite:///./jarvis_coding.db"
    )
    
    # SentinelOne Integration
    S1_HEC_TOKEN: Optional[str] = os.getenv("S1_HEC_TOKEN")
    S1_SDL_API_TOKEN: Optional[str] = os.getenv("S1_SDL_API_TOKEN")
    S1_HEC_URL: str = "https://hacktober2024-c02.s1.sentinelone.net/api/v1/cloud_connect/events/raw"
    
    # Generator Settings
    DEFAULT_EVENT_COUNT: int = 10
    MAX_EVENT_COUNT: int = 1000
    DEFAULT_FORMAT: str = "json"
    STAR_TREK_THEME: bool = True
    
    # Authentication Settings
    DISABLE_AUTH: bool = os.getenv("DISABLE_AUTH", "false").lower() in ("true", "1", "yes")
    API_KEYS_ADMIN: Optional[str] = os.getenv("API_KEYS_ADMIN")
    API_KEYS_READ_ONLY: Optional[str] = os.getenv("API_KEYS_READ_ONLY")
    API_KEYS_WRITE: Optional[str] = os.getenv("API_KEYS_WRITE")
    
    # Rate Limiting
    RATE_LIMIT_PER_MINUTE: int = 100
    RATE_LIMIT_AUTHENTICATED: int = 1000
    RATE_LIMIT_ADMIN: int = 2000
    
    # File Paths
    GENERATORS_PATH: Path = GENERATORS_PATH
    PARSERS_PATH: Path = PARSERS_PATH
    SCENARIOS_PATH: Path = SCENARIOS_PATH
    
    class Config:
        case_sensitive = True
        env_file = ".env"
        env_file_encoding = "utf-8"


settings = Settings()