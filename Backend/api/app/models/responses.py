"""
Pydantic models for API responses
"""
from pydantic import BaseModel, Field
from typing import Any, Dict, List, Optional
from datetime import datetime


class BaseResponse(BaseModel):
    """Base response model"""
    success: bool = Field(default=True, description="Request success status")
    data: Optional[Any] = Field(default=None, description="Response data")
    metadata: Optional[Dict[str, Any]] = Field(default=None, description="Response metadata")


class ErrorDetail(BaseModel):
    """Error detail model"""
    code: str = Field(description="Error code")
    message: str = Field(description="Error message")
    details: Optional[Dict[str, Any]] = Field(default=None, description="Additional error details")


class ErrorResponse(BaseModel):
    """Error response model"""
    success: bool = Field(default=False)
    error: ErrorDetail
    metadata: Optional[Dict[str, Any]] = Field(default=None)


class PaginationInfo(BaseModel):
    """Pagination information"""
    page: int = Field(default=1, ge=1)
    per_page: int = Field(default=20, ge=1, le=100)
    total: int = Field(ge=0)
    total_pages: int = Field(ge=0)


class GeneratorInfo(BaseModel):
    """Generator information model"""
    id: str
    name: str
    category: str
    vendor: str
    description: str
    supported_formats: List[str]
    star_trek_enabled: bool = True
    fields_count: Optional[int] = None
    ocsf_compliance: Optional[float] = None



class GeneratorExecuteResponse(BaseModel):
    """Generator execution response"""
    generator_id: str
    events: List[Dict[str, Any]]
    count: int
    format: str
    execution_time_ms: float
    metadata: Optional[Dict[str, Any]] = None


class ParserInfo(BaseModel):
    """Parser information model"""
    id: str
    name: str
    type: str  # community or marketplace
    vendor: str
    description: str
    input_format: str
    ocsf_compliance: float
    fields_extracted: int
    version: str
    last_updated: Optional[datetime] = None


class ValidationResult(BaseModel):
    """Validation result model"""
    generator_id: str
    parser_id: str
    compatibility_score: float
    format_compatible: bool
    field_coverage: Dict[str, Any]
    ocsf_compliance: Optional[Dict[str, Any]] = None
    issues: List[str] = Field(default_factory=list)
    warnings: List[str] = Field(default_factory=list)
    grade: str


class HealthStatus(BaseModel):
    """Health check status"""
    status: str = Field(description="Service status")
    version: str
    uptime_seconds: float
    generators_available: int
    parsers_available: int
    database_connected: bool
    timestamp: datetime