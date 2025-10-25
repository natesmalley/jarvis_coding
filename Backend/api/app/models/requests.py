"""
Request models with strict validation
"""
from pydantic import BaseModel, Field, validator
from typing import Dict, Any, List, Optional
import re


class GeneratorExecuteRequest(BaseModel):
    """Generator execution request with strict validation"""
    count: Optional[int] = Field(None, ge=1, le=10000, description="Number of events to generate (ignored if continuous=True)")
    format: str = Field(..., pattern="^(json|csv|syslog|key_value)$", description="Output format")
    star_trek_theme: bool = Field(default=True, description="Use Star Trek themed data")
    continuous: bool = Field(default=False, description="Run indefinitely (ignores count)")
    eps: Optional[float] = Field(None, ge=0.1, le=10000, description="Events per second rate")
    speed_mode: bool = Field(False, description="Pre-generate 1K events and loop for max throughput (auto-enabled for EPS > 1000)")
    options: Dict[str, Any] = Field(default_factory=dict, description="Generator-specific options")
    
    @validator('count')
    def validate_count(cls, v, values):
        continuous = values.get('continuous', False)
        if not continuous and v is None:
            raise ValueError('count is required when continuous=False')
        return v
    
    class Config:
        validate_assignment = True
        extra = "forbid"  # Reject extra fields


class BatchExecuteRequest(BaseModel):
    """Batch execution request with proper validation"""
    executions: List[Dict[str, Any]] = Field(..., min_items=1, max_items=50)
    
    @validator('executions')
    def validate_executions(cls, v):
        for i, execution in enumerate(v):
            if 'generator_id' not in execution:
                raise ValueError(f"Execution {i}: missing required field 'generator_id'")
            if 'count' in execution and (execution['count'] < 1 or execution['count'] > 1000):
                raise ValueError(f"Execution {i}: count must be between 1 and 1000")
            if 'format' in execution and execution['format'] not in ['json', 'csv', 'syslog', 'key_value']:
                raise ValueError(f"Execution {i}: invalid format '{execution['format']}'")
        return v
    
    class Config:
        extra = "forbid"
        validate_assignment = True


class ScenarioExecuteRequest(BaseModel):
    """Scenario execution request"""
    speed: str = Field("fast", pattern="^(realtime|fast|instant)$")
    dry_run: bool = Field(False)
    
    class Config:
        extra = "forbid"


class CustomScenarioRequest(BaseModel):
    """Custom scenario creation request"""
    name: str = Field(..., min_length=3, max_length=100)
    description: str = Field(..., min_length=10, max_length=500)
    phases: List[Dict[str, Any]] = Field(..., min_items=1)
    
    @validator('name')
    def validate_name(cls, v):
        if not re.match(r'^[a-zA-Z0-9_\- ]+$', v):
            raise ValueError('Name can only contain letters, numbers, spaces, hyphens, and underscores')
        return v
    
    class Config:
        extra = "forbid"


class ExportGeneratorsRequest(BaseModel):
    """Export generators request"""
    format: str = Field("json", pattern="^(json|csv|yaml)$")
    category: Optional[str] = None
    
    class Config:
        extra = "forbid"


class ExportEventsRequest(BaseModel):
    """Export events request"""
    generator_ids: List[str] = Field(..., min_items=1, max_items=20)
    count_per_generator: int = Field(5, ge=1, le=100)
    format: str = Field("json", pattern="^(json|csv)$")
    
    class Config:
        extra = "forbid"


class SearchRequest(BaseModel):
    """Search request"""
    q: str = Field(..., min_length=2, description="Search query")
    types: List[str] = Field(["generators", "parsers", "scenarios"])
    page: int = Field(1, ge=1)
    per_page: int = Field(20, ge=1, le=100)
    
    @validator('types')
    def validate_types(cls, v):
        allowed_types = ["generators", "parsers", "scenarios"]
        for search_type in v:
            if search_type not in allowed_types:
                raise ValueError(f"Invalid search type '{search_type}'. Must be one of: {allowed_types}")
        return v
    
    class Config:
        extra = "forbid"


class GeneratorSearchRequest(BaseModel):
    """Generator search request"""
    q: str = Field(..., min_length=2, description="Search query")
    category: Optional[str] = None
    vendor: Optional[str] = None
    page: int = Field(1, ge=1)
    per_page: int = Field(20, ge=1, le=100)
    
    class Config:
        extra = "forbid"


class ParserSearchRequest(BaseModel):
    """Parser search request"""
    q: str = Field(..., min_length=2, description="Search query")
    type: Optional[str] = Field(None, pattern="^(community|marketplace)$")
    
    class Config:
        extra = "forbid"