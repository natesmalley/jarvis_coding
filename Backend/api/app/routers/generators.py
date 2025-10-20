"""
Generator endpoints for the API
"""
from fastapi import APIRouter, HTTPException, Query, Path, Depends
from typing import List, Optional
import importlib.util
import sys
from pathlib import Path as PathLib
import json
import time
import traceback

from app.models.responses import (
    BaseResponse,
    GeneratorInfo,
    GeneratorExecuteResponse,
    PaginationInfo,
    ErrorResponse,
    ErrorDetail
)
from app.models.requests import BatchExecuteRequest, GeneratorExecuteRequest
from app.core.config import settings
from app.services.generator_service import GeneratorService
from app.core.simple_auth import require_read_access, require_write_access

router = APIRouter()

# Initialize generator service
generator_service = GeneratorService()


@router.get("", response_model=BaseResponse)
async def list_generators(
    category: Optional[str] = Query(None, description="Filter by category"),
    vendor: Optional[str] = Query(None, description="Filter by vendor"),
    search: Optional[str] = Query(None, description="Search in names and descriptions"),
    page: int = Query(1, ge=1, description="Page number"),
    per_page: int = Query(20, ge=1, le=100, description="Items per page"),
    _: str = Depends(require_read_access)
):
    """List all available generators"""
    try:
        generators = await generator_service.list_generators(
            category=category,
            vendor=vendor,
            search=search
        )
        
        # Apply pagination
        total = len(generators)
        start = (page - 1) * per_page
        end = start + per_page
        paginated_generators = generators[start:end]
        
        return BaseResponse(
            success=True,
            data={
                "generators": paginated_generators,
                "total": total
            },
            metadata={
                "pagination": {
                    "page": page,
                    "per_page": per_page,
                    "total": total,
                    "total_pages": (total + per_page - 1) // per_page
                }
            }
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/categories", response_model=BaseResponse)
async def list_categories(_: str = Depends(require_read_access)):
    """List all generator categories"""
    try:
        categories = await generator_service.list_categories()
        return BaseResponse(
            success=True,
            data={"categories": categories}
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/{generator_id}", response_model=BaseResponse)
async def get_generator(
    generator_id: str = Path(..., description="Generator identifier"),
    _: str = Depends(require_read_access)
):
    """Get details for a specific generator"""
    try:
        generator = await generator_service.get_generator(generator_id)
        if not generator:
            raise HTTPException(
                status_code=404,
                detail=f"Generator '{generator_id}' not found"
            )
        return BaseResponse(
            success=True,
            data=generator
        )
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/batch/execute", response_model=BaseResponse)
async def batch_execute_generators(
    request: BatchExecuteRequest,
    _: str = Depends(require_write_access)
):
    """Execute multiple generators in batch"""
    try:
        results = []
        total_events = 0
        total_time = 0
        
        for execution in request.executions:
            generator_id = execution.get("generator_id")
            count = execution.get("count", 1)
            format = execution.get("format", "json")
            
            try:
                start_time = time.time()
                events = await generator_service.execute_generator(
                    generator_id,
                    count=count,
                    format=format
                )
                execution_time = (time.time() - start_time) * 1000
                
                results.append({
                    "generator_id": generator_id,
                    "success": True,
                    "events_count": len(events),
                    "execution_time_ms": execution_time
                })
                total_events += len(events)
                total_time += execution_time
                
            except Exception as e:
                results.append({
                    "generator_id": generator_id,
                    "success": False,
                    "error": str(e),
                    "events_count": 0,
                    "execution_time_ms": 0
                })
        
        return BaseResponse(
            success=True,
            data={
                "batch_id": f"batch_{int(time.time())}",
                "executions": results,
                "total_events": total_events,
                "total_execution_time_ms": total_time
            }
        )
        
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Batch execution failed: {str(e)}"
        )


@router.post("/{generator_id}/execute", response_model=BaseResponse)
async def execute_generator(
    generator_id: str = Path(..., description="Generator identifier"),
    request: GeneratorExecuteRequest = ...,
    _: str = Depends(require_write_access)
):
    """Execute a generator and return events"""
    try:
        # Validate generator exists
        generator = await generator_service.get_generator(generator_id)
        if not generator:
            raise HTTPException(
                status_code=404,
                detail=f"Generator '{generator_id}' not found"
            )
        
        # Execute generator
        start_time = time.time()
        events = await generator_service.execute_generator(
            generator_id,
            count=request.count,
            format=request.format,
            star_trek_theme=request.star_trek_theme,
            options=request.options
        )
        execution_time = (time.time() - start_time) * 1000  # Convert to ms
        
        response = GeneratorExecuteResponse(
            generator_id=generator_id,
            events=events,
            count=len(events),
            format=request.format,
            execution_time_ms=execution_time,
            metadata={
                "star_trek_theme": request.star_trek_theme,
                "options": request.options
            }
        )
        
        return BaseResponse(
            success=True,
            data=response.model_dump()
        )
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Generator execution failed: {str(e)}"
        )


@router.post("/{generator_id}/validate", response_model=BaseResponse)
async def validate_generator(
    generator_id: str = Path(..., description="Generator identifier"),
    sample_size: int = Query(5, ge=1, le=100, description="Number of samples to validate"),
    _: str = Depends(require_read_access)
):
    """Validate generator output"""
    try:
        # Validate generator exists
        generator = await generator_service.get_generator(generator_id)
        if not generator:
            raise HTTPException(
                status_code=404,
                detail=f"Generator '{generator_id}' not found"
            )
        
        # Validate generator output
        validation_result = await generator_service.validate_generator(
            generator_id,
            sample_size=sample_size
        )
        
        return BaseResponse(
            success=True,
            data=validation_result
        )
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Validation failed: {str(e)}"
        )


@router.get("/{generator_id}/schema", response_model=BaseResponse)
async def get_generator_schema(
    generator_id: str = Path(..., description="Generator identifier"),
    _: str = Depends(require_read_access)
):
    """Get the output schema for a generator"""
    try:
        generator = await generator_service.get_generator(generator_id)
        if not generator:
            raise HTTPException(
                status_code=404,
                detail=f"Generator '{generator_id}' not found"
            )
        
        # Generate schema from sample output
        schema = await generator_service.get_generator_schema(generator_id)
        
        return BaseResponse(
            success=True,
            data={
                "generator_id": generator_id,
                "schema": schema
            }
        )
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to get schema: {str(e)}"
        )


