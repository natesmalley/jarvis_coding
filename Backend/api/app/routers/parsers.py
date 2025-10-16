"""
Parser endpoints for the API
"""
import time
from fastapi import APIRouter, HTTPException, Query, Path, Depends
from typing import Optional

from app.models.responses import BaseResponse
from app.core.config import settings
from app.core.simple_auth import require_read_access, require_write_access
from app.services.parser_service import ParserService

router = APIRouter()

# Initialize parser service
parser_service = ParserService()


@router.get("/stats", response_model=BaseResponse)
async def get_parser_stats(
    _: str = Depends(require_read_access)
):
    """Get parser statistics"""
    try:
        stats = await parser_service.get_parser_stats()
        return BaseResponse(
            success=True,
            data=stats
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get parser stats: {str(e)}")


@router.get("", response_model=BaseResponse)
async def list_parsers(
    type: Optional[str] = Query(None, description="Filter by parser type (community, marketplace)"),
    vendor: Optional[str] = Query(None, description="Filter by vendor"),
    search: Optional[str] = Query(None, description="Search in parser names"),
    valid_only: bool = Query(False, description="Show only valid parsers"),
    page: int = Query(1, ge=1),
    per_page: int = Query(20, ge=1, le=100),
    _: str = Depends(require_read_access)
):
    """List all available parsers"""
    try:
        # Get all parsers
        parsers = await parser_service.list_parsers(
            type=type,
            vendor=vendor,
            search=search,
            valid_only=valid_only
        )
        
        # Apply pagination
        total = len(parsers)
        start = (page - 1) * per_page
        end = start + per_page
        paginated_parsers = parsers[start:end]
        
        total_pages = (total + per_page - 1) // per_page
        
        return BaseResponse(
            success=True,
            data={
                "parsers": paginated_parsers,
                "total": total
            },
            metadata={
                "pagination": {
                    "page": page,
                    "per_page": per_page,
                    "total": total,
                    "total_pages": total_pages
                }
            }
        )
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to list parsers: {str(e)}")


@router.get("/{parser_id}", response_model=BaseResponse)
async def get_parser(
    parser_id: str = Path(..., description="Parser identifier"),
    _: str = Depends(require_read_access)
):
    """Get details for a specific parser"""
    try:
        parser = await parser_service.get_parser(parser_id)
        if not parser:
            raise HTTPException(status_code=404, detail=f"Parser '{parser_id}' not found")
        
        return BaseResponse(
            success=True,
            data=parser
        )
    
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get parser: {str(e)}")


@router.post("/{parser_id}/validate", response_model=BaseResponse)
async def validate_parser(
    parser_id: str = Path(..., description="Parser identifier"),
    _: str = Depends(require_read_access)
):
    """Validate a parser configuration"""
    try:
        validation = await parser_service.validate_parser(parser_id)
        return BaseResponse(
            success=True,
            data=validation
        )
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to validate parser: {str(e)}")


@router.post("/{parser_id}/test", response_model=BaseResponse)
async def test_parser(
    parser_id: str = Path(..., description="Parser identifier"),
    _: str = Depends(require_write_access),
    input_event: dict = None
):
    """Test a parser with sample input"""
    try:
        # Get parser details
        parser = await parser_service.get_parser(parser_id)
        if not parser:
            raise HTTPException(status_code=404, detail=f"Parser '{parser_id}' not found")
        
        # For now, return basic testing info
        # TODO: Implement actual parser testing when parser engine is available
        return BaseResponse(
            success=True,
            data={
                "parser_id": parser_id,
                "parsing_success": parser.get("config_valid", False),
                "message": "Parser configuration validated" if parser.get("config_valid", False) else "Parser has configuration errors",
                "parser_method": parser.get("parse_method", "unknown"),
                "field_count": parser.get("field_count", 0),
                "input_event": input_event
            }
        )
    
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to test parser: {str(e)}")