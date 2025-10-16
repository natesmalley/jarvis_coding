"""
Search and filtering API endpoints
"""
from fastapi import APIRouter, HTTPException, Query, Depends
from typing import Optional, List, Dict, Any

from app.models.responses import BaseResponse
from app.core.config import settings
from app.core.simple_auth import require_read_access
from app.services.search_service import SearchService

router = APIRouter()
search_service = SearchService()


@router.get("/generators", response_model=BaseResponse)
async def search_generators(
    q: Optional[str] = Query(None, description="Search query"),
    category: Optional[str] = Query(None, description="Filter by category"),
    vendor: Optional[str] = Query(None, description="Filter by vendor"),
    format: Optional[str] = Query(None, description="Filter by output format"),
    star_trek: Optional[bool] = Query(None, description="Filter by Star Trek theme"),
    page: int = Query(1, ge=1),
    per_page: int = Query(20, ge=1, le=100),
    _: str = Depends(require_read_access)
):
    """Search and filter event generators"""
    try:
        results = await search_service.search_generators(
            query=q,
            category=category,
            vendor=vendor,
            format=format,
            star_trek=star_trek
        )
        
        # Pagination
        total = len(results)
        start = (page - 1) * per_page
        end = start + per_page
        
        return BaseResponse(
            success=True,
            data={
                "results": results[start:end],
                "total": total,
                "filters_applied": {
                    "query": q,
                    "category": category,
                    "vendor": vendor,
                    "format": format,
                    "star_trek": star_trek
                }
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


@router.get("/parsers", response_model=BaseResponse)
async def search_parsers(
    q: Optional[str] = Query(None, description="Search query"),
    type: Optional[str] = Query(None, description="Parser type: community, sentinelone, marketplace"),
    vendor: Optional[str] = Query(None, description="Filter by vendor"),
    min_fields: Optional[int] = Query(None, description="Minimum field count"),
    page: int = Query(1, ge=1),
    per_page: int = Query(20, ge=1, le=100),
    _: str = Depends(require_read_access)
):
    """Search and filter log parsers"""
    try:
        results = await search_service.search_parsers(
            query=q,
            parser_type=type,
            vendor=vendor,
            min_fields=min_fields
        )
        
        # Sort by fields count
        results.sort(key=lambda x: x.get("fields_count", 0), reverse=True)
        
        # Pagination
        total = len(results)
        start = (page - 1) * per_page
        end = start + per_page
        
        return BaseResponse(
            success=True,
            data={
                "results": results[start:end],
                "total": total,
                "filters_applied": {
                    "query": q,
                    "type": type,
                    "vendor": vendor,
                    "min_fields": min_fields
                }
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


@router.get("/scenarios", response_model=BaseResponse)
async def search_scenarios(
    q: Optional[str] = Query(None, description="Search query"),
    category: Optional[str] = Query(None, description="Filter by category"),
    min_phases: Optional[int] = Query(None, description="Minimum phase count"),
    _: str = Depends(require_read_access)
):
    """Search and filter attack scenarios"""
    try:
        results = await search_service.search_scenarios(
            query=q,
            category=category,
            min_phases=min_phases
        )
        
        return BaseResponse(
            success=True,
            data={
                "results": results,
                "total": len(results),
                "filters_applied": {
                    "query": q,
                    "category": category,
                    "min_phases": min_phases
                }
            }
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/global", response_model=BaseResponse)
async def global_search(
    q: str = Query(..., description="Search query"),
    types: Optional[List[str]] = Query(None, description="Resource types to search"),
    _: str = Depends(require_read_access)
):
    """Search across all resource types"""
    try:
        results = await search_service.global_search(
            query=q,
            types=types
        )
        
        # Count total results
        total_results = sum(len(items) for items in results.values())
        
        return BaseResponse(
            success=True,
            data={
                "query": q,
                "total_results": total_results,
                "results": results
            }
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/compatibility", response_model=BaseResponse)
async def check_compatibility(
    generator_id: Optional[str] = Query(None, description="Generator ID"),
    parser_id: Optional[str] = Query(None, description="Parser ID"),
    _: str = Depends(require_read_access)
):
    """Find compatible generators and parsers"""
    try:
        if not generator_id and not parser_id:
            raise HTTPException(
                status_code=400,
                detail="Either generator_id or parser_id must be provided"
            )
        
        matches = await search_service.get_compatibility_matches(
            generator_id=generator_id,
            parser_id=parser_id
        )
        
        return BaseResponse(
            success=True,
            data=matches
        )
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/statistics", response_model=BaseResponse)
async def get_search_statistics(
    _: str = Depends(require_read_access)
):
    """Get statistics about searchable resources"""
    try:
        stats = await search_service.get_statistics()
        
        return BaseResponse(
            success=True,
            data=stats
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/recommendations", response_model=BaseResponse)
async def get_recommendations(
    type: str = Query("generator", description="Resource type: generator, parser, scenario"),
    based_on: Optional[str] = Query(None, description="Resource ID to base recommendations on"),
    _: str = Depends(require_read_access)
):
    """Get recommendations based on similarity or usage"""
    try:
        recommendations = await search_service.get_recommendations(
            resource_type=type,
            based_on=based_on
        )
        
        return BaseResponse(
            success=True,
            data={
                "type": type,
                "based_on": based_on,
                "recommendations": recommendations
            }
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/autocomplete", response_model=BaseResponse)
async def autocomplete(
    q: str = Query(..., min_length=2, description="Partial query"),
    type: str = Query("all", description="Resource type: all, generator, parser, scenario"),
    limit: int = Query(10, ge=1, le=50),
    _: str = Depends(require_read_access)
):
    """Get autocomplete suggestions"""
    try:
        suggestions = []
        
        if type in ["all", "generator"]:
            generators = await search_service.search_generators(query=q)
            suggestions.extend([
                {
                    "type": "generator",
                    "id": g["id"],
                    "label": f"{g['vendor']} {g['product']}",
                    "category": g["category"]
                }
                for g in generators[:limit]
            ])
        
        if type in ["all", "parser"]:
            parsers = await search_service.search_parsers(query=q)
            suggestions.extend([
                {
                    "type": "parser",
                    "id": p["id"],
                    "label": f"{p['vendor']} Parser",
                    "fields": p["fields_count"]
                }
                for p in parsers[:limit]
            ])
        
        if type in ["all", "scenario"]:
            scenarios = await search_service.search_scenarios(query=q)
            suggestions.extend([
                {
                    "type": "scenario",
                    "id": s["id"],
                    "label": s["id"].replace("_", " ").title(),
                    "category": s.get("category", "")
                }
                for s in scenarios[:limit]
            ])
        
        # Limit total suggestions
        suggestions = suggestions[:limit]
        
        return BaseResponse(
            success=True,
            data={
                "query": q,
                "suggestions": suggestions
            }
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/filters", response_model=BaseResponse)
async def get_available_filters(
    type: str = Query("generator", description="Resource type: generator, parser, scenario"),
    _: str = Depends(require_read_access)
):
    """Get available filter options for a resource type"""
    try:
        await search_service.build_search_index()
        
        filters = {}
        
        if type == "generator":
            generators = search_service._cache["generators"]
            filters = {
                "categories": list(generators["by_category"].keys()),
                "vendors": list(generators["by_vendor"].keys()),
                "formats": list(generators["by_format"].keys()),
                "features": ["star_trek", "recent_timestamps", "has_parser"]
            }
        
        elif type == "parser":
            parsers = search_service._cache["parsers"]
            filters = {
                "types": list(parsers["by_type"].keys()),
                "vendors": list(parsers["by_vendor"].keys()),
                "field_ranges": [
                    {"label": "0-50 fields", "min": 0, "max": 50},
                    {"label": "50-100 fields", "min": 50, "max": 100},
                    {"label": "100-200 fields", "min": 100, "max": 200},
                    {"label": "200+ fields", "min": 200, "max": 10000}
                ]
            }
        
        elif type == "scenario":
            scenarios = search_service._cache["scenarios"]
            filters = {
                "categories": list(scenarios["by_category"].keys()),
                "phase_ranges": [
                    {"label": "Quick (1-3 phases)", "min": 1, "max": 3},
                    {"label": "Medium (4-5 phases)", "min": 4, "max": 5},
                    {"label": "Long (6+ phases)", "min": 6, "max": 20}
                ]
            }
        
        return BaseResponse(
            success=True,
            data={
                "type": type,
                "filters": filters
            }
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))