"""
Categories endpoints for the API
"""
from fastapi import APIRouter, HTTPException, Depends

from app.models.responses import BaseResponse
from app.core.simple_auth import require_read_access
from app.services.generator_service import GeneratorService

router = APIRouter()

# Initialize generator service
generator_service = GeneratorService()


@router.get("", response_model=BaseResponse)
async def list_categories(
    _: str = Depends(require_read_access)
):
    """List all generator categories with counts"""
    try:
        categories = await generator_service.list_categories()
        return BaseResponse(
            success=True,
            data={
                "categories": categories,
                "total": len(categories)
            }
        )
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to list categories: {str(e)}")


@router.get("/{category_id}", response_model=BaseResponse)
async def get_category(
    category_id: str,
    _: str = Depends(require_read_access)
):
    """Get generators in a specific category"""
    try:
        generators = await generator_service.list_generators(category=category_id)
        
        if not generators:
            raise HTTPException(status_code=404, detail=f"Category '{category_id}' not found or has no generators")
        
        return BaseResponse(
            success=True,
            data={
                "category_id": category_id,
                "category_name": category_id.replace('_', ' ').title(),
                "generators": generators,
                "total": len(generators)
            }
        )
    
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get category: {str(e)}")