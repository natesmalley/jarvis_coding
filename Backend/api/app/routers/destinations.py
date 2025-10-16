"""API endpoints for destination management"""
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from typing import Optional, List
from sqlalchemy.ext.asyncio import AsyncSession
import logging

from app.services.destination_service import DestinationService, get_session, init_db
from app.core.simple_auth import get_api_key

logger = logging.getLogger(__name__)

router = APIRouter()


# Pydantic models for request/response
class DestinationCreate(BaseModel):
    """Request model for creating a destination"""
    name: str = Field(..., description="Destination name (must be unique)")
    type: str = Field(..., description="Destination type: 'hec' or 'syslog'")
    
    # HEC fields
    url: Optional[str] = Field(None, description="HEC URL (required for HEC destinations)")
    token: Optional[str] = Field(None, description="HEC token (required for HEC destinations)")
    
    # Syslog fields
    ip: Optional[str] = Field(None, description="Syslog IP (required for syslog destinations)")
    port: Optional[int] = Field(None, description="Syslog port (required for syslog destinations)")
    protocol: Optional[str] = Field(None, description="Syslog protocol: 'UDP' or 'TCP'")


class DestinationUpdate(BaseModel):
    """Request model for updating a destination"""
    name: Optional[str] = None
    url: Optional[str] = None
    token: Optional[str] = None
    ip: Optional[str] = None
    port: Optional[int] = None
    protocol: Optional[str] = None


class DestinationResponse(BaseModel):
    """Response model for a destination (without sensitive data)"""
    id: str
    name: str
    type: str
    url: Optional[str] = None
    ip: Optional[str] = None
    port: Optional[int] = None
    protocol: Optional[str] = None
    created_at: Optional[str] = None
    updated_at: Optional[str] = None


class DestinationWithToken(DestinationResponse):
    """Response model including decrypted token (for internal use)"""
    token: Optional[str] = None


@router.on_event("startup")
async def startup():
    """Initialize database on startup"""
    await init_db()


@router.post("", response_model=DestinationResponse, status_code=status.HTTP_201_CREATED)
async def create_destination(
    destination: DestinationCreate,
    session: AsyncSession = Depends(get_session),
    auth_info: tuple = Depends(get_api_key)
):
    """
    Create a new destination
    
    - **name**: Unique destination name
    - **type**: 'hec' or 'syslog'
    - For HEC: provide **url** and **token**
    - For Syslog: provide **ip**, **port**, and **protocol** (UDP/TCP)
    """
    service = DestinationService(session)
    
    # Validate required fields based on type
    if destination.type == 'hec':
        if not destination.url or not destination.token:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="HEC destinations require 'url' and 'token'"
            )
        # Normalize URL
        base_url = destination.url.rstrip('/')
        if not (base_url.endswith('/event') or base_url.endswith('/raw') or '/services/collector' in base_url):
            base_url = base_url + '/services/collector'
        destination.url = base_url
    elif destination.type == 'syslog':
        if not destination.ip or not destination.port or not destination.protocol:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Syslog destinations require 'ip', 'port', and 'protocol'"
            )
        if destination.protocol.upper() not in ('UDP', 'TCP'):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Protocol must be 'UDP' or 'TCP'"
            )
        destination.protocol = destination.protocol.upper()
    else:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Type must be 'hec' or 'syslog'"
        )
    
    # Check for duplicate name
    existing = await service.get_destination_by_name(destination.name)
    if existing:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Destination with name '{destination.name}' already exists"
        )
    
    try:
        logger.info(f"Creating destination: name={destination.name}, type={destination.type}")
        dest = await service.create_destination(
            name=destination.name,
            dest_type=destination.type,
            url=destination.url,
            token=destination.token,
            ip=destination.ip,
            port=destination.port,
            protocol=destination.protocol
        )
        logger.info(f"Successfully created destination: {dest.id}")
        return dest.to_dict()
    except Exception as e:
        logger.error(f"Failed to create destination: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to create destination: {str(e)}"
        )


@router.get("", response_model=List[DestinationResponse])
async def list_destinations(
    session: AsyncSession = Depends(get_session),
    auth_info: tuple = Depends(get_api_key)
):
    """
    List all destinations (without sensitive token data)
    """
    service = DestinationService(session)
    destinations = await service.list_destinations()
    logger.debug(f"Listing {len(destinations)} destinations")
    return [dest.to_dict() for dest in destinations]


@router.get("/{dest_id}", response_model=DestinationResponse)
async def get_destination(
    dest_id: str,
    session: AsyncSession = Depends(get_session),
    auth_info: tuple = Depends(get_api_key)
):
    """
    Get a specific destination by ID
    """
    service = DestinationService(session)
    destination = await service.get_destination(dest_id)
    if not destination:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Destination '{dest_id}' not found"
        )
    return destination.to_dict()


@router.get("/{dest_id}/token")
async def get_destination_token(
    dest_id: str,
    session: AsyncSession = Depends(get_session),
    auth_info: tuple = Depends(get_api_key)
):
    """
    Get decrypted token for a destination (internal use only)
    
    Returns the decrypted HEC token for use by scenarios and generators
    """
    service = DestinationService(session)
    destination = await service.get_destination(dest_id)
    if not destination:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Destination '{dest_id}' not found"
        )
    
    if destination.type != 'hec':
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Only HEC destinations have tokens"
        )
    
    if not destination.token_encrypted:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="No token found for this destination"
        )
    
    try:
        token = service.decrypt_token(destination.token_encrypted)
        logger.info(f"Successfully decrypted token for destination: {dest_id}")
        return {"token": token}
    except Exception as e:
        logger.error(f"Failed to decrypt token: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to decrypt token"
        )


@router.put("/{dest_id}", response_model=DestinationResponse)
async def update_destination(
    dest_id: str,
    update: DestinationUpdate,
    session: AsyncSession = Depends(get_session),
    auth_info: tuple = Depends(get_api_key)
):
    """
    Update a destination
    
    Only provided fields will be updated
    """
    service = DestinationService(session)
    
    # Validate protocol if provided
    if update.protocol and update.protocol.upper() not in ('UDP', 'TCP'):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Protocol must be 'UDP' or 'TCP'"
        )
    
    if update.protocol:
        update.protocol = update.protocol.upper()
    
    try:
        destination = await service.update_destination(
            dest_id=dest_id,
            name=update.name,
            url=update.url,
            token=update.token,
            ip=update.ip,
            port=update.port,
            protocol=update.protocol
        )
        
        if not destination:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Destination '{dest_id}' not found"
            )
        
        return destination.to_dict()
    except Exception as e:
        logger.error(f"Failed to update destination: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to update destination: {str(e)}"
        )


@router.delete("/{dest_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_destination(
    dest_id: str,
    session: AsyncSession = Depends(get_session),
    auth_info: tuple = Depends(get_api_key)
):
    """
    Delete a destination
    """
    service = DestinationService(session)
    deleted = await service.delete_destination(dest_id)
    
    if not deleted:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Destination '{dest_id}' not found"
        )
    
    return None
