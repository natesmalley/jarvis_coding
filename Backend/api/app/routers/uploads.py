"""API endpoints for file upload and processing"""
from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, status, BackgroundTasks
from pydantic import BaseModel, Field
from typing import Optional, List
import logging
import os
import json
import csv
import shutil
import uuid
import gzip
from pathlib import Path
from datetime import datetime

from app.core.simple_auth import get_api_key

logger = logging.getLogger(__name__)

router = APIRouter()

# Configure upload directory
UPLOAD_DIR = Path("/app/data/uploads") if os.path.exists("/app/data") else Path("./data/uploads")
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)

# File size limit: 1GB
MAX_FILE_SIZE = 1 * 1024 * 1024 * 1024  # 1GB in bytes

# Store upload metadata in memory (could be moved to database)
_UPLOADS = {}


class FileUploadResponse(BaseModel):
    """Response model for file upload"""
    id: str
    filename: str
    file_type: str
    size: int
    line_count: Optional[int] = None
    uploaded_at: str
    status: str = "uploaded"


class FileProcessRequest(BaseModel):
    """Request model for processing uploaded file"""
    upload_id: str = Field(..., description="ID of uploaded file")
    destination_id: str = Field(..., description="HEC destination ID")
    batch_size: int = Field(100, ge=1, le=1000, description="Number of events per batch")
    sourcetype: str = Field(..., description="Sourcetype for HEC parsing")
    endpoint: str = Field("event", description="HEC endpoint: 'event' or 'raw'")


@router.post("/upload", response_model=FileUploadResponse, status_code=status.HTTP_201_CREATED)
async def upload_file(
    file: UploadFile = File(...),
    auth_info: tuple = Depends(get_api_key)
):
    """
    Upload a file for processing
    
    - **file**: CSV, JSON, TXT, LOG, or GZ file (max 1GB)
    - Accepted formats: .csv, .json, .txt, .log, .gz
    - GZ files will be automatically decompressed
    """
    # Validate file extension
    if not file.filename:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No filename provided"
        )
    
    file_ext = Path(file.filename).suffix.lower()
    allowed_extensions = ['.csv', '.json', '.txt', '.log', '.gz']
    if file_ext not in allowed_extensions:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid file type '{file_ext}'. Allowed: {', '.join(allowed_extensions)}"
        )
    
    # Generate unique ID for this upload
    upload_id = str(uuid.uuid4())
    
    # Create safe filename
    safe_filename = f"{upload_id}_{file.filename}"
    file_path = UPLOAD_DIR / safe_filename
    
    try:
        # Stream file to disk with size checking
        total_size = 0
        with open(file_path, "wb") as buffer:
            while chunk := await file.read(1024 * 1024):  # Read 1MB at a time
                total_size += len(chunk)
                if total_size > MAX_FILE_SIZE:
                    buffer.close()
                    file_path.unlink()  # Delete partial file
                    raise HTTPException(
                        status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                        detail=f"File size exceeds maximum allowed size of 1GB"
                    )
                buffer.write(chunk)
        
        logger.info(f"File uploaded: {safe_filename} ({total_size} bytes)")
        
        # Handle gzip decompression
        actual_file_type = file_ext.lstrip('.')
        decompressed_path = file_path
        
        if file_ext == '.gz':
            logger.info(f"Decompressing gzip file: {safe_filename}")
            try:
                # Decompress to a new file
                decompressed_filename = safe_filename.rsplit('.gz', 1)[0]
                decompressed_path = UPLOAD_DIR / decompressed_filename
                
                with gzip.open(file_path, 'rb') as f_in:
                    with open(decompressed_path, 'wb') as f_out:
                        shutil.copyfileobj(f_in, f_out)
                
                # Remove original gz file
                file_path.unlink()
                file_path = decompressed_path
                safe_filename = decompressed_filename
                
                # Detect actual file type from decompressed filename
                inner_ext = Path(decompressed_filename).suffix.lower()
                if inner_ext in ['.csv', '.json', '.txt', '.log']:
                    actual_file_type = inner_ext.lstrip('.')
                else:
                    actual_file_type = 'txt'  # Default to txt for unknown extensions
                
                logger.info(f"Decompressed to: {decompressed_filename}, detected type: {actual_file_type}")
            except Exception as e:
                logger.error(f"Failed to decompress gzip file: {e}")
                if file_path.exists():
                    file_path.unlink()
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Failed to decompress gzip file: {str(e)}"
                )
        
        # Count lines/records
        line_count = None
        try:
            if actual_file_type == 'json':
                with open(file_path, 'r') as f:
                    data = json.load(f)
                    if isinstance(data, list):
                        line_count = len(data)
                    else:
                        line_count = 1
            elif actual_file_type == 'csv':
                with open(file_path, 'r') as f:
                    line_count = sum(1 for _ in csv.reader(f)) - 1  # Subtract header
            elif actual_file_type in ['txt', 'log']:
                with open(file_path, 'r') as f:
                    line_count = sum(1 for _ in f)
        except Exception as e:
            logger.warning(f"Could not count lines in {safe_filename}: {e}")
        
        # Store metadata
        upload_metadata = {
            'id': upload_id,
            'filename': file.filename,
            'safe_filename': safe_filename,
            'file_type': actual_file_type,
            'size': total_size,
            'line_count': line_count,
            'uploaded_at': datetime.utcnow().isoformat(),
            'status': 'uploaded',
            'file_path': str(file_path)
        }
        _UPLOADS[upload_id] = upload_metadata
        
        return FileUploadResponse(**upload_metadata)
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to upload file: {e}", exc_info=True)
        if file_path.exists():
            file_path.unlink()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to upload file: {str(e)}"
        )


@router.get("/uploads", response_model=List[FileUploadResponse])
async def list_uploads(
    auth_info: tuple = Depends(get_api_key)
):
    """
    List all uploaded files
    """
    return [
        FileUploadResponse(**upload)
        for upload in _UPLOADS.values()
    ]


@router.get("/uploads/{upload_id}", response_model=FileUploadResponse)
async def get_upload(
    upload_id: str,
    auth_info: tuple = Depends(get_api_key)
):
    """
    Get details about a specific upload
    """
    if upload_id not in _UPLOADS:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Upload '{upload_id}' not found"
        )
    
    return FileUploadResponse(**_UPLOADS[upload_id])


@router.delete("/uploads/{upload_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_upload(
    upload_id: str,
    auth_info: tuple = Depends(get_api_key)
):
    """
    Delete an uploaded file
    """
    if upload_id not in _UPLOADS:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Upload '{upload_id}' not found"
        )
    
    upload = _UPLOADS[upload_id]
    file_path = Path(upload['file_path'])
    
    try:
        if file_path.exists():
            file_path.unlink()
        del _UPLOADS[upload_id]
        logger.info(f"Deleted upload: {upload_id}")
        return None
    except Exception as e:
        logger.error(f"Failed to delete upload: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to delete upload: {str(e)}"
        )
