"""
Export and streaming API endpoints for events
"""
from fastapi import APIRouter, HTTPException, Query, Depends, BackgroundTasks, Response
from fastapi.responses import FileResponse, StreamingResponse
from typing import Optional, List
import json
import csv
import io
from datetime import datetime, timedelta
import asyncio

from app.models.responses import BaseResponse
from app.models.requests import ExportGeneratorsRequest, ExportEventsRequest
from app.core.config import settings
from app.core.simple_auth import require_read_access
from app.services.generator_service import GeneratorService

router = APIRouter()
generator_service = GeneratorService()


@router.get("/generators", response_model=BaseResponse)
async def export_generators_list(
    format: str = Query("json", pattern="^(json|csv|yaml)$"),
    category: Optional[str] = Query(None),
    _: str = Depends(require_read_access)
):
    """Export generators list in various formats"""
    try:
        generators = await generator_service.list_generators(category=category)
        
        if format == "csv":
            output = io.StringIO()
            if generators:
                fieldnames = generators[0].keys()
                writer = csv.DictWriter(output, fieldnames=fieldnames)
                writer.writeheader()
                writer.writerows(generators)
            
            return Response(
                content=output.getvalue(),
                media_type="text/csv",
                headers={"Content-Disposition": "attachment; filename=generators.csv"}
            )
        
        elif format == "yaml":
            import yaml
            yaml_content = yaml.dump({"generators": generators}, default_flow_style=False)
            return Response(
                content=yaml_content,
                media_type="text/yaml",
                headers={"Content-Disposition": "attachment; filename=generators.yaml"}
            )
        
        else:  # json
            return BaseResponse(
                success=True,
                data={"generators": generators, "exported_at": datetime.utcnow().isoformat()}
            )
            
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/events", response_model=BaseResponse)
async def export_generated_events(
    request: ExportEventsRequest,
    _: str = Depends(require_read_access)
):
    """Export events from multiple generators"""
    try:
        all_events = []
        
        for generator_id in request.generator_ids:
            events = await generator_service.execute_generator(
                generator_id, 
                count=request.count_per_generator, 
                format="json"
            )
            
            # Add metadata to each event
            for event in events:
                event["_generator"] = generator_id
                event["_exported_at"] = datetime.utcnow().isoformat()
            
            all_events.extend(events)
        
        if request.format == "csv":
            if not all_events:
                return Response(content="", media_type="text/csv")
            
            output = io.StringIO()
            # Flatten nested objects for CSV
            flattened_events = []
            for event in all_events:
                flat_event = {}
                for key, value in event.items():
                    if isinstance(value, (dict, list)):
                        flat_event[key] = json.dumps(value)
                    else:
                        flat_event[key] = value
                flattened_events.append(flat_event)
            
            fieldnames = flattened_events[0].keys()
            writer = csv.DictWriter(output, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(flattened_events)
            
            return Response(
                content=output.getvalue(),
                media_type="text/csv",
                headers={"Content-Disposition": "attachment; filename=events.csv"}
            )
        
        else:  # json
            return BaseResponse(
                success=True,
                data={
                    "events": all_events,
                    "total_events": len(all_events),
                    "generators": request.generator_ids,
                    "exported_at": datetime.utcnow().isoformat()
                }
            )
            
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/stream", response_model=BaseResponse)
async def stream_events(
    generator_id: str = Query(..., description="Generator to stream from"),
    count: int = Query(100, ge=1, le=10000, description="Number of events"),
    interval_ms: int = Query(1000, ge=100, le=60000, description="Interval between events (ms)"),
    format: str = Query("json", description="Output format"),
    _: str = Depends(require_read_access)
):
    """Stream events in real-time with configurable interval"""
    
    async def event_generator():
        """Generate events with delay"""
        for i in range(count):
            try:
                events = await generator_service.execute_generator(
                    generator_id,
                    count=1,
                    format=format
                )
                
                if events:
                    event_data = {
                        "index": i + 1,
                        "timestamp": datetime.utcnow().isoformat(),
                        "generator": generator_id,
                        "event": events[0]
                    }
                    
                    yield f"data: {json.dumps(event_data)}\n\n"
                
                # Wait for specified interval
                await asyncio.sleep(interval_ms / 1000)
                
            except Exception as e:
                yield f"data: {json.dumps({'error': str(e)})}\n\n"
                break
    
    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no"
        }
    )


@router.post("/batch", response_model=BaseResponse)
async def export_batch_events(
    generators: List[str] = Query(..., description="List of generator IDs"),
    count_per_generator: int = Query(10, ge=1, le=1000),
    format: str = Query("json", description="Export format: json, csv, ndjson"),
    _: str = Depends(require_read_access)
):
    """Export events from multiple generators in batch"""
    
    all_events = []
    export_metadata = {
        "export_time": datetime.utcnow().isoformat(),
        "generators": {},
        "total_events": 0
    }
    
    for generator_id in generators:
        try:
            events = await generator_service.execute_generator(
                generator_id,
                count=count_per_generator,
                format="json"  # Always get as JSON internally
            )
            
            all_events.extend(events)
            export_metadata["generators"][generator_id] = len(events)
            export_metadata["total_events"] += len(events)
            
        except Exception as e:
            export_metadata["generators"][generator_id] = f"Error: {str(e)}"
    
    # Format output based on requested format
    if format == "csv":
        output = await _convert_to_csv(all_events)
        media_type = "text/csv"
    elif format == "ndjson":
        output = "\n".join(json.dumps(event) for event in all_events)
        media_type = "application/x-ndjson"
    else:  # json
        output = json.dumps({
            "metadata": export_metadata,
            "events": all_events
        }, indent=2)
        media_type = "application/json"
    
    return BaseResponse(
        success=True,
        data={
            "export": output,
            "metadata": export_metadata,
            "format": format
        }
    )


@router.get("/download/{generator_id}", response_class=FileResponse)
async def download_events(
    generator_id: str,
    count: int = Query(100, ge=1, le=10000),
    format: str = Query("json", description="File format: json, csv, txt"),
    _: str = Depends(require_read_access)
):
    """Download events as a file"""
    
    try:
        # Generate events
        events = await generator_service.execute_generator(
            generator_id,
            count=count,
            format="json"
        )
        
        # Create file content based on format
        if format == "csv":
            content = await _convert_to_csv(events)
            filename = f"{generator_id}_events_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
            media_type = "text/csv"
        elif format == "txt":
            content = "\n".join(json.dumps(event) for event in events)
            filename = f"{generator_id}_events_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
            media_type = "text/plain"
        else:  # json
            content = json.dumps(events, indent=2)
            filename = f"{generator_id}_events_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            media_type = "application/json"
        
        # Create temporary file
        import tempfile
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix=f".{format}") as f:
            f.write(content)
            temp_path = f.name
        
        return FileResponse(
            path=temp_path,
            filename=filename,
            media_type=media_type,
            headers={
                "Content-Disposition": f"attachment; filename={filename}"
            }
        )
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/filter", response_model=BaseResponse)
async def export_filtered_events(
    generator_id: str = Query(..., description="Generator ID"),
    count: int = Query(100, ge=1, le=10000),
    filters: dict = {},
    _: str = Depends(require_read_access)
):
    """Export events with filtering applied"""
    
    try:
        # Generate events
        events = await generator_service.execute_generator(
            generator_id,
            count=count * 2,  # Generate more to account for filtering
            format="json"
        )
        
        # Apply filters
        filtered_events = []
        for event in events:
            if _matches_filters(event, filters):
                filtered_events.append(event)
                if len(filtered_events) >= count:
                    break
        
        return BaseResponse(
            success=True,
            data={
                "events": filtered_events,
                "total": len(filtered_events),
                "filters_applied": filters
            }
        )
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/formats", response_model=BaseResponse)
async def get_export_formats():
    """Get available export formats and their capabilities"""
    
    formats = [
        {
            "format": "json",
            "name": "JSON",
            "description": "JavaScript Object Notation",
            "mime_type": "application/json",
            "supports_streaming": True,
            "supports_filtering": True,
            "file_extension": ".json"
        },
        {
            "format": "ndjson",
            "name": "Newline Delimited JSON",
            "description": "One JSON object per line",
            "mime_type": "application/x-ndjson",
            "supports_streaming": True,
            "supports_filtering": True,
            "file_extension": ".ndjson"
        },
        {
            "format": "csv",
            "name": "CSV",
            "description": "Comma-Separated Values",
            "mime_type": "text/csv",
            "supports_streaming": False,
            "supports_filtering": True,
            "file_extension": ".csv"
        },
        {
            "format": "syslog",
            "name": "Syslog",
            "description": "RFC 5424 Syslog format",
            "mime_type": "text/plain",
            "supports_streaming": True,
            "supports_filtering": False,
            "file_extension": ".log"
        },
        {
            "format": "cef",
            "name": "CEF",
            "description": "Common Event Format",
            "mime_type": "text/plain",
            "supports_streaming": True,
            "supports_filtering": False,
            "file_extension": ".cef"
        }
    ]
    
    return BaseResponse(
        success=True,
        data={"formats": formats}
    )


@router.post("/schedule", response_model=BaseResponse)
async def schedule_export(
    generator_id: str = Query(..., description="Generator ID"),
    count: int = Query(100, ge=1, le=10000),
    interval_hours: int = Query(24, ge=1, le=168, description="Export interval in hours"),
    destination: str = Query("api", description="Export destination: api, s3, email"),
    _: str = Depends(require_read_access)
):
    """Schedule recurring event exports"""
    
    # In production, this would create a scheduled job
    schedule_id = f"schedule_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    
    schedule_config = {
        "schedule_id": schedule_id,
        "generator_id": generator_id,
        "count": count,
        "interval_hours": interval_hours,
        "destination": destination,
        "created_at": datetime.utcnow().isoformat(),
        "next_run": (datetime.utcnow() + timedelta(hours=interval_hours)).isoformat(),
        "status": "active"
    }
    
    return BaseResponse(
        success=True,
        data=schedule_config,
        metadata={
            "message": "Export schedule created successfully"
        }
    )


async def _convert_to_csv(events: List[dict]) -> str:
    """Convert events to CSV format"""
    if not events:
        return ""
    
    # Get all unique keys from events
    all_keys = set()
    for event in events:
        all_keys.update(event.keys())
    
    # Create CSV
    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=sorted(all_keys))
    writer.writeheader()
    
    for event in events:
        # Flatten nested objects
        flat_event = _flatten_dict(event)
        writer.writerow(flat_event)
    
    return output.getvalue()


def _flatten_dict(d: dict, parent_key: str = '', sep: str = '.') -> dict:
    """Flatten nested dictionary"""
    items = []
    for k, v in d.items():
        new_key = f"{parent_key}{sep}{k}" if parent_key else k
        if isinstance(v, dict):
            items.extend(_flatten_dict(v, new_key, sep=sep).items())
        else:
            items.append((new_key, v))
    return dict(items)


def _matches_filters(event: dict, filters: dict) -> bool:
    """Check if event matches all filters"""
    if not filters:
        return True
    
    for key, value in filters.items():
        if key not in event:
            return False
        if event[key] != value:
            return False
    
    return True