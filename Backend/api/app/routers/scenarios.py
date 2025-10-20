"""
Scenario execution and management API endpoints
"""
from fastapi import APIRouter, HTTPException, Query, Path, Depends, BackgroundTasks
from typing import List, Optional, Dict, Any
import asyncio
import time
import json
from datetime import datetime, timedelta
from pathlib import Path as PathLib

from app.models.responses import BaseResponse
from app.core.config import settings
from app.core.simple_auth import require_read_access, require_write_access
from app.services.scenario_service import ScenarioService

router = APIRouter()

# Initialize scenario service
scenario_service = ScenarioService()


@router.get("", response_model=BaseResponse)
async def list_scenarios(
    category: Optional[str] = Query(None, description="Filter by attack category"),
    search: Optional[str] = Query(None, description="Search in scenario names"),
    page: int = Query(1, ge=1),
    per_page: int = Query(20, ge=1, le=100),
    _: str = Depends(require_read_access)
):
    """List all available attack scenarios"""
    try:
        scenarios = await scenario_service.list_scenarios(
            category=category,
            search=search
        )
        
        # Pagination
        total = len(scenarios)
        start = (page - 1) * per_page
        end = start + per_page
        
        return BaseResponse(
            success=True,
            data={
                "scenarios": scenarios[start:end],
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


@router.get("/templates", response_model=BaseResponse)
async def get_scenario_templates(
    _: str = Depends(require_read_access)
):
    """Get pre-built scenario templates"""
    templates = [
        {
            "id": "phishing_campaign",
            "name": "Phishing Campaign",
            "description": "Multi-stage phishing attack with credential harvesting",
            "duration_minutes": 30,
            "generators": ["mimecast", "okta_authentication", "crowdstrike_falcon"],
            "severity": "high",
            "mitre_tactics": ["T1566", "T1078", "T1136"]
        },
        {
            "id": "ransomware_attack",
            "name": "Ransomware Attack",
            "description": "Ransomware deployment and lateral movement",
            "duration_minutes": 60,
            "generators": ["crowdstrike_falcon", "microsoft_windows_eventlog", "veeam_backup"],
            "severity": "critical",
            "mitre_tactics": ["T1486", "T1021", "T1490"]
        },
        {
            "id": "insider_threat",
            "name": "Insider Threat",
            "description": "Malicious insider data exfiltration",
            "duration_minutes": 120,
            "generators": ["microsoft_365_collaboration", "aws_cloudtrail", "netskope"],
            "severity": "high",
            "mitre_tactics": ["T1074", "T1567", "T1530"]
        },
        {
            "id": "supply_chain",
            "name": "Supply Chain Attack",
            "description": "Third-party compromise and backdoor installation",
            "duration_minutes": 240,
            "generators": ["github_audit", "buildkite", "sentinelone_endpoint"],
            "severity": "critical",
            "mitre_tactics": ["T1195", "T1072", "T1053"]
        },
        {
            "id": "cloud_breach",
            "name": "Cloud Infrastructure Breach",
            "description": "AWS account compromise and resource abuse",
            "duration_minutes": 90,
            "generators": ["aws_guardduty", "aws_cloudtrail", "aws_vpc_dns"],
            "severity": "high",
            "mitre_tactics": ["T1078.004", "T1580", "T1530"]
        }
    ]
    
    return BaseResponse(
        success=True,
        data={"templates": templates}
    )


@router.get("/{scenario_id}", response_model=BaseResponse)
async def get_scenario_details(
    scenario_id: str = Path(..., description="Scenario identifier"),
    _: str = Depends(require_read_access)
):
    """Get detailed information about a scenario"""
    try:
        scenario = await scenario_service.get_scenario(scenario_id)
        if not scenario:
            raise HTTPException(status_code=404, detail=f"Scenario '{scenario_id}' not found")
        
        return BaseResponse(
            success=True,
            data=scenario
        )
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/{scenario_id}/execute", response_model=BaseResponse)
async def execute_scenario(
    background_tasks: BackgroundTasks,
    scenario_id: str = Path(..., description="Scenario identifier"),
    speed: str = Query("fast", description="Execution speed: realtime, fast, instant"),
    dry_run: bool = Query(False, description="Simulate without generating events"),
    _: str = Depends(require_write_access)
):
    """Execute an attack scenario"""
    try:
        # Validate scenario exists
        scenario = await scenario_service.get_scenario(scenario_id)
        if not scenario:
            raise HTTPException(status_code=404, detail=f"Scenario '{scenario_id}' not found")
        
        # Start execution
        execution_id = await scenario_service.start_scenario(
            scenario_id=scenario_id,
            speed=speed,
            dry_run=dry_run,
            background_tasks=background_tasks
        )
        
        return BaseResponse(
            success=True,
            data={
                "execution_id": execution_id,
                "scenario_id": scenario_id,
                "status": "started",
                "speed": speed,
                "dry_run": dry_run,
                "started_at": datetime.utcnow().isoformat()
            }
        )
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/{scenario_id}/status", response_model=BaseResponse)
async def get_scenario_status(
    scenario_id: str = Path(..., description="Scenario identifier"),
    execution_id: Optional[str] = Query(None, description="Specific execution ID"),
    _: str = Depends(require_read_access)
):
    """Get the status of a scenario execution"""
    try:
        status = await scenario_service.get_execution_status(scenario_id, execution_id)
        if not status:
            raise HTTPException(status_code=404, detail="Execution not found")
        
        return BaseResponse(
            success=True,
            data=status
        )
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/{scenario_id}/stop", response_model=BaseResponse)
async def stop_scenario(
    scenario_id: str = Path(..., description="Scenario identifier"),
    execution_id: str = Query(..., description="Execution ID to stop"),
    _: str = Depends(require_write_access)
):
    """Stop a running scenario execution"""
    try:
        success = await scenario_service.stop_execution(scenario_id, execution_id)
        if not success:
            raise HTTPException(status_code=404, detail="Execution not found or already stopped")
        
        return BaseResponse(
            success=True,
            data={
                "scenario_id": scenario_id,
                "execution_id": execution_id,
                "status": "stopped",
                "stopped_at": datetime.utcnow().isoformat()
            }
        )
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/{scenario_id}/results", response_model=BaseResponse)
async def get_scenario_results(
    scenario_id: str = Path(..., description="Scenario identifier"),
    execution_id: str = Query(..., description="Execution ID"),
    include_events: bool = Query(False, description="Include generated events"),
    _: str = Depends(require_read_access)
):
    """Get the results of a scenario execution"""
    try:
        results = await scenario_service.get_execution_results(
            scenario_id, 
            execution_id,
            include_events=include_events
        )
        
        if not results:
            raise HTTPException(status_code=404, detail="Results not found")
        
        return BaseResponse(
            success=True,
            data=results
        )
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/custom", response_model=BaseResponse)
async def create_custom_scenario(
    scenario_config: Dict[str, Any],
    _: str = Depends(require_write_access)
):
    """Create and execute a custom scenario"""
    try:
        # Validate scenario configuration
        required_fields = ["name", "description", "phases"]
        for field in required_fields:
            if field not in scenario_config:
                raise HTTPException(status_code=400, detail=f"Missing required field: {field}")
        
        # Create custom scenario
        scenario_id = await scenario_service.create_custom_scenario(scenario_config)
        
        return BaseResponse(
            success=True,
            data={
                "scenario_id": scenario_id,
                "name": scenario_config["name"],
                "status": "created",
                "message": "Custom scenario created successfully"
            }
        )
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/analytics/timeline", response_model=BaseResponse)
async def get_scenario_timeline(
    scenario_id: str = Query(..., description="Scenario identifier"),
    execution_id: str = Query(..., description="Execution ID"),
    _: str = Depends(require_read_access)
):
    """Get a timeline view of scenario execution"""
    try:
        timeline = await scenario_service.get_execution_timeline(scenario_id, execution_id)
        
        return BaseResponse(
            success=True,
            data={
                "scenario_id": scenario_id,
                "execution_id": execution_id,
                "timeline": timeline
            }
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/batch", response_model=BaseResponse)
async def execute_batch_scenarios(
    scenarios: List[Dict[str, Any]],
    parallel: bool = Query(False, description="Execute scenarios in parallel"),
    _: str = Depends(require_write_access)
):
    """Execute multiple scenarios in batch"""
    try:
        batch_id = f"batch_{int(time.time())}"
        results = []
        
        for scenario in scenarios:
            execution_id = await scenario_service.start_scenario(
                scenario_id=scenario.get("scenario_id"),
                speed=scenario.get("speed", "fast"),
                dry_run=scenario.get("dry_run", False)
            )
            
            results.append({
                "scenario_id": scenario.get("scenario_id"),
                "execution_id": execution_id,
                "status": "started"
            })
        
        return BaseResponse(
            success=True,
            data={
                "batch_id": batch_id,
                "executions": results,
                "parallel": parallel,
                "total": len(results)
            }
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))