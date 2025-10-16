"""
Metrics and analytics API endpoints
"""
from fastapi import APIRouter, HTTPException, Query, Depends
from typing import Optional, List, Dict, Any
from datetime import datetime, timedelta

from app.models.responses import BaseResponse
from app.core.config import settings
from app.core.simple_auth import require_read_access, require_admin_access
from app.services.metrics_service import MetricsService

router = APIRouter()
metrics_service = MetricsService()


@router.get("", response_model=BaseResponse)
async def get_base_metrics(_: str = Depends(require_read_access)):
    """Get base API metrics"""
    try:
        metrics = await metrics_service.get_base_metrics()
        
        return BaseResponse(
            success=True,
            data=metrics
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/summary", response_model=BaseResponse)
async def get_metrics_summary(
    _: str = Depends(require_read_access)
):
    """Get overall system metrics summary"""
    try:
        metrics = await metrics_service.get_system_metrics()
        
        return BaseResponse(
            success=True,
            data=metrics,
            metadata={
                "generated_at": datetime.utcnow().isoformat()
            }
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/generators", response_model=BaseResponse)
async def get_generator_metrics(
    generator_id: Optional[str] = Query(None, description="Specific generator ID"),
    time_range: str = Query("24h", description="Time range: 1h, 24h, 7d, 30d"),
    _: str = Depends(require_read_access)
):
    """Get generator usage metrics"""
    try:
        metrics = await metrics_service.get_generator_metrics(
            generator_id=generator_id,
            time_range=time_range
        )
        
        return BaseResponse(
            success=True,
            data=metrics
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/api", response_model=BaseResponse)
async def get_api_metrics(
    time_range: str = Query("24h", description="Time range: 1h, 24h, 7d, 30d"),
    _: str = Depends(require_read_access)
):
    """Get API endpoint usage metrics"""
    try:
        metrics = await metrics_service.get_api_metrics(time_range=time_range)
        
        return BaseResponse(
            success=True,
            data=metrics
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/errors", response_model=BaseResponse)
async def get_error_metrics(
    _: str = Depends(require_read_access)
):
    """Get error metrics and analysis"""
    try:
        metrics = await metrics_service.get_error_metrics()
        
        return BaseResponse(
            success=True,
            data=metrics
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/users", response_model=BaseResponse)
async def get_user_metrics(
    user_id: Optional[str] = Query(None, description="Specific user ID"),
    _: str = Depends(require_admin_access)
):
    """Get user activity metrics (Admin only)"""
    try:
        metrics = await metrics_service.get_user_metrics(user_id=user_id)
        
        return BaseResponse(
            success=True,
            data=metrics
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/scenarios", response_model=BaseResponse)
async def get_scenario_metrics(
    _: str = Depends(require_read_access)
):
    """Get scenario execution metrics"""
    try:
        metrics = await metrics_service.get_scenario_metrics()
        
        return BaseResponse(
            success=True,
            data=metrics
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/exports", response_model=BaseResponse)
async def get_export_metrics(
    _: str = Depends(require_read_access)
):
    """Get export format usage metrics"""
    try:
        metrics = await metrics_service.get_export_metrics()
        
        return BaseResponse(
            success=True,
            data=metrics
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/timeseries", response_model=BaseResponse)
async def get_timeseries_metrics(
    metric: str = Query("events", description="Metric type: events, errors, api_calls, response_time"),
    interval: str = Query("hour", description="Interval: minute, hour, day"),
    duration: str = Query("24h", description="Duration: 1h, 24h, 7d"),
    _: str = Depends(require_read_access)
):
    """Get time series metrics data for charts"""
    try:
        data = await metrics_service.get_time_series_metrics(
            metric_type=metric,
            interval=interval,
            duration=duration
        )
        
        return BaseResponse(
            success=True,
            data={
                "metric": metric,
                "interval": interval,
                "duration": duration,
                "data_points": data
            }
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/health", response_model=BaseResponse)
async def get_health_status():
    """Get system health status (no auth required)"""
    try:
        health = await metrics_service.get_health_status()
        
        return BaseResponse(
            success=True,
            data=health
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/performance", response_model=BaseResponse)
async def get_performance_metrics(
    _: str = Depends(require_read_access)
):
    """Get detailed performance metrics"""
    try:
        system_metrics = await metrics_service.get_system_metrics()
        performance = system_metrics.get("performance", {})
        
        # Add additional performance insights
        api_metrics = await metrics_service.get_api_metrics("24h")
        generator_metrics = await metrics_service.get_generator_metrics(time_range="24h")
        
        return BaseResponse(
            success=True,
            data={
                "overall": performance,
                "api_performance": {
                    "total_endpoints": api_metrics.get("total_endpoints", 0),
                    "total_calls": api_metrics.get("total_calls", 0),
                    "top_endpoints": api_metrics.get("endpoints", [])[:5]
                },
                "generator_performance": {
                    "total_generators": generator_metrics.get("total_generators", 0),
                    "top_generators": generator_metrics.get("top_generators", [])[:5]
                }
            }
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/dashboard", response_model=BaseResponse)
async def get_dashboard_metrics(
    _: str = Depends(require_read_access)
):
    """Get comprehensive dashboard metrics"""
    try:
        # Gather all metrics for dashboard
        system = await metrics_service.get_system_metrics()
        generators = await metrics_service.get_generator_metrics(time_range="24h")
        api = await metrics_service.get_api_metrics("24h")
        errors = await metrics_service.get_error_metrics()
        scenarios = await metrics_service.get_scenario_metrics()
        exports = await metrics_service.get_export_metrics()
        health = await metrics_service.get_health_status()
        
        # Get time series for charts
        events_timeseries = await metrics_service.get_time_series_metrics(
            metric_type="events",
            interval="hour",
            duration="24h"
        )
        
        errors_timeseries = await metrics_service.get_time_series_metrics(
            metric_type="errors",
            interval="hour",
            duration="24h"
        )
        
        return BaseResponse(
            success=True,
            data={
                "health": health,
                "summary": {
                    "uptime": system["system"]["uptime_human"],
                    "total_events": system["totals"]["total_events_generated"],
                    "total_api_calls": system["totals"]["total_api_calls"],
                    "total_errors": system["totals"]["total_errors"],
                    "unique_generators": system["totals"]["unique_generators_used"],
                    "unique_users": system["totals"]["unique_users"]
                },
                "charts": {
                    "events": events_timeseries,
                    "errors": errors_timeseries
                },
                "top_lists": {
                    "generators": generators.get("top_generators", [])[:5],
                    "endpoints": api.get("endpoints", [])[:5],
                    "scenarios": scenarios.get("top_scenarios", [])[:5],
                    "errors": errors.get("top_errors", [])[:5]
                },
                "exports": exports,
                "performance": system.get("performance", {})
            },
            metadata={
                "generated_at": datetime.utcnow().isoformat(),
                "dashboard_version": "1.0.0"
            }
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/record", response_model=BaseResponse)
async def record_custom_metric(
    metric_data: Dict[str, Any],
    _: str = Depends(require_admin_access)
):
    """Record custom metrics (Admin only)"""
    try:
        # Extract metric information
        metric_type = metric_data.get("type", "custom")
        
        if metric_type == "generator":
            await metrics_service.record_generator_usage(
                generator_id=metric_data.get("generator_id"),
                event_count=metric_data.get("event_count", 1),
                response_time_ms=metric_data.get("response_time_ms", 0),
                success=metric_data.get("success", True),
                user_id=metric_data.get("user_id")
            )
        elif metric_type == "api":
            await metrics_service.record_api_call(
                endpoint=metric_data.get("endpoint"),
                method=metric_data.get("method", "GET"),
                response_time_ms=metric_data.get("response_time_ms", 0),
                status_code=metric_data.get("status_code", 200),
                user_id=metric_data.get("user_id")
            )
        else:
            # Store custom metric
            metrics_service.metrics_storage["custom"][metric_type] = metric_data
        
        return BaseResponse(
            success=True,
            data={"message": "Metric recorded successfully"}
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))