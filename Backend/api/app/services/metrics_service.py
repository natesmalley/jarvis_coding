"""
Metrics and analytics service for tracking system usage and performance
"""
import asyncio
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
from collections import defaultdict, Counter
import statistics
import json

from app.core.config import settings


class MetricsService:
    """Service for collecting and analyzing system metrics"""
    
    def __init__(self):
        self.metrics_storage = {
            "generator_usage": defaultdict(int),
            "parser_usage": defaultdict(int),
            "api_calls": defaultdict(int),
            "event_counts": defaultdict(int),
            "error_counts": defaultdict(int),
            "response_times": defaultdict(list),
            "scenario_executions": defaultdict(int),
            "export_formats": defaultdict(int),
            "user_activity": defaultdict(lambda: defaultdict(int))
        }
        self.start_time = datetime.utcnow()
    
    async def record_generator_usage(
        self,
        generator_id: str,
        event_count: int,
        response_time_ms: float,
        success: bool = True,
        user_id: Optional[str] = None
    ):
        """Record generator usage metrics"""
        self.metrics_storage["generator_usage"][generator_id] += 1
        self.metrics_storage["event_counts"][generator_id] += event_count
        self.metrics_storage["response_times"][generator_id].append(response_time_ms)
        
        if not success:
            self.metrics_storage["error_counts"][generator_id] += 1
        
        if user_id:
            self.metrics_storage["user_activity"][user_id]["generators"] += 1
    
    async def record_api_call(
        self,
        endpoint: str,
        method: str,
        response_time_ms: float,
        status_code: int,
        user_id: Optional[str] = None
    ):
        """Record API call metrics"""
        api_key = f"{method}:{endpoint}"
        self.metrics_storage["api_calls"][api_key] += 1
        self.metrics_storage["response_times"][api_key].append(response_time_ms)
        
        if status_code >= 400:
            self.metrics_storage["error_counts"][api_key] += 1
        
        if user_id:
            self.metrics_storage["user_activity"][user_id]["api_calls"] += 1
    
    async def get_system_metrics(self) -> Dict[str, Any]:
        """Get comprehensive system metrics"""
        uptime = datetime.utcnow() - self.start_time
        
        return {
            "system": {
                "uptime_seconds": uptime.total_seconds(),
                "uptime_human": str(uptime),
                "start_time": self.start_time.isoformat(),
                "current_time": datetime.utcnow().isoformat()
            },
            "totals": {
                "total_api_calls": sum(self.metrics_storage["api_calls"].values()),
                "total_events_generated": sum(self.metrics_storage["event_counts"].values()),
                "total_errors": sum(self.metrics_storage["error_counts"].values()),
                "unique_generators_used": len(self.metrics_storage["generator_usage"]),
                "unique_users": len(self.metrics_storage["user_activity"])
            },
            "performance": await self._calculate_performance_metrics()
        }
    
    async def get_generator_metrics(
        self,
        generator_id: Optional[str] = None,
        time_range: Optional[str] = "24h"
    ) -> Dict[str, Any]:
        """Get metrics for generators"""
        if generator_id:
            return await self._get_single_generator_metrics(generator_id)
        
        # Get top generators
        top_generators = sorted(
            self.metrics_storage["generator_usage"].items(),
            key=lambda x: x[1],
            reverse=True
        )[:10]
        
        generator_metrics = []
        for gen_id, usage_count in top_generators:
            metrics = await self._get_single_generator_metrics(gen_id)
            generator_metrics.append(metrics)
        
        return {
            "time_range": time_range,
            "total_generators": len(self.metrics_storage["generator_usage"]),
            "top_generators": generator_metrics
        }
    
    async def _get_single_generator_metrics(self, generator_id: str) -> Dict[str, Any]:
        """Get metrics for a single generator"""
        usage = self.metrics_storage["generator_usage"].get(generator_id, 0)
        events = self.metrics_storage["event_counts"].get(generator_id, 0)
        errors = self.metrics_storage["error_counts"].get(generator_id, 0)
        response_times = self.metrics_storage["response_times"].get(generator_id, [])
        
        return {
            "generator_id": generator_id,
            "usage_count": usage,
            "total_events": events,
            "error_count": errors,
            "error_rate": (errors / usage * 100) if usage > 0 else 0,
            "avg_events_per_call": events / usage if usage > 0 else 0,
            "response_times": {
                "avg_ms": statistics.mean(response_times) if response_times else 0,
                "min_ms": min(response_times) if response_times else 0,
                "max_ms": max(response_times) if response_times else 0,
                "p95_ms": self._calculate_percentile(response_times, 95) if response_times else 0
            }
        }
    
    async def get_api_metrics(self, time_range: Optional[str] = "24h") -> Dict[str, Any]:
        """Get API endpoint metrics"""
        endpoint_metrics = []
        
        for api_key, count in self.metrics_storage["api_calls"].items():
            method, endpoint = api_key.split(":", 1)
            response_times = self.metrics_storage["response_times"].get(api_key, [])
            errors = self.metrics_storage["error_counts"].get(api_key, 0)
            
            endpoint_metrics.append({
                "endpoint": endpoint,
                "method": method,
                "call_count": count,
                "error_count": errors,
                "error_rate": (errors / count * 100) if count > 0 else 0,
                "avg_response_ms": statistics.mean(response_times) if response_times else 0,
                "p95_response_ms": self._calculate_percentile(response_times, 95) if response_times else 0
            })
        
        # Sort by call count
        endpoint_metrics.sort(key=lambda x: x["call_count"], reverse=True)
        
        return {
            "time_range": time_range,
            "total_endpoints": len(endpoint_metrics),
            "total_calls": sum(self.metrics_storage["api_calls"].values()),
            "endpoints": endpoint_metrics[:20]  # Top 20
        }
    
    async def get_error_metrics(self) -> Dict[str, Any]:
        """Get error metrics and analysis"""
        error_summary = []
        
        for resource, error_count in self.metrics_storage["error_counts"].items():
            total_calls = 0
            if ":" in resource:  # API endpoint
                total_calls = self.metrics_storage["api_calls"].get(resource, 0)
            else:  # Generator
                total_calls = self.metrics_storage["generator_usage"].get(resource, 0)
            
            if total_calls > 0:
                error_summary.append({
                    "resource": resource,
                    "error_count": error_count,
                    "total_calls": total_calls,
                    "error_rate": (error_count / total_calls * 100)
                })
        
        # Sort by error count
        error_summary.sort(key=lambda x: x["error_count"], reverse=True)
        
        return {
            "total_errors": sum(self.metrics_storage["error_counts"].values()),
            "resources_with_errors": len(self.metrics_storage["error_counts"]),
            "top_errors": error_summary[:10]
        }
    
    async def get_user_metrics(self, user_id: Optional[str] = None) -> Dict[str, Any]:
        """Get user activity metrics"""
        if user_id:
            user_data = self.metrics_storage["user_activity"].get(user_id, {})
            return {
                "user_id": user_id,
                "total_generators_used": user_data.get("generators", 0),
                "total_api_calls": user_data.get("api_calls", 0),
                "total_scenarios_run": user_data.get("scenarios", 0),
                "total_exports": user_data.get("exports", 0)
            }
        
        # Get top users
        user_summary = []
        for uid, activities in self.metrics_storage["user_activity"].items():
            total_activity = sum(activities.values())
            user_summary.append({
                "user_id": uid,
                "total_activity": total_activity,
                "generators_used": activities.get("generators", 0),
                "api_calls": activities.get("api_calls", 0)
            })
        
        user_summary.sort(key=lambda x: x["total_activity"], reverse=True)
        
        return {
            "total_users": len(self.metrics_storage["user_activity"]),
            "top_users": user_summary[:10]
        }
    
    async def get_scenario_metrics(self) -> Dict[str, Any]:
        """Get scenario execution metrics"""
        scenario_summary = []
        
        for scenario_id, count in self.metrics_storage["scenario_executions"].items():
            scenario_summary.append({
                "scenario_id": scenario_id,
                "execution_count": count
            })
        
        scenario_summary.sort(key=lambda x: x["execution_count"], reverse=True)
        
        return {
            "total_scenarios_run": sum(self.metrics_storage["scenario_executions"].values()),
            "unique_scenarios": len(self.metrics_storage["scenario_executions"]),
            "top_scenarios": scenario_summary[:10]
        }
    
    async def get_export_metrics(self) -> Dict[str, Any]:
        """Get export format usage metrics"""
        format_summary = []
        
        for format_type, count in self.metrics_storage["export_formats"].items():
            format_summary.append({
                "format": format_type,
                "usage_count": count
            })
        
        format_summary.sort(key=lambda x: x["usage_count"], reverse=True)
        
        return {
            "total_exports": sum(self.metrics_storage["export_formats"].values()),
            "format_usage": format_summary
        }
    
    async def get_time_series_metrics(
        self,
        metric_type: str = "events",
        interval: str = "hour",
        duration: str = "24h"
    ) -> List[Dict[str, Any]]:
        """Get time series metrics data"""
        # In production, this would query from time-series database
        # For now, return sample data
        now = datetime.utcnow()
        data_points = []
        
        if interval == "hour":
            points = 24
            delta = timedelta(hours=1)
        elif interval == "minute":
            points = 60
            delta = timedelta(minutes=1)
        else:  # day
            points = 7
            delta = timedelta(days=1)
        
        for i in range(points):
            timestamp = now - (delta * i)
            value = 100 + (i * 10) % 50  # Sample data
            
            data_points.append({
                "timestamp": timestamp.isoformat(),
                "value": value,
                "metric": metric_type
            })
        
        return list(reversed(data_points))
    
    async def _calculate_performance_metrics(self) -> Dict[str, Any]:
        """Calculate overall performance metrics"""
        all_response_times = []
        for times in self.metrics_storage["response_times"].values():
            all_response_times.extend(times)
        
        if not all_response_times:
            return {
                "avg_response_ms": 0,
                "min_response_ms": 0,
                "max_response_ms": 0,
                "p50_response_ms": 0,
                "p95_response_ms": 0,
                "p99_response_ms": 0
            }
        
        return {
            "avg_response_ms": statistics.mean(all_response_times),
            "min_response_ms": min(all_response_times),
            "max_response_ms": max(all_response_times),
            "p50_response_ms": self._calculate_percentile(all_response_times, 50),
            "p95_response_ms": self._calculate_percentile(all_response_times, 95),
            "p99_response_ms": self._calculate_percentile(all_response_times, 99)
        }
    
    def _calculate_percentile(self, data: List[float], percentile: int) -> float:
        """Calculate percentile value"""
        if not data:
            return 0
        
        sorted_data = sorted(data)
        index = int(len(sorted_data) * (percentile / 100))
        
        if index >= len(sorted_data):
            return sorted_data[-1]
        
        return sorted_data[index]
    
    async def get_health_status(self) -> Dict[str, Any]:
        """Get system health status"""
        total_errors = sum(self.metrics_storage["error_counts"].values())
        total_calls = sum(self.metrics_storage["api_calls"].values())
        error_rate = (total_errors / total_calls * 100) if total_calls > 0 else 0
        
        # Determine health status
        if error_rate < 1:
            status = "healthy"
            status_code = "green"
        elif error_rate < 5:
            status = "degraded"
            status_code = "yellow"
        else:
            status = "unhealthy"
            status_code = "red"
        
        performance = await self._calculate_performance_metrics()
        
        return {
            "status": status,
            "status_code": status_code,
            "checks": {
                "api_availability": True,
                "error_rate": error_rate,
                "avg_response_time": performance.get("avg_response_ms", 0),
                "uptime_seconds": (datetime.utcnow() - self.start_time).total_seconds()
            },
            "timestamp": datetime.utcnow().isoformat()
        }
    
    async def get_base_metrics(self) -> Dict[str, Any]:
        """Get base API metrics"""
        uptime_seconds = (datetime.utcnow() - self.start_time).total_seconds()
        
        # Basic counts
        total_generators = len(self.metrics_storage["generator_usage"])
        total_api_calls = sum(self.metrics_storage["api_calls"].values())
        total_events = sum(self.metrics_storage["event_counts"].values())
        total_errors = sum(self.metrics_storage["error_counts"].values())
        
        # Calculate error rate
        error_rate = (total_errors / max(total_api_calls, 1)) * 100
        
        # Calculate average response time
        all_response_times = []
        for times in self.metrics_storage["response_times"].values():
            all_response_times.extend(times)
        
        avg_response_time = statistics.mean(all_response_times) if all_response_times else 0
        
        return {
            "uptime_seconds": uptime_seconds,
            "uptime_human": self._format_uptime(uptime_seconds),
            "total_generators": total_generators,
            "total_api_calls": total_api_calls, 
            "total_events_generated": total_events,
            "total_errors": total_errors,
            "error_rate_percent": round(error_rate, 2),
            "avg_response_time_ms": round(avg_response_time, 2),
            "status": "healthy" if error_rate < 1 else "degraded" if error_rate < 5 else "unhealthy",
            "timestamp": datetime.utcnow().isoformat()
        }
    
    def _format_uptime(self, seconds: float) -> str:
        """Format uptime in human readable format"""
        if seconds < 60:
            return f"{int(seconds)}s"
        elif seconds < 3600:
            return f"{int(seconds // 60)}m {int(seconds % 60)}s"
        elif seconds < 86400:
            hours = int(seconds // 3600)
            minutes = int((seconds % 3600) // 60)
            return f"{hours}h {minutes}m"
        else:
            days = int(seconds // 86400)
            hours = int((seconds % 86400) // 3600)
            return f"{days}d {hours}h"