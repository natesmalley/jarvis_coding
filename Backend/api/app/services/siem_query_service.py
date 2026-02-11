"""
SIEM Query Service
==================

Service for querying existing data in SentinelOne AI SIEM (Singularity Data Lake)
to support correlation scenarios that need to align timestamps with pre-existing events.

Uses the PowerQuery API: POST /api/powerQuery
"""

import httpx
import logging
from datetime import datetime
from typing import Dict, List, Optional, Any

logger = logging.getLogger(__name__)


class SIEMQueryService:
    """Service for executing PowerQuery queries against SentinelOne Singularity Data Lake"""
    
    def __init__(self):
        self.timeout = 120.0  # Query timeout in seconds (PowerQuery can be slow)
    
    async def execute_query(
        self,
        config_api_url: str,
        config_read_token: str,
        query: str,
        start_time_hours: int = 24,
        end_time_hours: int = 0
    ) -> Dict[str, Any]:
        """
        Execute a PowerQuery against the Singularity Data Lake and return results.
        
        Args:
            config_api_url: Base URL for the Console (e.g., https://xdr.us1.sentinelone.net)
            config_read_token: Log Read Access API key (Bearer token)
            query: PowerQuery string to execute
            start_time_hours: How far back to start searching (default 24h)
            end_time_hours: How far back to stop searching (default 0 = now)
            
        Returns:
            Dict with 'results' list and 'metadata'
        """
        # Clean up the URL
        base_url = config_api_url.rstrip('/')
        
        # PowerQuery API endpoint
        query_url = f"{base_url}/api/powerQuery"
        
        # Use Bearer token format as recommended
        headers = {
            "Authorization": f"Bearer {config_read_token}",
            "Content-Type": "application/json",
            "Accept": "application/json"
        }
        
        # Build startTime and endTime strings (e.g., "24h" and "0h")
        start_time = f"{start_time_hours}h"
        end_time = f"{end_time_hours}h"
        
        payload = {
            "query": query,
            "startTime": start_time,
            "priority": "low"  # Use low priority for generous rate limits
        }
        if end_time_hours > 0:
            payload["endTime"] = end_time
        
        logger.info(f"Executing PowerQuery: {query[:100]}... (startTime: {start_time}, endTime: {end_time})")
        
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.post(
                    query_url,
                    headers=headers,
                    json=payload
                )
                
                if response.status_code == 200:
                    data = response.json()
                    
                    # Check for API-level errors
                    if data.get("status") != "success":
                        error_msg = data.get("message", data.get("error", "Unknown API error"))
                        return {
                            "success": False,
                            "error": f"PowerQuery API error: {error_msg}",
                            "results": []
                        }
                    
                    # Parse PowerQuery response format
                    # Response has: columns (array of {name: ...}), values (array of arrays)
                    columns = [col.get("name") for col in data.get("columns", [])]
                    values = data.get("values", [])
                    
                    # Convert to list of dicts for easier processing
                    results = []
                    for row in values:
                        row_dict = {}
                        for i, col_name in enumerate(columns):
                            if i < len(row):
                                value = row[i]
                                # Handle special values
                                if isinstance(value, dict) and "special" in value:
                                    value = value["special"]
                                row_dict[col_name] = value
                        results.append(row_dict)
                    
                    return {
                        "success": True,
                        "results": results,
                        "metadata": {
                            "total_results": len(results),
                            "matching_events": data.get("matchingEvents", 0),
                            "omitted_events": data.get("omittedEvents", 0),
                            "columns": columns,
                            "query": query,
                            "start_time_hours": start_time_hours,
                            "end_time_hours": end_time_hours
                        }
                    }
                elif response.status_code == 401:
                    return {
                        "success": False,
                        "error": "Authentication failed. Check your Log Read Access API key.",
                        "results": []
                    }
                elif response.status_code == 403:
                    return {
                        "success": False,
                        "error": "Permission denied. Token may lack Log Read Access permissions.",
                        "results": []
                    }
                else:
                    error_text = response.text[:500] if response.text else "Unknown error"
                    # Try to parse JSON error
                    try:
                        error_data = response.json()
                        if "message" in error_data:
                            error_text = error_data["message"]
                        elif "error" in error_data:
                            error_text = error_data["error"]
                    except:
                        pass
                    return {
                        "success": False,
                        "error": f"Query failed with status {response.status_code}: {error_text}",
                        "results": []
                    }
                    
        except httpx.TimeoutException:
            return {
                "success": False,
                "error": f"Query timed out after {self.timeout} seconds. Try a shorter time range or simpler query.",
                "results": []
            }
        except httpx.RequestError as e:
            return {
                "success": False,
                "error": f"Request failed: {str(e)}",
                "results": []
            }
        except Exception as e:
            logger.exception("Unexpected error executing PowerQuery")
            return {
                "success": False,
                "error": f"Unexpected error: {str(e)}",
                "results": []
            }
    
    def parse_timestamp(self, timestamp_str: str) -> Optional[datetime]:
        """
        Parse various timestamp formats from SIEM results.
        
        Handles formats like:
        - ISO 8601: 2026-02-03T09:28:40.100Z
        - Human readable: Feb 3 · 9:28:40.100 am
        - Unix milliseconds: 1770236573000
        """
        if not timestamp_str:
            return None
            
        # Try ISO format first
        try:
            if 'T' in str(timestamp_str):
                return datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
        except (ValueError, TypeError):
            pass
        
        # Try unix timestamp (seconds, milliseconds, microseconds, or nanoseconds)
        try:
            if isinstance(timestamp_str, (int, float)) or str(timestamp_str).isdigit():
                ts = int(timestamp_str)
                if ts > 1e18:  # nanoseconds
                    ts = ts / 1e9
                elif ts > 1e15:  # microseconds
                    ts = ts / 1e6
                elif ts > 1e12:  # milliseconds
                    ts = ts / 1e3
                return datetime.utcfromtimestamp(ts)
        except (ValueError, TypeError, OSError):
            pass
        
        # Try human readable format "Feb 3 · 9:28:40.100 am"
        try:
            import re
            match = re.match(
                r'(\w+)\s+(\d+)\s*·\s*(\d+):(\d+):(\d+)(?:\.(\d+))?\s*(am|pm)?',
                str(timestamp_str),
                re.IGNORECASE
            )
            if match:
                month_str, day, hour, minute, second, ms, ampm = match.groups()
                month_map = {
                    'jan': 1, 'feb': 2, 'mar': 3, 'apr': 4, 'may': 5, 'jun': 6,
                    'jul': 7, 'aug': 8, 'sep': 9, 'oct': 10, 'nov': 11, 'dec': 12
                }
                month = month_map.get(month_str.lower()[:3], 1)
                hour = int(hour)
                if ampm and ampm.lower() == 'pm' and hour < 12:
                    hour += 12
                elif ampm and ampm.lower() == 'am' and hour == 12:
                    hour = 0
                
                # Assume current year
                year = datetime.utcnow().year
                microsecond = int(ms) * 1000 if ms else 0
                
                return datetime(year, month, int(day), hour, int(minute), int(second), microsecond)
        except (ValueError, TypeError):
            pass
        
        return None
    
    def extract_anchors_from_results(
        self,
        results: List[Dict],
        anchor_configs: List[Dict]
    ) -> Dict[str, Dict]:
        """
        Extract time anchors from query results based on anchor configurations.
        
        Args:
            results: List of query result rows
            anchor_configs: List of anchor configuration dicts with:
                - id: Anchor identifier
                - query_match: Dict of field->value to match
                - use_field: Which timestamp field to use
                
        Returns:
            Dict mapping anchor_id to {timestamp, row_data}
        """
        anchors = {}
        
        if results:
            sample_row = results[0]
            logger.info(f"Anchor extraction: {len(results)} result rows, columns: {list(sample_row.keys())}")
            logger.info(f"Anchor extraction: sample row: {sample_row}")
        else:
            logger.warning("Anchor extraction: no results to extract from")
        
        for anchor in anchor_configs:
            anchor_id = anchor["id"]
            query_match = anchor.get("query_match", {})
            use_field = anchor.get("use_field", "oldest_timestamp")
            
            logger.info(f"Anchor '{anchor_id}': looking for query_match={query_match}, use_field='{use_field}'")
            
            for row in results:
                # Check if row matches the query criteria
                match = True
                for key, value in query_match.items():
                    row_value = row.get(key, "")
                    # Case-insensitive partial match
                    if isinstance(value, str):
                        if value.lower() not in str(row_value).lower():
                            match = False
                            break
                    elif row_value != value:
                        match = False
                        break
                
                if match:
                    timestamp_str = row.get(use_field)
                    logger.info(f"Anchor '{anchor_id}': matched row, use_field='{use_field}' -> raw value: {repr(timestamp_str)}")
                    parsed_ts = self.parse_timestamp(timestamp_str)
                    
                    if parsed_ts:
                        anchors[anchor_id] = {
                            "timestamp": parsed_ts.isoformat(),
                            "timestamp_raw": timestamp_str,
                            "matched_row": row
                        }
                        logger.info(f"Anchor '{anchor_id}': resolved to {parsed_ts.isoformat()}")
                        break  # Use first match for this anchor
                    else:
                        logger.warning(f"Anchor '{anchor_id}': matched row but failed to parse timestamp: {repr(timestamp_str)}")
            
            if anchor_id not in anchors:
                logger.warning(f"Anchor '{anchor_id}': no matching row found in {len(results)} results")
        
        return anchors


# Singleton instance
siem_query_service = SIEMQueryService()
