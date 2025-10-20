"""
SentinelOne SDK Integration Module
Provides authentication, query building, and response handling for SentinelOne API
"""

import requests
import json
import logging
import time
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Union, Any
from urllib.parse import urljoin
import os

class SentinelOneSDKError(Exception):
    """Custom exception for SDK errors"""
    pass

class SentinelOneSDK:
    """
    Comprehensive SentinelOne SDK for event querying and field extraction validation
    """
    
    def __init__(self, 
                 api_url: str = "https://usea1-purple.sentinelone.net",
                 api_token: str = None,
                 timeout: int = 30,
                 retry_attempts: int = 3):
        """
        Initialize SentinelOne SDK
        
        Args:
            api_url: SentinelOne console URL
            api_token: API authentication token
            timeout: Request timeout in seconds
            retry_attempts: Number of retry attempts for failed requests
        """
        self.api_url = api_url.rstrip('/')
        self.api_token = api_token or os.getenv('S1_SDL_API_TOKEN')
        self.timeout = timeout
        self.retry_attempts = retry_attempts
        
        if not self.api_token:
            raise SentinelOneSDKError("API token is required. Set S1_SDL_API_TOKEN environment variable or pass api_token parameter")
        
        self.session = requests.Session()
        self.session.headers.update({
            'Authorization': f'Bearer {self.api_token}',
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        })
        
        # Setup logging
        self.logger = logging.getLogger(__name__)
        self._setup_logging()
        
        # Validate connection
        self._validate_connection()
    
    def _setup_logging(self):
        """Configure logging for SDK"""
        if not self.logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            )
            handler.setFormatter(formatter)
            self.logger.addHandler(handler)
            self.logger.setLevel(logging.INFO)
    
    def _validate_connection(self):
        """Validate API connectivity and authentication"""
        try:
            response = self._make_request('GET', '/web/api/v2.1/system/info')
            self.logger.info("Successfully connected to SentinelOne API")
            return response
        except Exception as e:
            raise SentinelOneSDKError(f"Failed to connect to SentinelOne API: {str(e)}")
    
    def _make_request(self, method: str, endpoint: str, params: Dict = None, data: Dict = None) -> Dict:
        """
        Make HTTP request with retry logic and error handling
        
        Args:
            method: HTTP method (GET, POST, etc.)
            endpoint: API endpoint
            params: Query parameters
            data: Request body data
            
        Returns:
            Response data as dictionary
        """
        url = urljoin(self.api_url, endpoint)
        
        for attempt in range(self.retry_attempts + 1):
            try:
                if method.upper() == 'GET':
                    response = self.session.get(url, params=params, timeout=self.timeout)
                elif method.upper() == 'POST':
                    response = self.session.post(url, params=params, json=data, timeout=self.timeout)
                else:
                    response = self.session.request(method, url, params=params, json=data, timeout=self.timeout)
                
                response.raise_for_status()
                return response.json()
                
            except requests.exceptions.RequestException as e:
                if attempt < self.retry_attempts:
                    self.logger.warning(f"Request failed (attempt {attempt + 1}/{self.retry_attempts + 1}): {str(e)}")
                    time.sleep(2 ** attempt)  # Exponential backoff
                    continue
                else:
                    raise SentinelOneSDKError(f"Request failed after {self.retry_attempts + 1} attempts: {str(e)}")
        
    def query_events(self, 
                    query: str,
                    from_date: datetime = None,
                    to_date: datetime = None,
                    limit: int = 100,
                    offset: int = 0) -> Dict:
        """
        Query events using SDL (SentinelOne Deep Learning) API
        
        Args:
            query: SDL query string
            from_date: Start time for query (defaults to 1 hour ago)
            to_date: End time for query (defaults to now)
            limit: Maximum number of events to return
            offset: Offset for pagination
            
        Returns:
            Query results with events and metadata
        """
        if not from_date:
            from_date = datetime.utcnow() - timedelta(hours=1)
        if not to_date:
            to_date = datetime.utcnow()
        
        params = {
            'query': query,
            'fromDate': from_date.isoformat() + 'Z',
            'toDate': to_date.isoformat() + 'Z',
            'limit': limit,
            'offset': offset
        }
        
        self.logger.info(f"Executing query: {query}")
        self.logger.info(f"Time range: {from_date} to {to_date}")
        
        response = self._make_request('GET', '/web/api/v2.1/dv/events', params=params)
        
        self.logger.info(f"Query returned {len(response.get('data', []))} events")
        return response
    
    def query_events_by_tracking_id(self, tracking_id: str, time_window_minutes: int = 15) -> Dict:
        """
        Query events by tracking ID with time window
        
        Args:
            tracking_id: Unique tracking identifier
            time_window_minutes: Time window to search in minutes
            
        Returns:
            Events matching the tracking ID
        """
        from_date = datetime.utcnow() - timedelta(minutes=time_window_minutes)
        to_date = datetime.utcnow()
        
        query = f'tracking_id = "{tracking_id}"'
        return self.query_events(query, from_date, to_date, limit=1000)
    
    def get_parsed_fields(self, event_id: str) -> Dict:
        """
        Get parsed fields for a specific event
        
        Args:
            event_id: Event identifier
            
        Returns:
            Parsed field data for the event
        """
        response = self._make_request('GET', f'/web/api/v2.1/dv/events/{event_id}/fields')
        return response
    
    def validate_parser_extraction(self, 
                                  generator_name: str,
                                  expected_fields: List[str],
                                  time_window_minutes: int = 10) -> Dict:
        """
        Validate parser field extraction for a specific generator
        
        Args:
            generator_name: Name of the event generator
            expected_fields: List of fields expected to be extracted
            time_window_minutes: Time window to search for events
            
        Returns:
            Validation results with extraction metrics
        """
        from_date = datetime.utcnow() - timedelta(minutes=time_window_minutes)
        
        # Query for events from this generator
        query = f'src.name contains "{generator_name}" OR event_source = "{generator_name}"'
        results = self.query_events(query, from_date, limit=50)
        
        if not results.get('data'):
            return {
                'generator': generator_name,
                'status': 'no_events',
                'events_found': 0,
                'field_extraction': {}
            }
        
        # Analyze field extraction across events
        extraction_analysis = {
            'total_events': len(results['data']),
            'fields_found': set(),
            'field_coverage': {},
            'sample_events': []
        }
        
        for event in results['data'][:5]:  # Analyze first 5 events
            event_fields = set(event.keys())
            extraction_analysis['fields_found'].update(event_fields)
            extraction_analysis['sample_events'].append({
                'event_id': event.get('id', 'unknown'),
                'fields_count': len(event_fields),
                'timestamp': event.get('time', 'unknown')
            })
        
        # Calculate field coverage
        for field in expected_fields:
            found_count = sum(1 for event in results['data'] if field in event)
            extraction_analysis['field_coverage'][field] = {
                'found_in_events': found_count,
                'percentage': (found_count / len(results['data'])) * 100
            }
        
        return {
            'generator': generator_name,
            'status': 'analyzed',
            'events_found': len(results['data']),
            'field_extraction': extraction_analysis,
            'expected_fields': expected_fields,
            'extraction_rate': len(extraction_analysis['fields_found']) / len(expected_fields) if expected_fields else 0
        }
    
    def bulk_field_validation(self, generator_configs: List[Dict]) -> List[Dict]:
        """
        Perform bulk field validation for multiple generators
        
        Args:
            generator_configs: List of generator configurations with name and expected fields
            
        Returns:
            List of validation results for each generator
        """
        results = []
        
        for config in generator_configs:
            generator_name = config.get('name')
            expected_fields = config.get('expected_fields', [])
            
            self.logger.info(f"Validating field extraction for {generator_name}")
            
            try:
                validation_result = self.validate_parser_extraction(
                    generator_name, expected_fields
                )
                results.append(validation_result)
                
                # Brief pause between requests
                time.sleep(1)
                
            except Exception as e:
                self.logger.error(f"Error validating {generator_name}: {str(e)}")
                results.append({
                    'generator': generator_name,
                    'status': 'error',
                    'error': str(e),
                    'events_found': 0,
                    'field_extraction': {}
                })
        
        return results
    
    def get_system_info(self) -> Dict:
        """Get SentinelOne system information"""
        return self._make_request('GET', '/web/api/v2.1/system/info')
    
    def get_account_info(self) -> Dict:
        """Get account information"""
        return self._make_request('GET', '/web/api/v2.1/accounts')
    
    def test_connection(self) -> Dict:
        """
        Test API connection and return status
        
        Returns:
            Connection test results
        """
        try:
            system_info = self.get_system_info()
            account_info = self.get_account_info()
            
            return {
                'status': 'connected',
                'system_version': system_info.get('data', {}).get('version', 'unknown'),
                'account_count': len(account_info.get('data', [])),
                'api_url': self.api_url,
                'timestamp': datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            return {
                'status': 'failed',
                'error': str(e),
                'api_url': self.api_url,
                'timestamp': datetime.utcnow().isoformat()
            }