#!/usr/bin/env python3
"""
SentinelOne API Client for parser testing and validation
Provides comprehensive SentinelOne API integration for testing parsers
"""
import json
import os
import time
import requests
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Any
from dataclasses import dataclass
from urllib.parse import urljoin

@dataclass
class ParseResult:
    """Parser test result"""
    success: bool
    parser_name: str
    events_sent: int
    events_parsed: int
    parse_errors: List[str]
    field_mappings: Dict[str, Any]
    raw_response: Dict[str, Any]

class SentinelOneAPI:
    """SentinelOne API client for parser testing"""
    
    def __init__(self, base_url: str = None, api_token: str = None, hec_token: str = None):
        """Initialize SentinelOne API client
        
        Args:
            base_url: SentinelOne console URL (e.g., https://example.sentinelone.net)
            api_token: API token for management API
            hec_token: HEC token for event ingestion
        """
        self.base_url = base_url or os.getenv('S1_API_URL', '').rstrip('/')
        self.api_token = api_token or os.getenv('S1_API_TOKEN')
        self.hec_token = hec_token or os.getenv('S1_HEC_TOKEN')
        
        if not self.base_url:
            raise ValueError("SentinelOne base URL required (S1_API_URL env var)")
        if not self.api_token:
            raise ValueError("SentinelOne API token required (S1_API_TOKEN env var)")
        if not self.hec_token:
            raise ValueError("SentinelOne HEC token required (S1_HEC_TOKEN env var)")
            
        self.session = requests.Session()
        self.session.headers.update({
            'Authorization': f'ApiToken {self.api_token}',
            'Content-Type': 'application/json'
        })
        
        # HEC endpoint
        self.hec_url = urljoin(self.base_url, '/hec/event')
        
    def _make_request(self, method: str, endpoint: str, **kwargs) -> Dict[str, Any]:
        """Make authenticated API request"""
        url = urljoin(self.base_url, endpoint)
        
        try:
            response = self.session.request(method, url, **kwargs)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            raise Exception(f"API request failed: {e}")
    
    def get_parser_status(self, parser_name: str) -> Dict[str, Any]:
        """Get parser configuration and status"""
        return self._make_request('GET', f'/web/api/v2.1/parsers/{parser_name}')
    
    def list_parsers(self) -> List[Dict[str, Any]]:
        """List all available parsers"""
        response = self._make_request('GET', '/web/api/v2.1/parsers')
        return response.get('data', [])
    
    def upload_parser(self, parser_name: str, parser_config: Dict[str, Any]) -> Dict[str, Any]:
        """Upload/update parser configuration"""
        return self._make_request('POST', f'/web/api/v2.1/parsers/{parser_name}', 
                                json=parser_config)
    
    def send_test_events(self, events: List[Dict[str, Any]], 
                        source_type: str = None) -> Dict[str, Any]:
        """Send test events via HEC"""
        hec_session = requests.Session()
        hec_session.headers.update({
            'Authorization': f'Splunk {self.hec_token}',
            'Content-Type': 'application/json'
        })
        
        results = []
        for event in events:
            hec_event = {
                'event': event,
                'time': int(time.time()),
                'source': source_type or 'api_test',
                'sourcetype': source_type or 'json'
            }
            
            try:
                response = hec_session.post(self.hec_url, json=hec_event)
                response.raise_for_status()
                results.append({
                    'success': True,
                    'response': response.json()
                })
            except requests.exceptions.RequestException as e:
                results.append({
                    'success': False,
                    'error': str(e)
                })
        
        return {
            'events_sent': len(events),
            'results': results,
            'success_count': sum(1 for r in results if r['success'])
        }
    
    def query_events(self, query: str, 
                    from_time: datetime = None,
                    to_time: datetime = None,
                    limit: int = 100) -> Dict[str, Any]:
        """Query events using SentinelOne query language"""
        if not from_time:
            from_time = datetime.now(timezone.utc) - timedelta(hours=1)
        if not to_time:
            to_time = datetime.now(timezone.utc)
            
        params = {
            'query': query,
            'fromDate': from_time.isoformat(),
            'toDate': to_time.isoformat(),
            'limit': limit
        }
        
        return self._make_request('GET', '/web/api/v2.1/dv/events', params=params)
    
    def test_parser(self, parser_name: str, 
                   test_events: List[Dict[str, Any]], 
                   wait_time: int = 30) -> ParseResult:
        """Test a parser with sample events
        
        Args:
            parser_name: Name of the parser to test
            test_events: List of test events to send
            wait_time: Seconds to wait before querying results
            
        Returns:
            ParseResult with test results
        """
        print(f"Testing parser: {parser_name}")
        print(f"Sending {len(test_events)} test events...")
        
        # Send test events
        send_result = self.send_test_events(test_events, source_type=parser_name)
        
        if send_result['success_count'] == 0:
            return ParseResult(
                success=False,
                parser_name=parser_name,
                events_sent=len(test_events),
                events_parsed=0,
                parse_errors=["Failed to send any events"],
                field_mappings={},
                raw_response=send_result
            )
        
        print(f"Successfully sent {send_result['success_count']}/{len(test_events)} events")
        print(f"Waiting {wait_time} seconds for processing...")
        time.sleep(wait_time)
        
        # Query for parsed events
        query = f'dataSource.name = "{parser_name}" OR source = "{parser_name}"'
        query_result = self.query_events(query, 
                                       from_time=datetime.now(timezone.utc) - timedelta(minutes=10))
        
        events_found = len(query_result.get('data', []))
        
        # Analyze results
        parse_errors = []
        field_mappings = {}
        
        if events_found == 0:
            parse_errors.append("No parsed events found - parser may have failed")
        else:
            # Analyze field mappings
            sample_event = query_result['data'][0] if query_result.get('data') else {}
            field_mappings = self._analyze_field_mappings(sample_event)
            
            # Check for common parsing issues
            if 'unmapped' in sample_event:
                parse_errors.append("Events contain unmapped fields")
            
            if not sample_event.get('class_uid'):
                parse_errors.append("Missing OCSF class_uid - parser may not be OCSF compliant")
        
        return ParseResult(
            success=(events_found > 0 and len(parse_errors) == 0),
            parser_name=parser_name,
            events_sent=len(test_events),
            events_parsed=events_found,
            parse_errors=parse_errors,
            field_mappings=field_mappings,
            raw_response=query_result
        )
    
    def _analyze_field_mappings(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze field mappings in a parsed event"""
        mappings = {}
        
        # OCSF standard fields
        ocsf_fields = ['class_uid', 'class_name', 'category_uid', 'category_name', 
                      'activity_id', 'activity_name', 'type_uid', 'type_name',
                      'severity', 'time', 'uid', 'message']
        
        for field in ocsf_fields:
            if field in event:
                mappings[f'ocsf.{field}'] = event[field]
        
        # Network fields
        network_fields = ['src_endpoint', 'dst_endpoint', 'connection_info', 'traffic']
        for field in network_fields:
            if field in event:
                mappings[f'network.{field}'] = event[field]
        
        # Identity fields
        identity_fields = ['user', 'actor', 'session']
        for field in identity_fields:
            if field in event:
                mappings[f'identity.{field}'] = event[field]
        
        return mappings
    
    def batch_test_parsers(self, parser_tests: Dict[str, List[Dict[str, Any]]], 
                          wait_time: int = 30) -> Dict[str, ParseResult]:
        """Test multiple parsers with their respective test events"""
        results = {}
        
        for parser_name, test_events in parser_tests.items():
            try:
                result = self.test_parser(parser_name, test_events, wait_time)
                results[parser_name] = result
            except Exception as e:
                results[parser_name] = ParseResult(
                    success=False,
                    parser_name=parser_name,
                    events_sent=len(test_events),
                    events_parsed=0,
                    parse_errors=[f"Test failed: {e}"],
                    field_mappings={},
                    raw_response={}
                )
        
        return results
    
    def generate_parser_report(self, results: Dict[str, ParseResult]) -> str:
        """Generate a comprehensive parser test report"""
        report = ["# SentinelOne Parser Test Report", ""]
        report.append(f"Generated: {datetime.now(timezone.utc).isoformat()}")
        report.append(f"Total Parsers Tested: {len(results)}")
        
        successful = sum(1 for r in results.values() if r.success)
        report.append(f"Successful: {successful}/{len(results)}")
        report.append("")
        
        # Summary table
        report.append("## Summary")
        report.append("| Parser | Status | Events Sent | Events Parsed | Errors |")
        report.append("|--------|--------|-------------|---------------|--------|")
        
        for parser_name, result in results.items():
            status = "✅ PASS" if result.success else "❌ FAIL"
            errors = len(result.parse_errors)
            report.append(f"| {parser_name} | {status} | {result.events_sent} | {result.events_parsed} | {errors} |")
        
        report.append("")
        
        # Detailed results
        report.append("## Detailed Results")
        for parser_name, result in results.items():
            report.append(f"\n### {parser_name}")
            report.append(f"- **Status**: {'✅ PASS' if result.success else '❌ FAIL'}")
            report.append(f"- **Events Sent**: {result.events_sent}")
            report.append(f"- **Events Parsed**: {result.events_parsed}")
            
            if result.parse_errors:
                report.append("- **Errors**:")
                for error in result.parse_errors:
                    report.append(f"  - {error}")
            
            if result.field_mappings:
                report.append("- **Field Mappings**:")
                for field, value in result.field_mappings.items():
                    report.append(f"  - `{field}`: `{value}`")
        
        return "\n".join(report)


def main():
    """CLI interface for SentinelOne API testing"""
    import argparse
    
    parser = argparse.ArgumentParser(description='SentinelOne Parser Testing Tool')
    parser.add_argument('--parser', '-p', help='Specific parser to test')
    parser.add_argument('--list-parsers', action='store_true', help='List available parsers')
    parser.add_argument('--test-ping', action='store_true', help='Test all Ping parsers')
    parser.add_argument('--generate-events', '-g', type=int, default=5, help='Number of test events to generate')
    parser.add_argument('--wait-time', '-w', type=int, default=30, help='Wait time for event processing')
    parser.add_argument('--output', '-o', help='Output file for report')
    
    args = parser.parse_args()
    
    try:
        client = SentinelOneAPI()
        
        if args.list_parsers:
            parsers = client.list_parsers()
            print(f"Found {len(parsers)} parsers:")
            for p in parsers[:10]:  # Show first 10
                print(f"  - {p.get('name', 'Unknown')}")
            return
        
        if args.test_ping:
            # Test Ping parsers with generated events
            from pingfederate import pingfederate_log
            from pingone_mfa import pingone_mfa_log  
            from pingprotect import pingprotect_log
            
            ping_tests = {
                'pingfederate': [json.loads(pingfederate_log()) for _ in range(args.generate_events)],
                'pingone_mfa': [pingone_mfa_log() for _ in range(args.generate_events)],
                'pingprotect': [pingprotect_log() for _ in range(args.generate_events)]
            }
            
            results = client.batch_test_parsers(ping_tests, args.wait_time)
            report = client.generate_parser_report(results)
            
            if args.output:
                with open(args.output, 'w') as f:
                    f.write(report)
                print(f"Report saved to {args.output}")
            else:
                print(report)
        
        elif args.parser:
            print(f"Testing single parser: {args.parser}")
            # Implementation for single parser testing
            pass
        
        else:
            print("No action specified. Use --help for options.")
    
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    main()