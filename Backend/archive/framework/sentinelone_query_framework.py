#!/usr/bin/env python3
"""
SentinelOne Comprehensive Query Framework
=========================================

A comprehensive framework that integrates:
1. SentinelOne SDK for direct API queries
2. PowerQuery capabilities for advanced analytics
3. Field extraction validation and comparison
4. Automated testing and batch processing
5. Result analysis and comprehensive reporting

This framework provides enterprise-grade validation of parser effectiveness
by comparing expected vs actual field extraction across 100+ security generators.
"""

import os
import sys
import json
import time
import uuid
import hashlib
import requests
import argparse
import logging
import threading
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Any, Tuple, Union, Callable
from dataclasses import dataclass, asdict, field
from collections import defaultdict, Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urljoin, urlparse
import importlib.util

# Add generator paths
current_dir = os.path.dirname(os.path.abspath(__file__))
generator_root = os.path.join(os.path.dirname(current_dir), 'event_generators')
for category in ['cloud_infrastructure', 'network_security', 'endpoint_security', 
                 'identity_access', 'email_security', 'web_security', 'infrastructure']:
    sys.path.insert(0, os.path.join(generator_root, category))

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

@dataclass
class QueryMetrics:
    """Metrics for SDL query performance"""
    query: str
    execution_time: float
    events_returned: int
    api_calls: int
    success: bool
    error_message: Optional[str] = None

@dataclass
class FieldExtractionAnalysis:
    """Comprehensive field extraction analysis"""
    generator_name: str
    parser_name: str
    events_sent: int
    events_found: int
    events_processed: int
    expected_fields: Dict[str, Any]
    extracted_fields: Dict[str, Any]
    field_mapping: Dict[str, str]
    extraction_rate: float
    precision: float  # How accurate are the extracted values
    recall: float     # How many expected fields were found
    f1_score: float   # Harmonic mean of precision and recall
    ocsf_score: int
    observables_found: List[str]
    missing_critical_fields: List[str]
    format_compatibility_score: float
    parser_effectiveness_grade: str
    recommendations: List[str]
    validation_timestamp: datetime
    query_metrics: List[QueryMetrics] = field(default_factory=list)

@dataclass
class BatchAnalysisResult:
    """Results from batch analysis across multiple generators"""
    total_generators: int
    successful_analyses: int
    total_events_processed: int
    overall_success_rate: float
    average_extraction_rate: float
    average_ocsf_score: float
    category_performance: Dict[str, Dict[str, float]]
    top_performers: List[str]
    improvement_candidates: List[str]
    critical_issues: List[str]
    analysis_duration: timedelta
    individual_results: List[FieldExtractionAnalysis] = field(default_factory=list)

class SentinelOneSDK:
    """Enhanced SentinelOne SDK with comprehensive query capabilities"""
    
    def __init__(self, api_token: str = None, api_url: str = None, timeout: int = 30):
        """Initialize SentinelOne SDK
        
        Args:
            api_token: SDL API token (defaults to S1_SDL_API_TOKEN env var)
            api_url: SDL API URL (defaults to S1_SDL_API_URL env var)
            timeout: Request timeout in seconds
        """
        self.api_token = api_token or os.getenv('S1_SDL_API_TOKEN')
        self.api_url = api_url or os.getenv('S1_SDL_API_URL', 
                                           'https://usea1-purple.sentinelone.net/web/api/v2.1')
        self.query_endpoint = f"{self.api_url.rstrip('/')}/dv/events/search"
        self.timeout = timeout
        
        if not self.api_token:
            raise ValueError("SentinelOne API token required (S1_SDL_API_TOKEN env var)")
        
        self.session = requests.Session()
        self.session.headers.update({
            'Authorization': f'ApiToken {self.api_token}',
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        })
        
        # Query performance tracking
        self.query_count = 0
        self.total_query_time = 0.0
        self.cache = {}
        
        logger.info(f"SentinelOne SDK initialized with endpoint: {self.query_endpoint}")
    
    def execute_query(self, query: str, start_time: datetime = None, 
                     end_time: datetime = None, limit: int = 1000,
                     use_cache: bool = True) -> Tuple[List[Dict[str, Any]], QueryMetrics]:
        """Execute SDL query with enhanced error handling and caching
        
        Args:
            query: SDL query string
            start_time: Query start time
            end_time: Query end time
            limit: Maximum events to return
            use_cache: Whether to use query caching
            
        Returns:
            Tuple of (events_list, query_metrics)
        """
        if not start_time:
            start_time = datetime.now(timezone.utc) - timedelta(hours=4)
        if not end_time:
            end_time = datetime.now(timezone.utc)
        
        # Create cache key
        cache_key = None
        if use_cache:
            cache_data = f"{query}:{start_time.isoformat()}:{end_time.isoformat()}:{limit}"
            cache_key = hashlib.md5(cache_data.encode()).hexdigest()
            
            if cache_key in self.cache:
                logger.debug(f"Using cached result for query: {query[:50]}...")
                cached_events, cached_metrics = self.cache[cache_key]
                return cached_events, cached_metrics
        
        # Prepare query payload
        query_payload = {
            "queryType": "events",
            "query": query,
            "fromDate": start_time.isoformat(),
            "toDate": end_time.isoformat(),
            "limit": limit
        }
        
        start_exec_time = time.time()
        metrics = QueryMetrics(
            query=query,
            execution_time=0.0,
            events_returned=0,
            api_calls=1,
            success=False
        )
        
        try:
            logger.debug(f"Executing SDL query: {query[:100]}...")
            response = self.session.post(
                self.query_endpoint, 
                json=query_payload, 
                timeout=self.timeout
            )
            
            execution_time = time.time() - start_exec_time
            self.query_count += 1
            self.total_query_time += execution_time
            
            if response.status_code == 200:
                result = response.json()
                events = result.get('data', [])
                
                # Process events to standardize format
                processed_events = []
                for event in events:
                    processed_event = {
                        'timestamp': event.get('createdDate'),
                        'message': event.get('data', {}),
                        'raw_data': event.get('data', {}),
                        'event_id': event.get('id'),
                        'source': event.get('source'),
                        'parsed_fields': event.get('data', {})
                    }
                    processed_events.append(processed_event)
                
                metrics.events_returned = len(processed_events)
                metrics.execution_time = execution_time
                metrics.success = True
                
                # Cache successful results
                if use_cache and cache_key:
                    self.cache[cache_key] = (processed_events, metrics)
                
                logger.info(f"SDL query completed: {len(processed_events)} events in {execution_time:.2f}s")
                return processed_events, metrics
                
            else:
                error_msg = f"SDL API error {response.status_code}: {response.text}"
                logger.error(error_msg)
                metrics.error_message = error_msg
                metrics.execution_time = execution_time
                return [], metrics
                
        except Exception as e:
            execution_time = time.time() - start_exec_time
            error_msg = f"SDL query failed: {str(e)}"
            logger.error(error_msg)
            metrics.error_message = error_msg
            metrics.execution_time = execution_time
            return [], metrics
    
    def get_parser_events(self, parser_name: str, hours_back: int = 4,
                         additional_filters: str = "") -> Tuple[List[Dict[str, Any]], List[QueryMetrics]]:
        """Get events processed by a specific parser with multiple query strategies
        
        Args:
            parser_name: Name of the parser
            hours_back: Hours back to search
            additional_filters: Additional filter conditions
            
        Returns:
            Tuple of (events_list, metrics_list)
        """
        # Multiple query strategies for finding parser events
        base_filters = [additional_filters] if additional_filters else []
        
        query_strategies = [
            f'sourcetype="{parser_name}"',
            f'source="{parser_name}"',
            f'parser="{parser_name}"',
            f'dataSource.name="{parser_name}"',
            f'* | search parser="{parser_name}"',
            f'* | search source="{parser_name}"',
            f'index=* sourcetype="{parser_name}"'
        ]
        
        all_events = []
        all_metrics = []
        events_found = False
        
        for i, base_query in enumerate(query_strategies):
            # Combine with additional filters if provided
            if base_filters:
                query = f"({base_query}) AND ({' AND '.join(base_filters)})"
            else:
                query = base_query
            
            events, metrics = self.execute_query(
                query=query,
                start_time=datetime.now(timezone.utc) - timedelta(hours=hours_back),
                limit=1000
            )
            
            all_metrics.append(metrics)
            
            if events:
                all_events.extend(events)
                events_found = True
                logger.info(f"Strategy {i+1} successful: {len(events)} events found with query: {query[:100]}...")
                break  # Use first successful strategy
            else:
                logger.debug(f"Strategy {i+1} returned no events: {query[:100]}...")
        
        if not events_found:
            logger.warning(f"No events found for parser {parser_name} using any strategy")
        
        # Remove duplicates
        unique_events = self._deduplicate_events(all_events)
        
        logger.info(f"Parser {parser_name}: {len(unique_events)} unique events found")
        return unique_events, all_metrics
    
    def _deduplicate_events(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Remove duplicate events based on content hash"""
        seen_hashes = set()
        unique_events = []
        
        for event in events:
            # Create hash of event content for deduplication
            event_content = json.dumps(event.get('raw_data', {}), sort_keys=True, default=str)
            event_hash = hashlib.md5(event_content.encode()).hexdigest()
            
            if event_hash not in seen_hashes:
                unique_events.append(event)
                seen_hashes.add(event_hash)
        
        return unique_events
    
    def get_performance_stats(self) -> Dict[str, Any]:
        """Get SDK performance statistics"""
        avg_query_time = self.total_query_time / self.query_count if self.query_count > 0 else 0
        
        return {
            'total_queries': self.query_count,
            'total_query_time': self.total_query_time,
            'average_query_time': avg_query_time,
            'cache_hits': len(self.cache),
            'cache_size_mb': sys.getsizeof(self.cache) / (1024 * 1024)
        }

class PowerQueryBuilder:
    """Advanced PowerQuery builder with specialized templates for field analysis"""
    
    @staticmethod
    def field_extraction_comprehensive(parser_name: str, time_range: str = "4h") -> str:
        """Comprehensive field extraction analysis query"""
        return f"""
        sourcetype="{parser_name}" OR parser="{parser_name}"
        | eval event_size=len(_raw),
               field_count=mvcount(split(_raw, ",")),
               json_fields=if(match(_raw, "^\\s*{{"), mvcount(spath(_raw)), 0),
               kv_fields=if(match(_raw, "\\w+=\\w+"), mvcount(rex(_raw, "(?<kv_field>\\w+)=")), 0),
               syslog_fields=if(match(_raw, "^\\w+\\s+\\d+"), 10, 0)
        | stats 
            count as total_events,
            avg(field_count) as avg_fields_per_event,
            max(field_count) as max_fields_per_event,
            min(field_count) as min_fields_per_event,
            avg(event_size) as avg_event_size,
            dc(_raw) as unique_event_patterns,
            sum(json_fields) as total_json_fields,
            sum(kv_fields) as total_kv_fields,
            sum(syslog_fields) as total_syslog_fields
        | eval format_type=case(
            total_json_fields > total_kv_fields AND total_json_fields > total_syslog_fields, "JSON",
            total_kv_fields > total_json_fields AND total_kv_fields > total_syslog_fields, "Key-Value",
            total_syslog_fields > 0, "Syslog",
            1=1, "Mixed"
        )
        | addtime range={time_range}
        """
    
    @staticmethod
    def ocsf_compliance_detailed(parser_name: str) -> str:
        """Detailed OCSF compliance analysis"""
        return f"""
        sourcetype="{parser_name}" OR parser="{parser_name}"
        | eval 
            has_class_uid=if(isnotnull(class_uid) OR match(_raw, "class_uid"), 1, 0),
            has_activity_id=if(isnotnull(activity_id) OR match(_raw, "activity_id"), 1, 0),
            has_category_uid=if(isnotnull(category_uid) OR match(_raw, "category_uid"), 1, 0),
            has_severity=if(isnotnull(severity) OR match(_raw, "severity"), 1, 0),
            has_time=if(isnotnull(time) OR match(_raw, "\\"time\\""), 1, 0),
            has_metadata=if(isnotnull(metadata) OR match(_raw, "metadata"), 1, 0),
            has_actor=if(isnotnull(actor) OR match(_raw, "actor"), 1, 0),
            has_device=if(isnotnull(device) OR match(_raw, "device"), 1, 0),
            has_src_endpoint=if(isnotnull(src_endpoint) OR match(_raw, "src_endpoint"), 1, 0),
            has_dst_endpoint=if(isnotnull(dst_endpoint) OR match(_raw, "dst_endpoint"), 1, 0)
        | stats 
            count as total_events,
            sum(has_class_uid) as events_with_class_uid,
            sum(has_activity_id) as events_with_activity_id,
            sum(has_category_uid) as events_with_category_uid,
            sum(has_severity) as events_with_severity,
            sum(has_time) as events_with_time,
            sum(has_metadata) as events_with_metadata,
            sum(has_actor) as events_with_actor,
            sum(has_device) as events_with_device,
            sum(has_src_endpoint) as events_with_src_endpoint,
            sum(has_dst_endpoint) as events_with_dst_endpoint
        | eval 
            class_uid_pct=round((events_with_class_uid/total_events)*100, 2),
            activity_id_pct=round((events_with_activity_id/total_events)*100, 2),
            category_uid_pct=round((events_with_category_uid/total_events)*100, 2),
            core_ocsf_compliance=round(((events_with_class_uid+events_with_activity_id+events_with_category_uid)/(total_events*3))*100, 2),
            extended_ocsf_compliance=round(((events_with_class_uid+events_with_activity_id+events_with_category_uid+events_with_severity+events_with_time)/(total_events*5))*100, 2)
        """
    
    @staticmethod
    def observable_extraction_advanced(parser_name: str) -> str:
        """Advanced observable extraction analysis"""
        return f"""
        sourcetype="{parser_name}" OR parser="{parser_name}"
        | rex field=_raw max_match=0 "(?<ip_addresses>(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))"
        | rex field=_raw max_match=0 "(?<domains>[a-zA-Z0-9]([a-zA-Z0-9\\-]{{0,61}}[a-zA-Z0-9])?\\.([a-zA-Z]{{2,}}|xn--[a-zA-Z0-9]+))"
        | rex field=_raw max_match=0 "(?<email_addresses>[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{{2,}})"
        | rex field=_raw max_match=0 "(?<file_hashes>\\b[a-fA-F0-9]{{32,64}}\\b)"
        | rex field=_raw max_match=0 "(?<urls>https?://[^\\s<>\\[\\]{{}}\\|\\\\^`]+)"
        | rex field=_raw max_match=0 "(?<mac_addresses>(?:[0-9A-Fa-f]{{2}}[:-]){{5}}[0-9A-Fa-f]{{2}})"
        | eval 
            ip_count=if(isnull(ip_addresses), 0, mvcount(ip_addresses)),
            domain_count=if(isnull(domains), 0, mvcount(domains)),
            email_count=if(isnull(email_addresses), 0, mvcount(email_addresses)),
            hash_count=if(isnull(file_hashes), 0, mvcount(file_hashes)),
            url_count=if(isnull(urls), 0, mvcount(urls)),
            mac_count=if(isnull(mac_addresses), 0, mvcount(mac_addresses)),
            total_observables=ip_count+domain_count+email_count+hash_count+url_count+mac_count
        | stats 
            count as total_events,
            sum(ip_count) as total_ip_addresses,
            sum(domain_count) as total_domains,
            sum(email_count) as total_emails,
            sum(hash_count) as total_hashes,
            sum(url_count) as total_urls,
            sum(mac_count) as total_macs,
            sum(total_observables) as total_observables_extracted,
            avg(total_observables) as avg_observables_per_event,
            dc(ip_addresses) as unique_ip_addresses,
            dc(domains) as unique_domains,
            dc(file_hashes) as unique_hashes,
            count(eval(if(total_observables>0, 1, null()))) as events_with_observables
        | eval 
            observable_extraction_rate=round((events_with_observables/total_events)*100, 2),
            ip_extraction_efficiency=if(total_ip_addresses>0, round((unique_ip_addresses/total_ip_addresses)*100, 2), 0),
            domain_extraction_efficiency=if(total_domains>0, round((unique_domains/total_domains)*100, 2), 0)
        """
    
    @staticmethod
    def parser_performance_benchmark(parser_name: str) -> str:
        """Parser performance benchmarking query"""
        return f"""
        sourcetype="{parser_name}" OR parser="{parser_name}"
        | eval 
            parse_success=case(
                isnotnull(class_uid), "full_parse",
                mvcount(spath(_raw)) > 5, "partial_parse", 
                len(_raw) > 100, "raw_only",
                1=1, "parse_failed"
            ),
            event_complexity=case(
                len(_raw) > 2000, "high",
                len(_raw) > 500, "medium",
                1=1, "low"
            )
        | stats 
            count as total_events,
            count(eval(if(parse_success="full_parse", 1, null()))) as fully_parsed,
            count(eval(if(parse_success="partial_parse", 1, null()))) as partially_parsed,
            count(eval(if(parse_success="raw_only", 1, null()))) as raw_only,
            count(eval(if(parse_success="parse_failed", 1, null()))) as parse_failed,
            avg(len(_raw)) as avg_event_size,
            count(eval(if(event_complexity="high", 1, null()))) as high_complexity_events,
            count(eval(if(event_complexity="medium", 1, null()))) as medium_complexity_events,
            count(eval(if(event_complexity="low", 1, null()))) as low_complexity_events
        by parse_success, event_complexity
        | eval 
            parse_success_rate=round((fully_parsed/(fully_parsed+partially_parsed+raw_only+parse_failed))*100, 2),
            complexity_distribution=round((eval(count)/total_events)*100, 2)
        """
    
    @staticmethod
    def field_mapping_analysis(parser_name: str, expected_fields: List[str]) -> str:
        """Analyze field mapping effectiveness for specific expected fields"""
        field_checks = []
        for field_name in expected_fields[:20]:  # Limit to first 20 fields
            field_checks.append(f'has_{field_name}=if(isnotnull({field_name}) OR match(_raw, "{field_name}"), 1, 0)')
        
        field_checks_str = ",\n            ".join(field_checks)
        field_sums = []
        for field_name in expected_fields[:20]:
            field_sums.append(f'sum(has_{field_name}) as found_{field_name}')
        
        field_sums_str = ",\n            ".join(field_sums)
        
        return f"""
        sourcetype="{parser_name}" OR parser="{parser_name}"
        | eval 
            {field_checks_str}
        | stats 
            count as total_events,
            {field_sums_str}
        | eval field_mapping_effectiveness=round(({" + ".join([f"found_{field}" for field in expected_fields[:20]])})/(total_events*{len(expected_fields[:20])})*100, 2)
        """
    
    @staticmethod
    def time_series_extraction_trends(parser_name: str, time_bucket: str = "1h") -> str:
        """Time series analysis of extraction trends"""
        return f"""
        sourcetype="{parser_name}" OR parser="{parser_name}"
        | bin _time span={time_bucket}
        | eval 
            field_count=mvcount(split(_raw, ",")),
            has_ocsf=if(match(_raw, "class_uid|activity_id"), 1, 0),
            event_size=len(_raw)
        | stats 
            count as events_per_interval,
            avg(field_count) as avg_fields_per_interval,
            sum(has_ocsf) as ocsf_events_per_interval,
            avg(event_size) as avg_event_size_per_interval,
            max(field_count) as max_fields_per_interval
        by _time
        | eval 
            ocsf_percentage=round((ocsf_events_per_interval/events_per_interval)*100, 2),
            field_extraction_trend=case(
                avg_fields_per_interval > 20, "high",
                avg_fields_per_interval > 10, "medium",
                1=1, "low"
            )
        | sort _time
        """

class FieldExtractionValidator:
    """Advanced field extraction validator with ML-like comparison capabilities"""
    
    def __init__(self, sdk: SentinelOneSDK):
        """Initialize validator with SentinelOne SDK"""
        self.sdk = sdk
        self.generator_cache = {}
        self.field_importance_weights = self._load_field_importance_weights()
    
    def _load_field_importance_weights(self) -> Dict[str, float]:
        """Load field importance weights for scoring"""
        return {
            # OCSF Core Fields (highest importance)
            'class_uid': 1.0,
            'activity_id': 1.0,
            'category_uid': 1.0,
            'severity': 0.9,
            'time': 0.9,
            
            # Security-relevant fields (high importance)
            'src_endpoint': 0.8,
            'dst_endpoint': 0.8,
            'actor': 0.8,
            'device': 0.8,
            'user': 0.8,
            
            # Observable fields (medium-high importance)
            'src_ip': 0.7,
            'dst_ip': 0.7,
            'hostname': 0.7,
            'domain': 0.7,
            'url': 0.7,
            'file_hash': 0.7,
            
            # Metadata fields (medium importance)
            'timestamp': 0.6,
            'message': 0.6,
            'event_id': 0.5,
            'source': 0.5,
            
            # Default weight for unlisted fields
            '_default': 0.4
        }
    
    def load_generator_function(self, generator_name: str) -> Optional[Callable]:
        """Dynamically load generator function with enhanced mapping"""
        if generator_name in self.generator_cache:
            return self.generator_cache[generator_name]
        
        # Enhanced generator mapping with category-aware loading
        generator_mappings = {
            # Cloud Infrastructure
            'aws_cloudtrail': ('cloud_infrastructure.aws_cloudtrail', 'cloudtrail_log'),
            'aws_guardduty': ('cloud_infrastructure.aws_guardduty', 'guardduty_log'),
            'aws_vpcflowlogs': ('cloud_infrastructure.aws_vpcflowlogs', 'vpcflowlogs_log'),
            'aws_waf': ('cloud_infrastructure.aws_waf', 'waf_log'),
            'google_workspace': ('cloud_infrastructure.google_workspace', 'workspace_log'),
            
            # Network Security
            'fortinet_fortigate': ('network_security.fortinet_fortigate', 'fortigate_log'),
            'cisco_firewall_threat_defense': ('network_security.cisco_firewall_threat_defense', 'cisco_firewall_threat_defense_log'),
            'paloalto_firewall': ('network_security.paloalto_firewall', 'paloalto_firewall_log'),
            'corelight_conn': ('network_security.corelight_conn', 'corelight_conn_log'),
            'netskope': ('web_security.netskope', 'netskope_log'),
            
            # Endpoint Security
            'sentinelone_endpoint': ('endpoint_security.sentinelone_endpoint', 'sentinelone_endpoint_log'),
            'crowdstrike_falcon': ('endpoint_security.crowdstrike_falcon', 'falcon_log'),
            'microsoft_windows_eventlog': ('endpoint_security.microsoft_windows_eventlog', 'windows_eventlog_log'),
            
            # Identity & Access
            'okta_authentication': ('identity_access.okta_authentication', 'okta_authentication_log'),
            'microsoft_azuread': ('identity_access.microsoft_azuread', 'azuread_log'),
            'cisco_duo': ('network_security.cisco_duo', 'duo_log'),
            
            # Email Security
            'proofpoint': ('email_security.proofpoint', 'proofpoint_log'),
            'mimecast': ('email_security.mimecast', 'mimecast_log'),
        }
        
        if generator_name not in generator_mappings:
            logger.warning(f"Generator {generator_name} not found in enhanced mapping")
            return None
        
        try:
            module_path, function_name = generator_mappings[generator_name]
            module = importlib.import_module(module_path)
            generator_func = getattr(module, function_name)
            
            self.generator_cache[generator_name] = generator_func
            logger.debug(f"Successfully loaded generator: {generator_name}")
            return generator_func
            
        except Exception as e:
            logger.error(f"Failed to load generator {generator_name}: {e}")
            return None
    
    def analyze_expected_fields(self, generator_name: str, sample_count: int = 10) -> Dict[str, Any]:
        """Comprehensive analysis of expected fields from generator"""
        generator_func = self.load_generator_function(generator_name)
        if not generator_func:
            return {}
        
        field_analysis = {
            'field_names': set(),
            'field_types': defaultdict(Counter),
            'field_examples': defaultdict(list),
            'field_frequency': Counter(),
            'sample_events': [],
            'format_type': 'unknown',
            'estimated_complexity': 'low'
        }
        
        for i in range(sample_count):
            try:
                event = generator_func()
                
                # Handle different event formats
                if isinstance(event, str):
                    # Try to parse JSON
                    try:
                        parsed_event = json.loads(event)
                        field_analysis['format_type'] = 'json'
                        event = parsed_event
                    except json.JSONDecodeError:
                        # Handle syslog or key=value formats
                        if '=' in event and not event.strip().startswith('<'):
                            field_analysis['format_type'] = 'key_value'
                            # Parse key=value pairs
                            parsed_event = {}
                            for pair in event.split():
                                if '=' in pair:
                                    key, value = pair.split('=', 1)
                                    parsed_event[key] = value
                            event = parsed_event
                        else:
                            field_analysis['format_type'] = 'syslog'
                            # For syslog, extract basic structure
                            event = {'raw_message': event}
                
                if isinstance(event, dict):
                    field_analysis['sample_events'].append(event)
                    
                    for field_name, field_value in event.items():
                        field_analysis['field_names'].add(field_name)
                        field_analysis['field_frequency'][field_name] += 1
                        
                        # Analyze field types
                        field_type = type(field_value).__name__
                        field_analysis['field_types'][field_name][field_type] += 1
                        
                        # Store field examples (limit to 5 per field)
                        if len(field_analysis['field_examples'][field_name]) < 5:
                            field_analysis['field_examples'][field_name].append(str(field_value)[:100])
                
            except Exception as e:
                logger.warning(f"Error generating sample event {i}: {e}")
                continue
        
        # Determine complexity
        if len(field_analysis['field_names']) > 30:
            field_analysis['estimated_complexity'] = 'high'
        elif len(field_analysis['field_names']) > 15:
            field_analysis['estimated_complexity'] = 'medium'
        
        # Convert sets to lists for JSON serialization
        field_analysis['field_names'] = list(field_analysis['field_names'])
        field_analysis['field_types'] = dict(field_analysis['field_types'])
        field_analysis['field_examples'] = dict(field_analysis['field_examples'])
        field_analysis['field_frequency'] = dict(field_analysis['field_frequency'])
        
        return field_analysis
    
    def analyze_extracted_fields(self, events: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Comprehensive analysis of fields extracted by parser"""
        if not events:
            return {
                'field_names': [],
                'field_frequency': {},
                'field_examples': {},
                'ocsf_analysis': {},
                'observable_analysis': {},
                'quality_metrics': {}
            }
        
        extraction_analysis = {
            'field_names': set(),
            'field_frequency': Counter(),
            'field_examples': defaultdict(list),
            'field_types': defaultdict(Counter),
            'ocsf_analysis': {
                'core_fields_found': [],
                'ocsf_compliance_score': 0,
                'missing_core_fields': []
            },
            'observable_analysis': {
                'observables_found': [],
                'observable_types': Counter(),
                'unique_observables': set()
            },
            'quality_metrics': {
                'avg_fields_per_event': 0,
                'field_consistency': 0,
                'data_completeness': 0
            }
        }
        
        total_field_count = 0
        
        for event in events:
            event_data = event.get('raw_data', {})
            if isinstance(event_data, dict):
                for field_name, field_value in event_data.items():
                    extraction_analysis['field_names'].add(field_name)
                    extraction_analysis['field_frequency'][field_name] += 1
                    total_field_count += 1
                    
                    # Analyze field types
                    field_type = type(field_value).__name__
                    extraction_analysis['field_types'][field_name][field_type] += 1
                    
                    # Store examples
                    if len(extraction_analysis['field_examples'][field_name]) < 3:
                        extraction_analysis['field_examples'][field_name].append(str(field_value)[:100])
                    
                    # OCSF analysis
                    if field_name in ['class_uid', 'activity_id', 'category_uid', 'severity', 'time']:
                        extraction_analysis['ocsf_analysis']['core_fields_found'].append(field_name)
                    
                    # Observable analysis
                    observable_type = self._identify_observable_type(field_name, str(field_value))
                    if observable_type:
                        extraction_analysis['observable_analysis']['observables_found'].append(field_name)
                        extraction_analysis['observable_analysis']['observable_types'][observable_type] += 1
                        extraction_analysis['observable_analysis']['unique_observables'].add(str(field_value))
        
        # Calculate quality metrics
        if events:
            extraction_analysis['quality_metrics']['avg_fields_per_event'] = total_field_count / len(events)
            
            # Field consistency: how often fields appear across events
            max_frequency = max(extraction_analysis['field_frequency'].values()) if extraction_analysis['field_frequency'] else 1
            consistency_scores = [freq / max_frequency for freq in extraction_analysis['field_frequency'].values()]
            extraction_analysis['quality_metrics']['field_consistency'] = sum(consistency_scores) / len(consistency_scores) if consistency_scores else 0
        
        # OCSF compliance score
        core_ocsf_fields = ['class_uid', 'activity_id', 'category_uid']
        found_core_fields = set(extraction_analysis['ocsf_analysis']['core_fields_found'])
        extraction_analysis['ocsf_analysis']['ocsf_compliance_score'] = len(found_core_fields) / len(core_ocsf_fields) * 100
        extraction_analysis['ocsf_analysis']['missing_core_fields'] = list(set(core_ocsf_fields) - found_core_fields)
        
        # Convert sets and counters for JSON serialization
        extraction_analysis['field_names'] = list(extraction_analysis['field_names'])
        extraction_analysis['field_frequency'] = dict(extraction_analysis['field_frequency'])
        extraction_analysis['field_examples'] = dict(extraction_analysis['field_examples'])
        extraction_analysis['field_types'] = dict(extraction_analysis['field_types'])
        extraction_analysis['observable_analysis']['observable_types'] = dict(extraction_analysis['observable_analysis']['observable_types'])
        extraction_analysis['observable_analysis']['unique_observables'] = list(extraction_analysis['observable_analysis']['unique_observables'])
        
        return extraction_analysis
    
    def _identify_observable_type(self, field_name: str, field_value: str) -> Optional[str]:
        """Identify if a field contains an observable and its type"""
        import re
        
        # IP addresses
        if re.match(r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$', field_value):
            return 'ip_address'
        
        # Domain names
        if re.match(r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.([a-zA-Z]{2,}|xn--[a-zA-Z0-9]+)$', field_value):
            return 'domain'
        
        # Email addresses
        if re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', field_value):
            return 'email'
        
        # File hashes
        if re.match(r'^[a-fA-F0-9]{32,64}$', field_value):
            return 'file_hash'
        
        # URLs
        if field_value.startswith(('http://', 'https://')):
            return 'url'
        
        # MAC addresses
        if re.match(r'^(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}$', field_value):
            return 'mac_address'
        
        return None
    
    def compare_field_extractions(self, expected_analysis: Dict[str, Any], 
                                 extracted_analysis: Dict[str, Any]) -> Dict[str, Any]:
        """Compare expected vs extracted fields with advanced metrics"""
        expected_fields = set(expected_analysis.get('field_names', []))
        extracted_fields = set(extracted_analysis.get('field_names', []))
        
        # Basic set operations
        matched_fields = expected_fields & extracted_fields
        missing_fields = expected_fields - extracted_fields
        extra_fields = extracted_fields - expected_fields
        
        # Calculate weighted scores
        weighted_precision = self._calculate_weighted_precision(matched_fields, extracted_fields)
        weighted_recall = self._calculate_weighted_recall(matched_fields, expected_fields)
        
        # Calculate F1 score
        if weighted_precision + weighted_recall > 0:
            f1_score = 2 * (weighted_precision * weighted_recall) / (weighted_precision + weighted_recall)
        else:
            f1_score = 0.0
        
        # Format compatibility analysis
        expected_format = expected_analysis.get('format_type', 'unknown')
        extracted_format = self._infer_extracted_format(extracted_analysis)
        format_compatibility = 1.0 if expected_format == extracted_format else 0.5
        
        comparison_result = {
            'field_matching': {
                'expected_count': len(expected_fields),
                'extracted_count': len(extracted_fields),
                'matched_count': len(matched_fields),
                'missing_count': len(missing_fields),
                'extra_count': len(extra_fields),
                'matched_fields': list(matched_fields),
                'missing_fields': list(missing_fields),
                'extra_fields': list(extra_fields)
            },
            'performance_metrics': {
                'precision': weighted_precision,
                'recall': weighted_recall,
                'f1_score': f1_score,
                'extraction_rate': len(matched_fields) / len(expected_fields) * 100 if expected_fields else 0,
                'format_compatibility_score': format_compatibility
            },
            'ocsf_comparison': {
                'expected_ocsf_support': self._has_ocsf_fields(expected_fields),
                'extracted_ocsf_score': extracted_analysis.get('ocsf_analysis', {}).get('ocsf_compliance_score', 0),
                'ocsf_gap': self._calculate_ocsf_gap(expected_fields, extracted_fields)
            },
            'observable_comparison': {
                'expected_observables': self._count_expected_observables(expected_analysis),
                'extracted_observables': len(extracted_analysis.get('observable_analysis', {}).get('observables_found', [])),
                'observable_extraction_rate': self._calculate_observable_extraction_rate(expected_analysis, extracted_analysis)
            }
        }
        
        return comparison_result
    
    def _calculate_weighted_precision(self, matched_fields: set, extracted_fields: set) -> float:
        """Calculate precision with field importance weighting"""
        if not extracted_fields:
            return 0.0
        
        matched_weight = sum(self.field_importance_weights.get(field, self.field_importance_weights['_default']) 
                           for field in matched_fields)
        total_extracted_weight = sum(self.field_importance_weights.get(field, self.field_importance_weights['_default']) 
                                   for field in extracted_fields)
        
        return matched_weight / total_extracted_weight if total_extracted_weight > 0 else 0.0
    
    def _calculate_weighted_recall(self, matched_fields: set, expected_fields: set) -> float:
        """Calculate recall with field importance weighting"""
        if not expected_fields:
            return 0.0
        
        matched_weight = sum(self.field_importance_weights.get(field, self.field_importance_weights['_default']) 
                           for field in matched_fields)
        total_expected_weight = sum(self.field_importance_weights.get(field, self.field_importance_weights['_default']) 
                                  for field in expected_fields)
        
        return matched_weight / total_expected_weight if total_expected_weight > 0 else 0.0
    
    def _infer_extracted_format(self, extracted_analysis: Dict[str, Any]) -> str:
        """Infer the format type from extracted field analysis"""
        field_names = extracted_analysis.get('field_names', [])
        
        # Check for common JSON indicators
        json_indicators = ['class_uid', 'activity_id', 'metadata', 'actor', 'device']
        if any(field in field_names for field in json_indicators):
            return 'json'
        
        # Check for syslog indicators
        syslog_indicators = ['facility', 'severity', 'hostname', 'program']
        if any(field in field_names for field in syslog_indicators):
            return 'syslog'
        
        # Check for key-value indicators
        if len(field_names) > 5 and all(len(field) < 20 for field in field_names[:10]):
            return 'key_value'
        
        return 'mixed'
    
    def _has_ocsf_fields(self, field_names: set) -> bool:
        """Check if expected fields include OCSF fields"""
        ocsf_indicators = ['class_uid', 'activity_id', 'category_uid', 'time', 'metadata']
        return any(field in field_names for field in ocsf_indicators)
    
    def _calculate_ocsf_gap(self, expected_fields: set, extracted_fields: set) -> List[str]:
        """Calculate missing OCSF fields"""
        ocsf_fields = {'class_uid', 'activity_id', 'category_uid', 'severity', 'time'}
        expected_ocsf = expected_fields & ocsf_fields
        extracted_ocsf = extracted_fields & ocsf_fields
        return list(expected_ocsf - extracted_ocsf)
    
    def _count_expected_observables(self, expected_analysis: Dict[str, Any]) -> int:
        """Count expected observables from field examples"""
        observable_count = 0
        field_examples = expected_analysis.get('field_examples', {})
        
        for field_name, examples in field_examples.items():
            for example in examples:
                if self._identify_observable_type(field_name, str(example)):
                    observable_count += 1
                    break  # Count field once if it has observables
        
        return observable_count
    
    def _calculate_observable_extraction_rate(self, expected_analysis: Dict[str, Any], 
                                            extracted_analysis: Dict[str, Any]) -> float:
        """Calculate observable extraction rate"""
        expected_count = self._count_expected_observables(expected_analysis)
        extracted_count = len(extracted_analysis.get('observable_analysis', {}).get('observables_found', []))
        
        if expected_count == 0:
            return 100.0 if extracted_count == 0 else 0.0
        
        return min(100.0, (extracted_count / expected_count) * 100)

class ComprehensiveQueryFramework:
    """Main framework coordinating all components"""
    
    def __init__(self, api_token: str = None, api_url: str = None):
        """Initialize the comprehensive framework"""
        self.sdk = SentinelOneSDK(api_token, api_url)
        self.validator = FieldExtractionValidator(self.sdk)
        self.query_builder = PowerQueryBuilder()
        
        # Framework state
        self.analysis_session_id = str(uuid.uuid4())
        self.start_time = datetime.now(timezone.utc)
        
        logger.info(f"Comprehensive Query Framework initialized (Session: {self.analysis_session_id[:8]})")
    
    def analyze_single_generator(self, generator_name: str, parser_name: str,
                                hours_back: int = 4) -> FieldExtractionAnalysis:
        """Comprehensive analysis of a single generator-parser pair"""
        logger.info(f"Starting comprehensive analysis: {generator_name} -> {parser_name}")
        
        analysis_start = datetime.now(timezone.utc)
        
        # Step 1: Analyze expected fields from generator
        expected_analysis = self.validator.analyze_expected_fields(generator_name)
        
        # Step 2: Query events from SentinelOne
        events, query_metrics = self.sdk.get_parser_events(parser_name, hours_back)
        
        # Step 3: Analyze extracted fields
        extracted_analysis = self.validator.analyze_extracted_fields(events)
        
        # Step 4: Compare expected vs extracted
        comparison = self.validator.compare_field_extractions(expected_analysis, extracted_analysis)
        
        # Step 5: Calculate comprehensive metrics
        metrics = comparison['performance_metrics']
        ocsf_score = extracted_analysis.get('ocsf_analysis', {}).get('ocsf_compliance_score', 0)
        
        # Step 6: Generate recommendations
        recommendations = self._generate_recommendations(comparison, expected_analysis, extracted_analysis)
        
        # Step 7: Assign performance grade
        grade = self._calculate_performance_grade(metrics, ocsf_score, len(events))
        
        result = FieldExtractionAnalysis(
            generator_name=generator_name,
            parser_name=parser_name,
            events_sent=0,  # Not tracked in this analysis
            events_found=len(events),
            events_processed=len(events),
            expected_fields=expected_analysis,
            extracted_fields=extracted_analysis,
            field_mapping=comparison['field_matching'],
            extraction_rate=metrics['extraction_rate'],
            precision=metrics['precision'],
            recall=metrics['recall'],
            f1_score=metrics['f1_score'],
            ocsf_score=int(ocsf_score),
            observables_found=extracted_analysis.get('observable_analysis', {}).get('observables_found', []),
            missing_critical_fields=comparison['field_matching']['missing_fields'],
            format_compatibility_score=metrics['format_compatibility_score'],
            parser_effectiveness_grade=grade,
            recommendations=recommendations,
            validation_timestamp=analysis_start,
            query_metrics=query_metrics
        )
        
        logger.info(f"Analysis completed: {grade} grade, {metrics['extraction_rate']:.1f}% extraction")
        return result
    
    def batch_analyze_generators(self, generator_parser_map: Dict[str, str],
                               max_workers: int = 5) -> BatchAnalysisResult:
        """Batch analysis of multiple generator-parser pairs with parallel processing"""
        logger.info(f"Starting batch analysis of {len(generator_parser_map)} generators")
        
        batch_start = datetime.now(timezone.utc)
        results = []
        
        # Parallel processing with thread pool
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_generator = {
                executor.submit(self.analyze_single_generator, gen_name, parser_name): gen_name
                for gen_name, parser_name in generator_parser_map.items()
            }
            
            for i, future in enumerate(as_completed(future_to_generator), 1):
                generator_name = future_to_generator[future]
                
                try:
                    result = future.result(timeout=120)  # 2 minute timeout per generator
                    results.append(result)
                    
                    logger.info(f"[{i:3d}/{len(generator_parser_map)}] ✅ {generator_name}: "
                              f"{result.parser_effectiveness_grade} grade")
                    
                except Exception as e:
                    logger.error(f"[{i:3d}/{len(generator_parser_map)}] ❌ {generator_name}: {e}")
                    
                    # Create failed analysis result
                    failed_result = FieldExtractionAnalysis(
                        generator_name=generator_name,
                        parser_name=generator_parser_map.get(generator_name, 'unknown'),
                        events_sent=0,
                        events_found=0,
                        events_processed=0,
                        expected_fields={},
                        extracted_fields={},
                        field_mapping={},
                        extraction_rate=0.0,
                        precision=0.0,
                        recall=0.0,
                        f1_score=0.0,
                        ocsf_score=0,
                        observables_found=[],
                        missing_critical_fields=[],
                        format_compatibility_score=0.0,
                        parser_effectiveness_grade='F',
                        recommendations=[f"Analysis failed: {str(e)}"],
                        validation_timestamp=datetime.now(timezone.utc),
                        query_metrics=[]
                    )
                    results.append(failed_result)
        
        # Calculate batch metrics
        successful_results = [r for r in results if r.parser_effectiveness_grade != 'F']
        total_events = sum(r.events_processed for r in results)
        
        batch_metrics = BatchAnalysisResult(
            total_generators=len(generator_parser_map),
            successful_analyses=len(successful_results),
            total_events_processed=total_events,
            overall_success_rate=len(successful_results) / len(results) * 100,
            average_extraction_rate=sum(r.extraction_rate for r in successful_results) / len(successful_results) if successful_results else 0,
            average_ocsf_score=sum(r.ocsf_score for r in successful_results) / len(successful_results) if successful_results else 0,
            category_performance=self._calculate_category_performance(results),
            top_performers=self._identify_top_performers(results),
            improvement_candidates=self._identify_improvement_candidates(results),
            critical_issues=self._identify_critical_issues(results),
            analysis_duration=datetime.now(timezone.utc) - batch_start,
            individual_results=results
        )
        
        logger.info(f"Batch analysis completed: {batch_metrics.successful_analyses}/{batch_metrics.total_generators} successful")
        return batch_metrics
    
    def _generate_recommendations(self, comparison: Dict[str, Any], 
                                expected_analysis: Dict[str, Any],
                                extracted_analysis: Dict[str, Any]) -> List[str]:
        """Generate actionable recommendations based on analysis"""
        recommendations = []
        
        metrics = comparison['performance_metrics']
        field_matching = comparison['field_matching']
        
        # Low extraction rate
        if metrics['extraction_rate'] < 70:
            recommendations.append(f"Low field extraction rate ({metrics['extraction_rate']:.1f}%). Consider parser configuration review.")
            
            if metrics['format_compatibility_score'] < 0.8:
                recommendations.append("Format mismatch detected. Verify generator output format matches parser expectations.")
        
        # OCSF compliance
        ocsf_score = extracted_analysis.get('ocsf_analysis', {}).get('ocsf_compliance_score', 0)
        if ocsf_score < 60:
            recommendations.append(f"Poor OCSF compliance ({ocsf_score:.1f}%). Add OCSF field mappings to parser.")
        
        # Missing critical fields
        if field_matching['missing_count'] > field_matching['matched_count']:
            recommendations.append("More fields missing than found. Check if parser is correctly configured.")
        
        # Observable extraction
        observable_rate = comparison['observable_comparison']['observable_extraction_rate']
        if observable_rate < 50:
            recommendations.append("Low observable extraction rate. Enhance parser for threat intelligence extraction.")
        
        # Format-specific recommendations
        expected_format = expected_analysis.get('format_type', 'unknown')
        if expected_format == 'json' and metrics['extraction_rate'] < 80:
            recommendations.append("JSON format detected but low extraction. Verify JSON parsing configuration.")
        elif expected_format == 'syslog' and metrics['extraction_rate'] < 60:
            recommendations.append("Syslog format detected. Consider using regex-based parsing patterns.")
        
        return recommendations
    
    def _calculate_performance_grade(self, metrics: Dict[str, Any], ocsf_score: float, event_count: int) -> str:
        """Calculate comprehensive performance grade"""
        if event_count == 0:
            return 'F'
        
        # Weighted scoring
        extraction_weight = 0.4
        ocsf_weight = 0.3
        precision_weight = 0.2
        format_weight = 0.1
        
        weighted_score = (
            metrics['extraction_rate'] * extraction_weight +
            ocsf_score * ocsf_weight +
            metrics['precision'] * 100 * precision_weight +
            metrics['format_compatibility_score'] * 100 * format_weight
        )
        
        if weighted_score >= 90:
            return 'A+'
        elif weighted_score >= 85:
            return 'A'
        elif weighted_score >= 75:
            return 'B+'
        elif weighted_score >= 70:
            return 'B'
        elif weighted_score >= 60:
            return 'C+'
        elif weighted_score >= 50:
            return 'C'
        elif weighted_score >= 40:
            return 'D'
        else:
            return 'F'
    
    def _calculate_category_performance(self, results: List[FieldExtractionAnalysis]) -> Dict[str, Dict[str, float]]:
        """Calculate performance metrics by generator category"""
        categories = {
            'cloud_infrastructure': ['aws_', 'google_', 'azure_'],
            'network_security': ['cisco_', 'fortinet_', 'paloalto_', 'checkpoint_'],
            'endpoint_security': ['sentinelone_', 'crowdstrike_', 'microsoft_windows'],
            'identity_access': ['okta_', 'microsoft_azure', 'ping'],
            'email_security': ['proofpoint', 'mimecast', 'abnormal_'],
            'web_security': ['netskope', 'zscaler_', 'cloudflare_']
        }
        
        category_results = {}
        
        for category, prefixes in categories.items():
            category_analyses = [
                r for r in results 
                if any(r.generator_name.startswith(prefix) for prefix in prefixes)
            ]
            
            if category_analyses:
                successful = [r for r in category_analyses if r.parser_effectiveness_grade != 'F']
                
                category_results[category] = {
                    'total_generators': len(category_analyses),
                    'successful_generators': len(successful),
                    'success_rate': len(successful) / len(category_analyses) * 100,
                    'avg_extraction_rate': sum(r.extraction_rate for r in successful) / len(successful) if successful else 0,
                    'avg_ocsf_score': sum(r.ocsf_score for r in successful) / len(successful) if successful else 0,
                    'avg_events_processed': sum(r.events_processed for r in successful) / len(successful) if successful else 0
                }
        
        return category_results
    
    def _identify_top_performers(self, results: List[FieldExtractionAnalysis]) -> List[str]:
        """Identify top performing generators"""
        successful_results = [r for r in results if r.parser_effectiveness_grade in ['A+', 'A', 'B+']]
        sorted_results = sorted(successful_results, 
                               key=lambda x: (x.extraction_rate, x.ocsf_score, x.f1_score), 
                               reverse=True)
        return [r.generator_name for r in sorted_results[:10]]
    
    def _identify_improvement_candidates(self, results: List[FieldExtractionAnalysis]) -> List[str]:
        """Identify generators that need improvement"""
        candidates = [r for r in results if r.parser_effectiveness_grade in ['C', 'D'] and r.events_found > 0]
        return [r.generator_name for r in candidates]
    
    def _identify_critical_issues(self, results: List[FieldExtractionAnalysis]) -> List[str]:
        """Identify critical issues that need immediate attention"""
        issues = []
        
        no_events = [r for r in results if r.events_found == 0]
        if no_events:
            issues.append(f"{len(no_events)} generators have no events found - check HEC connectivity")
        
        failed_analyses = [r for r in results if r.parser_effectiveness_grade == 'F']
        if len(failed_analyses) > len(results) * 0.2:
            issues.append(f"High failure rate: {len(failed_analyses)}/{len(results)} analyses failed")
        
        low_extraction = [r for r in results if r.extraction_rate < 30 and r.events_found > 0]
        if low_extraction:
            issues.append(f"{len(low_extraction)} generators have very low field extraction (<30%)")
        
        return issues
    
    def generate_comprehensive_report(self, batch_result: BatchAnalysisResult) -> str:
        """Generate comprehensive analysis report"""
        report_lines = [
            "# SentinelOne Comprehensive Query Framework Analysis Report",
            f"Generated: {datetime.now(timezone.utc).isoformat()}",
            f"Session ID: {self.analysis_session_id}",
            f"Analysis Duration: {batch_result.analysis_duration}",
            "",
            "## Executive Summary",
            f"- **Total Generators Analyzed**: {batch_result.total_generators}",
            f"- **Successful Analyses**: {batch_result.successful_analyses}",
            f"- **Overall Success Rate**: {batch_result.overall_success_rate:.1f}%",
            f"- **Events Processed**: {batch_result.total_events_processed:,}",
            f"- **Average Extraction Rate**: {batch_result.average_extraction_rate:.1f}%",
            f"- **Average OCSF Score**: {batch_result.average_ocsf_score:.1f}%",
            "",
            "## Performance by Category",
            ""
        ]
        
        # Category performance table
        if batch_result.category_performance:
            report_lines.extend([
                "| Category | Generators | Success Rate | Avg Extraction | Avg OCSF |",
                "|----------|------------|--------------|----------------|----------|"
            ])
            
            for category, metrics in batch_result.category_performance.items():
                report_lines.append(
                    f"| {category.replace('_', ' ').title():<20s} | "
                    f"{metrics['successful_generators']:^10d} | "
                    f"{metrics['success_rate']:^12.1f}% | "
                    f"{metrics['avg_extraction_rate']:^14.1f}% | "
                    f"{metrics['avg_ocsf_score']:^8.1f}% |"
                )
        
        # Top performers
        if batch_result.top_performers:
            report_lines.extend([
                "",
                "## 🏆 Top Performers",
                ""
            ])
            
            for i, generator in enumerate(batch_result.top_performers, 1):
                result = next((r for r in batch_result.individual_results if r.generator_name == generator), None)
                if result:
                    report_lines.append(
                        f"{i}. **{generator}**: {result.parser_effectiveness_grade} grade, "
                        f"{result.extraction_rate:.1f}% extraction, {result.ocsf_score}% OCSF"
                    )
        
        # Improvement candidates
        if batch_result.improvement_candidates:
            report_lines.extend([
                "",
                "## 🎯 Improvement Candidates",
                ""
            ])
            
            for generator in batch_result.improvement_candidates:
                result = next((r for r in batch_result.individual_results if r.generator_name == generator), None)
                if result:
                    report_lines.append(
                        f"- **{generator}**: {result.parser_effectiveness_grade} grade, "
                        f"{result.extraction_rate:.1f}% extraction - {'; '.join(result.recommendations[:2])}"
                    )
        
        # Critical issues
        if batch_result.critical_issues:
            report_lines.extend([
                "",
                "## ⚠️ Critical Issues",
                ""
            ])
            
            for issue in batch_result.critical_issues:
                report_lines.append(f"- {issue}")
        
        # SDK performance stats
        sdk_stats = self.sdk.get_performance_stats()
        report_lines.extend([
            "",
            "## Framework Performance",
            f"- **Total SDL Queries**: {sdk_stats['total_queries']}",
            f"- **Total Query Time**: {sdk_stats['total_query_time']:.2f}s",
            f"- **Average Query Time**: {sdk_stats['average_query_time']:.2f}s",
            f"- **Cache Utilization**: {sdk_stats['cache_hits']} entries",
            ""
        ])
        
        return "\n".join(report_lines)
    
    def save_results(self, batch_result: BatchAnalysisResult, output_dir: str = ".") -> Dict[str, str]:
        """Save comprehensive results to multiple formats"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        files_created = {}
        
        # JSON results
        json_filename = os.path.join(output_dir, f"comprehensive_analysis_{timestamp}.json")
        with open(json_filename, 'w') as f:
            json.dump(asdict(batch_result), f, indent=2, default=str)
        files_created['json'] = json_filename
        
        # Markdown report
        report = self.generate_comprehensive_report(batch_result)
        md_filename = os.path.join(output_dir, f"comprehensive_report_{timestamp}.md")
        with open(md_filename, 'w') as f:
            f.write(report)
        files_created['report'] = md_filename
        
        # CSV summary for easy analysis
        csv_filename = os.path.join(output_dir, f"generator_summary_{timestamp}.csv")
        with open(csv_filename, 'w') as f:
            f.write("generator_name,parser_name,grade,extraction_rate,ocsf_score,events_found,f1_score\n")
            for result in batch_result.individual_results:
                f.write(f"{result.generator_name},{result.parser_name},{result.parser_effectiveness_grade},"
                       f"{result.extraction_rate:.1f},{result.ocsf_score},{result.events_found},{result.f1_score:.3f}\n")
        files_created['csv'] = csv_filename
        
        logger.info(f"Results saved to: {', '.join(files_created.values())}")
        return files_created

# CLI Interface and Usage Examples
def main():
    """Main CLI interface for the Comprehensive Query Framework"""
    parser = argparse.ArgumentParser(description='SentinelOne Comprehensive Query Framework')
    
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # Single analysis command
    single_parser = subparsers.add_parser('analyze-single', help='Analyze single generator')
    single_parser.add_argument('generator', help='Generator name')
    single_parser.add_argument('parser', help='Parser name')
    single_parser.add_argument('--hours-back', type=int, default=4, help='Hours back to search')
    
    # Batch analysis command
    batch_parser = subparsers.add_parser('analyze-batch', help='Batch analyze generators')
    batch_parser.add_argument('--config-file', help='JSON file with generator-parser mappings')
    batch_parser.add_argument('--max-workers', type=int, default=5, help='Max parallel workers')
    batch_parser.add_argument('--category', choices=['all', 'cloud', 'network', 'endpoint', 'identity', 'email', 'web'],
                             default='all', help='Generator category to analyze')
    
    # PowerQuery generation command
    query_parser = subparsers.add_parser('generate-query', help='Generate PowerQuery templates')
    query_parser.add_argument('parser_name', help='Parser name for query')
    query_parser.add_argument('--query-type', choices=['field-extraction', 'ocsf-compliance', 'observables'],
                             default='field-extraction', help='Type of query to generate')
    
    # Framework testing command
    test_parser = subparsers.add_parser('test-framework', help='Test framework functionality')
    test_parser.add_argument('--quick', action='store_true', help='Quick test with limited generators')
    
    # Common arguments
    for subparser in [single_parser, batch_parser, query_parser, test_parser]:
        subparser.add_argument('--output-dir', default='.', help='Output directory')
        subparser.add_argument('--verbose', '-v', action='store_true', help='Verbose logging')
        subparser.add_argument('--api-token', help='SentinelOne API token (or use S1_SDL_API_TOKEN env var)')
        subparser.add_argument('--api-url', help='SentinelOne API URL (or use S1_SDL_API_URL env var)')
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    try:
        # Initialize framework
        framework = ComprehensiveQueryFramework(args.api_token, args.api_url)
        
        if args.command == 'analyze-single':
            result = framework.analyze_single_generator(args.generator, args.parser, args.hours_back)
            
            # Print summary
            print(f"\n=== Analysis Results for {args.generator} ===")
            print(f"Parser: {args.parser}")
            print(f"Grade: {result.parser_effectiveness_grade}")
            print(f"Extraction Rate: {result.extraction_rate:.1f}%")
            print(f"OCSF Score: {result.ocsf_score}%")
            print(f"Events Found: {result.events_found}")
            print(f"F1 Score: {result.f1_score:.3f}")
            
            if result.recommendations:
                print("\nRecommendations:")
                for rec in result.recommendations:
                    print(f"  • {rec}")
            
            # Save results
            output_file = os.path.join(args.output_dir, f"analysis_{args.generator}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
            with open(output_file, 'w') as f:
                json.dump(asdict(result), f, indent=2, default=str)
            print(f"\nDetailed results saved to: {output_file}")
        
        elif args.command == 'analyze-batch':
            # Load generator mappings
            if args.config_file:
                with open(args.config_file, 'r') as f:
                    generator_parser_map = json.load(f)
            else:
                # Use predefined mappings based on category
                generator_parser_map = get_predefined_mappings(args.category)
            
            print(f"Starting batch analysis of {len(generator_parser_map)} generators...")
            batch_result = framework.batch_analyze_generators(generator_parser_map, args.max_workers)
            
            # Print summary
            print(f"\n=== Batch Analysis Summary ===")
            print(f"Total Generators: {batch_result.total_generators}")
            print(f"Successful Analyses: {batch_result.successful_analyses}")
            print(f"Success Rate: {batch_result.overall_success_rate:.1f}%")
            print(f"Average Extraction Rate: {batch_result.average_extraction_rate:.1f}%")
            print(f"Analysis Duration: {batch_result.analysis_duration}")
            
            # Save results
            files_created = framework.save_results(batch_result, args.output_dir)
            print(f"\nResults saved to:")
            for file_type, filename in files_created.items():
                print(f"  {file_type.upper()}: {filename}")
        
        elif args.command == 'generate-query':
            builder = PowerQueryBuilder()
            
            if args.query_type == 'field-extraction':
                query = builder.field_extraction_comprehensive(args.parser_name)
            elif args.query_type == 'ocsf-compliance':
                query = builder.ocsf_compliance_detailed(args.parser_name)
            elif args.query_type == 'observables':
                query = builder.observable_extraction_advanced(args.parser_name)
            
            print(f"\n=== PowerQuery for {args.parser_name} ({args.query_type}) ===")
            print(query)
            
            # Save query
            query_file = os.path.join(args.output_dir, f"powerquery_{args.parser_name}_{args.query_type}.txt")
            with open(query_file, 'w') as f:
                f.write(query)
            print(f"\nQuery saved to: {query_file}")
        
        elif args.command == 'test-framework':
            test_generators = get_test_generators(args.quick)
            
            print(f"Testing framework with {len(test_generators)} generators...")
            batch_result = framework.batch_analyze_generators(test_generators, 3)
            
            print(f"\n=== Framework Test Results ===")
            print(f"Success Rate: {batch_result.overall_success_rate:.1f}%")
            print(f"SDK Performance: {framework.sdk.get_performance_stats()}")
            
            if batch_result.overall_success_rate > 80:
                print("✅ Framework test PASSED")
            else:
                print("❌ Framework test FAILED")
        
        else:
            parser.print_help()
    
    except Exception as e:
        logger.error(f"Framework execution failed: {e}")
        raise

def get_predefined_mappings(category: str) -> Dict[str, str]:
    """Get predefined generator-parser mappings by category"""
    all_mappings = {
        # Cloud Infrastructure
        'aws_cloudtrail': 'aws_cloudtrail',
        'aws_guardduty': 'aws_guardduty_logs',
        'aws_vpcflowlogs': 'aws_vpcflowlogs',
        'google_workspace': 'google_workspace_logs',
        
        # Network Security
        'fortinet_fortigate': 'fortinet_fortigate',
        'cisco_firewall_threat_defense': 'cisco_firewall_threat_defense',
        'paloalto_firewall': 'paloalto_firewall',
        'netskope': 'netskope_netskope_logs',
        
        # Endpoint Security
        'sentinelone_endpoint': 'sentinelone_endpoint',
        'crowdstrike_falcon': 'crowdstrike_falcon',
        'microsoft_windows_eventlog': 'microsoft_windows_eventlog',
        
        # Identity & Access
        'okta_authentication': 'okta_authentication',
        'microsoft_azuread': 'microsoft_azuread',
        'cisco_duo': 'cisco_duo',
        
        # Email Security
        'proofpoint': 'proofpoint_proofpoint_logs',
        'mimecast': 'mimecast_mimecast_logs',
        
        # Web Security
        'zscaler': 'zscaler',
        'cloudflare_waf': 'cloudflare_waf_logs'
    }
    
    if category == 'all':
        return all_mappings
    
    category_filters = {
        'cloud': ['aws_', 'google_'],
        'network': ['fortinet_', 'cisco_', 'paloalto_', 'netskope'],
        'endpoint': ['sentinelone_', 'crowdstrike_', 'microsoft_windows'],
        'identity': ['okta_', 'microsoft_azure', 'cisco_duo'],
        'email': ['proofpoint', 'mimecast'],
        'web': ['zscaler', 'cloudflare_']
    }
    
    if category in category_filters:
        return {k: v for k, v in all_mappings.items() 
                if any(k.startswith(prefix) for prefix in category_filters[category])}
    
    return all_mappings

def get_test_generators(quick: bool = False) -> Dict[str, str]:
    """Get test generators for framework validation"""
    test_generators = {
        'sentinelone_endpoint': 'sentinelone_endpoint',
        'aws_guardduty': 'aws_guardduty_logs',
        'fortinet_fortigate': 'fortinet_fortigate'
    }
    
    if not quick:
        test_generators.update({
            'okta_authentication': 'okta_authentication',
            'cisco_firewall_threat_defense': 'cisco_firewall_threat_defense',
            'netskope': 'netskope_netskope_logs'
        })
    
    return test_generators

if __name__ == "__main__":
    main()