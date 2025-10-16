"""
PowerQuery Builder Module
Creates SDL queries, templates, and query optimization for SentinelOne
"""

from datetime import datetime, timedelta
from typing import Dict, List, Optional, Union, Any
import re
import json

class PowerQueryBuilder:
    """
    Advanced query builder for SentinelOne SDL (SentinelOne Deep Learning) API
    """
    
    def __init__(self):
        """Initialize PowerQuery Builder with templates and optimizations"""
        self.query_templates = self._load_query_templates()
        self.field_mappings = self._load_field_mappings()
        
    def _load_query_templates(self) -> Dict:
        """Load pre-built query templates for common use cases"""
        return {
            'field_extraction_analysis': """
                event_source = "{generator}" 
                | limit {limit} 
                | project time, event_source, *
                | sort by time desc
            """,
            
            'parser_effectiveness': """
                event_source = "{generator}"
                AND time >= "{from_time}"
                | summarize 
                    event_count = count(),
                    unique_fields = dcount(column_names),
                    avg_field_count = avg(array_length(column_names))
                by event_source
            """,
            
            'tracking_id_search': """
                tracking_id = "{tracking_id}"
                OR raw contains "{tracking_id}"
                | project time, tracking_id, event_source, *
                | sort by time desc
            """,
            
            'time_range_analysis': """
                time >= "{from_time}" AND time <= "{to_time}"
                {additional_filters}
                | project time, event_source, src_ip, dst_ip, username, *
                | sort by time desc
            """,
            
            'field_coverage_check': """
                event_source = "{generator}"
                | extend field_count = array_length(column_names)
                | summarize 
                    events = count(),
                    min_fields = min(field_count),
                    max_fields = max(field_count),
                    avg_fields = avg(field_count)
                by event_source
            """,
            
            'ocsf_compliance_check': """
                event_source = "{generator}"
                | extend 
                    has_activity_id = isnotnull(activity_id),
                    has_class_uid = isnotnull(class_uid),
                    has_category_uid = isnotnull(category_uid),
                    has_severity_id = isnotnull(severity_id)
                | summarize 
                    total_events = count(),
                    ocsf_activity_coverage = countif(has_activity_id) * 100.0 / count(),
                    ocsf_class_coverage = countif(has_class_uid) * 100.0 / count(),
                    ocsf_category_coverage = countif(has_category_uid) * 100.0 / count(),
                    ocsf_severity_coverage = countif(has_severity_id) * 100.0 / count()
                by event_source
            """,
            
            'security_observables_extraction': """
                event_source = "{generator}"
                | extend 
                    ip_addresses = extract_all(@"(\d+\.\d+\.\d+\.\d+)", raw),
                    usernames = extract_all(@"user[name]*[:=\s]+([^\s,;]+)", raw),
                    domains = extract_all(@"([a-zA-Z0-9-]+\.[a-zA-Z]{2,})", raw)
                | project time, event_source, ip_addresses, usernames, domains, *
            """,
            
            'generator_parser_alignment': """
                event_source = "{generator}"
                | extend 
                    expected_format = "{expected_format}",
                    actual_format = case(
                        raw startswith "{", "json",
                        raw contains "=", "key_value", 
                        raw contains ",", "csv",
                        "syslog"
                    )
                | summarize 
                    events = count(),
                    format_matches = countif(actual_format == expected_format),
                    format_compliance = (countif(actual_format == expected_format) * 100.0) / count()
                by event_source, expected_format, actual_format
            """
        }
    
    def _load_field_mappings(self) -> Dict:
        """Load common field mappings between generators and parsers"""
        return {
            'common_fields': [
                'time', 'timestamp', 'datetime',
                'src_ip', 'source_ip', 'src.ip',
                'dst_ip', 'dest_ip', 'dst.ip', 
                'username', 'user', 'user.name',
                'event_type', 'event_name', 'activity',
                'severity', 'level', 'priority',
                'message', 'msg', 'description'
            ],
            'ocsf_required_fields': [
                'activity_id', 'class_uid', 'category_uid',
                'severity_id', 'type_uid', 'time'
            ],
            'security_observables': [
                'src_ip', 'dst_ip', 'domain', 'url', 'hash',
                'username', 'email', 'file_path', 'process_name'
            ]
        }
    
    def build_field_extraction_query(self, 
                                   generator_name: str,
                                   time_window_minutes: int = 15,
                                   limit: int = 100) -> str:
        """
        Build query for field extraction analysis
        
        Args:
            generator_name: Name of the event generator
            time_window_minutes: Time window for query
            limit: Maximum number of events
            
        Returns:
            SDL query string
        """
        from_time = (datetime.utcnow() - timedelta(minutes=time_window_minutes)).isoformat() + 'Z'
        
        query = f'''
        event_source = "{generator_name}" 
        AND time >= "{from_time}"
        | limit {limit}
        | project time, event_source, raw, *
        | sort by time desc
        '''
        
        return self._clean_query(query)
    
    def build_parser_effectiveness_query(self, 
                                       generator_name: str,
                                       time_window_hours: int = 1) -> str:
        """
        Build query to measure parser effectiveness
        
        Args:
            generator_name: Name of the event generator
            time_window_hours: Time window in hours
            
        Returns:
            SDL query for parser effectiveness analysis
        """
        from_time = (datetime.utcnow() - timedelta(hours=time_window_hours)).isoformat() + 'Z'
        
        query = self.query_templates['parser_effectiveness'].format(
            generator=generator_name,
            from_time=from_time
        )
        
        return self._clean_query(query)
    
    def build_tracking_id_query(self, tracking_id: str) -> str:
        """
        Build query to find events by tracking ID
        
        Args:
            tracking_id: Unique tracking identifier
            
        Returns:
            SDL query string
        """
        query = self.query_templates['tracking_id_search'].format(
            tracking_id=tracking_id
        )
        
        return self._clean_query(query)
    
    def build_time_range_query(self,
                              from_time: datetime,
                              to_time: datetime,
                              generator_filter: str = "",
                              additional_filters: str = "") -> str:
        """
        Build time-range based query with optional filters
        
        Args:
            from_time: Start time
            to_time: End time
            generator_filter: Optional generator name filter
            additional_filters: Additional SDL filters
            
        Returns:
            SDL query string
        """
        filters = []
        if generator_filter:
            filters.append(f'AND event_source = "{generator_filter}"')
        if additional_filters:
            filters.append(f'AND {additional_filters}')
        
        combined_filters = ' '.join(filters)
        
        query = self.query_templates['time_range_analysis'].format(
            from_time=from_time.isoformat() + 'Z',
            to_time=to_time.isoformat() + 'Z',
            additional_filters=combined_filters
        )
        
        return self._clean_query(query)
    
    def build_ocsf_compliance_query(self, generator_name: str) -> str:
        """
        Build query to check OCSF compliance
        
        Args:
            generator_name: Name of the event generator
            
        Returns:
            SDL query for OCSF compliance analysis
        """
        query = self.query_templates['ocsf_compliance_check'].format(
            generator=generator_name
        )
        
        return self._clean_query(query)
    
    def build_security_observables_query(self, generator_name: str) -> str:
        """
        Build query to extract security observables
        
        Args:
            generator_name: Name of the event generator
            
        Returns:
            SDL query for security observables extraction
        """
        query = self.query_templates['security_observables_extraction'].format(
            generator=generator_name
        )
        
        return self._clean_query(query)
    
    def build_generator_alignment_query(self,
                                      generator_name: str,
                                      expected_format: str) -> str:
        """
        Build query to check generator-parser format alignment
        
        Args:
            generator_name: Name of the event generator
            expected_format: Expected format (json, csv, syslog, key_value)
            
        Returns:
            SDL query for format alignment check
        """
        query = self.query_templates['generator_parser_alignment'].format(
            generator=generator_name,
            expected_format=expected_format
        )
        
        return self._clean_query(query)
    
    def build_bulk_validation_query(self, generator_names: List[str]) -> str:
        """
        Build query for bulk generator validation
        
        Args:
            generator_names: List of generator names
            
        Returns:
            SDL query for bulk analysis
        """
        generator_list = '", "'.join(generator_names)
        
        query = f'''
        event_source in ("{generator_list}")
        | extend field_count = array_length(column_names)
        | summarize 
            events = count(),
            min_fields = min(field_count),
            max_fields = max(field_count),
            avg_fields = avg(field_count),
            latest_event = max(time)
        by event_source
        | sort by avg_fields desc
        '''
        
        return self._clean_query(query)
    
    def build_custom_query(self, 
                          base_filter: str,
                          projections: List[str] = None,
                          aggregations: Dict[str, str] = None,
                          sort_by: str = "time desc",
                          limit: int = 100) -> str:
        """
        Build custom SDL query with flexible parameters
        
        Args:
            base_filter: Base filter conditions
            projections: Fields to project
            aggregations: Aggregation operations
            sort_by: Sort order
            limit: Result limit
            
        Returns:
            Custom SDL query string
        """
        query_parts = [base_filter]
        
        if aggregations:
            # Build summarize clause
            agg_parts = []
            for alias, expression in aggregations.items():
                agg_parts.append(f"{alias} = {expression}")
            query_parts.append(f"| summarize {', '.join(agg_parts)}")
        
        if projections and not aggregations:
            # Only add project if not using summarize
            query_parts.append(f"| project {', '.join(projections)}")
        
        if sort_by:
            query_parts.append(f"| sort by {sort_by}")
        
        if limit and not aggregations:
            query_parts.append(f"| limit {limit}")
        
        return self._clean_query('\n'.join(query_parts))
    
    def optimize_query(self, query: str) -> str:
        """
        Optimize SDL query for better performance
        
        Args:
            query: Original SDL query
            
        Returns:
            Optimized query string
        """
        # Remove excessive whitespace
        query = re.sub(r'\s+', ' ', query.strip())
        
        # Ensure time filters are early in the query
        if 'time >=' in query and not query.strip().startswith('time'):
            # Move time filter to beginning if not already there
            parts = query.split('|')
            base_filter = parts[0].strip()
            
            if 'time >=' in base_filter and not base_filter.startswith('time'):
                # Reorganize filters to put time first
                conditions = [c.strip() for c in base_filter.split('AND')]
                time_conditions = [c for c in conditions if 'time' in c]
                other_conditions = [c for c in conditions if 'time' not in c]
                
                reordered = time_conditions + other_conditions
                base_filter = ' AND '.join(reordered)
                parts[0] = base_filter
                query = ' | '.join(parts)
        
        return query
    
    def validate_query_syntax(self, query: str) -> Dict:
        """
        Validate SDL query syntax
        
        Args:
            query: SDL query to validate
            
        Returns:
            Validation results
        """
        validation_result = {
            'valid': True,
            'errors': [],
            'warnings': [],
            'suggestions': []
        }
        
        # Check for common syntax errors
        if not query.strip():
            validation_result['valid'] = False
            validation_result['errors'].append("Query cannot be empty")
            return validation_result
        
        # Check for balanced parentheses
        if query.count('(') != query.count(')'):
            validation_result['valid'] = False
            validation_result['errors'].append("Unbalanced parentheses in query")
        
        # Check for proper pipe usage
        pipe_parts = query.split('|')
        for i, part in enumerate(pipe_parts):
            part = part.strip()
            if i > 0 and not any(part.startswith(op) for op in ['project', 'where', 'summarize', 'sort', 'limit', 'extend', 'join']):
                validation_result['warnings'].append(f"Unusual operator after pipe: {part[:20]}...")
        
        # Performance suggestions
        if 'time >=' not in query and 'time <=' not in query:
            validation_result['suggestions'].append("Consider adding time filters for better performance")
        
        if 'limit' not in query:
            validation_result['suggestions'].append("Consider adding a limit clause to prevent large result sets")
        
        return validation_result
    
    def _clean_query(self, query: str) -> str:
        """Clean and format SDL query"""
        # Remove extra whitespace and newlines
        lines = [line.strip() for line in query.split('\n') if line.strip()]
        return '\n'.join(lines)
    
    def get_query_templates(self) -> Dict:
        """Get all available query templates"""
        return self.query_templates
    
    def get_field_mappings(self) -> Dict:
        """Get field mapping configurations"""
        return self.field_mappings