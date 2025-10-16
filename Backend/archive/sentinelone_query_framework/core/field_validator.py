"""
Field Extraction Validation System
Validates parser field extraction effectiveness and generator-parser alignment
"""

import json
import os
import importlib.util
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Union, Any, Tuple
from pathlib import Path
import logging

class FieldExtractionValidator:
    """
    Comprehensive field extraction validation system for SentinelOne parsers
    """
    
    def __init__(self, 
                 generators_path: str = "/Users/nathanial.smalley/projects/jarvis_coding/event_generators",
                 parsers_path: str = "/Users/nathanial.smalley/projects/jarvis_coding/parsers/community"):
        """
        Initialize Field Extraction Validator
        
        Args:
            generators_path: Path to event generators directory
            parsers_path: Path to parsers directory
        """
        self.generators_path = Path(generators_path)
        self.parsers_path = Path(parsers_path)
        
        # Setup logging
        self.logger = logging.getLogger(__name__)
        self._setup_logging()
        
        # Load generator and parser mappings
        self.generator_mappings = self._load_generator_mappings()
        self.parser_mappings = self._load_parser_mappings()
        
    def _setup_logging(self):
        """Configure logging for validator"""
        if not self.logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            )
            handler.setFormatter(formatter)
            self.logger.addHandler(handler)
            self.logger.setLevel(logging.INFO)
    
    def _load_generator_mappings(self) -> Dict:
        """Load generator mappings and metadata"""
        mappings = {}
        
        for category_path in self.generators_path.iterdir():
            if category_path.is_dir() and not category_path.name.startswith('.'):
                category = category_path.name
                mappings[category] = {}
                
                for generator_file in category_path.glob("*.py"):
                    if generator_file.name.startswith('_') or generator_file.name.endswith('_backup'):
                        continue
                        
                    generator_name = generator_file.stem
                    
                    try:
                        # Load generator to analyze its output
                        spec = importlib.util.spec_from_file_location(generator_name, generator_file)
                        module = importlib.util.module_from_spec(spec)
                        spec.loader.exec_module(module)
                        
                        # Find the generator function
                        generator_func = None
                        for attr_name in dir(module):
                            if attr_name.endswith('_log') and callable(getattr(module, attr_name)):
                                generator_func = getattr(module, attr_name)
                                break
                        
                        if generator_func:
                            # Generate sample event to analyze fields
                            try:
                                sample_event = generator_func()
                                mappings[category][generator_name] = {
                                    'function': generator_func.__name__,
                                    'sample_fields': list(sample_event.keys()) if isinstance(sample_event, dict) else [],
                                    'output_format': self._detect_format(sample_event),
                                    'field_count': len(sample_event.keys()) if isinstance(sample_event, dict) else 0
                                }
                            except Exception as e:
                                self.logger.warning(f"Could not generate sample event for {generator_name}: {str(e)}")
                                mappings[category][generator_name] = {
                                    'function': generator_func.__name__,
                                    'sample_fields': [],
                                    'output_format': 'unknown',
                                    'field_count': 0,
                                    'error': str(e)
                                }
                        
                    except Exception as e:
                        self.logger.warning(f"Could not load generator {generator_name}: {str(e)}")
                        
        return mappings
    
    def _load_parser_mappings(self) -> Dict:
        """Load parser configurations and expected fields"""
        mappings = {}
        
        for parser_dir in self.parsers_path.iterdir():
            if parser_dir.is_dir() and parser_dir.name.endswith('-latest'):
                parser_name = parser_dir.name.replace('-latest', '')
                
                # Look for JSON configuration file
                json_files = list(parser_dir.glob("*.json"))
                if json_files:
                    try:
                        with open(json_files[0], 'r') as f:
                            parser_config = json.load(f)
                            
                        mappings[parser_name] = {
                            'config_file': str(json_files[0]),
                            'expected_fields': self._extract_parser_fields(parser_config),
                            'expected_format': self._detect_parser_format(parser_config),
                            'ocsf_compliance': self._check_ocsf_compliance(parser_config)
                        }
                        
                    except Exception as e:
                        self.logger.warning(f"Could not load parser config for {parser_name}: {str(e)}")
                        mappings[parser_name] = {
                            'config_file': str(json_files[0]),
                            'expected_fields': [],
                            'expected_format': 'unknown',
                            'error': str(e)
                        }
        
        return mappings
    
    def _detect_format(self, sample_data: Any) -> str:
        """Detect output format of sample data"""
        if isinstance(sample_data, dict):
            return 'json'
        elif isinstance(sample_data, str):
            if sample_data.startswith('{') and sample_data.endswith('}'):
                return 'json'
            elif '=' in sample_data and any(sep in sample_data for sep in [' ', '\t']):
                return 'key_value'
            elif ',' in sample_data:
                return 'csv'
            else:
                return 'syslog'
        return 'unknown'
    
    def _detect_parser_format(self, parser_config: Dict) -> str:
        """Detect expected input format from parser configuration"""
        # Analyze parser configuration to determine expected format
        if 'input_format' in parser_config:
            return parser_config['input_format']
        
        # Analyze patterns to infer format
        patterns = parser_config.get('patterns', [])
        if patterns:
            first_pattern = str(patterns[0]) if patterns else ""
            if 'json' in first_pattern.lower() or '{' in first_pattern:
                return 'json'
            elif 'csv' in first_pattern.lower() or ',' in first_pattern:
                return 'csv'
            elif '=' in first_pattern:
                return 'key_value'
            else:
                return 'syslog'
        
        return 'unknown'
    
    def _extract_parser_fields(self, parser_config: Dict) -> List[str]:
        """Extract expected fields from parser configuration"""
        fields = set()
        
        # Look for field mappings in various config structures
        if 'fields' in parser_config:
            fields.update(parser_config['fields'].keys())
        
        if 'field_mappings' in parser_config:
            fields.update(parser_config['field_mappings'].keys())
        
        if 'ocsf' in parser_config:
            ocsf_fields = parser_config['ocsf']
            if isinstance(ocsf_fields, dict):
                fields.update(ocsf_fields.keys())
        
        # Extract from patterns if available
        patterns = parser_config.get('patterns', [])
        for pattern in patterns[:3]:  # Check first 3 patterns
            if isinstance(pattern, dict) and 'fields' in pattern:
                fields.update(pattern['fields'].keys())
        
        return sorted(list(fields))
    
    def _check_ocsf_compliance(self, parser_config: Dict) -> Dict:
        """Check OCSF compliance indicators in parser config"""
        ocsf_fields = [
            'activity_id', 'class_uid', 'category_uid', 
            'severity_id', 'type_uid', 'time'
        ]
        
        config_fields = self._extract_parser_fields(parser_config)
        
        compliance = {
            'has_ocsf_section': 'ocsf' in parser_config,
            'ocsf_fields_mapped': sum(1 for field in ocsf_fields if field in config_fields),
            'total_ocsf_fields': len(ocsf_fields),
            'compliance_percentage': 0
        }
        
        if compliance['total_ocsf_fields'] > 0:
            compliance['compliance_percentage'] = (
                compliance['ocsf_fields_mapped'] / compliance['total_ocsf_fields']
            ) * 100
        
        return compliance
    
    def validate_generator_parser_alignment(self, 
                                          generator_name: str,
                                          parser_name: str = None) -> Dict:
        """
        Validate alignment between generator and parser
        
        Args:
            generator_name: Name of the generator
            parser_name: Name of the parser (auto-detected if None)
            
        Returns:
            Alignment validation results
        """
        # Find generator info
        generator_info = None
        generator_category = None
        
        for category, generators in self.generator_mappings.items():
            if generator_name in generators:
                generator_info = generators[generator_name]
                generator_category = category
                break
        
        if not generator_info:
            return {
                'generator': generator_name,
                'status': 'generator_not_found',
                'error': f"Generator {generator_name} not found"
            }
        
        # Auto-detect parser if not specified
        if not parser_name:
            parser_name = self._find_matching_parser(generator_name)
        
        if not parser_name or parser_name not in self.parser_mappings:
            return {
                'generator': generator_name,
                'parser': parser_name,
                'status': 'parser_not_found',
                'generator_info': generator_info
            }
        
        parser_info = self.parser_mappings[parser_name]
        
        # Perform alignment analysis
        alignment_result = {
            'generator': generator_name,
            'parser': parser_name,
            'category': generator_category,
            'status': 'analyzed',
            'generator_info': generator_info,
            'parser_info': parser_info,
            'alignment_analysis': {}
        }
        
        # Format compatibility
        gen_format = generator_info.get('output_format', 'unknown')
        parser_format = parser_info.get('expected_format', 'unknown')
        
        alignment_result['alignment_analysis']['format_compatibility'] = {
            'generator_format': gen_format,
            'parser_format': parser_format,
            'compatible': gen_format == parser_format or parser_format == 'unknown',
            'compatibility_score': 100 if gen_format == parser_format else 0
        }
        
        # Field coverage analysis
        gen_fields = set(generator_info.get('sample_fields', []))
        parser_fields = set(parser_info.get('expected_fields', []))
        
        common_fields = gen_fields.intersection(parser_fields)
        
        alignment_result['alignment_analysis']['field_coverage'] = {
            'generator_fields': len(gen_fields),
            'parser_expected_fields': len(parser_fields),
            'common_fields': len(common_fields),
            'coverage_percentage': (len(common_fields) / len(parser_fields) * 100) if parser_fields else 0,
            'missing_fields': list(parser_fields - gen_fields),
            'extra_fields': list(gen_fields - parser_fields)
        }
        
        # Overall alignment score
        format_score = alignment_result['alignment_analysis']['format_compatibility']['compatibility_score']
        field_score = alignment_result['alignment_analysis']['field_coverage']['coverage_percentage']
        
        alignment_result['alignment_analysis']['overall_score'] = (format_score + field_score) / 2
        
        return alignment_result
    
    def _find_matching_parser(self, generator_name: str) -> Optional[str]:
        """Find matching parser for a generator"""
        # Direct name matching
        for parser_name in self.parser_mappings.keys():
            if generator_name in parser_name or parser_name in generator_name:
                return parser_name
        
        # Vendor-based matching
        generator_parts = generator_name.replace('_', ' ').split()
        for parser_name in self.parser_mappings.keys():
            parser_parts = parser_name.replace('_', ' ').split()
            
            # Check for vendor match
            if len(generator_parts) > 0 and generator_parts[0] in parser_parts:
                return parser_name
        
        return None
    
    def bulk_validate_alignment(self, category: str = None) -> List[Dict]:
        """
        Perform bulk alignment validation
        
        Args:
            category: Optional category filter
            
        Returns:
            List of alignment validation results
        """
        results = []
        
        categories_to_check = [category] if category else self.generator_mappings.keys()
        
        for cat in categories_to_check:
            if cat not in self.generator_mappings:
                continue
                
            for generator_name in self.generator_mappings[cat].keys():
                self.logger.info(f"Validating alignment for {generator_name}")
                
                try:
                    result = self.validate_generator_parser_alignment(generator_name)
                    results.append(result)
                    
                except Exception as e:
                    self.logger.error(f"Error validating {generator_name}: {str(e)}")
                    results.append({
                        'generator': generator_name,
                        'status': 'validation_error',
                        'error': str(e)
                    })
        
        return results
    
    def generate_field_expectations(self, generator_name: str) -> Dict:
        """
        Generate field expectations for a generator based on sample output
        
        Args:
            generator_name: Name of the generator
            
        Returns:
            Field expectations and metadata
        """
        # Find generator
        generator_info = None
        for category, generators in self.generator_mappings.items():
            if generator_name in generators:
                generator_info = generators[generator_name]
                break
        
        if not generator_info:
            return {'error': f"Generator {generator_name} not found"}
        
        # Generate multiple samples for field analysis
        sample_events = []
        field_frequency = {}
        
        try:
            # Load generator module
            generator_path = None
            for category_path in self.generators_path.iterdir():
                if category_path.is_dir():
                    gen_file = category_path / f"{generator_name}.py"
                    if gen_file.exists():
                        generator_path = gen_file
                        break
            
            if not generator_path:
                return {'error': f"Generator file not found for {generator_name}"}
            
            spec = importlib.util.spec_from_file_location(generator_name, generator_path)
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            
            # Find generator function
            generator_func = None
            for attr_name in dir(module):
                if attr_name.endswith('_log') and callable(getattr(module, attr_name)):
                    generator_func = getattr(module, attr_name)
                    break
            
            if not generator_func:
                return {'error': f"No generator function found in {generator_name}"}
            
            # Generate 10 sample events
            for i in range(10):
                try:
                    event = generator_func()
                    if isinstance(event, dict):
                        sample_events.append(event)
                        for field in event.keys():
                            field_frequency[field] = field_frequency.get(field, 0) + 1
                except Exception as e:
                    self.logger.warning(f"Error generating sample {i} for {generator_name}: {str(e)}")
            
            # Analyze field consistency
            total_samples = len(sample_events)
            field_analysis = {}
            
            for field, count in field_frequency.items():
                consistency = (count / total_samples) * 100 if total_samples > 0 else 0
                
                # Analyze field values
                values = [event.get(field) for event in sample_events if field in event]
                field_analysis[field] = {
                    'frequency': count,
                    'consistency_percentage': consistency,
                    'sample_values': values[:3],  # First 3 sample values
                    'data_type': type(values[0]).__name__ if values else 'unknown',
                    'is_consistent': consistency >= 80  # Field appears in 80%+ of events
                }
            
            return {
                'generator': generator_name,
                'samples_generated': total_samples,
                'unique_fields': len(field_frequency),
                'field_analysis': field_analysis,
                'expected_format': generator_info.get('output_format', 'unknown'),
                'recommended_fields': [
                    field for field, analysis in field_analysis.items()
                    if analysis['is_consistent']
                ]
            }
            
        except Exception as e:
            return {
                'generator': generator_name,
                'error': f"Error analyzing generator: {str(e)}"
            }
    
    def get_alignment_summary(self) -> Dict:
        """Get high-level alignment summary"""
        total_generators = sum(len(generators) for generators in self.generator_mappings.values())
        total_parsers = len(self.parser_mappings)
        
        # Quick alignment check
        aligned_count = 0
        for category, generators in self.generator_mappings.items():
            for gen_name in generators.keys():
                if self._find_matching_parser(gen_name):
                    aligned_count += 1
        
        return {
            'total_generators': total_generators,
            'total_parsers': total_parsers,
            'aligned_generators': aligned_count,
            'alignment_percentage': (aligned_count / total_generators * 100) if total_generators > 0 else 0,
            'categories': list(self.generator_mappings.keys()),
            'summary_generated': datetime.utcnow().isoformat()
        }
    
    def get_generator_mappings(self) -> Dict:
        """Get generator mappings"""
        return self.generator_mappings
    
    def get_parser_mappings(self) -> Dict:
        """Get parser mappings"""
        return self.parser_mappings