#!/usr/bin/env python3
"""
Real Format Validator - Identify True Parser-Generator Mismatches

This tool tests each generator against its parser configuration to identify
REAL format mismatches (not just Star Trek integration issues).
"""

import os
import json
import sys
import re
import importlib.util
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple

project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

class FormatValidator:
    def __init__(self):
        self.project_root = project_root
        self.generators_dir = self.project_root / "event_generators"
        self.parsers_dir = self.project_root / "parsers" / "community"
        
    def detect_actual_generator_format(self, generator_path: Path) -> str:
        """Detect the ACTUAL output format by running the generator"""
        try:
            # Import and run the generator
            spec = importlib.util.spec_from_file_location("test_gen", generator_path)
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            
            # Find the log function
            function_name = f"{generator_path.stem}_log"
            if not hasattr(module, function_name):
                return "UNKNOWN - No log function found"
                
            log_function = getattr(module, function_name)
            
            # Generate sample output
            try:
                sample_output = log_function()
            except Exception as e:
                return f"ERROR - {str(e)}"
                
            # Analyze the actual output
            if isinstance(sample_output, dict):
                return "JSON_DICT"
            elif isinstance(sample_output, str):
                sample_lower = sample_output.lower().strip()
                
                # Check for JSON string
                if sample_output.startswith('{') and sample_output.endswith('}'):
                    try:
                        json.loads(sample_output)
                        return "JSON_STRING"
                    except:
                        pass
                        
                # Check for syslog format
                if re.match(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z.*', sample_output):
                    if 'queryName=' in sample_output or 'Route53' in sample_output:
                        return "SYSLOG_AWS_ROUTE53"
                    return "SYSLOG_GENERIC"
                    
                # Check for key-value pairs
                if '=' in sample_output and not sample_output.startswith('{'):
                    return "KEY_VALUE"
                    
                # Check for CSV
                if ',' in sample_output and not '=' in sample_output:
                    return "CSV"
                    
                return "TEXT_OTHER"
            else:
                return f"UNKNOWN_TYPE - {type(sample_output).__name__}"
                
        except Exception as e:
            return f"ERROR - {str(e)}"
            
    def detect_parser_expected_format(self, parser_config: Dict) -> str:
        """Detect what format the parser expects"""
        try:
            config_str = json.dumps(parser_config, default=str)
            
            # Check for gron (JSON) parsing
            if 'parse=gron' in config_str or '"format":"json"' in config_str:
                return "JSON_EXPECTED"
                
            # Check for specific format patterns
            formats = parser_config.get("formats", [])
            if formats:
                format_str = str(formats[0])
                
                # AWS Route53 specific syslog pattern
                if "Route53 queryName=" in format_str:
                    return "SYSLOG_AWS_ROUTE53_EXPECTED"
                    
                # Generic syslog patterns
                if "$timestamp$" in format_str and "queryName=" in format_str:
                    return "SYSLOG_EXPECTED"
                    
                # CEF format
                if "CEF:" in format_str:
                    return "CEF_EXPECTED"
                    
                # Key-value format
                if "$key{name=" in format_str:
                    return "KEY_VALUE_EXPECTED"
                    
                # CSV format
                if "$csv" in format_str:
                    return "CSV_EXPECTED"
                    
            return "JSON_EXPECTED"  # Default assumption
            
        except Exception as e:
            return f"ERROR - {str(e)}"
            
    def find_parser_for_generator(self, generator_name: str) -> Optional[Path]:
        """Find the parser configuration for a generator"""
        # Try different naming patterns
        possible_names = [
            f"{generator_name}-latest",
            f"{generator_name}_logs-latest", 
            f"{generator_name}_log-latest",
            # Handle special cases
            generator_name.replace("_", "")
        ]
        
        for name in possible_names:
            parser_dir = self.parsers_dir / name
            if parser_dir.exists():
                json_files = list(parser_dir.glob("*.json"))
                if json_files:
                    return json_files[0]
                    
        return None
        
    def validate_generator_parser_pair(self, generator_path: Path) -> Dict:
        """Validate a single generator-parser pair"""
        generator_name = generator_path.stem
        
        result = {
            "generator": generator_name,
            "generator_path": str(generator_path),
            "actual_format": "UNKNOWN",
            "expected_format": "UNKNOWN", 
            "format_match": False,
            "parser_found": False,
            "parser_path": "",
            "issue_type": "",
            "recommendation": ""
        }
        
        # Detect actual generator format
        result["actual_format"] = self.detect_actual_generator_format(generator_path)
        
        # Find parser
        parser_path = self.find_parser_for_generator(generator_name)
        if not parser_path:
            result["issue_type"] = "MISSING_PARSER"
            result["recommendation"] = "Create parser configuration"
            return result
            
        result["parser_found"] = True
        result["parser_path"] = str(parser_path)
        
        # Load parser config
        try:
            with open(parser_path, 'r') as f:
                parser_config = json.load(f)
                
            result["expected_format"] = self.detect_parser_expected_format(parser_config)
            
            # Check for format compatibility
            actual = result["actual_format"]
            expected = result["expected_format"]
            
            # Define compatibility matrix
            compatible_pairs = [
                ("JSON_DICT", "JSON_EXPECTED"),
                ("JSON_STRING", "JSON_EXPECTED"),
                ("SYSLOG_AWS_ROUTE53", "SYSLOG_AWS_ROUTE53_EXPECTED"),
                ("SYSLOG_GENERIC", "SYSLOG_EXPECTED"),
                ("KEY_VALUE", "KEY_VALUE_EXPECTED"),
                ("CSV", "CSV_EXPECTED")
            ]
            
            result["format_match"] = any(
                actual == pair[0] and expected == pair[1] 
                for pair in compatible_pairs
            )
            
            if not result["format_match"]:
                result["issue_type"] = "FORMAT_MISMATCH"
                result["recommendation"] = f"Convert generator from {actual} to match parser expectation {expected}"
            else:
                result["issue_type"] = "OK"
                result["recommendation"] = "Generator and parser formats are compatible"
                
        except Exception as e:
            result["issue_type"] = "PARSER_ERROR"
            result["recommendation"] = f"Fix parser configuration: {str(e)}"
            
        return result
        
    def validate_critical_generators(self) -> List[Dict]:
        """Validate the critical Tier 1 generators"""
        critical_generators = [
            # AWS (Tier 1)
            "aws_route53", "aws_vpc_dns", "aws_cloudtrail", "aws_guardduty", "aws_vpcflowlogs",
            # Microsoft (Tier 1) 
            "microsoft_365_collaboration", "microsoft_365_defender", "microsoft_azure_ad_signin",
            "microsoft_windows_eventlog",
            # Cisco (Tier 1)
            "cisco_duo", "cisco_firewall_threat_defense", "cisco_fmc", "cisco_ise",
            # Other Tier 1
            "crowdstrike_falcon", "sentinelone_endpoint", "okta_authentication", "google_workspace"
        ]
        
        results = []
        
        for gen_name in critical_generators:
            # Find generator file
            generator_path = None
            for category_dir in self.generators_dir.iterdir():
                if category_dir.is_dir() and category_dir.name != "shared":
                    potential_path = category_dir / f"{gen_name}.py"
                    if potential_path.exists():
                        generator_path = potential_path
                        break
                        
            if generator_path:
                result = self.validate_generator_parser_pair(generator_path)
                results.append(result)
            else:
                results.append({
                    "generator": gen_name,
                    "issue_type": "MISSING_GENERATOR",
                    "recommendation": "Create generator file"
                })
                
        return results
        
    def generate_validation_report(self, results: List[Dict]):
        """Generate validation report"""
        print("\n" + "="*80)
        print("🔍 REAL FORMAT VALIDATION REPORT")
        print("="*80)
        
        # Categorize results
        format_mismatches = [r for r in results if r.get("issue_type") == "FORMAT_MISMATCH"]
        working_correctly = [r for r in results if r.get("issue_type") == "OK"] 
        missing_parsers = [r for r in results if r.get("issue_type") == "MISSING_PARSER"]
        errors = [r for r in results if "ERROR" in r.get("actual_format", "")]
        
        print(f"\n📊 SUMMARY:")
        print(f"   • Working correctly: {len(working_correctly)}")
        print(f"   • Real format mismatches: {len(format_mismatches)}")
        print(f"   • Missing parsers: {len(missing_parsers)}")
        print(f"   • Errors: {len(errors)}")
        
        if format_mismatches:
            print(f"\n🚨 REAL FORMAT MISMATCHES ({len(format_mismatches)}):")
            for result in format_mismatches:
                print(f"   • {result['generator']}: {result['actual_format']} → {result['expected_format']}")
                print(f"     Recommendation: {result['recommendation']}")
                
        if working_correctly:
            print(f"\n✅ WORKING CORRECTLY ({len(working_correctly)}):")
            for result in working_correctly[:10]:  # Show first 10
                print(f"   • {result['generator']}: {result['actual_format']} matches {result['expected_format']}")
                
        if errors:
            print(f"\n❌ GENERATOR ERRORS ({len(errors)}):")
            for result in errors:
                print(f"   • {result['generator']}: {result['actual_format']}")

def main():
    """Main validation function"""
    print("🔍 Starting Real Format Validation (Critical Generators)")
    
    validator = FormatValidator()
    results = validator.validate_critical_generators()
    validator.generate_validation_report(results)
    
    # Save results
    output_file = validator.project_root / "scenarios" / "real_format_validation_results.json"
    with open(output_file, 'w') as f:
        json.dump(results, f, indent=2, default=str)
        
    print(f"\n💾 Detailed results saved to: {output_file}")

if __name__ == "__main__":
    main()