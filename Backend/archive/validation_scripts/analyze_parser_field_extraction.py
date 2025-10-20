#!/usr/bin/env python3
"""
Comprehensive analysis of parser field extraction capabilities vs generator outputs
"""
import json
import os
import sys
import re
from pathlib import Path
from typing import Dict, List, Any, Tuple
import importlib

# Set HEC token to avoid import errors
os.environ["S1_HEC_TOKEN"] = "1FUC88b9Z4BaHtQxwIXwYGqFPaVQO7jzXDuYxDuMD2q1s57bX4MvgEMxUCLaH7pbO"

class ParserFieldAnalyzer:
    def __init__(self):
        self.parsers_dir = Path("parsers/community")
        self.generators_dir = Path("event_generators")
        self.results = {}
        
    def load_parser_config(self, parser_path: Path) -> Dict:
        """Load and analyze a parser configuration"""
        parser_json = parser_path / f"{parser_path.name.replace('-latest', '')}.json"
        
        if not parser_json.exists():
            # Try alternate naming
            json_files = list(parser_path.glob("*.json"))
            if json_files:
                parser_json = json_files[0]
            else:
                return {"error": "No JSON config found"}
        
        try:
            with open(parser_json, 'r') as f:
                config = json.load(f)
                
            # Extract field information
            result = {
                "path": str(parser_json),
                "parse_method": config.get("parse", "unknown"),
                "expected_format": self._determine_format(config),
                "field_mappings": self._extract_field_mappings(config),
                "field_count": 0,
                "sample_fields": []
            }
            
            # Count and sample fields
            if result["field_mappings"]:
                result["field_count"] = len(result["field_mappings"])
                result["sample_fields"] = list(result["field_mappings"].keys())[:10]
            
            return result
            
        except Exception as e:
            return {"error": f"Failed to parse: {str(e)}"}
    
    def _determine_format(self, config: Dict) -> str:
        """Determine the expected input format for the parser"""
        parse_method = config.get("parse", "")
        
        if parse_method == "json":
            return "json"
        elif parse_method == "csv":
            return "csv"
        elif "logPattern" in config or "tsPattern" in config:
            return "syslog"
        elif parse_method == "gron":
            return "json"
        elif "payloadSelector" in config:
            # Check what the payload selector expects
            selector = config["payloadSelector"]
            if "split" in selector:
                return "delimited"
            else:
                return "structured"
        else:
            return "unknown"
    
    def _extract_field_mappings(self, config: Dict) -> Dict:
        """Extract all field mappings from parser config"""
        mappings = {}
        
        # Direct mappings
        if "mappings" in config:
            for mapping in config["mappings"]:
                if "ocsf" in mapping:
                    ocsf_field = mapping["ocsf"]
                    source = mapping.get("xpath") or mapping.get("jsonPath") or mapping.get("column")
                    if source:
                        mappings[ocsf_field] = source
        
        # Gron-based parsers
        if config.get("parse") == "gron" and "mappings" in config:
            for mapping in config["mappings"]:
                if "ocsf" in mapping and "gron" in mapping:
                    mappings[mapping["ocsf"]] = mapping["gron"]
        
        # CSV parsers
        if config.get("parse") == "csv" and "columns" in config:
            for i, col in enumerate(config["columns"]):
                if col and col != "-":
                    mappings[col] = f"column_{i}"
        
        # Pattern-based extraction
        if "logPattern" in config:
            pattern = config["logPattern"]
            # Extract named groups from regex pattern
            named_groups = re.findall(r'\?P<(\w+)>', pattern)
            for group in named_groups:
                mappings[group] = f"regex_group_{group}"
        
        return mappings
    
    def analyze_generator(self, generator_name: str) -> Dict:
        """Analyze a generator's output"""
        try:
            from event_generators.shared.hec_sender import PROD_MAP
            
            if generator_name not in PROD_MAP:
                return {"error": "Generator not in PROD_MAP"}
            
            mod_name, func_names = PROD_MAP[generator_name]
            
            # Import module
            if mod_name.startswith("event_generators."):
                gen_mod = importlib.import_module(mod_name)
            else:
                gen_mod = importlib.import_module(f"event_generators.{mod_name}")
            
            # Get first function
            func = getattr(gen_mod, func_names[0])
            
            # Generate sample event
            event = func()
            
            # Analyze event
            if isinstance(event, dict):
                return {
                    "format": "dict",
                    "field_count": self._count_fields(event),
                    "sample_fields": list(event.keys())[:10],
                    "sample_size": len(str(event))
                }
            elif isinstance(event, str):
                # Try to detect format
                if event.strip().startswith("{"):
                    try:
                        parsed = json.loads(event)
                        return {
                            "format": "json_string",
                            "field_count": self._count_fields(parsed),
                            "sample_fields": list(parsed.keys())[:10] if isinstance(parsed, dict) else [],
                            "sample_size": len(event)
                        }
                    except:
                        pass
                
                # Check for CSV
                if "\t" in event or "," in event:
                    delimiter = "\t" if "\t" in event else ","
                    fields = event.split(delimiter)
                    return {
                        "format": "csv" if "," in event else "tsv",
                        "field_count": len(fields),
                        "sample_fields": [f"field_{i}" for i in range(min(10, len(fields)))],
                        "sample_size": len(event)
                    }
                
                # Assume syslog/raw
                return {
                    "format": "syslog",
                    "field_count": 1,  # Raw string
                    "potential_fields": self._extract_syslog_fields(event),
                    "sample_size": len(event)
                }
            else:
                return {
                    "format": type(event).__name__,
                    "field_count": 1,
                    "sample_size": len(str(event)) if event else 0
                }
                
        except Exception as e:
            return {"error": str(e)}
    
    def _count_fields(self, obj, depth=0) -> int:
        """Recursively count fields in a nested structure"""
        if depth > 10:
            return 0
            
        count = 0
        if isinstance(obj, dict):
            for key, value in obj.items():
                count += 1
                if isinstance(value, (dict, list)):
                    count += self._count_fields(value, depth + 1) - 1
        elif isinstance(obj, list):
            for item in obj:
                if isinstance(item, (dict, list)):
                    count += self._count_fields(item, depth + 1)
        return count
    
    def _extract_syslog_fields(self, log_line: str) -> List[str]:
        """Extract potential fields from a syslog line"""
        fields = []
        
        # Common syslog patterns
        patterns = [
            r'(\w+)=([^\s]+)',  # key=value pairs
            r'<(\d+)>',  # Priority
            r'\b(?:\d{1,3}\.){3}\d{1,3}\b',  # IP addresses
            r':\d+',  # Ports
            r'\b[A-Z][A-Z0-9_]+\b',  # Constants/IDs
        ]
        
        for pattern in patterns:
            matches = re.findall(pattern, log_line)
            if matches:
                if isinstance(matches[0], tuple):
                    fields.extend([m[0] for m in matches])
                else:
                    fields.append(f"extracted_{pattern[:10]}")
        
        return fields[:20]  # Limit to 20 potential fields
    
    def compare_parser_generator(self, generator_name: str, parser_name: str) -> Dict:
        """Compare a generator's output with parser expectations"""
        # Load parser config
        parser_path = self.parsers_dir / parser_name
        if not parser_path.exists():
            parser_path = self.parsers_dir / f"{parser_name}-latest"
        
        if not parser_path.exists():
            return {"error": f"Parser {parser_name} not found"}
        
        parser_info = self.load_parser_config(parser_path)
        
        # Analyze generator
        generator_info = self.analyze_generator(generator_name)
        
        # Compare
        result = {
            "generator": generator_name,
            "parser": parser_name,
            "generator_format": generator_info.get("format", "unknown"),
            "parser_expects": parser_info.get("expected_format", "unknown"),
            "format_match": False,
            "generator_fields": generator_info.get("field_count", 0),
            "parser_can_extract": parser_info.get("field_count", 0),
            "extraction_potential": 0
        }
        
        # Check format compatibility
        gen_fmt = result["generator_format"]
        parse_fmt = result["parser_expects"]
        
        if gen_fmt == parse_fmt:
            result["format_match"] = True
        elif (gen_fmt == "dict" and parse_fmt == "json") or \
             (gen_fmt == "json_string" and parse_fmt == "json"):
            result["format_match"] = True
        elif gen_fmt == "syslog" and parse_fmt == "syslog":
            result["format_match"] = True
            # For syslog, parser can extract many fields from raw string
            if generator_info.get("potential_fields"):
                result["generator_fields"] = len(generator_info["potential_fields"])
        
        # Calculate extraction potential
        if result["parser_can_extract"] > 0:
            result["extraction_potential"] = min(100, 
                (result["generator_fields"] / result["parser_can_extract"]) * 100)
        
        return result
    
    def analyze_all(self) -> None:
        """Analyze all generator-parser pairs"""
        from event_generators.shared.hec_sender import PROD_MAP, SOURCETYPE_MAP
        
        results = []
        
        for generator_name in PROD_MAP:
            # Get parser name from SOURCETYPE_MAP
            parser_name = SOURCETYPE_MAP.get(generator_name)
            
            if parser_name:
                result = self.compare_parser_generator(generator_name, parser_name)
                results.append(result)
                
                # Print progress
                status = "✅" if result.get("format_match") else "❌"
                print(f"{status} {generator_name:30} -> {parser_name:40} "
                      f"({result.get('generator_format', 'unknown')} -> "
                      f"{result.get('parser_expects', 'unknown')})")
        
        self.results = results
        return results
    
    def generate_report(self) -> None:
        """Generate comprehensive report"""
        if not self.results:
            print("No results to report")
            return
        
        print("\n" + "=" * 80)
        print("PARSER-GENERATOR FIELD EXTRACTION ANALYSIS")
        print("=" * 80)
        
        # Format matches
        matches = [r for r in self.results if r.get("format_match")]
        mismatches = [r for r in self.results if not r.get("format_match") and "error" not in r]
        errors = [r for r in self.results if "error" in r]
        
        print(f"\n📊 Summary:")
        print(f"  Total analyzed: {len(self.results)}")
        print(f"  Format matches: {len(matches)}")
        print(f"  Format mismatches: {len(mismatches)}")
        print(f"  Errors: {len(errors)}")
        
        # Top extractors
        sorted_by_extraction = sorted(
            [r for r in self.results if "error" not in r],
            key=lambda x: x.get("parser_can_extract", 0),
            reverse=True
        )
        
        print(f"\n🏆 Top 10 Parsers by Field Extraction Capability:")
        for r in sorted_by_extraction[:10]:
            print(f"  {r['parser']:40} {r['parser_can_extract']:3} fields")
        
        # Format mismatches
        if mismatches:
            print(f"\n⚠️ Format Mismatches (need fixing):")
            for r in mismatches[:10]:
                print(f"  {r['generator']:30} ({r['generator_format']}) -> "
                      f"{r['parser']} expects ({r['parser_expects']})")
        
        # Save detailed results
        with open("field_extraction_analysis.json", "w") as f:
            json.dump(self.results, f, indent=2)
        
        print(f"\n💾 Detailed results saved to: field_extraction_analysis.json")

def main():
    analyzer = ParserFieldAnalyzer()
    
    print("🔍 Analyzing Parser-Generator Field Extraction...")
    print("=" * 80)
    
    analyzer.analyze_all()
    analyzer.generate_report()
    
    print("\n✅ Analysis complete!")

if __name__ == "__main__":
    main()