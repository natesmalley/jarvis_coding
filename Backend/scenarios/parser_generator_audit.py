#!/usr/bin/env python3
"""
Comprehensive Parser-Generator Compatibility Audit Tool

This tool systematically analyzes all parsers and generators to identify:
1. Format mismatches (JSON vs Syslog vs CSV vs Key-Value)
2. Missing generators for parsers
3. Missing parsers for generators  
4. Field mapping discrepancies
5. Star Trek character integration status
"""

import os
import json
import sys
import glob
import importlib
import subprocess
from pathlib import Path
from typing import Dict, List, Tuple, Any, Optional
from datetime import datetime

# Add the project root to Python path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

class ParserGeneratorAuditor:
    def __init__(self):
        self.project_root = project_root
        self.parsers_dir = self.project_root / "parsers" / "community"
        self.generators_dir = self.project_root / "event_generators"
        self.results = {
            "parsers_analyzed": 0,
            "generators_analyzed": 0,
            "format_mismatches": [],
            "missing_generators": [],
            "missing_parsers": [],
            "field_mismatches": [],
            "star_trek_status": [],
            "critical_fixes_needed": [],
            "recommendations": []
        }
        
    def audit_all_parsers(self):
        """Audit all parser configurations"""
        print("🔍 Auditing all parser configurations...")
        
        parser_dirs = [d for d in self.parsers_dir.iterdir() if d.is_dir()]
        self.results["parsers_analyzed"] = len(parser_dirs)
        
        for parser_dir in sorted(parser_dirs):
            self._audit_parser(parser_dir)
            
        print(f"✅ Analyzed {self.results['parsers_analyzed']} parsers")
        
    def audit_all_generators(self):
        """Audit all event generators"""
        print("🔍 Auditing all event generators...")
        
        generator_files = []
        for category_dir in self.generators_dir.iterdir():
            if category_dir.is_dir() and category_dir.name != "shared":
                generator_files.extend(list(category_dir.glob("*.py")))
                
        self.results["generators_analyzed"] = len(generator_files)
        
        for generator_file in sorted(generator_files):
            self._audit_generator(generator_file)
            
        print(f"✅ Analyzed {self.results['generators_analyzed']} generators")
        
    def _audit_parser(self, parser_dir: Path):
        """Audit a single parser configuration"""
        parser_name = parser_dir.name.replace("-latest", "").replace("_logs", "").replace("_", " ").title()
        
        # Find JSON configuration file
        json_files = list(parser_dir.glob("*.json"))
        if not json_files:
            self.results["critical_fixes_needed"].append({
                "type": "missing_config",
                "parser": parser_name,
                "issue": "No JSON configuration file found"
            })
            return
            
        config_file = json_files[0]
        
        try:
            with open(config_file, 'r') as f:
                config = json.load(f)
                
            # Determine expected input format
            expected_format = self._determine_parser_format(config)
            
            # Find corresponding generator
            generator_path = self._find_generator_for_parser(parser_dir.name)
            
            if not generator_path:
                self.results["missing_generators"].append({
                    "parser": parser_name,
                    "parser_dir": parser_dir.name,
                    "expected_format": expected_format,
                    "priority": self._get_parser_priority(parser_name)
                })
            else:
                # Check format compatibility
                generator_format = self._determine_generator_format(generator_path)
                if expected_format != generator_format:
                    self.results["format_mismatches"].append({
                        "parser": parser_name,
                        "parser_format": expected_format,
                        "generator_format": generator_format,
                        "generator_path": str(generator_path),
                        "priority": self._get_parser_priority(parser_name)
                    })
                    
                # Check Star Trek integration
                star_trek_status = self._check_star_trek_integration(generator_path)
                self.results["star_trek_status"].append({
                    "generator": generator_path.stem,
                    "has_star_trek": star_trek_status,
                    "priority": self._get_parser_priority(parser_name)
                })
                
        except Exception as e:
            self.results["critical_fixes_needed"].append({
                "type": "parse_error",
                "parser": parser_name,
                "issue": f"Error parsing config: {str(e)}"
            })
            
    def _audit_generator(self, generator_file: Path):
        """Audit a single generator file"""
        # Check if corresponding parser exists
        generator_name = generator_file.stem
        parser_exists = self._find_parser_for_generator(generator_name)
        
        if not parser_exists:
            self.results["missing_parsers"].append({
                "generator": generator_name,
                "generator_path": str(generator_file),
                "category": generator_file.parent.name
            })
            
    def _determine_parser_format(self, config: Dict) -> str:
        """Determine expected input format from parser config"""
        # Look for format indicators in the parser configuration
        config_str = json.dumps(config, default=str).lower()
        
        if "parse=gron" in config_str or '"format":"json"' in config_str:
            return "JSON"
        elif "parse=csv" in config_str or "csv" in config_str:
            return "CSV"
        elif any(keyword in config_str for keyword in ["syslog", "rfc3164", "rfc5424"]):
            return "Syslog"
        elif any(keyword in config_str for keyword in ["key=", "kv", "key-value"]):
            return "Key-Value"
        elif "cef" in config_str:
            return "CEF"
        else:
            # Default assumption based on common patterns
            return "JSON"
            
    def _determine_generator_format(self, generator_path: Path) -> str:
        """Determine output format from generator file"""
        try:
            with open(generator_path, 'r') as f:
                content = f.read().lower()
                
            if 'json.dumps' in content or 'return json' in content:
                return "JSON"
            elif 'csv' in content or 'csvwriter' in content:
                return "CSV"
            elif any(keyword in content for keyword in ["syslog", "rfc3164", "rfc5424", "priority", "<"]):
                return "Syslog"
            elif any(keyword in content for keyword in ["key=", "kv", " = ", "key-value"]):
                return "Key-Value"
            elif "cef" in content:
                return "CEF"
            else:
                return "JSON"  # Default assumption
                
        except Exception:
            return "Unknown"
            
    def _find_generator_for_parser(self, parser_dir_name: str) -> Optional[Path]:
        """Find corresponding generator for a parser"""
        # Clean parser name to match generator naming
        clean_name = (parser_dir_name
                      .replace("-latest", "")
                      .replace("_logs", "")
                      .replace("_log", ""))
        
        # Search through all generator categories
        for category_dir in self.generators_dir.iterdir():
            if category_dir.is_dir() and category_dir.name != "shared":
                # Try exact match first
                exact_match = category_dir / f"{clean_name}.py"
                if exact_match.exists():
                    return exact_match
                    
                # Try partial matches
                for generator_file in category_dir.glob("*.py"):
                    if clean_name.replace("_", "") in generator_file.stem.replace("_", ""):
                        return generator_file
                        
        return None
        
    def _find_parser_for_generator(self, generator_name: str) -> bool:
        """Check if parser exists for a generator"""
        # Try different naming patterns
        possible_names = [
            f"{generator_name}-latest",
            f"{generator_name}_logs-latest",
            f"{generator_name}_log-latest",
        ]
        
        for name in possible_names:
            parser_dir = self.parsers_dir / name
            if parser_dir.exists():
                return True
                
        return False
        
    def _get_parser_priority(self, parser_name: str) -> str:
        """Get priority level for parser based on importance"""
        high_priority = [
            "aws", "microsoft", "cisco", "fortinet", "palo alto", "crowdstrike",
            "sentinelone", "okta", "azure", "google", "cloudflare"
        ]
        
        medium_priority = [
            "checkpoint", "zscaler", "mimecast", "proofpoint", "jamf", "netskope",
            "abnormal", "cyberark", "hashicorp", "beyond trust"
        ]
        
        parser_lower = parser_name.lower()
        
        for vendor in high_priority:
            if vendor in parser_lower:
                return "HIGH"
                
        for vendor in medium_priority:
            if vendor in parser_lower:
                return "MEDIUM"
                
        return "LOW"
        
    def _check_star_trek_integration(self, generator_path: Path) -> bool:
        """Check if generator has Star Trek character integration"""
        try:
            with open(generator_path, 'r') as f:
                content = f.read()
                
            star_trek_indicators = [
                "jean.picard", "starfleet.corp", "worf.security", "data.android",
                "william.riker", "geordi.laforge", "deanna.troi"
            ]
            
            return any(indicator in content.lower() for indicator in star_trek_indicators)
            
        except Exception:
            return False
            
    def generate_report(self):
        """Generate comprehensive audit report"""
        print("\n" + "="*80)
        print("📊 PARSER-GENERATOR COMPATIBILITY AUDIT REPORT")
        print("="*80)
        
        # Summary statistics
        print(f"\n📈 SUMMARY STATISTICS:")
        print(f"   • Parsers analyzed: {self.results['parsers_analyzed']}")
        print(f"   • Generators analyzed: {self.results['generators_analyzed']}")
        print(f"   • Format mismatches: {len(self.results['format_mismatches'])}")
        print(f"   • Missing generators: {len(self.results['missing_generators'])}")
        print(f"   • Missing parsers: {len(self.results['missing_parsers'])}")
        
        # Critical format mismatches
        if self.results['format_mismatches']:
            print(f"\n🚨 CRITICAL FORMAT MISMATCHES ({len(self.results['format_mismatches'])}):")
            high_priority = [item for item in self.results['format_mismatches'] if item['priority'] == 'HIGH']
            medium_priority = [item for item in self.results['format_mismatches'] if item['priority'] == 'MEDIUM']
            
            if high_priority:
                print("   🔥 HIGH PRIORITY:")
                for item in high_priority[:10]:  # Show top 10
                    print(f"      • {item['parser']}: {item['generator_format']} → {item['parser_format']}")
                    
            if medium_priority:
                print("   ⚠️  MEDIUM PRIORITY:")
                for item in medium_priority[:10]:  # Show top 10
                    print(f"      • {item['parser']}: {item['generator_format']} → {item['parser_format']}")
        
        # Missing generators for existing parsers
        if self.results['missing_generators']:
            print(f"\n📋 MISSING GENERATORS ({len(self.results['missing_generators'])}):")
            high_priority = [item for item in self.results['missing_generators'] if item['priority'] == 'HIGH']
            
            if high_priority:
                print("   🔥 HIGH PRIORITY:")
                for item in high_priority[:10]:
                    print(f"      • {item['parser']} (expects {item['expected_format']})")
        
        # Star Trek integration status
        star_trek_missing = [item for item in self.results['star_trek_status'] if not item['has_star_trek']]
        if star_trek_missing:
            print(f"\n🖖 STAR TREK INTEGRATION MISSING ({len(star_trek_missing)}):")
            high_priority = [item for item in star_trek_missing if item['priority'] == 'HIGH']
            for item in high_priority[:10]:
                print(f"      • {item['generator']}")
        
        # Recommendations
        print(f"\n💡 RECOMMENDATIONS:")
        print("   1. Fix HIGH priority format mismatches first")
        print("   2. Create missing generators for HIGH priority parsers") 
        print("   3. Update remaining generators with Star Trek characters")
        print("   4. Develop automated testing for parser-generator compatibility")
        print("   5. Implement format validation in CI/CD pipeline")
        
    def save_results(self, output_file: str = "parser_generator_audit_results.json"):
        """Save audit results to JSON file"""
        output_path = self.project_root / "scenarios" / output_file
        
        # Add metadata
        self.results["metadata"] = {
            "audit_date": datetime.now().isoformat(),
            "project_root": str(self.project_root),
            "total_issues": (len(self.results['format_mismatches']) + 
                           len(self.results['missing_generators']) + 
                           len(self.results['missing_parsers']))
        }
        
        with open(output_path, 'w') as f:
            json.dump(self.results, f, indent=2, default=str)
            
        print(f"\n💾 Results saved to: {output_path}")
        
    def generate_fixing_plan(self):
        """Generate systematic plan for fixing issues"""
        plan = {
            "phase_1_critical_fixes": [],
            "phase_2_medium_fixes": [],
            "phase_3_improvements": [],
            "phase_4_automation": []
        }
        
        # Phase 1: Critical format mismatches (HIGH priority)
        high_priority_mismatches = [item for item in self.results['format_mismatches'] 
                                   if item['priority'] == 'HIGH']
        for item in high_priority_mismatches:
            plan["phase_1_critical_fixes"].append({
                "action": "fix_format_mismatch",
                "parser": item['parser'],
                "current_format": item['generator_format'],
                "target_format": item['parser_format'],
                "generator_path": item['generator_path'],
                "priority": "CRITICAL"
            })
            
        # Phase 2: Missing generators (HIGH priority)
        high_priority_missing = [item for item in self.results['missing_generators']
                                if item['priority'] == 'HIGH']
        for item in high_priority_missing:
            plan["phase_2_medium_fixes"].append({
                "action": "create_generator",
                "parser": item['parser'],
                "format": item['expected_format'],
                "priority": "HIGH"
            })
            
        # Phase 3: Star Trek integration
        star_trek_missing = [item for item in self.results['star_trek_status'] 
                           if not item['has_star_trek'] and item['priority'] in ['HIGH', 'MEDIUM']]
        for item in star_trek_missing[:20]:  # Limit to top 20
            plan["phase_3_improvements"].append({
                "action": "add_star_trek_integration",
                "generator": item['generator'],
                "priority": item['priority']
            })
            
        # Phase 4: Automation
        plan["phase_4_automation"] = [
            {"action": "create_format_validator", "description": "Validate generator output matches parser expectations"},
            {"action": "create_automated_tests", "description": "End-to-end parser-generator compatibility tests"},
            {"action": "add_ci_validation", "description": "Prevent format mismatches in CI/CD"},
            {"action": "create_generator_templates", "description": "Templates for creating new generators"}
        ]
        
        # Save plan
        plan_path = self.project_root / "scenarios" / "parser_generator_fixing_plan.json"
        with open(plan_path, 'w') as f:
            json.dump(plan, f, indent=2, default=str)
            
        print(f"\n📋 Systematic fixing plan saved to: {plan_path}")
        return plan

def main():
    """Main audit function"""
    print("🔍 Starting Comprehensive Parser-Generator Compatibility Audit")
    print("="*80)
    
    auditor = ParserGeneratorAuditor()
    
    # Run audit
    auditor.audit_all_parsers()
    auditor.audit_all_generators()
    
    # Generate reports
    auditor.generate_report()
    auditor.save_results()
    
    # Generate fixing plan
    plan = auditor.generate_fixing_plan()
    
    print(f"\n✅ Audit complete! Found {len(auditor.results['format_mismatches'])} format mismatches")
    print(f"📋 Systematic fixing plan created with {len(plan['phase_1_critical_fixes'])} critical fixes")

if __name__ == "__main__":
    main()