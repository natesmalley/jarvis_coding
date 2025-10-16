#!/usr/bin/env python3
"""
Generator Improvement Plan
Analyzes test results and creates a systematic plan to fix all issues
"""

import json
import sys
from pathlib import Path
from typing import Dict, List, Any
from datetime import datetime

project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

class GeneratorImprovementAnalyzer:
    def __init__(self):
        self.project_root = project_root
        self.test_results_file = self.project_root / "testing" / "comprehensive_test_results.json"
        self.improvement_plan = {
            "critical_fixes": [],  # Failed generators
            "star_trek_needed": [],  # Generators missing Star Trek
            "timestamp_updates": [],  # Generators with old timestamps
            "override_support": [],  # Generators missing override support
            "parser_missing": [],  # Generators without parsers
            "summary": {}
        }
        
    def load_test_results(self) -> Dict:
        """Load the comprehensive test results"""
        if not self.test_results_file.exists():
            print("❌ Test results not found. Run comprehensive_generator_test.py first")
            return {}
            
        with open(self.test_results_file, 'r') as f:
            return json.load(f)
            
    def analyze_results(self, results: Dict):
        """Analyze test results and categorize improvements needed"""
        generators = results.get("generators", {})
        
        for gen_name, gen_result in generators.items():
            # Critical: Failed generators
            if gen_result["status"] == "failed":
                self.improvement_plan["critical_fixes"].append({
                    "generator": gen_name,
                    "category": gen_result["category"],
                    "error": gen_result["execution"]["error"],
                    "fix_type": self._determine_fix_type(gen_result["execution"]["error"])
                })
                
            # Star Trek integration needed
            elif not gen_result["star_trek"]["present"]:
                self.improvement_plan["star_trek_needed"].append({
                    "generator": gen_name,
                    "category": gen_result["category"],
                    "current_format": gen_result["format"]["type"],
                    "priority": self._get_priority(gen_name, gen_result["category"])
                })
                
            # Timestamp updates needed
            elif not gen_result["timestamp"]["recent"]:
                self.improvement_plan["timestamp_updates"].append({
                    "generator": gen_name,
                    "category": gen_result["category"],
                    "current_timestamp": gen_result["timestamp"]["value"],
                    "priority": self._get_priority(gen_name, gen_result["category"])
                })
                
            # Override support needed
            if not gen_result["execution"].get("supports_overrides", False):
                self.improvement_plan["override_support"].append({
                    "generator": gen_name,
                    "category": gen_result["category"],
                    "priority": self._get_priority(gen_name, gen_result["category"])
                })
                
            # Parser missing
            if not gen_result["parser"]["exists"]:
                self.improvement_plan["parser_missing"].append({
                    "generator": gen_name,
                    "category": gen_result["category"],
                    "format": gen_result["format"]["type"]
                })
                
    def _determine_fix_type(self, error: str) -> str:
        """Determine what type of fix is needed based on error"""
        if "No log function found" in error:
            return "MISSING_LOG_FUNCTION"
        elif "No module named" in error:
            return "MISSING_DEPENDENCY"
        elif "TypeError" in error:
            return "FUNCTION_SIGNATURE_ERROR"
        else:
            return "OTHER_ERROR"
            
    def _get_priority(self, gen_name: str, category: str) -> str:
        """Determine priority based on vendor and category importance"""
        high_priority_vendors = ["aws", "microsoft", "cisco", "google", "crowdstrike", "sentinelone", "okta"]
        critical_categories = ["identity_access", "endpoint_security", "cloud_infrastructure"]
        
        gen_lower = gen_name.lower()
        
        # Check if high priority vendor
        for vendor in high_priority_vendors:
            if vendor in gen_lower:
                return "HIGH"
                
        # Check if critical category
        if category in critical_categories:
            return "MEDIUM"
            
        return "LOW"
        
    def generate_fixes(self):
        """Generate specific fix code for each issue"""
        fixes = []
        
        # Generate fixes for failed generators
        for issue in self.improvement_plan["critical_fixes"]:
            if issue["fix_type"] == "MISSING_LOG_FUNCTION":
                fix = {
                    "generator": issue["generator"],
                    "category": issue["category"],
                    "action": "ADD_LOG_FUNCTION",
                    "code": self._generate_log_function_code(issue["generator"])
                }
                fixes.append(fix)
            elif issue["fix_type"] == "MISSING_DEPENDENCY":
                fix = {
                    "generator": issue["generator"],
                    "category": issue["category"],
                    "action": "INSTALL_DEPENDENCY",
                    "command": self._extract_dependency(issue["error"])
                }
                fixes.append(fix)
                
        return fixes
        
    def _generate_log_function_code(self, generator_name: str) -> str:
        """Generate template log function code"""
        return f'''def {generator_name}_log(overrides: dict = None) -> Dict:
    """Generate a single {generator_name.replace('_', ' ').title()} event log"""
    now = datetime.now(timezone.utc)
    event_time = now - timedelta(minutes=random.randint(0, 10))
    
    event = {{
        "timestamp": event_time.isoformat(),
        "event_type": "{generator_name}",
        "source": "starfleet.corp",
        "user": random.choice(STAR_TREK_USERS),
        "action": "generated",
        **ATTR_FIELDS
    }}
    
    if overrides:
        event.update(overrides)
        
    return event'''
        
    def _extract_dependency(self, error: str) -> str:
        """Extract missing dependency from error message"""
        if "requests" in error:
            return "pip install requests"
        elif "pandas" in error:
            return "pip install pandas"
        else:
            return "pip install -r requirements.txt"
            
    def generate_report(self):
        """Generate improvement report"""
        print("\n" + "="*80)
        print("📊 GENERATOR IMPROVEMENT PLAN")
        print("="*80)
        
        # Summary statistics
        self.improvement_plan["summary"] = {
            "critical_fixes_needed": len(self.improvement_plan["critical_fixes"]),
            "star_trek_needed": len(self.improvement_plan["star_trek_needed"]),
            "timestamp_updates_needed": len(self.improvement_plan["timestamp_updates"]),
            "override_support_needed": len(self.improvement_plan["override_support"]),
            "parsers_missing": len(self.improvement_plan["parser_missing"])
        }
        
        print("\n📈 IMPROVEMENT SUMMARY:")
        for key, value in self.improvement_plan["summary"].items():
            print(f"  • {key.replace('_', ' ').title()}: {value}")
            
        # Critical fixes
        if self.improvement_plan["critical_fixes"]:
            print(f"\n🚨 CRITICAL FIXES NEEDED ({len(self.improvement_plan['critical_fixes'])}):")
            for fix in self.improvement_plan["critical_fixes"]:
                print(f"  • {fix['generator']} ({fix['category']}): {fix['fix_type']}")
                
        # Star Trek integration needed
        high_priority_st = [g for g in self.improvement_plan["star_trek_needed"] if g["priority"] == "HIGH"]
        if high_priority_st:
            print(f"\n🖖 HIGH PRIORITY STAR TREK INTEGRATION ({len(high_priority_st)}):")
            for gen in high_priority_st[:10]:
                print(f"  • {gen['generator']} ({gen['category']})")
                
        # Timestamp updates needed
        high_priority_ts = [g for g in self.improvement_plan["timestamp_updates"] if g["priority"] == "HIGH"]
        if high_priority_ts:
            print(f"\n⏰ HIGH PRIORITY TIMESTAMP UPDATES ({len(high_priority_ts)}):")
            for gen in high_priority_ts[:10]:
                print(f"  • {gen['generator']} ({gen['category']})")
                
        # Save detailed plan
        output_file = self.project_root / "scenarios" / "generator_improvement_plan.json"
        with open(output_file, 'w') as f:
            json.dump(self.improvement_plan, f, indent=2, default=str)
            
        print(f"\n💾 Detailed improvement plan saved to: {output_file}")
        
    def generate_fix_script(self):
        """Generate automated fix script"""
        fixes = self.generate_fixes()
        
        script_content = '''#!/usr/bin/env python3
"""
Automated Generator Fix Script
Generated on: {timestamp}
"""

import os
import sys
from pathlib import Path

project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

# Star Trek users for integration
STAR_TREK_USERS = [
    "jean.picard@starfleet.corp",
    "william.riker@starfleet.corp",
    "data.android@starfleet.corp",
    "geordi.laforge@starfleet.corp",
    "worf.security@starfleet.corp",
    "deanna.troi@starfleet.corp",
    "beverly.crusher@starfleet.corp"
]

def fix_generators():
    """Apply fixes to generators"""
    fixes_applied = 0
    
'''.format(timestamp=datetime.now().isoformat())
        
        # Add fixes to script
        for fix in fixes[:5]:  # Limit to first 5 for safety
            if fix["action"] == "ADD_LOG_FUNCTION":
                script_content += f'''
    # Fix {fix['generator']}
    print("Fixing {fix['generator']}...")
    # TODO: Add log function to {fix['category']}/{fix['generator']}.py
    
'''
                
        script_content += '''
    print(f"Applied {fixes_applied} fixes")

if __name__ == "__main__":
    fix_generators()
'''
        
        script_file = self.project_root / "scenarios" / "apply_generator_fixes.py"
        with open(script_file, 'w') as f:
            f.write(script_content)
            
        print(f"📝 Fix script generated: {script_file}")

def main():
    """Main analysis function"""
    print("🔍 Analyzing Generator Test Results")
    
    analyzer = GeneratorImprovementAnalyzer()
    
    # Load test results
    results = analyzer.load_test_results()
    if not results:
        return
        
    # Analyze and generate plan
    analyzer.analyze_results(results)
    analyzer.generate_report()
    analyzer.generate_fix_script()
    
    print("\n✅ Analysis complete!")

if __name__ == "__main__":
    main()