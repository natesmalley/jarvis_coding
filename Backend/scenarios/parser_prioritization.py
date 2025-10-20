#!/usr/bin/env python3
"""
Parser Priority Classification System

This tool prioritizes parsers based on:
1. Vendor importance and market adoption
2. Security criticality and use cases  
3. Integration complexity and effort required
4. OCSF compliance and field extraction quality
5. SentinelOne Marketplace parser availability
"""

import json
from pathlib import Path
from typing import Dict, List, Any
from datetime import datetime

project_root = Path(__file__).parent.parent

class ParserPrioritizer:
    def __init__(self):
        self.project_root = project_root
        
        # High-impact security vendors (Tier 1)
        self.tier_1_vendors = [
            "aws", "microsoft", "azure", "cisco", "fortinet", "palo alto", 
            "crowdstrike", "sentinelone", "okta", "google", "cloudflare"
        ]
        
        # Important security vendors (Tier 2)
        self.tier_2_vendors = [
            "checkpoint", "zscaler", "mimecast", "proofpoint", "jamf", "netskope",
            "abnormal", "cyberark", "hashicorp", "beyond trust", "darktrace",
            "vectra", "corelight", "extrahop", "imperva", "incapsula"
        ]
        
        # Specialized/Niche vendors (Tier 3)
        self.tier_3_vendors = [
            "akamai", "aruba", "axway", "buildkite", "cohesity", "extreme",
            "f5", "github", "harness", "hypr", "infoblox", "isc", "juniper",
            "manageengine", "pingfederate", "rsa", "securelink", "tailscale",
            "teleport", "ubiquiti", "veeam", "wiz"
        ]
        
        # Security category importance weights
        self.category_weights = {
            "endpoint_security": 0.95,      # Critical - endpoints are primary attack vectors
            "identity_access": 0.95,        # Critical - identity is new perimeter
            "network_security": 0.90,       # Very Important - network visibility
            "cloud_infrastructure": 0.90,   # Very Important - cloud-first world
            "email_security": 0.85,         # Important - major attack vector
            "web_security": 0.80,           # Important - web-based attacks
            "infrastructure": 0.70          # Moderate - supporting systems
        }
        
        # Format complexity scoring
        self.format_complexity = {
            "JSON": 1.0,      # Easiest to work with
            "Syslog": 0.8,    # Moderate complexity
            "Key-Value": 0.7, # More complex parsing
            "CSV": 0.6,       # Limited field flexibility
            "CEF": 0.5        # Most complex format
        }
        
    def load_audit_results(self) -> Dict:
        """Load audit results"""
        audit_file = self.project_root / "scenarios" / "parser_generator_audit_results.json"
        with open(audit_file, 'r') as f:
            return json.load(f)
            
    def classify_vendor_tier(self, parser_name: str) -> int:
        """Classify vendor into tier (1=highest, 3=lowest priority)"""
        parser_lower = parser_name.lower()
        
        for vendor in self.tier_1_vendors:
            if vendor in parser_lower:
                return 1
                
        for vendor in self.tier_2_vendors:
            if vendor in parser_lower:
                return 2
                
        return 3  # Tier 3 by default
        
    def get_security_category(self, generator_path: str) -> str:
        """Determine security category from generator path"""
        path_lower = generator_path.lower()
        
        if "endpoint_security" in path_lower:
            return "endpoint_security"
        elif "identity_access" in path_lower:
            return "identity_access"
        elif "network_security" in path_lower:
            return "network_security"
        elif "cloud_infrastructure" in path_lower:
            return "cloud_infrastructure"
        elif "email_security" in path_lower:
            return "email_security"
        elif "web_security" in path_lower:
            return "web_security"
        elif "infrastructure" in path_lower:
            return "infrastructure"
        else:
            return "other"
            
    def calculate_priority_score(self, item: Dict) -> float:
        """Calculate comprehensive priority score"""
        parser_name = item.get("parser", "")
        
        # Vendor tier weight (40% of score)
        tier = self.classify_vendor_tier(parser_name)
        if tier == 1:
            vendor_weight = 1.0
        elif tier == 2:
            vendor_weight = 0.7
        else:
            vendor_weight = 0.4
            
        # Security category weight (30% of score)
        generator_path = item.get("generator_path", "")
        category = self.get_security_category(generator_path)
        category_weight = self.category_weights.get(category, 0.5)
        
        # Format complexity weight (20% of score)
        parser_format = item.get("parser_format", "JSON")
        format_weight = self.format_complexity.get(parser_format, 0.5)
        
        # Current status weight (10% of score)
        current_format = item.get("current_format", "JSON")
        if current_format == parser_format:
            status_weight = 0.1  # Already compatible
        else:
            status_weight = 1.0  # Needs fixing
            
        # Calculate weighted score
        priority_score = (
            vendor_weight * 0.4 +
            category_weight * 0.3 +
            format_weight * 0.2 +
            status_weight * 0.1
        )
        
        return priority_score
        
    def prioritize_format_mismatches(self, audit_results: Dict) -> List[Dict]:
        """Prioritize format mismatches by importance"""
        format_mismatches = audit_results.get("format_mismatches", [])
        
        # Calculate priority scores
        for item in format_mismatches:
            item["priority_score"] = self.calculate_priority_score(item)
            item["vendor_tier"] = self.classify_vendor_tier(item["parser"])
            item["security_category"] = self.get_security_category(item.get("generator_path", ""))
            
        # Sort by priority score (highest first)
        prioritized = sorted(format_mismatches, key=lambda x: x["priority_score"], reverse=True)
        
        return prioritized
        
    def prioritize_missing_generators(self, audit_results: Dict) -> List[Dict]:
        """Prioritize missing generators by importance"""
        missing_generators = audit_results.get("missing_generators", [])
        
        for item in missing_generators:
            # Use parser name for priority calculation
            mock_item = {"parser": item["parser"], "generator_path": "", "parser_format": item["expected_format"]}
            item["priority_score"] = self.calculate_priority_score(mock_item)
            item["vendor_tier"] = self.classify_vendor_tier(item["parser"])
            
        # Sort by priority score
        prioritized = sorted(missing_generators, key=lambda x: x["priority_score"], reverse=True)
        
        return prioritized
        
    def create_phased_implementation_plan(self, audit_results: Dict) -> Dict:
        """Create phased implementation plan based on priorities"""
        plan = {
            "metadata": {
                "created": datetime.now().isoformat(),
                "total_issues": len(audit_results.get("format_mismatches", [])) + len(audit_results.get("missing_generators", []))
            },
            "phase_1_critical": {
                "description": "Tier 1 vendors with critical security impact",
                "timeline": "Week 1-2",
                "format_fixes": [],
                "missing_generators": []
            },
            "phase_2_high": {
                "description": "Tier 2 vendors and remaining Tier 1 issues",
                "timeline": "Week 3-4", 
                "format_fixes": [],
                "missing_generators": []
            },
            "phase_3_medium": {
                "description": "Tier 3 vendors and Star Trek integration",
                "timeline": "Week 5-6",
                "format_fixes": [],
                "missing_generators": [],
                "star_trek_integration": []
            },
            "phase_4_automation": {
                "description": "Automated testing and CI/CD integration",
                "timeline": "Week 7-8",
                "tasks": [
                    "Implement automated format validation",
                    "Create parser-generator compatibility tests",
                    "Add CI/CD pipeline integration",
                    "Create generator templates and documentation"
                ]
            }
        }
        
        # Categorize format mismatches
        prioritized_mismatches = self.prioritize_format_mismatches(audit_results)
        
        for item in prioritized_mismatches:
            task = {
                "parser": item["parser"],
                "generator": item.get("generator_path", ""),
                "current_format": item.get("generator_format", "Unknown"),
                "target_format": item.get("parser_format", "JSON"),
                "priority_score": item["priority_score"],
                "vendor_tier": item["vendor_tier"],
                "complexity": self.format_complexity.get(item.get("parser_format", "JSON"), 0.5)
            }
            
            if item["vendor_tier"] == 1 and item["priority_score"] > 0.8:
                plan["phase_1_critical"]["format_fixes"].append(task)
            elif item["vendor_tier"] <= 2 and item["priority_score"] > 0.6:
                plan["phase_2_high"]["format_fixes"].append(task)
            else:
                plan["phase_3_medium"]["format_fixes"].append(task)
                
        # Categorize missing generators
        prioritized_missing = self.prioritize_missing_generators(audit_results)
        
        for item in prioritized_missing:
            task = {
                "parser": item["parser"],
                "expected_format": item["expected_format"],
                "priority_score": item["priority_score"],
                "vendor_tier": item["vendor_tier"]
            }
            
            if item["vendor_tier"] == 1:
                plan["phase_1_critical"]["missing_generators"].append(task)
            elif item["vendor_tier"] == 2:
                plan["phase_2_high"]["missing_generators"].append(task)
            else:
                plan["phase_3_medium"]["missing_generators"].append(task)
                
        # Add Star Trek integration tasks
        star_trek_missing = audit_results.get("star_trek_status", [])
        high_priority_st = [item for item in star_trek_missing 
                           if not item.get("has_star_trek", False) and item.get("priority", "LOW") in ["HIGH", "MEDIUM"]]
        
        plan["phase_3_medium"]["star_trek_integration"] = [
            {"generator": item["generator"], "priority": item.get("priority", "LOW")} 
            for item in high_priority_st[:20]  # Limit to top 20
        ]
        
        return plan
        
    def generate_executive_summary(self, plan: Dict) -> str:
        """Generate executive summary"""
        phase_1_count = len(plan["phase_1_critical"]["format_fixes"]) + len(plan["phase_1_critical"]["missing_generators"])
        phase_2_count = len(plan["phase_2_high"]["format_fixes"]) + len(plan["phase_2_high"]["missing_generators"])
        phase_3_count = len(plan["phase_3_medium"]["format_fixes"]) + len(plan["phase_3_medium"]["missing_generators"])
        total_issues = plan["metadata"]["total_issues"]
        
        summary = f"""
# Parser-Generator Compatibility Implementation Plan

## Executive Summary

We have identified **{total_issues} compatibility issues** across 100+ security parsers and generators. 
These issues prevent optimal field extraction and OCSF compliance in the SentinelOne AI SIEM platform.

### Prioritized Implementation Phases:

**Phase 1 - Critical (Week 1-2): {phase_1_count} issues**
- Focus on Tier 1 security vendors (AWS, Microsoft, Cisco, etc.)
- Highest business impact and security coverage
- Endpoint security, identity, and cloud infrastructure priority

**Phase 2 - High Priority (Week 3-4): {phase_2_count} issues**  
- Tier 2 vendors and remaining critical systems
- Network security and email security platforms
- Moderate complexity format conversions

**Phase 3 - Medium Priority (Week 5-6): {phase_3_count} issues**
- Tier 3 specialized vendors
- Star Trek character integration for testing
- Infrastructure and supporting systems

**Phase 4 - Automation (Week 7-8)**
- Automated compatibility testing framework
- CI/CD pipeline integration
- Prevention of future format mismatches

### Success Metrics:
- **90%+ OCSF compliance** for Tier 1 vendors
- **Complete Star Trek integration** for testing scenarios
- **Automated validation** to prevent regressions
- **80%+ field extraction** improvement for critical parsers

### Resource Requirements:
- 1-2 engineers for 8 weeks
- Comprehensive testing environment
- Backup and rollback procedures
- Documentation and training materials
"""
        return summary.strip()

def main():
    """Main prioritization function"""
    print("📊 Starting Parser Priority Classification and Planning")
    print("="*70)
    
    prioritizer = ParserPrioritizer()
    
    # Load audit results
    try:
        audit_results = prioritizer.load_audit_results()
    except FileNotFoundError:
        print("❌ Audit results not found. Run parser_generator_audit.py first.")
        return
        
    # Create prioritized implementation plan
    plan = prioritizer.create_phased_implementation_plan(audit_results)
    
    # Generate executive summary
    executive_summary = prioritizer.generate_executive_summary(plan)
    
    # Save results
    plan_file = prioritizer.project_root / "scenarios" / "prioritized_implementation_plan.json"
    with open(plan_file, 'w') as f:
        json.dump(plan, f, indent=2, default=str)
        
    summary_file = prioritizer.project_root / "scenarios" / "implementation_executive_summary.md"
    with open(summary_file, 'w') as f:
        f.write(executive_summary)
        
    # Display summary
    print("\n" + "="*70)
    print("📋 PRIORITIZED IMPLEMENTATION PLAN")
    print("="*70)
    
    print(f"\nPhase 1 - Critical: {len(plan['phase_1_critical']['format_fixes'])} format fixes, {len(plan['phase_1_critical']['missing_generators'])} missing generators")
    print(f"Phase 2 - High: {len(plan['phase_2_high']['format_fixes'])} format fixes, {len(plan['phase_2_high']['missing_generators'])} missing generators")
    print(f"Phase 3 - Medium: {len(plan['phase_3_medium']['format_fixes'])} format fixes, {len(plan['phase_3_medium']['missing_generators'])} missing generators")
    
    # Show Phase 1 critical items
    if plan['phase_1_critical']['format_fixes']:
        print(f"\n🚨 PHASE 1 CRITICAL FORMAT FIXES:")
        for item in plan['phase_1_critical']['format_fixes'][:10]:
            print(f"   • {item['parser']}: {item['current_format']} → {item['target_format']} (Score: {item['priority_score']:.2f})")
            
    print(f"\n💾 Implementation plan saved to: {plan_file}")
    print(f"📄 Executive summary saved to: {summary_file}")
    print("\n✅ Parser prioritization complete!")

if __name__ == "__main__":
    main()