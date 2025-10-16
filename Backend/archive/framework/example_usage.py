#!/usr/bin/env python3
"""
Example Usage Scripts for SentinelOne Field Validation Framework

This module provides practical examples of how to use the Field Validation Framework
for various testing and analysis scenarios.
"""

import os
import sys
import json
from datetime import datetime

# Add framework to path
sys.path.insert(0, os.path.dirname(__file__))
from field_validation_framework import FieldValidationFramework, PowerQueryTemplates

class FrameworkExamples:
    """Example usage patterns for the Field Validation Framework"""
    
    def __init__(self):
        """Initialize framework with environment variables"""
        self.framework = FieldValidationFramework()
    
    def example_1_single_generator_validation(self):
        """Example 1: Validate a single generator with detailed analysis"""
        print("=" * 70)
        print("EXAMPLE 1: Single Generator Validation")
        print("=" * 70)
        
        # Validate a high-performing generator
        result = self.framework.validate_single_generator(
            generator_name='sentinelone_endpoint',
            parser_name='sentinelone_endpoint'
        )
        
        print(f"\nValidation Result:")
        print(f"  Performance Grade: {result.performance_grade}")
        print(f"  Field Extraction: {result.extraction_rate:.1f}%")
        print(f"  OCSF Compliance: {result.ocsf_score}%")
        print(f"  Events Found: {result.events_found}")
        
        return result
    
    def example_2_batch_validation_key_generators(self):
        """Example 2: Validate key generators from different categories"""
        print("=" * 70)
        print("EXAMPLE 2: Batch Validation - Key Generators")
        print("=" * 70)
        
        # Select representative generators from different categories
        key_generators = {
            'aws_guardduty': 'aws_guardduty_logs',  # Cloud security
            'sentinelone_endpoint': 'sentinelone_endpoint',  # Endpoint security
            'fortinet_fortigate': 'fortinet_fortigate',  # Network security
            'okta_authentication': 'okta_authentication',  # Identity
            'proofpoint': 'proofpoint_proofpoint_logs',  # Email security
        }
        
        results, report = self.framework.validate_generators(key_generators)
        
        print("\nKey Results Summary:")
        for result in results:
            print(f"  {result.generator_name:<25s}: {result.performance_grade} grade, "
                  f"{result.extraction_rate:.1f}% extraction")
        
        # Save example report
        with open('example_2_key_generators_report.md', 'w') as f:
            f.write(report)
        
        return results, report
    
    def example_3_format_compatibility_analysis(self):
        """Example 3: Analyze format compatibility issues"""
        print("=" * 70)
        print("EXAMPLE 3: Format Compatibility Analysis")
        print("=" * 70)
        
        # Test generators with different formats
        format_test_generators = {
            'cisco_firewall_threat_defense': 'cisco_firewall_threat_defense',  # Syslog format
            'aws_guardduty': 'aws_guardduty_logs',  # JSON format
            'fortinet_fortigate': 'fortinet_fortigate',  # Key=Value format
            'microsoft_windows_eventlog': 'microsoft_windows_eventlog',  # XML format
        }
        
        results, _ = self.framework.validate_generators(format_test_generators)
        
        print("\nFormat Compatibility Analysis:")
        print("| Generator | Format | Grade | Extraction% | Notes |")
        print("|-----------|--------|-------|-------------|-------|")
        
        for result in results:
            format_type = self._get_format_type(result.generator_name)
            notes = self._get_format_notes(result)
            
            print(f"| {result.generator_name:<25s} | {format_type:<6s} | "
                  f"{result.performance_grade:^5s} | {result.extraction_rate:^10.1f}% | {notes} |")
        
        return results
    
    def example_4_ocsf_compliance_deep_dive(self):
        """Example 4: Deep dive into OCSF compliance analysis"""
        print("=" * 70)
        print("EXAMPLE 4: OCSF Compliance Deep Dive")
        print("=" * 70)
        
        # Test generators with varying OCSF compliance
        ocsf_test_generators = {
            'sentinelone_endpoint': 'sentinelone_endpoint',  # Should be high OCSF
            'netskope': 'netskope_netskope_logs',  # Should be medium OCSF
            'cisco_duo': 'cisco_duo',  # Should be good OCSF
            'linux_auth': 'linux_auth',  # Might be lower OCSF
        }
        
        results, _ = self.framework.validate_generators(ocsf_test_generators)
        
        print("\nOCSF Compliance Analysis:")
        print("| Generator | OCSF Score | Observables | Key OCSF Fields |")
        print("|-----------|------------|-------------|------------------|")
        
        for result in results:
            observables_status = "✅" if result.has_observables else "❌"
            ocsf_fields = self._extract_ocsf_fields(result.sample_event)
            
            print(f"| {result.generator_name:<25s} | {result.ocsf_score:^10d}% | "
                  f"{observables_status:^11s} | {ocsf_fields} |")
        
        # Generate OCSF improvement recommendations
        print("\nOCSF Improvement Recommendations:")
        for result in results:
            if result.ocsf_score < 80:
                print(f"  🎯 {result.generator_name}:")
                print(f"     - Current OCSF score: {result.ocsf_score}%")
                print(f"     - Missing observables: {'Yes' if not result.has_observables else 'No'}")
                print(f"     - Recommended actions: Enhance parser to extract class_uid, activity_id")
        
        return results
    
    def example_5_performance_benchmarking(self):
        """Example 5: Performance benchmarking across vendor categories"""
        print("=" * 70)
        print("EXAMPLE 5: Performance Benchmarking by Vendor Category")
        print("=" * 70)
        
        # Categorize generators by vendor type
        vendor_categories = {
            'cloud_platforms': {
                'aws_guardduty': 'aws_guardduty_logs',
                'aws_cloudtrail': 'aws_cloudtrail',
                'microsoft_azuread': 'microsoft_azuread',
            },
            'network_security': {
                'fortinet_fortigate': 'fortinet_fortigate',
                'cisco_firewall_threat_defense': 'cisco_firewall_threat_defense',
                'paloalto_firewall': 'paloalto_firewall',
            },
            'endpoint_security': {
                'sentinelone_endpoint': 'sentinelone_endpoint',
                'crowdstrike_falcon': 'crowdstrike_falcon',
                'microsoft_windows_eventlog': 'microsoft_windows_eventlog',
            },
            'identity_providers': {
                'okta_authentication': 'okta_authentication',
                'cisco_duo': 'cisco_duo',
                'pingfederate': 'pingfederate',
            }
        }
        
        category_results = {}
        
        for category, generators in vendor_categories.items():
            print(f"\n📊 Testing {category.replace('_', ' ').title()} Category...")
            results, _ = self.framework.validate_generators(generators)
            
            # Calculate category metrics
            avg_extraction = sum(r.extraction_rate for r in results if r.status == 'success') / len(results)
            avg_ocsf = sum(r.ocsf_score for r in results if r.status == 'success') / len(results)
            success_rate = len([r for r in results if r.status == 'success']) / len(results) * 100
            
            category_results[category] = {
                'results': results,
                'avg_extraction': avg_extraction,
                'avg_ocsf': avg_ocsf,
                'success_rate': success_rate
            }
            
            print(f"  Category Performance: {avg_extraction:.1f}% extraction, "
                  f"{avg_ocsf:.1f}% OCSF, {success_rate:.1f}% success")
        
        # Generate benchmarking report
        print("\n" + "=" * 70)
        print("VENDOR CATEGORY BENCHMARKING RESULTS")
        print("=" * 70)
        print("| Category | Avg Extraction | Avg OCSF | Success Rate | Grade |")
        print("|----------|----------------|----------|--------------|-------|")
        
        for category, metrics in category_results.items():
            grade = self._calculate_category_grade(metrics)
            print(f"| {category.replace('_', ' ').title():<20s} | "
                  f"{metrics['avg_extraction']:^14.1f}% | "
                  f"{metrics['avg_ocsf']:^8.1f}% | "
                  f"{metrics['success_rate']:^12.1f}% | {grade:^5s} |")
        
        return category_results
    
    def example_6_powerquery_templates_demo(self):
        """Example 6: Demonstrate PowerQuery template usage"""
        print("=" * 70)
        print("EXAMPLE 6: PowerQuery Templates Demonstration")
        print("=" * 70)
        
        # Show available templates
        print("Available PowerQuery Templates:")
        print("1. Basic Field Extraction Analysis")
        print("2. OCSF Compliance Check")
        print("3. Observable Extraction Analysis")
        
        # Generate sample queries for a parser
        parser_name = "sentinelone_endpoint"
        
        print(f"\nSample PowerQuery for parser: {parser_name}")
        print("-" * 50)
        
        # Basic field extraction
        basic_query = PowerQueryTemplates.FIELD_EXTRACTION_BASIC.format(parser_name=parser_name)
        print("BASIC FIELD EXTRACTION:")
        print(basic_query)
        
        print("\n" + "-" * 50)
        
        # OCSF compliance check
        ocsf_query = PowerQueryTemplates.OCSF_COMPLIANCE_CHECK.format(parser_name=parser_name)
        print("OCSF COMPLIANCE CHECK:")
        print(ocsf_query)
        
        print("\n" + "-" * 50)
        
        # Observable extraction
        observable_query = PowerQueryTemplates.OBSERVABLE_EXTRACTION.format(parser_name=parser_name)
        print("OBSERVABLE EXTRACTION ANALYSIS:")
        print(observable_query)
        
        # Save queries to file for reference
        queries_file = "powerquery_examples.txt"
        with open(queries_file, 'w') as f:
            f.write("SentinelOne PowerQuery Examples\n")
            f.write("=" * 40 + "\n\n")
            f.write(f"Parser: {parser_name}\n\n")
            f.write("1. BASIC FIELD EXTRACTION:\n")
            f.write(basic_query + "\n\n")
            f.write("2. OCSF COMPLIANCE CHECK:\n")
            f.write(ocsf_query + "\n\n")
            f.write("3. OBSERVABLE EXTRACTION:\n")
            f.write(observable_query + "\n")
        
        print(f"\n📁 PowerQuery examples saved to: {queries_file}")
        
        return queries_file
    
    def example_7_troubleshooting_guide(self):
        """Example 7: Troubleshooting common issues"""
        print("=" * 70)
        print("EXAMPLE 7: Troubleshooting Common Issues")
        print("=" * 70)
        
        # Test a problematic generator to demonstrate troubleshooting
        problematic_generators = {
            'test_generator': 'test_parser'  # This will likely fail
        }
        
        try:
            results, _ = self.framework.validate_generators(problematic_generators)
            
            for result in results:
                if result.status != 'success':
                    print(f"\n🔍 Troubleshooting {result.generator_name}:")
                    print(f"   Status: {result.status}")
                    
                    if result.status == 'no_events':
                        print("   Issue: No events found in SentinelOne")
                        print("   Possible causes:")
                        print("     - Events not sent via HEC")
                        print("     - Parser name mismatch")
                        print("     - Events still processing (wait 10-15 minutes)")
                        print("     - SDL query syntax issues")
                    
                    elif result.extraction_rate < 30:
                        print("   Issue: Very low field extraction rate")
                        print("   Possible causes:")
                        print("     - Format mismatch (JSON vs syslog vs key=value)")
                        print("     - Parser not configured for generator format")
                        print("     - Field name mapping issues")
                    
                    elif result.ocsf_score < 40:
                        print("   Issue: Poor OCSF compliance")
                        print("   Possible causes:")
                        print("     - Parser missing OCSF field mappings")
                        print("     - Generator not producing OCSF-compatible events")
                        print("     - Parser configuration needs updates")
        
        except Exception as e:
            print(f"🔍 Framework Error Troubleshooting:")
            print(f"   Error: {e}")
            
            if "SDL API token" in str(e):
                print("   Solution: Set S1_SDL_API_TOKEN environment variable")
            elif "connection" in str(e).lower():
                print("   Solution: Check network connectivity to SentinelOne")
            elif "authentication" in str(e).lower():
                print("   Solution: Verify API token has correct permissions")
        
        # Print troubleshooting checklist
        print("\n" + "=" * 70)
        print("TROUBLESHOOTING CHECKLIST")
        print("=" * 70)
        checklist = [
            "✓ Environment variables set (S1_SDL_API_TOKEN)",
            "✓ Network connectivity to SentinelOne",
            "✓ Events sent via HEC within last 4 hours",
            "✓ Parser names match exactly",
            "✓ Generator produces expected format (JSON/syslog/etc)",
            "✓ Wait 10-15 minutes after sending events",
            "✓ Check SentinelOne UI for parsing errors"
        ]
        
        for item in checklist:
            print(f"  {item}")
        
        return checklist
    
    def _get_format_type(self, generator_name: str) -> str:
        """Get the expected format type for a generator"""
        format_map = {
            'aws_guardduty': 'JSON',
            'cisco_firewall_threat_defense': 'Syslog',
            'fortinet_fortigate': 'KV',  # Key=Value
            'microsoft_windows_eventlog': 'XML',
            'okta_authentication': 'JSON',
            'sentinelone_endpoint': 'JSON'
        }
        return format_map.get(generator_name, 'Unknown')
    
    def _get_format_notes(self, result) -> str:
        """Get format-specific notes for analysis"""
        if result.status != 'success':
            return "No events found"
        elif result.extraction_rate < 30:
            return "Possible format mismatch"
        elif result.extraction_rate > 80:
            return "Good format compatibility"
        else:
            return "Moderate extraction"
    
    def _extract_ocsf_fields(self, sample_event: dict) -> str:
        """Extract key OCSF fields from sample event"""
        ocsf_fields = []
        for field in ['class_uid', 'activity_id', 'category_uid', 'severity']:
            if field in sample_event:
                ocsf_fields.append(field)
        
        if not ocsf_fields:
            return "None found"
        
        return ", ".join(ocsf_fields[:3])  # Limit to first 3
    
    def _calculate_category_grade(self, metrics: dict) -> str:
        """Calculate performance grade for a vendor category"""
        avg_score = (metrics['avg_extraction'] + metrics['avg_ocsf'] + metrics['success_rate']) / 3
        
        if avg_score >= 90:
            return 'A+'
        elif avg_score >= 80:
            return 'A'
        elif avg_score >= 70:
            return 'B'
        elif avg_score >= 60:
            return 'C'
        elif avg_score >= 50:
            return 'D'
        else:
            return 'F'

def run_all_examples():
    """Run all example scenarios"""
    print("🚀 SentinelOne Field Validation Framework - Example Usage")
    print("=" * 70)
    
    # Check environment setup
    if not os.getenv('S1_SDL_API_TOKEN'):
        print("⚠️  Warning: S1_SDL_API_TOKEN not set. Examples may not work.")
        print("   Set the environment variable before running examples:")
        print("   export S1_SDL_API_TOKEN='your-token-here'")
        return
    
    examples = FrameworkExamples()
    
    try:
        # Run examples in sequence
        print("\n🔹 Running Example 1: Single Generator Validation")
        examples.example_1_single_generator_validation()
        
        print("\n🔹 Running Example 2: Batch Validation")
        examples.example_2_batch_validation_key_generators()
        
        print("\n🔹 Running Example 3: Format Compatibility Analysis")
        examples.example_3_format_compatibility_analysis()
        
        print("\n🔹 Running Example 4: OCSF Compliance Deep Dive")
        examples.example_4_ocsf_compliance_deep_dive()
        
        print("\n🔹 Running Example 5: Performance Benchmarking")
        examples.example_5_performance_benchmarking()
        
        print("\n🔹 Running Example 6: PowerQuery Templates Demo")
        examples.example_6_powerquery_templates_demo()
        
        print("\n🔹 Running Example 7: Troubleshooting Guide")
        examples.example_7_troubleshooting_guide()
        
        print("\n" + "=" * 70)
        print("✅ All examples completed successfully!")
        print("📁 Check current directory for generated reports and files.")
        
    except Exception as e:
        print(f"\n❌ Example execution failed: {e}")
        print("\n🔍 Troubleshooting tips:")
        print("  1. Ensure S1_SDL_API_TOKEN is set correctly")
        print("  2. Verify network connectivity to SentinelOne")
        print("  3. Check that test events were sent recently")

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description='Field Validation Framework Examples')
    parser.add_argument('--example', type=int, choices=range(1, 8),
                       help='Run specific example (1-7)')
    parser.add_argument('--all', action='store_true',
                       help='Run all examples')
    
    args = parser.parse_args()
    
    examples = FrameworkExamples()
    
    if args.all:
        run_all_examples()
    elif args.example:
        example_methods = {
            1: examples.example_1_single_generator_validation,
            2: examples.example_2_batch_validation_key_generators,
            3: examples.example_3_format_compatibility_analysis,
            4: examples.example_4_ocsf_compliance_deep_dive,
            5: examples.example_5_performance_benchmarking,
            6: examples.example_6_powerquery_templates_demo,
            7: examples.example_7_troubleshooting_guide
        }
        
        print(f"Running Example {args.example}...")
        example_methods[args.example]()
    else:
        print("Use --all to run all examples or --example N to run a specific example (1-7)")
        print("Use --help for more information")