#!/usr/bin/env python3
"""
Count the number of fields each generator produces
"""
import sys
import json
import importlib
from pathlib import Path
from typing import Dict, Any

# Add project root to path
sys.path.insert(0, '.')

def count_fields(obj, depth=0) -> int:
    """Recursively count all fields in a nested structure"""
    if depth > 10:  # Prevent infinite recursion
        return 0
        
    count = 0
    
    if isinstance(obj, dict):
        for key, value in obj.items():
            count += 1  # Count the key itself
            if isinstance(value, (dict, list)):
                count += count_fields(value, depth + 1) - 1  # Don't double count
            
    elif isinstance(obj, list):
        for item in obj:
            if isinstance(item, (dict, list)):
                count += count_fields(item, depth + 1)
                
    return count

def analyze_generator(generator_name: str) -> Dict[str, Any]:
    """Analyze a single generator"""
    try:
        # Set HEC token
        import os
        os.environ["S1_HEC_TOKEN"] = "1FUC88b9Z4BaHtQxwIXwYGqFPaVQO7jzXDuYxDuMD2q1s57bX4MvgEMxUCLaH7pbO"
        
        # Import from hec_sender's PROD_MAP
        from event_generators.shared.hec_sender import PROD_MAP
        
        if generator_name not in PROD_MAP:
            return {"error": f"Generator {generator_name} not found in PROD_MAP"}
        
        mod_name, func_names = PROD_MAP[generator_name]
        
        # Import the module
        gen_mod = importlib.import_module(mod_name)
        
        # Get the function
        func = getattr(gen_mod, func_names[0])
        
        # Generate an event
        event = func()
        
        # Analyze the event
        if isinstance(event, dict):
            field_count = count_fields(event)
            event_type = "dict"
            sample_keys = list(event.keys())[:10]
        elif isinstance(event, str):
            field_count = 1 if event else 0
            event_type = "string"
            # Try to detect format
            if event.startswith("{"):
                try:
                    parsed = json.loads(event)
                    field_count = count_fields(parsed)
                    event_type = "json_string"
                    sample_keys = list(parsed.keys())[:10] if isinstance(parsed, dict) else []
                except:
                    sample_keys = []
            else:
                sample_keys = []
        else:
            field_count = 1
            event_type = type(event).__name__
            sample_keys = []
        
        return {
            "generator": generator_name,
            "module": mod_name,
            "function": func_names[0],
            "field_count": field_count,
            "event_type": event_type,
            "sample_keys": sample_keys,
            "sample_size": len(str(event)) if event else 0
        }
        
    except Exception as e:
        return {
            "generator": generator_name,
            "error": str(e)
        }

def main():
    # Test generators
    generators = [
        "aws_guardduty",
        "aws_cloudtrail",
        "aws_waf",
        "aws_vpcflowlogs",
        "aws_route53",
        "aws_vpc_dns",
        "microsoft_365_defender",
        "microsoft_365_collaboration",
        "microsoft_azuread",
        "okta_authentication",
        "cisco_fmc",
        "cisco_asa",
        "cisco_duo",
        "paloalto_firewall",
        "fortinet_fortigate",
        "crowdstrike_falcon",
        "sentinelone_endpoint",
        "sentinelone_identity",
        "proofpoint",
        "mimecast",
        "cloudflare_waf",
        "zscaler",
        "netskope",
        "cyberark_pas",
        "hashicorp_vault",
        "beyondtrust_passwordsafe",
        "jamf_protect",
        "linux_auth",
        "pingfederate",
        "pingone_mfa"
    ]
    
    print("=" * 80)
    print("GENERATOR FIELD COUNT ANALYSIS")
    print("=" * 80)
    print(f"{'Generator':<30} {'Type':<15} {'Fields':<10} {'Size':<10} Status")
    print("-" * 80)
    
    results = []
    
    for generator in generators:
        result = analyze_generator(generator)
        
        if "error" in result:
            print(f"{generator:<30} {'ERROR':<15} {'N/A':<10} {'N/A':<10} ❌ {result['error'][:30]}")
        else:
            status = "✅" if result["field_count"] > 0 else "⚠️"
            print(f"{result['generator']:<30} {result['event_type']:<15} {result['field_count']:<10} {result['sample_size']:<10} {status}")
            
            if result["sample_keys"]:
                print(f"{'':30} Sample fields: {', '.join(result['sample_keys'][:5])}")
        
        results.append(result)
    
    # Summary statistics
    successful = [r for r in results if "error" not in r]
    
    if successful:
        print("\n" + "=" * 80)
        print("SUMMARY")
        print("=" * 80)
        
        # Group by type
        by_type = {}
        for r in successful:
            event_type = r["event_type"]
            if event_type not in by_type:
                by_type[event_type] = []
            by_type[event_type].append(r)
        
        print("\n📊 Event Types:")
        for event_type, items in by_type.items():
            avg_fields = sum(r["field_count"] for r in items) / len(items)
            print(f"  {event_type:<20} {len(items):3} generators, avg {avg_fields:.1f} fields")
        
        # Top performers
        sorted_results = sorted(successful, key=lambda x: x["field_count"], reverse=True)
        
        print("\n🏆 Top 10 (Most Fields):")
        for r in sorted_results[:10]:
            print(f"  {r['generator']:<30} {r['field_count']:3} fields ({r['event_type']})")
        
        print("\n⚠️ Bottom 10 (Fewest Fields):")
        for r in sorted_results[-10:]:
            if r["field_count"] < 5:
                print(f"  {r['generator']:<30} {r['field_count']:3} fields ({r['event_type']})")
        
        # Overall stats
        total_fields = sum(r["field_count"] for r in successful)
        avg_fields = total_fields / len(successful)
        
        print(f"\n📈 Overall Statistics:")
        print(f"  Total generators analyzed: {len(generators)}")
        print(f"  Successful: {len(successful)}")
        print(f"  Failed: {len(results) - len(successful)}")
        print(f"  Average fields per generator: {avg_fields:.1f}")
        print(f"  Total unique fields: {total_fields}")
    
    # Save results
    with open("generator_field_counts.json", "w") as f:
        json.dump(results, f, indent=2)
    
    print(f"\n💾 Results saved to: generator_field_counts.json")

if __name__ == "__main__":
    main()