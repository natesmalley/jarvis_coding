#!/usr/bin/env python3
"""
Direct comparison of generator field output vs parser field extraction capabilities
"""
import json
import os
import sys
from pathlib import Path
import importlib
import re

os.environ["S1_HEC_TOKEN"] = "1FUC88b9Z4BaHtQxwIXwYGqFPaVQO7jzXDuYxDuMD2q1s57bX4MvgEMxUCLaH7pbO"

def count_generator_fields(generator_name: str) -> dict:
    """Count actual fields produced by a generator"""
    try:
        from event_generators.shared.hec_sender import PROD_MAP
        
        if generator_name not in PROD_MAP:
            return {"error": f"Generator {generator_name} not found"}
        
        mod_name, func_names = PROD_MAP[generator_name]
        
        # Import module - handle different module path formats
        if not mod_name.startswith("event_generators."):
            # Check if it's a category/module format
            if "/" in mod_name:
                mod_name = f"event_generators.{mod_name.replace('/', '.')}"
            else:
                # Try to find the module in different categories
                categories = ["cloud_infrastructure", "network_security", "endpoint_security", 
                             "identity_access", "email_security", "web_security", "infrastructure"]
                for cat in categories:
                    try:
                        test_mod = f"event_generators.{cat}.{mod_name}"
                        gen_mod = importlib.import_module(test_mod)
                        mod_name = test_mod
                        break
                    except:
                        continue
                else:
                    # Fallback to direct path
                    mod_name = f"event_generators.{mod_name}"
        
        if 'gen_mod' not in locals():
            gen_mod = importlib.import_module(mod_name)
        func = getattr(gen_mod, func_names[0])
        
        # Generate event
        event = func()
        
        # Count fields based on type
        if isinstance(event, dict):
            field_count = count_dict_fields(event)
            return {
                "generator": generator_name,
                "format": "dict/json",
                "actual_fields": field_count,
                "sample_keys": list(event.keys())[:5]
            }
        elif isinstance(event, str):
            # Check if it's JSON
            if event.strip().startswith("{"):
                try:
                    parsed = json.loads(event)
                    field_count = count_dict_fields(parsed)
                    return {
                        "generator": generator_name,
                        "format": "json_string",
                        "actual_fields": field_count,
                        "sample_keys": list(parsed.keys())[:5] if isinstance(parsed, dict) else []
                    }
                except:
                    pass
            
            # For syslog/raw strings, count potential extractable fields
            extractable = count_syslog_fields(event)
            return {
                "generator": generator_name,
                "format": "syslog/raw",
                "actual_fields": extractable,
                "raw_string": event[:100]
            }
        else:
            return {
                "generator": generator_name,
                "format": "unknown",
                "actual_fields": 0
            }
    except Exception as e:
        return {"generator": generator_name, "error": str(e)}

def count_dict_fields(obj, depth=0):
    """Recursively count all fields in a dict"""
    if depth > 10:
        return 0
    
    count = 0
    if isinstance(obj, dict):
        for key, value in obj.items():
            count += 1
            if isinstance(value, dict):
                count += count_dict_fields(value, depth + 1) - 1
            elif isinstance(value, list):
                for item in value:
                    if isinstance(item, dict):
                        count += count_dict_fields(item, depth + 1)
    return count

def count_syslog_fields(log_line: str) -> int:
    """Count extractable fields from a syslog line"""
    field_count = 0
    
    # Count key=value pairs
    kv_pairs = re.findall(r'(\w+)=([^\s]+)', log_line)
    field_count += len(kv_pairs)
    
    # Standard syslog fields
    if re.search(r'<\d+>', log_line):  # Priority
        field_count += 1
    if re.search(r'\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}', log_line):  # Timestamp
        field_count += 1
    if re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', log_line):  # IP addresses
        ips = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', log_line)
        field_count += len(set(ips))  # Unique IPs
    if re.search(r':\d+', log_line):  # Ports
        field_count += len(re.findall(r':(\d+)', log_line))
    
    # If it's CSV/TSV
    if '\t' in log_line or (',' in log_line and not '=' in log_line):
        delimiter = '\t' if '\t' in log_line else ','
        field_count = max(field_count, len(log_line.split(delimiter)))
    
    return max(field_count, 1)  # At least 1 field (the message itself)

def count_parser_fields(parser_name: str) -> dict:
    """Count fields a parser can extract"""
    parser_path = Path(f"parsers/community/{parser_name}")
    if not parser_path.exists():
        return {"parser": parser_name, "error": "Parser not found"}
    
    # Find JSON config
    json_files = list(parser_path.glob("*.json"))
    if not json_files:
        return {"parser": parser_name, "error": "No JSON config"}
    
    try:
        with open(json_files[0], 'r') as f:
            config = json.load(f)
        
        field_count = 0
        
        # Count mappings
        if "mappings" in config:
            field_count = len(config["mappings"])
        
        # Count columns for CSV
        if "columns" in config:
            field_count = max(field_count, len([c for c in config["columns"] if c != "-"]))
        
        # Count regex groups
        if "logPattern" in config:
            pattern = config["logPattern"]
            named_groups = re.findall(r'\?P<(\w+)>', pattern)
            field_count = max(field_count, len(named_groups))
        
        return {
            "parser": parser_name,
            "parser_fields": field_count,
            "parse_type": config.get("parse", "regex")
        }
    except Exception as e:
        return {"parser": parser_name, "error": str(e)}

def main():
    from event_generators.shared.hec_sender import PROD_MAP, SOURCETYPE_MAP
    
    # Priority generators to analyze
    priority_generators = [
        "aws_guardduty", "aws_cloudtrail", "aws_waf", "aws_vpcflowlogs",
        "microsoft_365_defender", "microsoft_azuread", "okta_authentication",
        "cisco_fmc", "cisco_asa", "cisco_duo", "paloalto_firewall",
        "fortinet_fortigate", "crowdstrike_falcon", "sentinelone_endpoint",
        "proofpoint", "mimecast", "cloudflare_waf", "zscaler", "netskope",
        "cyberark_pas", "hashicorp_vault", "jamf_protect", "linux_auth"
    ]
    
    results = []
    
    print("=" * 80)
    print("GENERATOR FIELD OUTPUT vs PARSER EXTRACTION CAPABILITY")
    print("=" * 80)
    print(f"{'Generator':<30} {'Format':<15} {'Gen Fields':<12} {'Parser Fields':<12} Status")
    print("-" * 80)
    
    for gen_name in priority_generators:
        if gen_name not in PROD_MAP:
            continue
            
        # Count generator fields
        gen_result = count_generator_fields(gen_name)
        
        # Get parser and count its fields
        parser_name = SOURCETYPE_MAP.get(gen_name)
        if parser_name:
            parser_result = count_parser_fields(parser_name)
        else:
            parser_result = {"parser_fields": 0}
        
        # Compare
        gen_fields = gen_result.get("actual_fields", 0)
        parser_fields = parser_result.get("parser_fields", 0)
        
        if "error" in gen_result:
            status = f"❌ Gen error: {gen_result['error'][:20]}"
        elif "error" in parser_result:
            status = f"⚠️ Parser error: {parser_result['error'][:20]}"
        elif gen_fields > 0 and parser_fields > 0:
            ratio = (min(gen_fields, parser_fields) / max(gen_fields, parser_fields)) * 100
            if ratio > 80:
                status = f"✅ Good match ({ratio:.0f}%)"
            elif ratio > 50:
                status = f"🟡 Partial match ({ratio:.0f}%)"
            else:
                status = f"🔴 Poor match ({ratio:.0f}%)"
        elif gen_fields > 0:
            status = "⚠️ No parser fields"
        else:
            status = "❌ No data"
        
        print(f"{gen_name:<30} {gen_result.get('format', 'unknown'):<15} "
              f"{gen_fields:<12} {parser_fields:<12} {status}")
        
        results.append({
            "generator": gen_name,
            "format": gen_result.get("format", "unknown"),
            "generator_fields": gen_fields,
            "parser_fields": parser_fields,
            "status": status,
            "sample_keys": gen_result.get("sample_keys", [])
        })
    
    # Summary
    print("\n" + "=" * 80)
    print("SUMMARY")
    print("=" * 80)
    
    # Group by format
    by_format = {}
    for r in results:
        fmt = r["format"]
        if fmt not in by_format:
            by_format[fmt] = []
        by_format[fmt].append(r)
    
    print("\n📊 By Format:")
    for fmt, items in by_format.items():
        avg_gen = sum(r["generator_fields"] for r in items) / len(items) if items else 0
        avg_parser = sum(r["parser_fields"] for r in items) / len(items) if items else 0
        print(f"  {fmt:<15} {len(items):2} generators, "
              f"avg {avg_gen:.1f} gen fields, {avg_parser:.1f} parser fields")
    
    # Top performers
    sorted_by_fields = sorted(results, key=lambda x: x["generator_fields"], reverse=True)
    
    print("\n🏆 Top Generators by Field Count:")
    for r in sorted_by_fields[:5]:
        print(f"  {r['generator']:<30} {r['generator_fields']:3} fields ({r['format']})")
    
    # Mismatches
    mismatches = [r for r in results if "Poor match" in r.get("status", "")]
    if mismatches:
        print("\n⚠️ Poor Field Matching (needs attention):")
        for r in mismatches[:5]:
            print(f"  {r['generator']:<30} Gen: {r['generator_fields']:3}, Parser: {r['parser_fields']:3}")
    
    # Save results
    with open("field_extraction_results.json", "w") as f:
        json.dump(results, f, indent=2)
    
    print(f"\n💾 Results saved to: field_extraction_results.json")

if __name__ == "__main__":
    main()