#!/usr/bin/env python3
"""
Validate actual field extraction in SentinelOne by sending events and checking what fields are extracted
"""
import subprocess
import sys
import time
import json
import os
import uuid
from datetime import datetime
from typing import Dict, List, Any

class SentinelOneFieldValidator:
    def __init__(self):
        self.hec_token = "1FUC88b9Z4BaHtQxwIXwYGqFPaVQO7jzXDuYxDuMD2q1s57bX4MvgEMxUCLaH7pbO"
        os.environ["S1_HEC_TOKEN"] = self.hec_token
        self.results = {}
        self.test_id = str(uuid.uuid4())[:8]
        
    def send_test_event(self, generator: str) -> Dict[str, Any]:
        """Send a test event with a tracking ID"""
        print(f"\n📤 Sending {generator} test event...")
        
        # Add tracking ID to help find the event later
        tracking_id = f"test_{generator}_{self.test_id}"
        
        try:
            cmd = [
                sys.executable,
                "event_generators/shared/hec_sender.py",
                "--product", generator,
                "--count", "1"
            ]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=30
            )
            
            # Check for success in stdout or if return code is 0 with HEC response
            if result.returncode == 0 and ("successfully" in result.stdout.lower() or 
                                          "Success" in result.stdout or 
                                          "HEC response" in result.stdout):
                print(f"  ✅ Event sent successfully")
                return {
                    "success": True,
                    "tracking_id": tracking_id,
                    "timestamp": datetime.utcnow().isoformat()
                }
            else:
                print(f"  ❌ Failed to send: {result.stderr[:100]}")
                return {"success": False, "error": result.stderr[:200]}
                
        except Exception as e:
            print(f"  ❌ Error: {str(e)}")
            return {"success": False, "error": str(e)}
    
    def count_local_fields(self, generator: str) -> int:
        """Count fields the generator produces locally"""
        try:
            from event_generators.shared.hec_sender import PROD_MAP
            import importlib
            
            if generator not in PROD_MAP:
                return 0
            
            mod_name, func_names = PROD_MAP[generator]
            
            # Handle module paths
            if "/" in mod_name:
                mod_name = f"event_generators.{mod_name.replace('/', '.')}"
            elif not mod_name.startswith("event_generators."):
                # Find in categories
                categories = ["cloud_infrastructure", "network_security", "endpoint_security",
                             "identity_access", "email_security", "web_security", "infrastructure"]
                for cat in categories:
                    try:
                        test_mod = f"event_generators.{cat}.{mod_name}"
                        gen_mod = importlib.import_module(test_mod)
                        break
                    except:
                        continue
                else:
                    return 0
            else:
                gen_mod = importlib.import_module(mod_name)
            
            func = getattr(gen_mod, func_names[0])
            event = func()
            
            # Count fields
            if isinstance(event, dict):
                return self._count_dict_fields(event)
            elif isinstance(event, str):
                if event.strip().startswith("{"):
                    try:
                        parsed = json.loads(event)
                        return self._count_dict_fields(parsed)
                    except:
                        pass
                # For syslog, estimate extractable fields
                return self._count_syslog_fields(event)
            
            return 1
            
        except Exception as e:
            print(f"  ⚠️ Error counting fields: {e}")
            return 0
    
    def _count_dict_fields(self, obj, depth=0):
        """Count all fields in a nested dict"""
        if depth > 10:
            return 0
        count = 0
        if isinstance(obj, dict):
            for key, value in obj.items():
                count += 1
                if isinstance(value, dict):
                    count += self._count_dict_fields(value, depth + 1) - 1
                elif isinstance(value, list):
                    for item in value:
                        if isinstance(item, dict):
                            count += self._count_dict_fields(item, depth + 1)
        return count
    
    def _count_syslog_fields(self, log_line: str) -> int:
        """Estimate extractable fields from syslog"""
        import re
        field_count = 0
        
        # Key=value pairs
        kv_pairs = re.findall(r'(\w+)=([^\s]+)', log_line)
        field_count += len(kv_pairs)
        
        # Standard fields
        if re.search(r'<\d+>', log_line):
            field_count += 1
        if re.search(r'\d{4}-\d{2}-\d{2}|\w{3}\s+\d{1,2}', log_line):
            field_count += 1
        
        # IPs and ports
        ips = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', log_line)
        field_count += len(set(ips))
        
        ports = re.findall(r':(\d+)', log_line)
        field_count += len(set(ports))
        
        # CSV/TSV
        if '\t' in log_line or (',' in log_line and '=' not in log_line):
            delimiter = '\t' if '\t' in log_line else ','
            field_count = max(field_count, len(log_line.split(delimiter)))
        
        return max(field_count, 1)
    
    def validate_generator(self, generator: str) -> Dict[str, Any]:
        """Validate a single generator's field extraction"""
        print(f"\n{'='*60}")
        print(f"Validating: {generator}")
        print(f"{'='*60}")
        
        # Count local fields
        local_fields = self.count_local_fields(generator)
        print(f"📊 Local field count: {local_fields}")
        
        # Send test event
        send_result = self.send_test_event(generator)
        
        if not send_result.get("success"):
            return {
                "generator": generator,
                "local_fields": local_fields,
                "sent": False,
                "sentinelone_fields": 0,
                "extraction_rate": 0,
                "error": send_result.get("error")
            }
        
        # Wait for processing
        print(f"⏳ Waiting 10 seconds for SentinelOne processing...")
        time.sleep(10)
        
        # Note: Actual field extraction would be verified via SDL API or UI
        print(f"📝 Check SentinelOne UI for extracted fields:")
        print(f"   URL: https://usea1-purple.sentinelone.net")
        print(f"   Navigate to: Investigate → Events")
        print(f"   Filter: Last 10 minutes")
        print(f"   Look for: {generator} events")
        
        return {
            "generator": generator,
            "local_fields": local_fields,
            "sent": True,
            "sentinelone_fields": "Check UI",
            "tracking_id": send_result.get("tracking_id"),
            "timestamp": send_result.get("timestamp")
        }
    
    def run_validation(self, generators: List[str]) -> None:
        """Run validation for multiple generators"""
        print("🔍 SentinelOne Field Extraction Validation")
        print("=" * 60)
        print(f"Test ID: {self.test_id}")
        print(f"Generators to test: {len(generators)}")
        
        for generator in generators:
            result = self.validate_generator(generator)
            self.results[generator] = result
        
        self.generate_report()
    
    def generate_report(self) -> None:
        """Generate validation report"""
        print("\n" + "=" * 60)
        print("VALIDATION REPORT")
        print("=" * 60)
        
        successful = [r for r in self.results.values() if r.get("sent")]
        failed = [r for r in self.results.values() if not r.get("sent")]
        
        print(f"\n📊 Summary:")
        print(f"  Total tested: {len(self.results)}")
        print(f"  Successfully sent: {len(successful)}")
        print(f"  Failed to send: {len(failed)}")
        
        if successful:
            print(f"\n✅ Successfully Sent Events:")
            print(f"{'Generator':<30} {'Local Fields':<15} {'Tracking ID':<20}")
            print("-" * 65)
            for r in successful:
                print(f"{r['generator']:<30} {r['local_fields']:<15} {r.get('tracking_id', 'N/A'):<20}")
        
        if failed:
            print(f"\n❌ Failed Events:")
            for r in failed:
                print(f"  {r['generator']}: {r.get('error', 'Unknown error')[:50]}")
        
        # Save results
        with open(f"sentinelone_validation_{self.test_id}.json", "w") as f:
            json.dump(self.results, f, indent=2)
        
        print(f"\n💾 Results saved to: sentinelone_validation_{self.test_id}.json")
        
        print("\n" + "=" * 60)
        print("NEXT STEPS:")
        print("=" * 60)
        print("1. Go to: https://usea1-purple.sentinelone.net")
        print("2. Navigate to: Investigate → Events")
        print("3. Filter by: Last 15 minutes")
        print("4. For each generator, count the extracted fields")
        print("5. Compare with the 'Local Fields' count above")
        print("6. Document any field extraction gaps")

def main():
    # High-priority generators to validate
    test_generators = [
        # AWS services
        "aws_guardduty",
        "aws_cloudtrail",
        "aws_waf",
        
        # Microsoft
        "microsoft_365_defender",
        "microsoft_azuread",
        
        # Network security
        "cisco_fmc",
        "cisco_asa",
        "paloalto_firewall",
        "fortinet_fortigate",
        
        # Endpoint
        "crowdstrike_falcon",
        "sentinelone_endpoint",
        
        # Identity
        "okta_authentication",
        "cisco_duo",
        
        # Cloud security
        "zscaler",
        "cloudflare_waf"
    ]
    
    validator = SentinelOneFieldValidator()
    validator.run_validation(test_generators)

if __name__ == "__main__":
    main()