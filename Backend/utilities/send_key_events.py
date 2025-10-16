#!/usr/bin/env python3
"""
Simple Key Events Sender - Send substantial volumes from key generators
"""
import subprocess
import os

os.environ['S1_HEC_TOKEN'] = '1FUC88b9Z4BaHtQxwIXwYGpMGEMv7UQ1JjPHEkERjDEe2U7_AS67SJJRpbIqk78h7'

# Key generators with event counts
KEY_GENERATORS = [
    # AWS (should get substantial volume)
    ("aws_cloudtrail", 12),
    ("aws_guardduty", 8),
    ("aws_vpcflowlogs", 10),
    ("aws_waf", 8),
    ("aws_route53", 6),
    
    # Network Security
    ("fortinet_fortigate", 10),
    ("cisco_asa", 8),
    ("cisco_fmc", 6),
    ("cisco_duo", 8),
    ("paloalto_firewall", 6),
    
    # Identity
    ("okta_authentication", 10),
    ("microsoft_azuread", 8),
    ("pingfederate", 6),
    ("cyberark_pas", 6),
    
    # Endpoint
    ("sentinelone_endpoint", 10),
    ("crowdstrike_falcon", 8),
    ("jamf_protect", 6),
    
    # Web Security
    ("zscaler", 8),
    ("cloudflare_general", 6),
    ("imperva_waf", 6),
    
    # Email
    ("abnormal_security", 6),
    ("mimecast", 8),
    ("proofpoint", 6),
    
    # Network Analysis
    ("darktrace", 8),
    ("corelight_conn", 10),
    ("corelight_http", 8),
    
    # Others
    ("linux_auth", 8),
    ("buildkite", 6),
    ("github_audit", 6),
]

# Key marketplace parsers
MARKETPLACE_PARSERS = [
    ("marketplace-checkpointfirewall-latest", 8),
    ("marketplace-fortinetfortigate-latest", 10),
    ("marketplace-ciscofirewallthreatdefense-latest", 8),
    ("marketplace-zscalerinternetaccess-latest", 8),
    ("marketplace-zscalerprivateaccess-latest", 6),
    ("marketplace-corelight-conn-latest", 10),
    ("marketplace-paloaltonetworksfirewall-latest", 6),
]

def send_events(product, count, is_marketplace=False):
    """Send events from a generator"""
    try:
        if is_marketplace:
            cmd = ['.venv/bin/python', 'event_python_writer/hec_sender.py', 
                   '--marketplace-parser', product, '--count', str(count)]
            print(f"📤 MARKETPLACE {product:45s} → {count:2d} events", end=" ")
        else:
            cmd = ['.venv/bin/python', 'event_python_writer/hec_sender.py', 
                   '--product', product, '--count', str(count)]
            print(f"📤 COMMUNITY   {product:45s} → {count:2d} events", end=" ")
        
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=45)
        
        if result.returncode == 0 and 'Success' in result.stdout:
            success_count = result.stdout.count("'code': 0")
            print(f"✅ {success_count} sent")
            return success_count
        else:
            print(f"❌ Failed")
            return 0
            
    except Exception as e:
        print(f"❌ Error: {str(e)[:50]}")
        return 0

def main():
    print("🚀 KEY EVENTS SENDER")
    print("=" * 80)
    
    total_sent = 0
    
    print("📊 COMMUNITY GENERATORS")
    print("-" * 80)
    for product, count in KEY_GENERATORS:
        sent = send_events(product, count)
        total_sent += sent
    
    print(f"\n🏪 MARKETPLACE PARSERS")  
    print("-" * 80)
    for parser, count in MARKETPLACE_PARSERS:
        sent = send_events(parser, count, is_marketplace=True)
        total_sent += sent
    
    print(f"\n✅ COMPLETE - {total_sent} total events sent")
    print(f"🔍 Should see ~{total_sent} events in SentinelOne from {len(KEY_GENERATORS) + len(MARKETPLACE_PARSERS)} different sources")

if __name__ == "__main__":
    main()