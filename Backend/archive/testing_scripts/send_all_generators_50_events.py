#!/usr/bin/env python3
"""
Send 50 events for all generators to SentinelOne
================================================
"""

import subprocess
import sys
import os
import time
from datetime import datetime

# Set HEC token
os.environ['S1_HEC_TOKEN'] = '1FUC88b9Z4BaHtQxwIXwYGqFPaVQO7jzXDuYxDuMD2q1s57bX4MvgEMxUCLaH7pbO'

# List of working generators (based on previous run, excluding the 5 that failed)
generators = {
    "cloud_infrastructure": [
        "aws_cloudtrail",
        "aws_elasticloadbalancer",
        # "aws_elb",  # Failed
        "aws_guardduty",
        "aws_route53",
        "aws_vpc_dns",
        # "aws_vpcflow",  # Failed
        "aws_vpcflowlogs",
        "aws_waf",
        "google_cloud_dns",
        "google_workspace"
    ],
    "network_security": [
        "akamai_cdn",
        "akamai_dns",
        "akamai_general",
        "akamai_sitedefender",
        "cisco_asa",
        "cisco_firewall_threat_defense",
        "cisco_fmc",
        "cisco_ios",
        "cisco_ironport",
        # "cisco_isa3000",  # Failed
        "cisco_ise",
        "cisco_meraki",
        "cisco_meraki_flow",
        "cisco_networks",
        "cisco_umbrella",
        "cloudflare_general",
        "corelight_conn",
        "corelight_http",
        "corelight_ssl",
        "corelight_tunnel",
        "extreme_networks",
        "f5_networks",
        "f5_vpn",
        "fortinet_fortigate",
        "isc_bind",
        "isc_dhcp",
        "juniper_networks",
        "paloalto_firewall",
        "paloalto_prismasase",
        "ubiquiti_unifi",
        "zscaler",
        "zscaler_dns_firewall",
        "zscaler_firewall"
    ],
    "endpoint_security": [
        "crowdstrike_falcon",
        "jamf_protect",
        "microsoft_windows_eventlog",
        "sentinelone_endpoint",
        "sentinelone_identity",
        "armis"
    ],
    "identity_access": [
        "beyondtrust_passwordsafe",
        # "beyondtrust_privilegemgmtwindows",  # Failed
        "cisco_duo",
        "cyberark_conjur",
        "cyberark_pas",
        "hashicorp_vault",
        "hypr_auth",
        "microsoft_365_collaboration",
        "microsoft_365_defender",
        "microsoft_365_mgmt_api",
        "microsoft_azure_ad_signin",
        "microsoft_azuread",
        "okta_authentication",
        "pingfederate",
        "pingone_mfa",
        "pingprotect",
        "rsa_adaptive",
        "securelink"
    ],
    "email_security": [
        "abnormal_security",
        "mimecast",
        "microsoft_defender_email",
        "proofpoint"
    ],
    "web_security": [
        "apache_http",
        "cloudflare_waf",
        "iis_w3c",
        "imperva_sonar",
        "imperva_waf",
        "incapsula",
        "linux_auth",
        "netskope",
        "tailscale"
    ],
    "infrastructure": [
        "axway_sftp",
        "buildkite",
        "cohesity_backup",
        "darktrace",
        # "darktrace_darktrace",  # Failed
        "extrahop",
        "github_audit",
        "harness_ci",
        "manageengine_adauditplus",
        "manageengine_general",
        "manch_siem",
        "microsoft_azure_ad",
        "microsoft_eventhub_azure_signin",
        "microsoft_eventhub_defender_email",
        "microsoft_eventhub_defender_emailforcloud",
        "sap",
        "teleport",
        "veeam_backup",
        "vectra_ai",
        "wiz_cloud"
    ]
}

def send_events_for_generator(product: str, count: int = 50) -> bool:
    """Send events for a specific generator"""
    try:
        cmd = [
            '.venv/bin/python3',
            'event_generators/shared/hec_sender.py',
            '--product', product,
            '--count', str(count)
        ]
        
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=60
        )
        
        if result.returncode == 0:
            print(f"   ✅ {product}: Successfully sent {count} events")
            return True
        else:
            print(f"   ❌ {product}: Failed - {result.stderr[:100]}")
            return False
            
    except subprocess.TimeoutExpired:
        print(f"   ⏰ {product}: Timeout after 60 seconds")
        return False
    except Exception as e:
        print(f"   ❌ {product}: Error - {str(e)[:100]}")
        return False

def main():
    """Send 50 events for all generators"""
    print("🚀 SENDING 50 EVENTS FOR ALL GENERATORS")
    print("=" * 60)
    print(f"Started at: {datetime.now()}")
    print()
    
    total_generators = sum(len(gen_list) for gen_list in generators.values())
    successful = 0
    failed = 0
    
    for category, gen_list in generators.items():
        print(f"\n📁 {category.upper().replace('_', ' ')} ({len(gen_list)} generators)")
        print("-" * 40)
        
        for generator in gen_list:
            if send_events_for_generator(generator, 50):
                successful += 1
            else:
                failed += 1
            
            # Small delay to avoid overwhelming the HEC endpoint
            time.sleep(0.5)
    
    # Summary
    print("\n" + "=" * 60)
    print("📊 SUMMARY")
    print("=" * 60)
    print(f"✅ Successful: {successful}/{total_generators}")
    print(f"❌ Failed: {failed}/{total_generators}")
    print(f"📈 Success Rate: {(successful/total_generators)*100:.1f}%")
    print(f"🕐 Completed at: {datetime.now()}")
    
    # Calculate total events sent
    total_events = successful * 50
    print(f"\n🎯 Total Events Sent: {total_events:,}")
    
    # Save results to file
    with open('generator_50_events_results.txt', 'w') as f:
        f.write(f"Successfully sent 50 events for {successful}/{total_generators} generators\n")
        f.write(f"Total Events Sent: {total_events}\n")
        f.write(f"Completed at: {datetime.now()}\n")

if __name__ == "__main__":
    main()