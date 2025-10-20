#!/usr/bin/env python3
"""Update import paths in hec_sender.py after reorganization"""

import os
import sys

# Generator categories and their modules
CATEGORY_MAP = {
    'cloud_infrastructure': [
        'aws_cloudtrail', 'aws_elasticloadbalancer', 'aws_guardduty', 'aws_route53', 
        'aws_vpc_dns', 'aws_vpcflowlogs', 'aws_waf', 'google_cloud_dns', 'google_workspace'
    ],
    'network_security': [
        'cisco_asa', 'cisco_duo', 'cisco_firewall_threat_defense', 'cisco_fmc', 'cisco_ios',
        'cisco_ironport', 'cisco_isa3000', 'cisco_ise', 'cisco_meraki', 'cisco_meraki_flow',
        'cisco_networks', 'cisco_umbrella', 'paloalto_firewall', 'paloalto_prismasase',
        'fortinet_fortigate', 'f5_networks', 'f5_vpn', 'checkpoint', 'extreme_networks',
        'juniper_networks', 'corelight_conn', 'corelight_http', 'corelight_ssl', 'corelight_tunnel',
        'darktrace', 'extrahop', 'vectra_ai', 'manch_siem', 'armis', 'infoblox_ddi',
        'apache_http', 'forcepoint_firewall', 'fortimanager', 'aruba_clearpass'
    ],
    'endpoint_security': [
        'crowdstrike_falcon', 'sentinelone_endpoint', 'sentinelone_identity', 'microsoft_windows_eventlog',
        'jamf_protect', 'linux_auth'
    ],
    'identity_access': [
        'okta_authentication', 'microsoft_azuread', 'microsoft_azure_ad', 'microsoft_azure_ad_signin',
        'microsoft_365_collaboration', 'microsoft_365_defender', 'microsoft_365_mgmt_api',
        'microsoft_eventhub_azure_signin', 'microsoft_eventhub_defender_email', 
        'microsoft_eventhub_defender_emailforcloud', 'pingfederate', 'pingone_mfa', 'pingprotect',
        'rsa_adaptive', 'hypr_auth', 'cyberark_conjur', 'cyberark_pas', 'beyondtrust_passwordsafe',
        'beyondtrust_privilegemgmt_windows', 'hashicorp_vault'
    ],
    'email_security': [
        'mimecast', 'proofpoint', 'abnormal_security', 'microsoft_defender_email'
    ],
    'web_security': [
        'zscaler', 'zscaler_dns_firewall', 'zscaler_firewall', 'zscaler_private_access',
        'cloudflare_general', 'cloudflare_waf', 'imperva_sonar', 'imperva_waf', 'incapsula',
        'akamai_cdn', 'akamai_dns', 'akamai_general', 'akamai_sitedefender', 'netskope'
    ],
    'infrastructure': [
        'veeam_backup', 'cohesity_backup', 'vmware_vcenter', 'github_audit', 'buildkite',
        'harness_ci', 'iis_w3c', 'isc_bind', 'isc_dhcp', 'axway_sftp', 'wiz_cloud',
        'sap', 'tailscale', 'teleport', 'ubiquiti_unifi', 'windows_dhcp',
        'manageengine_adauditplus', 'manageengine_general', 'securelink'
    ]
}

def get_generator_category(generator_name):
    """Find which category a generator belongs to"""
    for category, generators in CATEGORY_MAP.items():
        if generator_name in generators:
            return category
    return None

def update_hec_sender_imports():
    """Update the hec_sender.py file with new import paths"""
    hec_sender_path = 'event_generators/shared/hec_sender.py'
    
    if not os.path.exists(hec_sender_path):
        print(f"Error: {hec_sender_path} not found")
        return
    
    with open(hec_sender_path, 'r') as f:
        content = f.read()
    
    # Add sys.path modifications at the top
    sys_path_addition = '''
# Add generator category paths to sys.path
import os
import sys
current_dir = os.path.dirname(os.path.abspath(__file__))
generator_root = os.path.dirname(current_dir)
for category in ['cloud_infrastructure', 'network_security', 'endpoint_security', 
                 'identity_access', 'email_security', 'web_security', 'infrastructure']:
    sys.path.insert(0, os.path.join(generator_root, category))
'''
    
    # Insert after the first import line
    lines = content.split('\n')
    import_line_idx = next(i for i, line in enumerate(lines) if line.startswith('import '))
    lines.insert(import_line_idx + 1, sys_path_addition)
    
    # Write the updated file
    with open(hec_sender_path, 'w') as f:
        f.write('\n'.join(lines))
    
    print(f"Updated {hec_sender_path} with new import paths")

if __name__ == "__main__":
    update_hec_sender_imports()