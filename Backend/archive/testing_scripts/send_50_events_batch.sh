#!/bin/bash

# Send 50 events for all working generators
export S1_HEC_TOKEN="1FUC88b9Z4BaHtQxwIXwYGqFPaVQO7jzXDuYxDuMD2q1s57bX4MvgEMxUCLaH7pbO"

echo "🚀 SENDING 50 EVENTS FOR ALL WORKING GENERATORS"
echo "==============================================="
echo "Started at: $(date)"
echo ""

# List of all working generators (96 total from previous successful run)
generators=(
    # Cloud Infrastructure (9 working)
    aws_cloudtrail aws_elasticloadbalancer aws_guardduty aws_route53 
    aws_vpc_dns aws_vpcflowlogs aws_waf google_cloud_dns google_workspace
    
    # Network Security (32 working)
    akamai_cdn akamai_dns akamai_general akamai_sitedefender cisco_asa
    cisco_firewall_threat_defense cisco_fmc cisco_ios cisco_ironport
    cisco_ise cisco_meraki cisco_meraki_flow cisco_networks cisco_umbrella
    cloudflare_general corelight_conn corelight_http corelight_ssl
    corelight_tunnel extreme_networks f5_networks f5_vpn fortinet_fortigate
    isc_bind isc_dhcp juniper_networks paloalto_firewall paloalto_prismasase
    ubiquiti_unifi zscaler zscaler_dns_firewall zscaler_firewall
    
    # Endpoint Security (6 working)
    crowdstrike_falcon jamf_protect microsoft_windows_eventlog
    sentinelone_endpoint sentinelone_identity armis
    
    # Identity Access (17 working)
    beyondtrust_passwordsafe cisco_duo cyberark_conjur cyberark_pas
    hashicorp_vault hypr_auth microsoft_365_collaboration
    microsoft_365_defender microsoft_365_mgmt_api microsoft_azure_ad_signin
    microsoft_azuread okta_authentication pingfederate pingone_mfa
    pingprotect rsa_adaptive securelink
    
    # Email Security (4 working)
    abnormal_security mimecast microsoft_defender_email proofpoint
    
    # Web Security (9 working)
    apache_http cloudflare_waf iis_w3c imperva_sonar imperva_waf
    incapsula linux_auth netskope tailscale
    
    # Infrastructure (19 working)
    axway_sftp buildkite cohesity_backup darktrace extrahop github_audit
    harness_ci manageengine_adauditplus manageengine_general manch_siem
    microsoft_azure_ad microsoft_eventhub_azure_signin
    microsoft_eventhub_defender_email microsoft_eventhub_defender_emailforcloud
    sap teleport veeam_backup vectra_ai wiz_cloud
)

total=${#generators[@]}
success=0
failed=0

for product in "${generators[@]}"; do
    echo -n "[$((success + failed + 1))/$total] $product: "
    if .venv/bin/python3 event_generators/shared/hec_sender.py --product $product --count 50 2>/dev/null; then
        ((success++))
        echo " ✅"
    else
        ((failed++))
        echo " ❌"
    fi
done

# Summary
echo ""
echo "==============================================="
echo "📊 SUMMARY"
echo "==============================================="
echo "✅ Successful: $success/$total"
echo "❌ Failed: $failed/$total"
echo "📈 Success Rate: $(( success * 100 / total ))%"
echo "🎯 Total Events Sent: $(( success * 50 ))"
echo "🕐 Completed at: $(date)"