#!/bin/bash

# Send 20 events for all generators to SentinelOne
export S1_HEC_TOKEN="1FUC88b9Z4BaHtQxwIXwYGqFPaVQO7jzXDuYxDuMD2q1s57bX4MvgEMxUCLaH7pbO"

echo "🚀 SENDING 20 EVENTS FOR ALL GENERATORS"
echo "========================================"
echo "Started at: $(date)"
echo ""

# Counter variables
total=0
success=0
failed=0

# Cloud Infrastructure
echo "📁 CLOUD INFRASTRUCTURE"
echo "------------------------"
for product in aws_cloudtrail aws_elasticloadbalancer aws_elb aws_guardduty aws_route53 aws_vpc_dns aws_vpcflow aws_vpcflowlogs aws_waf google_cloud_dns google_workspace; do
    echo -n "  $product: "
    if .venv/bin/python3 event_generators/shared/hec_sender.py --product $product --count 20 2>/dev/null; then
        ((success++))
        echo " ✅"
    else
        ((failed++))
        echo " ❌"
    fi
    ((total++))
done

# Network Security
echo ""
echo "📁 NETWORK SECURITY"
echo "-------------------"
for product in cisco_asa cisco_firewall_threat_defense cisco_fmc cisco_ios cisco_ironport cisco_isa3000 cisco_ise cisco_meraki cisco_meraki_flow cisco_umbrella fortinet_fortigate paloalto_firewall zscaler; do
    echo -n "  $product: "
    if .venv/bin/python3 event_generators/shared/hec_sender.py --product $product --count 20 2>/dev/null; then
        ((success++))
        echo " ✅"
    else
        ((failed++))
        echo " ❌"
    fi
    ((total++))
done

# Endpoint Security
echo ""
echo "📁 ENDPOINT SECURITY"
echo "--------------------"
for product in crowdstrike_falcon jamf_protect microsoft_windows_eventlog sentinelone_endpoint; do
    echo -n "  $product: "
    if .venv/bin/python3 event_generators/shared/hec_sender.py --product $product --count 20 2>/dev/null; then
        ((success++))
        echo " ✅"
    else
        ((failed++))
        echo " ❌"
    fi
    ((total++))
done

# Identity & Access
echo ""
echo "📁 IDENTITY & ACCESS"
echo "--------------------"
for product in okta_authentication microsoft_azuread microsoft_azure_ad_signin cyberark_pas cisco_duo pingfederate pingone_mfa; do
    echo -n "  $product: "
    if .venv/bin/python3 event_generators/shared/hec_sender.py --product $product --count 20 2>/dev/null; then
        ((success++))
        echo " ✅"
    else
        ((failed++))
        echo " ❌"
    fi
    ((total++))
done

# Email Security
echo ""
echo "📁 EMAIL SECURITY"
echo "-----------------"
for product in abnormal_security mimecast proofpoint; do
    echo -n "  $product: "
    if .venv/bin/python3 event_generators/shared/hec_sender.py --product $product --count 20 2>/dev/null; then
        ((success++))
        echo " ✅"
    else
        ((failed++))
        echo " ❌"
    fi
    ((total++))
done

# Web Security
echo ""
echo "📁 WEB SECURITY"
echo "---------------"
for product in cloudflare_waf imperva_waf netskope; do
    echo -n "  $product: "
    if .venv/bin/python3 event_generators/shared/hec_sender.py --product $product --count 20 2>/dev/null; then
        ((success++))
        echo " ✅"
    else
        ((failed++))
        echo " ❌"
    fi
    ((total++))
done

# Infrastructure
echo ""
echo "📁 INFRASTRUCTURE"
echo "-----------------"
for product in github_audit veeam_backup extrahop darktrace; do
    echo -n "  $product: "
    if .venv/bin/python3 event_generators/shared/hec_sender.py --product $product --count 20 2>/dev/null; then
        ((success++))
        echo " ✅"
    else
        ((failed++))
        echo " ❌"
    fi
    ((total++))
done

# Summary
echo ""
echo "========================================"
echo "📊 SUMMARY"
echo "========================================"
echo "✅ Successful: $success/$total"
echo "❌ Failed: $failed/$total"
echo "📈 Success Rate: $(( success * 100 / total ))%"
echo "🎯 Total Events Sent: $(( success * 20 ))"
echo "🕐 Completed at: $(date)"