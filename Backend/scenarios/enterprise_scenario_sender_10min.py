#!/usr/bin/env python3
"""
Enterprise Scenario Sender - 10 Minute Version
===============================================
Sends compressed 10-minute attack scenario to SentinelOne AI-SIEM
"""

import os
import json
import sys
import time
from datetime import datetime, timezone

# Add path to shared utilities
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'event_generators', 'shared'))
from env_loader import load_env_if_present

# Load .env if present (check scenarios/ and repo root), then require token
this_dir = os.path.dirname(__file__)
repo_root = os.path.abspath(os.path.join(this_dir, '..'))
load_env_if_present(os.path.join(this_dir, '.env'))
load_env_if_present(os.path.join(repo_root, '.env'))
if not os.getenv('S1_HEC_TOKEN'):
    sys.exit('S1_HEC_TOKEN not set. Create a .env file or export it (e.g., export S1_HEC_TOKEN=...)')

from hec_sender import send_one, SOURCETYPE_MAP, JSON_PRODUCTS
from enterprise_attack_scenario_10min import generate_10min_attack_scenario

def send_to_hec(event_data, source):
    """Send event to SentinelOne HEC using proper routing"""
    # Map source to product name
    product = source.replace(' ', '_').lower()
    
    # Map sources to actual product names
    source_to_product = {
        'fortinet_fortigate': 'fortinet_fortigate',
        'cisco_umbrella': 'cisco_umbrella',
        'imperva_waf': 'imperva_waf',
        'proofpoint': 'proofpoint',
        'zscaler': 'zscaler',
        'netskope': 'netskope',
        'crowdstrike_falcon': 'crowdstrike_falcon',
        'okta_authentication': 'okta_authentication',
        'microsoft_azuread': 'microsoft_azuread',
        'cisco_duo': 'cisco_duo',
        'pingone_mfa': 'pingone_mfa',
        'microsoft_windows_eventlog': 'microsoft_windows_eventlog',
        'cisco_ise': 'cisco_ise',
        'f5_networks': 'f5_networks',
        'aws_cloudtrail': 'aws_cloudtrail',
        'hashicorp_vault': 'hashicorp_vault',
        'github_audit': 'github_audit',
        'harness_ci': 'harness_ci',
        'pingprotect': 'pingprotect'
    }
    
    # Get the actual product name
    if product in source_to_product:
        product = source_to_product[product]
    
    # Ensure we have proper attributes
    attr_fields = {
        "dataSource.vendor": source.split('_')[0].title() if '_' in source else source,
        "dataSource.name": source.replace('_', ' ').title(),
        "dataSource.category": "security"
    }
    
    try:
        # Use the send_one function from hec_sender which handles routing correctly
        result = send_one(event_data, product, attr_fields)
        return True
    except Exception as e:
        print(f" Error: {str(e)}", end="")
        return False

def send_10min_scenario():
    """Send the 10-minute compressed enterprise attack scenario"""
    print("🚀 ENTERPRISE ATTACK SCENARIO - 10 MINUTE VERSION")
    print("=" * 80)
    
    # Generate fresh scenario with current timestamps (last 10 minutes)
    print("📝 Generating 10-minute attack scenario (last 10 minutes)...")
    scenario = generate_10min_attack_scenario()
    
    events = scenario["events"]
    print(f"\n🎯 SENDING {len(events)} EVENTS TO SENTINELONE AI-SIEM")
    print(f"📊 Attack spans last {scenario['metadata']['duration_minutes']} minutes")
    print(f"🏢 {len(scenario['data_sources'])} data sources involved")
    print(f"🔥 {len(scenario['attack_phases'])} attack phases")
    print(f"⏰ Timeline: {scenario['metadata']['timeline_start']} to {scenario['metadata']['timeline_end']}")
    print("=" * 80)
    
    # Phase tracking
    phase_counts = {}
    success_count = 0
    current_phase = None
    
    # Send events
    for i, event_entry in enumerate(events, 1):
        source = event_entry["source"]
        phase = event_entry["phase"]
        event_data = event_entry["event"]
        
        # Track phases and show phase transitions
        if phase != current_phase:
            current_phase = phase
            print(f"\n🔥 {phase.upper().replace('_', ' ')}:")
        
        if phase not in phase_counts:
            phase_counts[phase] = 0
        phase_counts[phase] += 1
        
        # Display progress (more compact)
        if i % 10 == 1 or i == len(events):
            print(f"[{i:3d}/{len(events)}] ", end="", flush=True)
        
        # Send event
        success = send_to_hec(event_data, source)
        if success:
            print("✅", end="", flush=True)
            success_count += 1
        else:
            print("❌", end="", flush=True) 
        
        # No delay for faster sending
    
    # Summary
    print("\n\n" + "=" * 80)
    print("🎯 10-MINUTE ATTACK SCENARIO COMPLETE")
    print("=" * 80)
    print(f"✅ Events Delivered: {success_count}/{len(events)}")
    print(f"📈 Success Rate: {success_count/len(events)*100:.1f}%")
    
    print(f"\n📊 EVENTS BY ATTACK PHASE:")
    for phase, count in phase_counts.items():
        print(f"   {phase.replace('_', ' ').title():25s}: {count:3d} events")
    
    print(f"\n🔍 SEARCH IN SENTINELONE (Last 10 Minutes):")
    print("   🔍 Reconnaissance: sourcetype=\"marketplace-fortinetfortigate-latest\" OR sourcetype=\"community-ciscoumbrella-latest\"")
    print("   🔍 Initial Compromise: sourcetype=\"community-proofpoint-latest\" OR sourcetype=\"community-zscaler-latest\"")
    print("   🔍 Credential Access: sourcetype=\"community-oktaauthentication-latest\" OR sourcetype=\"community-ciscoduo-latest\"")
    print("   🔍 Lateral Movement: sourcetype=\"community-ciscoise-latest\" OR sourcetype=\"community-f5networks-latest\"")
    print("   🔍 Data Exfiltration: sourcetype=\"community-zscaler-latest\" AND bytes_out>10000000")
    
    print(f"\n💡 TIP: Search for events in the last 10 minutes to see real-time attack progression")

if __name__ == "__main__":
    send_10min_scenario()
