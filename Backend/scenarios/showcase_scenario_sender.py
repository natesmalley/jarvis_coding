#!/usr/bin/env python3
"""
Showcase Attack Scenario Sender
===============================

Sends the enterprise showcase attack scenario to SentinelOne AI-SIEM
for demonstration of advanced multi-platform correlation capabilities.
"""

import os
import json
import sys
import requests
import time
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading
from showcase_attack_scenario import generate_showcase_attack_scenario
from env_loader import load_env_if_present

# Load .env if present (check scenarios/ and repo root), then require token
this_dir = os.path.dirname(__file__)
repo_root = os.path.abspath(os.path.join(this_dir, '..'))
load_env_if_present(os.path.join(this_dir, '.env'))
load_env_if_present(os.path.join(repo_root, '.env'))
if not os.getenv('S1_HEC_TOKEN'):
    sys.exit('S1_HEC_TOKEN not set. Create a .env file or export it (e.g., export S1_HEC_TOKEN=...)')

from hec_sender import send_one, SOURCETYPE_MAP, JSON_PRODUCTS

def send_to_hec(event_data, source):
    """Send event to SentinelOne HEC using proper routing"""
    # Map source to product name (remove underscores and special chars)
    product = source.replace(' ', '_').lower()
    
    # Map some showcase sources to actual product names
    source_to_product = {
        'fortinet_fortigate': 'fortinet_fortigate',
        'microsoft_windows': 'microsoft_windows_eventlog',
        'imperva_waf': 'imperva_waf',
        'aws_cloudtrail': 'aws_cloudtrail',
        'okta': 'okta_authentication',
        'azure_ad': 'microsoft_azuread',
        'cisco_duo': 'cisco_duo',
        'zscaler': 'zscaler',
        'proofpoint': 'proofpoint',
        'crowdstrike': 'crowdstrike_falcon',
        'hashicorp_vault': 'hashicorp_vault',
        'harness_ci': 'harness_ci',
        'pingone_mfa': 'pingone_mfa',
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
        result = send_one(json.dumps(event_data) if isinstance(event_data, dict) else event_data, 
                         product, attr_fields)
        return True
    except Exception as e:
        print(f" Error: {str(e)}", end="")
        return False

def send_showcase_scenario():
    """Send the showcase attack scenario"""
    # Get worker count from environment (set by frontend)
    worker_count = int(os.getenv('S1_HEC_WORKERS', '10'))
    
    print("🚀 ENTERPRISE SHOWCASE ATTACK SCENARIO SENDER")
    print("=" * 80)
    
    # Generate scenario
    print("📝 Generating enterprise attack scenario...")
    scenario = generate_showcase_attack_scenario()
    
    events = scenario["events"]
    print(f"\n🎯 SENDING {len(events)} EVENTS TO SENTINELONE AI-SIEM")
    print(f"📊 Demonstrating correlation across {len(scenario['data_sources'])} data sources")
    print(f"🔥 {len(scenario['attack_phases'])} attack phases")
    print(f"⚡ Using {worker_count} parallel workers for high-speed transmission")
    print("=" * 80)
    
    # Phase tracking (thread-safe)
    phase_counts = {}
    phase_lock = threading.Lock()
    success_count = 0
    success_lock = threading.Lock()
    start_time = time.time()
    
    def send_event_worker(i, event_entry):
        """Worker function to send a single event"""
        nonlocal success_count
        source = event_entry["source"]
        phase = event_entry["phase"]
        event_data = event_entry["event"]
        
        # Track phases (thread-safe)
        with phase_lock:
            if phase not in phase_counts:
                phase_counts[phase] = 0
            phase_counts[phase] += 1
        
        # Send event
        success = send_to_hec(event_data, source)
        
        if success:
            with success_lock:
                success_count += 1
        
        return (i, source, phase, success)
    
    # Send events in parallel using ThreadPoolExecutor
    print(f"\n📤 Transmitting events with {worker_count} parallel workers...\n")
    
    with ThreadPoolExecutor(max_workers=worker_count) as executor:
        # Submit all events
        futures = {executor.submit(send_event_worker, i, event): i 
                  for i, event in enumerate(events, 1)}
        
        completed = 0
        last_update = time.time()
        
        # Process completed events
        for future in as_completed(futures):
            completed += 1
            i, source, phase, success = future.result()
            
            # Show progress every second or every 50 events
            if time.time() - last_update > 1.0 or completed % 50 == 0 or completed == len(events):
                elapsed = time.time() - start_time
                eps = completed / elapsed if elapsed > 0 else 0
                progress_pct = (completed / len(events)) * 100
                
                status = "✅" if success else "❌"
                print(f"[{completed:3d}/{len(events)}] {progress_pct:5.1f}% | "
                      f"EPS: {eps:6.1f} | Success: {success_count}/{completed} {status}")
                last_update = time.time()
    
    # Summary
    print("\n" + "=" * 80)
    print("🎯 SHOWCASE SCENARIO DELIVERY COMPLETE")
    print("=" * 80)
    print(f"✅ Events Delivered: {success_count}/{len(events)}")
    print(f"📈 Success Rate: {success_count/len(events)*100:.1f}%")
    
    print(f"\n📊 EVENTS BY ATTACK PHASE:")
    for phase, count in phase_counts.items():
        print(f"   {phase.replace('_', ' ').title():20s}: {count:2d} events")
    
    print(f"\n🏆 SENTINELONE AI-SIEM CORRELATION DEMONSTRATION:")
    for opportunity in scenario["correlation_opportunities"]:
        print(f"   {opportunity}")
    
    print(f"\n🎯 Expected SentinelOne AI-SIEM Analytics:")
    print(f"   • Multi-platform attack timeline reconstruction")
    print(f"   • Cross-source user behavior analysis")
    print(f"   • Infrastructure traversal path mapping") 
    print(f"   • Advanced threat hunting alerts")
    print(f"   • Behavioral anomaly detection")
    print(f"   • Attack technique correlation (MITRE ATT&CK)")

if __name__ == "__main__":
    send_showcase_scenario()
