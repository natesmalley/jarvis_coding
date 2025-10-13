#!/usr/bin/env python3
"""
Continuous sender for top 5 data sources (excluding Palo Alto, EDR, CrowdStrike, Okta)
Sends realistic security events to SentinelOne AI SIEM continuously
"""

import json
import requests
import time
import threading
from datetime import datetime, timezone
import sys
import os

# Add event_generators to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'event_generators'))

# Import top 5 generators
from cloud_infrastructure.aws_cloudtrail import cloudtrail_log
from network_security.fortinet_fortigate import forward_log as fortinet_fortigate_log
from network_security.cisco_firewall_threat_defense import cisco_firewall_threat_defense_log
from identity_access.microsoft_azuread import azure_ad_log as microsoft_azuread_log
from infrastructure.zscaler import zscaler_log

# Configuration
HEC_TOKEN = "1FUC88b9Z4BaHtQxwIXwYGpMGEMv7UQ1JjPHEkERjDEe2U7_AS67SJJRpbIqk78h7"
HEC_URL = "https://ingest.us1.sentinelone.net/services/collector"

# Global stats
stats = {
    "aws_cloudtrail": {"sent": 0, "failed": 0},
    "fortinet_fortigate": {"sent": 0, "failed": 0},
    "cisco_ftd": {"sent": 0, "failed": 0},
    "microsoft_azuread": {"sent": 0, "failed": 0},
    "zscaler": {"sent": 0, "failed": 0}
}

def send_events(product_name, product_code, generator_func, interval_seconds=30, batch_size=10):
    """Send events continuously for a specific product"""
    session = requests.Session()
    session.headers.update({
        'Authorization': f'Splunk {HEC_TOKEN}',
        'Content-Type': 'application/json'
    })
    
    event_count = 0
    
    while True:
        try:
            # Generate batch of events
            events_batch = []
            for _ in range(batch_size):
                try:
                    event_data = generator_func()
                    
                    # Handle different return types
                    if isinstance(event_data, str):
                        try:
                            # Try to parse as JSON
                            event_data = json.loads(event_data)
                        except:
                            # Keep as raw string for syslog format
                            pass
                    
                    events_batch.append({
                        "event": event_data,
                        "sourcetype": product_code,
                        "source": product_name,
                        "time": int(time.time())
                    })
                except Exception as e:
                    print(f"[{datetime.now(timezone.utc).strftime('%H:%M:%S')}] {product_name}: Error generating event: {e}")
            
            # Send batch to HEC
            successful = 0
            for event in events_batch:
                try:
                    response = session.post(HEC_URL, json=event, timeout=10)
                    if response.status_code == 200:
                        successful += 1
                        event_count += 1
                        stats[product_code]["sent"] += 1
                    else:
                        stats[product_code]["failed"] += 1
                except Exception as e:
                    stats[product_code]["failed"] += 1
            
            timestamp = datetime.now(timezone.utc).strftime('%H:%M:%S')
            print(f"[{timestamp}] {product_name}: Sent {successful}/{batch_size} events (Total: {event_count})")
            
        except Exception as e:
            print(f"[{datetime.now(timezone.utc).strftime('%H:%M:%S')}] {product_name}: Error in batch send: {e}")
        
        # Wait before next batch
        time.sleep(interval_seconds)

def print_stats():
    """Print statistics every minute"""
    while True:
        time.sleep(60)
        print("\n" + "="*70)
        print("📊 STATISTICS UPDATE")
        print("="*70)
        total_sent = 0
        total_failed = 0
        for product, counts in stats.items():
            total_sent += counts["sent"]
            total_failed += counts["failed"]
            success_rate = (counts["sent"] / (counts["sent"] + counts["failed"]) * 100) if (counts["sent"] + counts["failed"]) > 0 else 0
            print(f"{product:20} - Sent: {counts['sent']:5} | Failed: {counts['failed']:3} | Success: {success_rate:.1f}%")
        print("-"*70)
        print(f"{'TOTAL':20} - Sent: {total_sent:5} | Failed: {total_failed:3}")
        print("="*70 + "\n")

def main():
    """Main function to start all threads"""
    print("="*70)
    print("🚀 TOP 5 DATA SOURCES CONTINUOUS SENDER")
    print("="*70)
    print("Starting continuous data transmission to SentinelOne AI SIEM...")
    print(f"Target: {HEC_URL}")
    print()
    print("📊 Data Sources:")
    print("1. AWS CloudTrail - Cloud infrastructure audit logs")
    print("2. Fortinet FortiGate - Network firewall events")
    print("3. Cisco Firewall Threat Defense - Network security events")
    print("4. Microsoft Azure AD - Identity and authentication events")
    print("5. Zscaler - Web security and proxy events")
    print()
    print("Sending 10 events every 30 seconds per source...")
    print("="*70)
    print()
    
    # Create threads for each data source
    threads = [
        threading.Thread(target=send_events, args=("AWS CloudTrail", "aws_cloudtrail", cloudtrail_log, 30, 10)),
        threading.Thread(target=send_events, args=("FortiGate Firewall", "fortinet_fortigate", fortinet_fortigate_log, 30, 10)),
        threading.Thread(target=send_events, args=("Cisco FTD", "cisco_ftd", cisco_firewall_threat_defense_log, 30, 10)),
        threading.Thread(target=send_events, args=("Microsoft Azure AD", "microsoft_azuread", microsoft_azuread_log, 30, 10)),
        threading.Thread(target=send_events, args=("Zscaler Proxy", "zscaler", zscaler_log, 30, 10)),
        threading.Thread(target=print_stats)  # Statistics thread
    ]
    
    # Start all threads
    for thread in threads:
        thread.daemon = True
        thread.start()
    
    # Keep main thread alive
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n\n📊 Final Statistics:")
        print("="*70)
        total_sent = 0
        total_failed = 0
        for product, counts in stats.items():
            total_sent += counts["sent"]
            total_failed += counts["failed"]
            print(f"{product:20} - Sent: {counts['sent']:5} | Failed: {counts['failed']:3}")
        print("-"*70)
        print(f"{'TOTAL':20} - Sent: {total_sent:5} | Failed: {total_failed:3}")
        print("="*70)
        print("\n✅ Continuous sender stopped.")

if __name__ == "__main__":
    main()