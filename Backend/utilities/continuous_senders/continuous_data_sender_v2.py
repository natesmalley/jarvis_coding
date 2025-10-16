#!/usr/bin/env python3
"""
Continuous Data Sender V2 - Direct Implementation
=================================================
Sends events directly without relying on hec_sender.py
"""

import time
import json
import random
import requests
from datetime import datetime, timezone, timedelta
import signal
import sys
import threading

# Configuration
HEC_TOKEN = "1FUC88b9Z4BaHtQxwIXwYGpMGEMv7UQ1JjPHEkERjDEe2U7_AS67SJJRpbIqk78h7"
HEC_URL = "https://ingest.us1.sentinelone.net/services/collector"

# Control flag
running = True

def signal_handler(sig, frame):
    """Handle Ctrl+C gracefully"""
    global running
    print("\n🛑 Stopping continuous data sending...")
    running = False
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)

def generate_pingfederate_event():
    """Generate PingFederate authentication event"""
    outcomes = ["SUCCESS", "FAILURE", "SUCCESS", "SUCCESS"]
    users = ["john.smith@company.com", "sarah.johnson@company.com", "mike.wilson@company.com"]
    
    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event_type": "AUTH.LOGIN",
        "user": random.choice(users),
        "client_ip": f"192.168.{random.randint(1,254)}.{random.randint(1,254)}",
        "outcome": random.choice(outcomes),
        "product": "PingFederate"
    }

def generate_cloudtrail_event():
    """Generate AWS CloudTrail event"""
    actions = ["GetObject", "PutObject", "DeleteObject", "ListBuckets", "AssumeRole"]
    users = ["admin-user", "service-account", "developer-01"]
    
    return {
        "eventTime": datetime.now(timezone.utc).isoformat(),
        "eventName": random.choice(actions),
        "userIdentity": {"userName": random.choice(users)},
        "sourceIPAddress": f"10.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}",
        "awsRegion": "us-east-1",
        "eventSource": "s3.amazonaws.com"
    }

def generate_fortigate_event():
    """Generate FortiGate firewall event"""
    actions = ["accept", "deny", "accept", "accept"]
    
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    src_ip = f"192.168.{random.randint(1,254)}.{random.randint(1,254)}"
    dst_ip = f"203.0.113.{random.randint(1,254)}"
    action = random.choice(actions)
    
    # FortiGate uses key=value format
    return f'date={timestamp} devname="FG-HQ-01" srcip={src_ip} dstip={dst_ip} action={action} proto=6 service="HTTPS"'

def send_event(product_name, event_data, sourcetype):
    """Send a single event to HEC"""
    try:
        if isinstance(event_data, str):
            # Raw event (FortiGate)
            url = f"{HEC_URL}/raw?sourcetype={sourcetype}"
            headers = {
                "Authorization": f"Splunk {HEC_TOKEN}",
                "Content-Type": "text/plain"
            }
            response = requests.post(url, headers=headers, data=event_data, verify=False, timeout=10)
        else:
            # JSON event (PingFederate, CloudTrail)
            url = f"{HEC_URL}/event"
            headers = {
                "Authorization": f"Splunk {HEC_TOKEN}",
                "Content-Type": "application/json"
            }
            payload = {
                "event": event_data,
                "sourcetype": sourcetype
            }
            response = requests.post(url, headers=headers, json=payload, verify=False, timeout=10)
        
        if response.status_code == 200:
            return True
        else:
            print(f"⚠️  {product_name}: HTTP {response.status_code} - {response.text[:100]}", flush=True)
            return False
    except Exception as e:
        print(f"❌ {product_name}: {str(e)[:100]}")
        return False

def continuous_sender(product_name, generator_func, sourcetype, interval=30, batch_size=10):
    """Send events continuously for a product"""
    global running
    
    print(f"🚀 Starting {product_name} sender", flush=True)
    event_count = 0
    
    while running:
        try:
            # Send batch
            successful = 0
            print(f"  [{product_name}] Sending batch of {batch_size} events...", flush=True)
            for i in range(batch_size):
                event = generator_func()
                if send_event(product_name, event, sourcetype):
                    successful += 1
                time.sleep(0.1)  # Small delay between events
            
            event_count += successful
            if successful > 0:
                timestamp = datetime.now().strftime("%H:%M:%S")
                print(f"[{timestamp}] {product_name}: Sent {successful}/{batch_size} events (Total: {event_count})", flush=True)
            
            # Wait before next batch
            time.sleep(interval)
            
        except Exception as e:
            print(f"❌ {product_name}: Error - {str(e)[:100]}")
            time.sleep(5)

def main():
    """Main function"""
    print("=" * 70, flush=True)
    print("🔄 CONTINUOUS DATA SENDER V2", flush=True)
    print("=" * 70, flush=True)
    print("Sending continuous data for:", flush=True)
    print("  • PingFederate (Authentication)", flush=True)
    print("  • AWS CloudTrail (Cloud Activity)", flush=True)
    print("  • FortiGate (Firewall)", flush=True)
    print(flush=True)
    print("Configuration:", flush=True)
    print("  • Batch size: 10 events", flush=True)
    print("  • Interval: 30 seconds", flush=True)
    print("  • Direct HEC integration", flush=True)
    print(f"  • HEC URL: {HEC_URL}", flush=True)
    print(flush=True)
    print("Press Ctrl+C to stop", flush=True)
    print("=" * 70, flush=True)
    print(flush=True)
    
    # Disable SSL warnings for self-signed certs
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    
    # Start threads
    threads = [
        threading.Thread(
            target=continuous_sender,
            args=("PingFederate", generate_pingfederate_event, "community-pingfederate-latest", 30, 10),
            daemon=True
        ),
        threading.Thread(
            target=continuous_sender,
            args=("AWS CloudTrail", generate_cloudtrail_event, "marketplace-awscloudtrail-latest", 30, 10),
            daemon=True
        ),
        threading.Thread(
            target=continuous_sender,
            args=("FortiGate", generate_fortigate_event, "marketplace-fortinetfortigate-latest", 30, 10),
            daemon=True
        )
    ]
    
    for thread in threads:
        thread.start()
    
    # Keep main thread alive
    try:
        while running:
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    
    print("\n✅ Continuous data sending stopped")

if __name__ == "__main__":
    main()