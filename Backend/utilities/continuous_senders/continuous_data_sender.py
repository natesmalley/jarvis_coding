#!/usr/bin/env python3
"""
Continuous Data Sender for PingIdentity, AWS CloudTrail, and FortiGate
========================================================================
Sends continuous realistic events to SentinelOne for these three critical services.
"""

import subprocess
import time
import threading
import signal
import sys
from datetime import datetime
import random
import os

# Set the correct HEC token
HEC_TOKEN = "1FUC88b9Z4BaHtQxwIXwYGpMGEMv7UQ1JjPHEkERjDEe2U7_AS67SJJRpbIqk78h7"

# Control flag for graceful shutdown
running = True

def signal_handler(sig, frame):
    """Handle Ctrl+C gracefully"""
    global running
    print("\n\n🛑 Stopping continuous data sending...")
    running = False
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)

def send_events(product_name, product_code, interval_seconds=30, batch_size=10):
    """Send events continuously for a specific product"""
    global running
    
    # Check which PingIdentity product to use
    if product_name == "PingIdentity":
        # Try different PingIdentity products
        ping_products = ["pingfederate", "pingone_mfa", "pingprotect"]
        product_code = random.choice(ping_products)
    
    print(f"🚀 Starting continuous sender for {product_name} ({product_code})")
    sys.stdout.flush()
    
    event_count = 0
    start_time = datetime.now()
    
    while running:
        try:
            # Send batch of events
            cmd = [
                "python3",
                "event_generators/shared/hec_sender.py",
                "--product", product_code,
                "--count", str(batch_size)
            ]
            
            env = {"S1_HEC_TOKEN": HEC_TOKEN}
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                env={**subprocess.os.environ, **env},
                timeout=30
            )
            
            if result.returncode == 0:
                event_count += batch_size
                elapsed = (datetime.now() - start_time).total_seconds()
                rate = event_count / elapsed if elapsed > 0 else 0
                
                timestamp = datetime.now().strftime("%H:%M:%S")
                print(f"[{timestamp}] {product_name}: Sent {batch_size} events (Total: {event_count}, Rate: {rate:.1f}/sec)")
            else:
                print(f"⚠️  {product_name}: Failed to send batch - {result.stderr[:100]}")
                # Try alternative product for PingIdentity
                if product_name == "PingIdentity" and product_code in ping_products:
                    ping_products.remove(product_code)
                    if ping_products:
                        product_code = random.choice(ping_products)
                        print(f"   Switching to {product_code}...")
            
            # Wait before next batch
            time.sleep(interval_seconds)
            
        except subprocess.TimeoutExpired:
            print(f"⏰ {product_name}: Timeout sending batch")
        except Exception as e:
            print(f"❌ {product_name}: Error - {str(e)[:100]}")
            time.sleep(5)  # Wait a bit on error

def main():
    """Main function to start continuous senders"""
    print("=" * 70)
    print("🔄 CONTINUOUS DATA SENDER")
    print("=" * 70)
    print("Sending continuous data for:")
    print("  • PingIdentity (PingFederate/PingOne MFA/PingProtect)")
    print("  • AWS CloudTrail")
    print("  • Fortinet FortiGate")
    print()
    print("Configuration:")
    print("  • Batch size: 10 events per send")
    print("  • Interval: 30 seconds between batches")
    print("  • Rate: ~20 events/minute per service")
    print()
    print("Press Ctrl+C to stop")
    print("=" * 70)
    print()
    
    # Start threads for each service
    threads = []
    
    # PingIdentity thread
    ping_thread = threading.Thread(
        target=send_events,
        args=("PingIdentity", "pingfederate", 30, 10),
        daemon=True
    )
    threads.append(ping_thread)
    
    # AWS CloudTrail thread
    cloudtrail_thread = threading.Thread(
        target=send_events,
        args=("AWS CloudTrail", "aws_cloudtrail", 30, 10),
        daemon=True
    )
    threads.append(cloudtrail_thread)
    
    # FortiGate thread
    fortigate_thread = threading.Thread(
        target=send_events,
        args=("FortiGate", "fortinet_fortigate", 30, 10),
        daemon=True
    )
    threads.append(fortigate_thread)
    
    # Start all threads
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
    import sys
    sys.stdout.flush()
    sys.stderr.flush()
    main()