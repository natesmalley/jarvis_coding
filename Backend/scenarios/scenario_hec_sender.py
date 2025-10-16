#!/usr/bin/env python3
"""
Scenario HEC Sender - Send attack scenario events to SentinelOne AI-SIEM
========================================================================

This script takes the JSON output from attack_scenario_orchestrator.py and sends
the events to the appropriate HEC endpoints based on their platform type.
"""

import json
import os
import time
import random
import requests
from datetime import datetime, timezone
from typing import Dict, List

# Import the existing hec_sender functionality
from hec_sender import send_one

class ScenarioHECSender:
    def __init__(self):
        self.hec_token = os.getenv("S1_HEC_TOKEN")
        if not self.hec_token:
            raise RuntimeError("export S1_HEC_TOKEN=... first")
        
        # Platform to product mapping
        self.platform_mapping = {
            "email_security": ["proofpoint", "mimecast", "microsoft_defender_email"],
            "identity": ["microsoft_azure_ad_signin"],
            "endpoint": ["crowdstrike_falcon"],
            "network": ["darktrace"],
            "cloud": ["netskope", "microsoft_365_mgmt_api"],
            "privileged_access": ["cyberark_pas", "beyondtrust_passwordsafe"],
            "secrets": ["hashicorp_vault"],
            "m365": ["microsoft_365_mgmt_api"],
            "sentinelone_endpoint": ["sentinelone_endpoint"],
            "sentinelone_identity": ["sentinelone_identity"]
        }
        
        # Get ATTR_FIELDS for each product
        self.product_attr_fields = {}
        for platform, products in self.platform_mapping.items():
            for product in products:
                try:
                    module = __import__(product.replace("-", "_"))
                    self.product_attr_fields[product] = getattr(module, "ATTR_FIELDS", {})
                except ImportError:
                    print(f"Warning: Could not import {product} module")
                    self.product_attr_fields[product] = {}
    
    def load_scenario(self, scenario_file: str) -> List[Dict]:
        """Load scenario events from JSON file"""
        print(f"📁 Loading scenario from: {scenario_file}")
        
        with open(scenario_file, 'r') as f:
            events = json.load(f)
        
        print(f"📊 Loaded {len(events)} events")
        return events
    
    def send_scenario_events(self, events: List[Dict], 
                           real_time: bool = False,
                           speed_multiplier: float = 1.0,
                           batch_size: int = 1,
                           preserve_timestamps: bool = True) -> Dict:
        """
        Send scenario events to HEC
        
        Args:
            events: List of scenario events
            real_time: If True, respect original event timing (for real-time replay)
            speed_multiplier: Speed up factor (2.0 = 2x faster, 0.5 = 2x slower)
            batch_size: Number of events to send in parallel
            preserve_timestamps: If True, send events with their original timestamps (for historical data)
        """
        print(f"🚀 Starting scenario event transmission")
        print(f"   Real-time mode: {real_time}")
        print(f"   Speed multiplier: {speed_multiplier}x")
        print(f"   Batch size: {batch_size}")
        print(f"   Preserve timestamps: {preserve_timestamps}")
        print("=" * 50)
        
        results = {
            "total_events": len(events),
            "successful": 0,
            "failed": 0,
            "by_platform": {},
            "errors": []
        }
        
        # Sort events by timestamp for proper chronological order
        sorted_events = sorted(events, key=lambda x: x.get('timestamp', ''))
        
        start_time = datetime.now()
        last_timestamp = None
        
        for i, event in enumerate(sorted_events):
            try:
                # Handle timing
                if real_time and last_timestamp:
                    current_time = datetime.fromisoformat(event['timestamp'].replace('Z', '+00:00'))
                    last_time = datetime.fromisoformat(last_timestamp.replace('Z', '+00:00'))
                    time_diff = (current_time - last_time).total_seconds()
                    
                    # Apply speed multiplier
                    adjusted_delay = time_diff / speed_multiplier
                    if adjusted_delay > 0:
                        time.sleep(min(adjusted_delay, 60))  # Cap at 60 seconds
                
                # Send the event
                success = self._send_single_event(event, preserve_timestamp=preserve_timestamps)
                
                # Update results
                platform = event.get('platform', 'unknown')
                if platform not in results["by_platform"]:
                    results["by_platform"][platform] = {"successful": 0, "failed": 0}
                
                if success:
                    results["successful"] += 1
                    results["by_platform"][platform]["successful"] += 1
                else:
                    results["failed"] += 1
                    results["by_platform"][platform]["failed"] += 1
                
                # Progress update
                if (i + 1) % 10 == 0:
                    elapsed = (datetime.now() - start_time).total_seconds()
                    rate = (i + 1) / elapsed
                    remaining = len(sorted_events) - (i + 1)
                    eta = remaining / rate if rate > 0 else 0
                    
                    print(f"📈 Progress: {i + 1}/{len(sorted_events)} events "
                          f"({(i + 1)/len(sorted_events)*100:.1f}%) "
                          f"- ETA: {eta/60:.1f}m")
                
                last_timestamp = event.get('timestamp')
                
            except Exception as e:
                results["failed"] += 1
                results["errors"].append({
                    "event_index": i,
                    "error": str(e),
                    "event_platform": event.get('platform', 'unknown')
                })
                print(f"❌ Error sending event {i}: {e}")
        
        # Final summary
        total_time = (datetime.now() - start_time).total_seconds()
        print(f"\n✅ Scenario transmission complete!")
        print(f"   Total time: {total_time/60:.1f} minutes")
        print(f"   Events per second: {len(sorted_events)/total_time:.2f}")
        print(f"   Success rate: {results['successful']/len(sorted_events)*100:.1f}%")
        
        return results
    
    def _send_single_event(self, event: Dict, preserve_timestamp: bool = True) -> bool:
        """Send a single event to the appropriate HEC endpoint"""
        try:
            platform = event.get('platform', 'unknown')
            raw_event = event.get('raw_event', '{}')
            
            # Determine which product to use for this platform
            if platform in self.platform_mapping:
                products = self.platform_mapping[platform]
                product = random.choice(products)  # Randomly select from available products
            else:
                print(f"⚠️  Unknown platform: {platform}")
                return False
            
            # Get ATTR_FIELDS for this product
            attr_fields = self.product_attr_fields.get(product, {})
            
            # Add scenario context to attr_fields
            enhanced_attr_fields = {
                **attr_fields,
                "scenario.campaign_id": event.get('campaign_id', ''),
                "scenario.phase": event.get('phase', ''),
                "scenario.day": str(event.get('day', '')),
                "scenario.platform": platform
            }
            
            # If preserving timestamps and this is a JSON product, inject the timestamp into the event
            if preserve_timestamp and event.get('timestamp') and product in self.product_attr_fields:
                try:
                    # Parse the raw event JSON
                    event_data = json.loads(raw_event)
                    # Ensure the event has the original timestamp
                    event_data['_time'] = event['timestamp']
                    raw_event = json.dumps(event_data, separators=(',', ':'))
                except:
                    # If we can't parse/modify, just send as-is
                    pass
            
            # Send the event using existing hec_sender functionality
            response = send_one(raw_event, product, enhanced_attr_fields)
            
            return True
            
        except Exception as e:
            print(f"❌ Failed to send event: {e}")
            return False
    
    def analyze_scenario(self, events: List[Dict]) -> Dict:
        """Analyze the loaded scenario for insights"""
        analysis = {
            "total_events": len(events),
            "date_range": {},
            "platforms": {},
            "phases": {},
            "timeline": []
        }
        
        # Analyze events
        timestamps = []
        for event in events:
            timestamp = event.get('timestamp')
            platform = event.get('platform', 'unknown')
            phase = event.get('phase', 'unknown')
            
            if timestamp:
                timestamps.append(timestamp)
            
            # Count by platform
            analysis["platforms"][platform] = analysis["platforms"].get(platform, 0) + 1
            
            # Count by phase
            analysis["phases"][phase] = analysis["phases"].get(phase, 0) + 1
        
        # Date range
        if timestamps:
            analysis["date_range"] = {
                "start": min(timestamps),
                "end": max(timestamps)
            }
        
        # Create timeline summary
        phase_order = ["reconnaissance", "initial_access", "persistence", "escalation", "exfiltration"]
        for phase in phase_order:
            if phase in analysis["phases"]:
                analysis["timeline"].append({
                    "phase": phase,
                    "event_count": analysis["phases"][phase]
                })
        
        return analysis

def main():
    """Main execution function"""
    print("📡 SCENARIO HEC SENDER")
    print("Send attack scenario events to SentinelOne AI-SIEM")
    print("=" * 50)
    
    # Initialize sender
    try:
        sender = ScenarioHECSender()
    except RuntimeError as e:
        print(f"❌ Configuration error: {e}")
        return
    
    # Get scenario file
    scenario_file = input("Enter scenario JSON file path: ").strip()
    if not scenario_file:
        print("❌ No file specified")
        return
    
    if not os.path.exists(scenario_file):
        print(f"❌ File not found: {scenario_file}")
        return
    
    # Load and analyze scenario
    events = sender.load_scenario(scenario_file)
    analysis = sender.analyze_scenario(events)
    
    print(f"\n📊 SCENARIO ANALYSIS")
    print(f"   Total Events: {analysis['total_events']}")
    print(f"   Date Range: {analysis['date_range'].get('start', 'N/A')} to {analysis['date_range'].get('end', 'N/A')}")
    print(f"   Platforms: {', '.join(analysis['platforms'].keys())}")
    print(f"   Attack Phases: {len(analysis['phases'])}")
    
    print(f"\n📈 Timeline:")
    for phase_info in analysis["timeline"]:
        print(f"   {phase_info['phase'].title()}: {phase_info['event_count']} events")
    
    # Configuration options
    print(f"\n⚙️  TRANSMISSION OPTIONS")
    
    # Check if events are historical (in the past)
    first_event_time = datetime.fromisoformat(events[0]['timestamp'].replace('Z', '+00:00'))
    is_historical = first_event_time < datetime.now(timezone.utc)
    
    if is_historical:
        print(f"📅 Historical data detected (events from {analysis['date_range'].get('start', 'N/A')})")
        preserve_timestamps = input("Preserve original timestamps? (Y/n): ").lower() != 'n'
    else:
        preserve_timestamps = True
    
    real_time = input("Respect original event timing for replay? (y/N): ").lower().startswith('y')
    
    if real_time:
        speed_multiplier = float(input("Speed multiplier (1.0 = normal, 2.0 = 2x faster): ") or "1.0")
    else:
        speed_multiplier = 1.0
        delay = float(input("Delay between events in seconds (default 0.1): ") or "0.1")
    
    # Confirm transmission
    print(f"\n🚨 Ready to transmit {len(events)} events to HEC")
    if not input("Continue? (y/N): ").lower().startswith('y'):
        print("❌ Transmission cancelled")
        return
    
    # Send events
    if real_time:
        results = sender.send_scenario_events(
            events, 
            real_time=True, 
            speed_multiplier=speed_multiplier,
            preserve_timestamps=preserve_timestamps
        )
    else:
        results = sender.send_scenario_events(
            events, 
            real_time=False,
            preserve_timestamps=preserve_timestamps
        )
        # Add artificial delay between events if specified
        if 'delay' in locals():
            time.sleep(delay)
    
    # Results summary
    print(f"\n📋 TRANSMISSION RESULTS")
    print(f"   Total Events: {results['total_events']}")
    print(f"   Successful: {results['successful']}")
    print(f"   Failed: {results['failed']}")
    print(f"   Success Rate: {results['successful']/results['total_events']*100:.1f}%")
    
    print(f"\n📊 By Platform:")
    for platform, stats in results["by_platform"].items():
        total = stats["successful"] + stats["failed"]
        success_rate = stats["successful"] / total * 100 if total > 0 else 0
        print(f"   {platform}: {stats['successful']}/{total} ({success_rate:.1f}%)")
    
    if results["errors"]:
        print(f"\n❌ Errors ({len(results['errors'])}):")
        for error in results["errors"][:5]:  # Show first 5 errors
            print(f"   Event {error['event_index']}: {error['error']}")
        if len(results["errors"]) > 5:
            print(f"   ... and {len(results['errors']) - 5} more errors")

if __name__ == "__main__":
    main()