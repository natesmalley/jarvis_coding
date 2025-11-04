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
import argparse
import uuid
import requests
import re
from datetime import datetime, timezone
from typing import Dict, List, Optional

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
            data = json.load(f)
        # Support either a plain list of events or an object with 'events'
        if isinstance(data, dict) and 'events' in data:
            events = data['events']
        else:
            events = data
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
                    current_time = self._parse_timestamp(event.get('timestamp'))
                    last_time = self._parse_timestamp(last_timestamp)
                    time_diff = (current_time - last_time).total_seconds() if current_time and last_time else 0
                    
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
            # Product is the generator/source identifier (e.g., okta_authentication)
            product = event.get('source') or event.get('product') or 'unknown'
            if product == 'unknown':
                print("⚠️  Event missing 'source' field; skipping")
                return False

            # Build raw event body from 'event' field (dict -> JSON, str -> as-is)
            payload = event.get('event', {})
            if isinstance(payload, dict):
                raw_event = json.dumps(payload, separators=(',', ':'))
            else:
                raw_event = str(payload)

            # Build attributes
            attr_fields = self.product_attr_fields.get(product, {})
            # Decide whether to include scenario.phase
            env_tag_phase = os.getenv("S1_TAG_PHASE")
            include_phase_tag = True if env_tag_phase is None else env_tag_phase not in ("0", "false", "False")
            enhanced_attr_fields = {
                **attr_fields,
                "scenario.timestamp": event.get('timestamp', ''),
            }
            if include_phase_tag:
                enhanced_attr_fields["scenario.phase"] = event.get('phase', '')
            # Trace tagging via environment
            env_tag_trace = os.getenv("S1_TAG_TRACE")
            include_trace_tag = True if env_tag_trace is None else env_tag_trace not in ("0", "false", "False")
            trace_id_env = os.getenv("S1_TRACE_ID")
            if include_trace_tag and trace_id_env:
                enhanced_attr_fields["scenario.trace_id"] = trace_id_env

            # Inject scenario timestamp into JSON payload for consistent downstream time handling
            if preserve_timestamp and isinstance(payload, dict) and event.get('timestamp'):
                try:
                    payload_copy = dict(payload)
                    ts = event['timestamp']
                    # Set _time to scenario timestamp for HEC/Splunk indexing
                    payload_copy.setdefault('_time', ts)
                    raw_event = json.dumps(payload_copy, separators=(',', ':'))
                except Exception:
                    pass

            # Preserve original event time in HEC envelope if available
            event_time_sec = None
            ts = event.get('timestamp')
            if ts:
                dt = self._parse_timestamp(ts)
                if dt:
                    event_time_sec = dt.timestamp()

            # Send via existing hec sender (passing event_time to set HEC envelope time)
            send_one(raw_event, product, enhanced_attr_fields, event_time=event_time_sec)
            
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
            source = event.get('source', 'unknown')
            phase = event.get('phase', 'unknown')

            if timestamp:
                timestamps.append(timestamp)

            # Count by platform (use source as proxy)
            analysis["platforms"][source] = analysis["platforms"].get(source, 0) + 1
            
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

    def _parse_timestamp(self, ts: str) -> Optional[datetime]:
        """Parse various ISO8601-like timestamp formats into a timezone-aware datetime.
        Returns None if parsing fails.
        """
        if not ts:
            return None
        s = str(ts).strip()
        try:
            # Normalize space separator to 'T'
            if ' ' in s and 'T' not in s:
                s = s.replace(' ', 'T')
            # Normalize Zulu designator
            if s.endswith('Z'):
                s = s[:-1] + '+00:00'
            # Add missing colon in timezone offset (e.g., +0000 -> +00:00)
            if re.search(r"[+-]\d{4}$", s):
                s = s[:-5] + s[-5:-2] + ':' + s[-2:]
            # If no timezone provided, assume UTC
            if re.match(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?$", s):
                s = s + '+00:00'
            return datetime.fromisoformat(s)
        except Exception:
            # Best-effort strptime fallbacks
            fmts = [
                '%Y-%m-%dT%H:%M:%S%z',
                '%Y-%m-%dT%H:%M:%S.%f%z',
                '%Y-%m-%d %H:%M:%S%z',
                '%Y-%m-%d %H:%M:%S.%f%z',
                '%Y-%m-%dT%H:%M:%S',
                '%Y-%m-%dT%H:%M:%S.%f',
            ]
            for fmt in fmts:
                try:
                    dt = datetime.strptime(s, fmt)
                    # Assume UTC if naive
                    if dt.tzinfo is None:
                        return dt.replace(tzinfo=timezone.utc)
                    return dt
                except Exception:
                    continue
        return None

def main():
    """Main execution function"""
    print("📡 SCENARIO HEC SENDER")
    print("Send attack scenario events to SentinelOne AI-SIEM")
    print("=" * 50)

    parser = argparse.ArgumentParser(description="Replay scenario events to HEC")
    parser.add_argument("--scenario", help="Path to scenario JSON file")
    parser.add_argument("--auto", action="store_true", help="Run non-interactively with sane defaults")
    parser.add_argument("--preserve-timestamps", action="store_true", help="Preserve original timestamps")
    parser.add_argument("--real-time", action="store_true", help="Respect original event timing for replay")
    parser.add_argument("--speed", type=float, default=1.0, help="Speed multiplier for real-time mode")
    parser.add_argument("--delay", type=float, default=0.0, help="Delay between events (non real-time mode)")
    parser.add_argument("--no-phase-tag", action="store_true", help="Disable adding scenario.phase attribute field")
    parser.add_argument("--trace-id", help="Attach this trace ID (GUID) to every event as scenario.trace_id")
    args = parser.parse_args()

    # Initialize sender
    try:
        sender = ScenarioHECSender()
    except RuntimeError as e:
        print(f"❌ Configuration error: {e}")
        return

    # Determine scenario file
    if args.scenario:
        scenario_file = args.scenario
    else:
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

    print(f"\n⚙️  TRANSMISSION OPTIONS")

    # Determine whether to include scenario.phase tag
    env_tag_phase = os.getenv("S1_TAG_PHASE")
    include_phase_tag = True
    if env_tag_phase is not None:
        include_phase_tag = env_tag_phase not in ("0", "false", "False")
    if args.no_phase_tag:
        include_phase_tag = False

    # Trace ID handling (env or CLI). Default: enabled and generate if not provided
    env_tag_trace = os.getenv("S1_TAG_TRACE")
    include_trace_tag = True if env_tag_trace is None else env_tag_trace not in ("0", "false", "False")
    trace_id = args.trace_id or os.getenv("S1_TRACE_ID")
    if include_trace_tag and not trace_id:
        trace_id = str(uuid.uuid4())
    if include_trace_tag:
        print(f"🧵 Trace ID: {trace_id}")

    if args.auto:
        preserve_timestamps = args.preserve_timestamps or True
        real_time = args.real_time or False
        speed_multiplier = args.speed
        delay = args.delay
    else:
        # Interactive prompts
        first_event_time = sender._parse_timestamp(events[0].get('timestamp'))
        is_historical = (first_event_time or datetime.now(timezone.utc)) < datetime.now(timezone.utc)
        if is_historical:
            print(f"📅 Historical data detected (events from {analysis['date_range'].get('start', 'N/A')})")
            preserve_timestamps = input("Preserve original timestamps? (Y/n): ").lower() != 'n'
        else:
            preserve_timestamps = True
        real_time = input("Respect original event timing for replay? (y/N): ").lower().startswith('y')
        if real_time:
            speed_multiplier = float(input("Speed multiplier (1.0 = normal, 2.0 = 2x faster): ") or "1.0")
            delay = 0.0
        else:
            speed_multiplier = 1.0
            delay = float(input("Delay between events in seconds (default 0.1): ") or "0.1")

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
        if delay and delay > 0:
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
        for error in results["errors"][:5]:
            print(f"   Event {error['event_index']}: {error['error']}")
        if len(results["errors"]) > 5:
            print(f"   ... and {len(results['errors'])} more errors")

if __name__ == "__main__":
    main()