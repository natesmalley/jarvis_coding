#!/usr/bin/env python3
"""
Send 5 events from each generator to SentinelOne via HEC
This will actually ingest the data into your SentinelOne instance
"""

import os
import sys
import time
import json
import subprocess
from datetime import datetime
from pathlib import Path

# Add event_generators to path
sys.path.insert(0, str(Path(__file__).parent))
sys.path.insert(0, str(Path(__file__).parent / "event_generators"))

class SentinelOneBulkSender:
    def __init__(self):
        self.results = {
            "timestamp": datetime.now().isoformat(),
            "total_generators": 0,
            "successful_sends": [],
            "failed_sends": [],
            "total_events_sent": 0
        }
        
    def send_generator_events(self, generator_name: str, count: int = 5) -> bool:
        """Send events from a specific generator to SentinelOne"""
        try:
            print(f"  Sending {count} events from {generator_name}...", end=" ", flush=True)
            
            # Use the hec_sender.py script directly
            cmd = [
                sys.executable,
                "event_generators/shared/hec_sender.py",
                "--product", generator_name,
                "--count", str(count)
            ]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode == 0:
                print("✅ SENT")
                self.results["successful_sends"].append(generator_name)
                self.results["total_events_sent"] += count
                return True
            else:
                error_msg = result.stderr[:100] if result.stderr else result.stdout[:100]
                print(f"❌ FAILED: {error_msg}")
                self.results["failed_sends"].append({
                    "generator": generator_name,
                    "error": error_msg
                })
                return False
                
        except subprocess.TimeoutExpired:
            print("❌ TIMEOUT")
            self.results["failed_sends"].append({
                "generator": generator_name,
                "error": "Timeout after 30 seconds"
            })
            return False
        except Exception as e:
            print(f"❌ ERROR: {str(e)[:50]}")
            self.results["failed_sends"].append({
                "generator": generator_name,
                "error": str(e)
            })
            return False
    
    def get_all_generators(self):
        """Get list of all available generators"""
        generators = []
        
        # Categories to check
        categories = [
            "cloud_infrastructure",
            "network_security", 
            "endpoint_security",
            "identity_access",
            "email_security",
            "web_security",
            "infrastructure"
        ]
        
        base_path = Path("event_generators")
        
        for category in categories:
            category_path = base_path / category
            if category_path.exists():
                for file in category_path.glob("*.py"):
                    if not file.name.startswith("_") and file.name != "__init__.py":
                        generator_name = file.stem
                        generators.append((generator_name, category))
        
        return generators
    
    def run(self):
        """Run the bulk send operation"""
        print("=" * 80)
        print("SENDING ALL GENERATORS TO SENTINELONE VIA HEC")
        print("=" * 80)
        print(f"Started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("-" * 80)
        
        # Check for HEC token
        hec_token = os.getenv("S1_HEC_TOKEN")
        if not hec_token:
            print("ERROR: S1_HEC_TOKEN environment variable not set!")
            print("Please set: export S1_HEC_TOKEN='your-token-here'")
            return
        
        print(f"HEC Token configured: {hec_token[:10]}...")
        print("-" * 80)
        
        # Get all generators
        generators = self.get_all_generators()
        self.results["total_generators"] = len(generators)
        
        if not generators:
            print("No generators found!")
            return
        
        print(f"Found {len(generators)} generators to send")
        print("-" * 80)
        
        # Send events from each generator
        for i, (gen_name, category) in enumerate(generators, 1):
            print(f"[{i:3}/{len(generators)}] {category:20} / {gen_name:40}", end=" ")
            
            success = self.send_generator_events(gen_name, count=5)
            
            # Small delay between sends to avoid overwhelming
            time.sleep(0.5)
        
        # Print summary
        self.print_summary()
        
    def print_summary(self):
        """Print summary of the operation"""
        print("\n" + "=" * 80)
        print("SUMMARY")
        print("=" * 80)
        
        total = self.results["total_generators"]
        successful = len(self.results["successful_sends"])
        failed = len(self.results["failed_sends"])
        
        print(f"Total Generators: {total}")
        print(f"Successfully Sent: {successful} ({successful/total*100:.1f}%)")
        print(f"Failed: {failed}")
        print(f"Total Events Sent to SentinelOne: {self.results['total_events_sent']}")
        
        if self.results["failed_sends"]:
            print("\n" + "-" * 80)
            print("FAILED GENERATORS:")
            print("-" * 80)
            for failure in self.results["failed_sends"][:10]:
                print(f"  - {failure['generator']:40} {failure['error'][:60]}")
            
            if len(self.results["failed_sends"]) > 10:
                print(f"  ... and {len(self.results['failed_sends']) - 10} more")
        
        # Save results
        output_file = f"sentinelone_send_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(output_file, 'w') as f:
            json.dump(self.results, f, indent=2)
        
        print(f"\n💾 Results saved to: {output_file}")
        print("\n🔍 Check your SentinelOne console for the ingested events!")
        print("   Note: Events may take 1-2 minutes to appear in the console")
        print("=" * 80)

def main():
    # First check if we have the HEC token
    if not os.getenv("S1_HEC_TOKEN"):
        print("Setting up S1_HEC_TOKEN from known configuration...")
        # Use the token from our earlier sessions
        os.environ["S1_HEC_TOKEN"] = "1FUC88b9Z4BaHtQxwIXwYGqFPaVQO7jzXDuYxDuMD2q1s57bX4MvgEMxUCLaH7pbO"
    
    sender = SentinelOneBulkSender()
    sender.run()

if __name__ == "__main__":
    main()