#!/usr/bin/env python3
"""
Manageengine Adauditplus Logs Event Generator
Generates synthetic Manageengine Adauditplus Logs security events for testing
"""

import random
import time
import json
from datetime import datetime, timezone

# SentinelOne AI-SIEM specific field attributes
def manageengine_adauditplus_log():
    """Generate a synthetic Manageengine Adauditplus Logs log event."""
    
    # Timestamp 
    timestamp = datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')
    
    # Base event structure
    event = {
        "timestamp": timestamp,
        "vendor": "Manageengine",
        "product": "Adauditplus Logs",
        "version": "1.0",
        "event_type": "security_event",
        
        # Common fields that parsers often expect
        "message": f"Sample Manageengine Adauditplus Logs event at {timestamp}",
        "severity": random.choice(["low", "medium", "high", "critical"]),
        "category": "security",
        
        # Network/Identity fields (commonly used)
        "source_ip": f"192.168.{random.randint(1,254)}.{random.randint(1,254)}",
        "user": f"user{random.randint(1000,9999)}",
        "device": f"device-{random.randint(100,999)}",
        
        # Add parser-specific fields based on common patterns
        "log_level": random.choice(["INFO", "WARN", "ERROR"]),
        "event_id": random.randint(10000, 99999),
        "session_id": f"sess_{random.randint(100000,999999)}",
        
        # OCSF compliance helpers
        "class_name": "Security Event",
        "activity_name": "Log Generated"
    }
    
    # Add some randomization for testing
    if random.random() < 0.3:  # 30% chance
        event["location"] = random.choice(["New York", "London", "Tokyo", "Sydney"])
    
    if random.random() < 0.4:  # 40% chance  
        event["risk_score"] = random.randint(1, 100)
    
    return event

if __name__ == "__main__":
    # Generate and print sample event
    event = manageengine_adauditplus_log()
    print(json.dumps(event, indent=2))
