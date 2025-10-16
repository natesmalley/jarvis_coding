#!/usr/bin/env python3
"""
Cisco Networks event generator
Generates synthetic Cisco network infrastructure events
"""
import json
import random
import time
from datetime import datetime, timezone, timedelta
from typing import Dict

# Device types
DEVICE_TYPES = ["Switch", "Router", "Access Point", "Firewall", "Load Balancer"]

# Event severity levels
SEVERITY_LEVELS = ["Emergency", "Alert", "Critical", "Error", "Warning", "Notice", "Info", "Debug"]

# Facility codes
FACILITIES = ["LOCAL0", "LOCAL1", "LOCAL2", "LOCAL3", "LOCAL4", "LOCAL5", "LOCAL6", "LOCAL7"]

# Common network events
NETWORK_EVENTS = [
    {"message": "Interface GigabitEthernet0/1 is up", "severity": "Notice"},
    {"message": "Interface GigabitEthernet0/2 is down", "severity": "Warning"},
    {"message": "OSPF neighbor 192.168.1.1 is up", "severity": "Notice"},
    {"message": "OSPF neighbor 192.168.1.2 is down", "severity": "Error"},
    {"message": "BGP peer 10.0.0.1 established", "severity": "Notice"},
    {"message": "BGP peer 10.0.0.2 down", "severity": "Error"},
    {"message": "STP topology change", "severity": "Warning"},
    {"message": "VLAN 100 created", "severity": "Info"},
    {"message": "Access denied from 192.168.100.50", "severity": "Warning"},
    {"message": "High CPU utilization detected", "severity": "Alert"},
    {"message": "Memory usage exceeded threshold", "severity": "Warning"},
    {"message": "Temperature sensor alarm", "severity": "Critical"},
    {"message": "Power supply failure", "severity": "Critical"},
    {"message": "Authentication failure for user admin", "severity": "Warning"},
    {"message": "Configuration change detected", "severity": "Notice"}
]

def generate_ip() -> str:
    """Generate a random IP address"""
    return f"{random.randint(10, 192)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"

def cisco_networks_log() -> Dict:
    """Generate a single Cisco Networks event log"""
    now = datetime.now(timezone.utc)
    event_time = now - timedelta(minutes=random.randint(0, 1440))
    
    event_info = random.choice(NETWORK_EVENTS)
    device_type = random.choice(DEVICE_TYPES)
    hostname = f"{device_type.lower().replace(' ', '-')}-{random.randint(1, 100)}"
    
    event = {
        "timestamp": event_time.isoformat(),
        "hostname": hostname,
        "device_type": device_type,
        "facility": random.choice(FACILITIES),
        "severity": event_info["severity"],
        "priority": f"{random.choice([16, 17, 18, 19, 20, 21, 22, 23])}.{random.randint(0, 7)}",
        "message": event_info["message"],
        "source_ip": generate_ip(),
        "interface": f"GigabitEthernet0/{random.randint(1, 48)}" if "Interface" in event_info["message"] else "",
        "vlan_id": random.randint(1, 4094) if "VLAN" in event_info["message"] else None,
        "process_name": random.choice(["OSPF", "BGP", "STP", "SNMP", "SSH", "TELNET", "SYSTEM"]),
        "process_id": random.randint(1000, 9999),
        "sequence_number": random.randint(1, 999999),
        "uptime": f"{random.randint(1, 365)}d {random.randint(0, 23)}h {random.randint(0, 59)}m",
        "software_version": f"IOS {random.randint(12, 17)}.{random.randint(0, 9)}.{random.randint(0, 9)}",
        "hardware_platform": random.choice(["C9300", "C9400", "C2960", "ISR4321", "ASR1001"]),
        "location": random.choice(["Building-A", "Building-B", "DataCenter-1", "Branch-Office"])
    }
    
    # Add interface-specific details
    if "Interface" in event_info["message"]:
        event.update({
            "interface_status": "up" if "is up" in event_info["message"] else "down",
            "interface_speed": random.choice(["10", "100", "1000", "10000"]) + "Mbps",
            "interface_duplex": random.choice(["full", "half", "auto"])
        })
    
    # Add routing protocol details
    if any(proto in event_info["message"] for proto in ["OSPF", "BGP"]):
        event["neighbor_ip"] = generate_ip()
        event["routing_table_changes"] = random.randint(0, 100)
    
    # Remove None values
    event = {k: v for k, v in event.items() if v is not None}
    
    return event

if __name__ == "__main__":
    # Generate sample events
    print("Sample Cisco Networks Events:")
    print("=" * 50)
    for i in range(3):
        print(f"\nEvent {i+1}:")
        print(cisco_networks_log())