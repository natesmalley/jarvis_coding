#!/usr/bin/env python3
"""
Juniper Networks event generator
Generates synthetic Juniper network device events
"""
import json
import random
import time
from datetime import datetime, timezone, timedelta
from typing import Dict

# Device types  
DEVICE_TYPES = ["SRX", "EX", "QFX", "MX", "PTX", "ACX"]

# Event types by category
EVENTS = {
    "interface": [
        {"name": "Interface ge-0/0/0 is up", "severity": "notice"},
        {"name": "Interface ge-0/0/1 is down", "severity": "warning"},
        {"name": "Interface xe-0/0/0 link flap detected", "severity": "error"}
    ],
    "routing": [
        {"name": "BGP neighbor 192.168.1.1 up", "severity": "notice"},
        {"name": "BGP neighbor 192.168.1.2 down", "severity": "error"},
        {"name": "OSPF neighbor 10.0.0.1 up", "severity": "notice"},
        {"name": "OSPF area 0.0.0.0 LSA timeout", "severity": "warning"}
    ],
    "security": [
        {"name": "Security policy permit applied", "severity": "info"},
        {"name": "Security policy deny applied", "severity": "warning"},
        {"name": "IDP attack detected", "severity": "alert"},
        {"name": "VPN tunnel established", "severity": "notice"},
        {"name": "Authentication failure", "severity": "warning"}
    ],
    "system": [
        {"name": "Chassis temperature normal", "severity": "notice"},
        {"name": "Chassis temperature high", "severity": "critical"},
        {"name": "Power supply 0 OK", "severity": "notice"},
        {"name": "Power supply 1 failure", "severity": "critical"},
        {"name": "Configuration committed", "severity": "notice"}
    ]
}

def generate_ip() -> str:
    """Generate a random IP address"""
    return f"{random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"

def juniper_networks_log() -> Dict:
    """Generate a single Juniper Networks event log"""
    now = datetime.now(timezone.utc)
    event_time = now - timedelta(minutes=random.randint(0, 1440))
    
    device_type = random.choice(DEVICE_TYPES)
    category = random.choice(list(EVENTS.keys()))
    event_info = random.choice(EVENTS[category])
    
    event = {
        "timestamp": event_time.isoformat(),
        "hostname": f"{device_type.lower()}-{random.randint(1, 50)}",
        "device_type": device_type,
        "device_ip": generate_ip(),
        "facility": "daemon",
        "severity": event_info["severity"],
        "tag": random.choice(["chassisd", "rpd", "mib2d", "kmd", "mgd"]),
        "process_name": random.choice(["rpd", "chassisd", "kmd", "dcd", "mgd"]),
        "process_id": random.randint(1000, 9999),
        "message": event_info["name"],
        "event_category": category,
        "software_version": f"Junos {random.randint(15, 22)}.{random.randint(1, 4)}R{random.randint(1, 9)}",
        "model": f"{device_type}{random.randint(100, 5000)}",
        "serial_number": f"{''.join(random.choices('ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789', k=11))}",
        "uptime": f"{random.randint(1, 365)} days, {random.randint(0, 23)}:{random.randint(0, 59)}:{random.randint(0, 59)}"
    }
    
    # Add category-specific fields
    if category == "interface":
        event.update({
            "interface_name": f"ge-0/0/{random.randint(0, 47)}",
            "interface_status": "up" if "up" in event_info["name"] else "down",
            "interface_speed": random.choice(["1G", "10G", "40G", "100G"]),
            "vlan_id": random.randint(1, 4094)
        })
    
    elif category == "routing":
        event.update({
            "neighbor_ip": generate_ip(),
            "routing_instance": random.choice(["default", "vpn1", "management"]),
            "protocol": "BGP" if "BGP" in event_info["name"] else "OSPF",
            "as_number": random.randint(64512, 65535) if "BGP" in event_info["name"] else None
        })
    
    elif category == "security":
        event.update({
            "source_ip": generate_ip(),
            "destination_ip": generate_ip(),
            "source_port": random.randint(1024, 65535),
            "destination_port": random.choice([22, 23, 80, 443, 53, 25]),
            "protocol": random.choice(["TCP", "UDP", "ICMP"]),
            "zone_from": random.choice(["trust", "untrust", "dmz"]),
            "zone_to": random.choice(["trust", "untrust", "dmz"]),
            "policy_name": f"policy-{random.randint(1, 100)}",
            "rule_number": random.randint(1, 1000)
        })
        
        if "IDP" in event_info["name"]:
            event.update({
                "attack_name": random.choice([
                    "HTTP:INVALID:MSNG-METHOD",
                    "TCP:SCAN:PORT-SCAN",
                    "HTTP:SQL:SQLI-DETECT",
                    "SHELLCODE:X86:GENERIC"
                ]),
                "severity_level": random.randint(1, 10)
            })
    
    elif category == "system":
        if "temperature" in event_info["name"]:
            event["temperature_celsius"] = random.randint(25, 75)
        elif "power" in event_info["name"]:
            event["power_supply_number"] = random.randint(0, 1)
    
    # Remove None values
    event = {k: v for k, v in event.items() if v is not None}
    
    return event

if __name__ == "__main__":
    # Generate sample events
    print("Sample Juniper Networks Events:")
    print("=" * 50)
    for i in range(3):
        print(f"\nEvent {i+1}:")
        print(juniper_networks_log())