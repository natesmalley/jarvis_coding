#!/usr/bin/env python3
"""
Ubiquiti UniFi event generator
Generates synthetic UniFi network equipment events
"""
import json
import random
import time
from datetime import datetime, timezone, timedelta
from typing import Dict

# Device types
DEVICE_TYPES = ["UAP", "USW", "UDM", "USG", "UCK"]

# Event types
EVENT_TYPES = [
    {"type": "EVT_AP_Connected", "category": "wireless", "severity": "info"},
    {"type": "EVT_AP_Disconnected", "category": "wireless", "severity": "warning"},
    {"type": "EVT_SW_Connected", "category": "switching", "severity": "info"},
    {"type": "EVT_SW_Disconnected", "category": "switching", "severity": "warning"},
    {"type": "EVT_GW_Connected", "category": "routing", "severity": "info"},
    {"type": "EVT_GW_Disconnected", "category": "routing", "severity": "warning"},
    {"type": "EVT_WU_Connected", "category": "wireless", "severity": "info"},
    {"type": "EVT_WU_Disconnected", "category": "wireless", "severity": "info"},
    {"type": "EVT_WU_Blocked", "category": "security", "severity": "warning"},
    {"type": "EVT_WU_Unblocked", "category": "security", "severity": "info"},
    {"type": "EVT_IPS_Alert", "category": "security", "severity": "alert"},
    {"type": "EVT_AD_Block", "category": "security", "severity": "info"},
    {"type": "EVT_Port_Link_Up", "category": "switching", "severity": "info"},
    {"type": "EVT_Port_Link_Down", "category": "switching", "severity": "warning"}
]

# SSID names
SSIDS = ["HomeWiFi", "GuestNetwork", "IoT", "Office", "Staff"]

def generate_mac() -> str:
    """Generate a random MAC address"""
    return ":".join([f"{random.randint(0, 255):02x}" for _ in range(6)])

def generate_ip() -> str:
    """Generate a random IP address"""
    return f"192.168.{random.randint(1, 10)}.{random.randint(1, 254)}"

def ubiquiti_unifi_log() -> Dict:
    """Generate a single UniFi event log"""
    now = datetime.now(timezone.utc)
    event_time = now - timedelta(minutes=random.randint(0, 1440))
    
    event_info = random.choice(EVENT_TYPES)
    device_type = random.choice(DEVICE_TYPES)
    
    event = {
        "datetime": event_time.isoformat(),
        "timestamp": int(event_time.timestamp()),
        "key": event_info["type"],
        "subsystem": "lan",
        "site_id": f"site_{random.randint(100000, 999999)}",
        "time": int(event_time.timestamp() * 1000),  # milliseconds
        "msg": f"{event_info['type']} event occurred",
        "category": event_info["category"],
        "severity": event_info["severity"],
        "admin": f"admin@unifi.local",
        "is_negative": event_info["severity"] in ["warning", "alert", "error"]
    }
    
    # Add device-specific fields
    if "AP" in device_type or "wireless" in event_info["category"]:
        event.update({
            "ap": f"UAP-{random.choice(['AC-Pro', 'WiFi6-Lite', 'nanoHD', 'AC-Lite'])}",
            "ap_name": f"AP-{random.randint(1, 20)}",
            "ap_mac": generate_mac(),
            "channel": random.choice([1, 6, 11, 36, 40, 44, 48]),
            "radio": random.choice(["ng", "na"]),
            "ssid": random.choice(SSIDS),
            "bssid": generate_mac()
        })
        
        if "WU" in event_info["type"]:  # Wireless user events
            event.update({
                "user": generate_mac(),
                "hostname": f"device-{random.randint(1, 100)}",
                "ip": generate_ip(),
                "user_agent": random.choice([
                    "iPhone", "Android", "Windows", "MacOS", "Linux"
                ]),
                "duration": random.randint(60, 86400) if "Disconnected" in event_info["type"] else 0,
                "bytes": random.randint(1000000, 1000000000) if "Disconnected" in event_info["type"] else 0
            })
    
    elif "SW" in device_type or "switching" in event_info["category"]:
        event.update({
            "sw": f"USW-{random.choice(['24', '48', 'Pro-24', 'Flex'])}",
            "sw_name": f"Switch-{random.randint(1, 10)}",
            "sw_mac": generate_mac(),
            "port": random.randint(1, 48),
            "port_name": f"Port {random.randint(1, 48)}",
            "speed": random.choice(["10", "100", "1000"]) + "Mbps",
            "duplex": "full"
        })
    
    elif "GW" in device_type or "UDM" in device_type or "routing" in event_info["category"]:
        event.update({
            "gw": f"UDM-{random.choice(['Pro', 'Base', 'SE'])}",
            "gw_name": f"Gateway-{random.randint(1, 5)}",
            "gw_mac": generate_mac(),
            "wan_ip": f"{random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}",
            "lan_ip": generate_ip()
        })
    
    # Add security event specific fields
    if event_info["category"] == "security":
        event.update({
            "source_ip": generate_ip() if random.choice([True, False]) else f"{random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}",
            "dest_ip": generate_ip(),
            "source_port": random.randint(1024, 65535),
            "dest_port": random.choice([22, 23, 80, 443, 53, 25, 993, 995]),
            "protocol": random.choice(["TCP", "UDP", "ICMP"])
        })
        
        if "IPS" in event_info["type"]:
            event.update({
                "signature_id": random.randint(1000, 9999),
                "signature": random.choice([
                    "ET SCAN NMAP -sS window 1024",
                    "ET TROJAN Suspicious User-Agent",
                    "ET WEB_SERVER Suspicious User-Agent",
                    "ET SCAN Potential SSH Scan"
                ]),
                "classification": random.choice(["Attempted Reconnaissance", "Trojan Activity", "Web Application Attack"]),
                "priority": random.randint(1, 4)
            })
    
    # Add performance metrics
    event.update({
        "version": "7.3.83",
        "model": f"{device_type}-{random.choice(['Gen2', 'Gen3', 'Pro', 'Lite'])}",
        "uptime": random.randint(3600, 2592000),  # 1 hour to 30 days in seconds
        "loadavg_1": round(random.uniform(0.1, 2.0), 2),
        "loadavg_5": round(random.uniform(0.1, 2.0), 2),
        "loadavg_15": round(random.uniform(0.1, 2.0), 2),
        "mem_used": random.randint(30, 80),  # percentage
        "mem_buffer": random.randint(5, 20)   # percentage
    })
    
    return event

if __name__ == "__main__":
    # Generate sample events
    print("Sample Ubiquiti UniFi Events:")
    print("=" * 50)
    for i in range(3):
        print(f"\nEvent {i+1}:")
        print(ubiquiti_unifi_log())