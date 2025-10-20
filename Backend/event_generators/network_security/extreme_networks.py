#!/usr/bin/env python3
"""
Extreme Networks event generator
Generates synthetic Extreme Networks switch and access point events
"""
import json
import random
import time
from datetime import datetime, timezone, timedelta
from typing import Dict

# Device types
DEVICE_TYPES = ["Switch", "Access Point", "Router", "Controller"]

# Event types
EVENT_TYPES = [
    {"type": "PORT_UP", "severity": "INFO", "message": "Port {port} link up"},
    {"type": "PORT_DOWN", "severity": "WARNING", "message": "Port {port} link down"},
    {"type": "STP_TOPOLOGY_CHANGE", "severity": "INFO", "message": "STP topology change detected"},
    {"type": "VLAN_CREATE", "severity": "INFO", "message": "VLAN {vlan} created"},
    {"type": "VLAN_DELETE", "severity": "INFO", "message": "VLAN {vlan} deleted"},
    {"type": "AUTH_SUCCESS", "severity": "INFO", "message": "Authentication successful for user {user}"},
    {"type": "AUTH_FAILURE", "severity": "WARNING", "message": "Authentication failed for user {user}"},
    {"type": "HIGH_CPU", "severity": "CRITICAL", "message": "CPU utilization high: {cpu}%"},
    {"type": "HIGH_MEMORY", "severity": "WARNING", "message": "Memory utilization high: {memory}%"},
    {"type": "TEMPERATURE_ALARM", "severity": "CRITICAL", "message": "Temperature alarm: {temp}°C"},
    {"type": "FAN_FAILURE", "severity": "CRITICAL", "message": "Fan failure detected"},
    {"type": "POWER_SUPPLY_FAILURE", "severity": "CRITICAL", "message": "Power supply {psu} failure"},
    {"type": "CONFIG_CHANGE", "severity": "INFO", "message": "Configuration changed by {user}"},
    {"type": "WIRELESS_CLIENT_CONNECT", "severity": "INFO", "message": "Client {mac} connected to SSID {ssid}"},
    {"type": "WIRELESS_CLIENT_DISCONNECT", "severity": "INFO", "message": "Client {mac} disconnected from SSID {ssid}"}
]

# SSID names
SSIDS = ["Corporate", "Guest", "IoT", "Management", "BYOD"]

# User names
USERS = ["admin", "netadmin", "operator", "guest", "service"]

def generate_mac() -> str:
    """Generate a random MAC address"""
    return ":".join([f"{random.randint(0, 255):02x}" for _ in range(6)])

def generate_ip() -> str:
    """Generate a random IP address"""
    return f"10.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"

def extreme_networks_log() -> Dict:
    """Generate a single Extreme Networks event log"""
    now = datetime.now(timezone.utc)
    event_time = now - timedelta(minutes=random.randint(0, 1440))
    
    device_type = random.choice(DEVICE_TYPES)
    event_info = random.choice(EVENT_TYPES)
    hostname = f"{device_type.lower().replace(' ', '-')}-{random.randint(1, 50)}"
    
    # Format message with dynamic values
    message = event_info["message"]
    replacements = {
        "port": f"1:{random.randint(1, 48)}",
        "vlan": random.randint(1, 4094),
        "user": random.choice(USERS),
        "cpu": random.randint(80, 95),
        "memory": random.randint(75, 90),
        "temp": random.randint(65, 85),
        "psu": random.randint(1, 2),
        "mac": generate_mac(),
        "ssid": random.choice(SSIDS)
    }
    
    for key, value in replacements.items():
        message = message.replace(f"{{{key}}}", str(value))
    
    event = {
        "timestamp": event_time.isoformat(),
        "hostname": hostname,
        "device_type": device_type,
        "device_ip": generate_ip(),
        "event_type": event_info["type"],
        "severity": event_info["severity"],
        "message": message,
        "facility": "LOCAL0",
        "priority": random.randint(16, 23),
        "slot": random.randint(1, 8) if device_type == "Switch" else None,
        "port": random.randint(1, 48) if "PORT_" in event_info["type"] else None,
        "vlan_id": random.randint(1, 4094) if "VLAN" in event_info["type"] else None,
        "mac_address": generate_mac() if "CLIENT" in event_info["type"] else None,
        "ssid": random.choice(SSIDS) if "WIRELESS" in event_info["type"] else None,
        "software_version": f"EXOS {random.randint(22, 32)}.{random.randint(1, 7)}.{random.randint(1, 5)}.{random.randint(1, 10)}",
        "hardware_model": random.choice(["X440-G2", "X460-G2", "X670-G2", "X770", "AP3912", "AP410C"]),
        "uptime": f"{random.randint(1, 365)}d {random.randint(0, 23)}h {random.randint(0, 59)}m",
        "serial_number": f"{''.join(random.choices('ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789', k=12))}",
        "location": random.choice(["Building-A-Floor-1", "Building-B-Floor-2", "Warehouse", "Data-Center"])
    }
    
    # Add wireless-specific fields
    if device_type == "Access Point":
        event.update({
            "channel": random.randint(1, 13),
            "signal_strength": random.randint(-80, -30),
            "data_rate": random.choice(["54", "150", "300", "867", "1200"]) + "Mbps",
            "encryption": random.choice(["WPA2-PSK", "WPA3-SAE", "Open", "WEP"])
        })
    
    # Add switch-specific fields
    if device_type == "Switch":
        event.update({
            "stp_state": random.choice(["Forwarding", "Blocking", "Learning", "Listening"]),
            "link_speed": random.choice(["10", "100", "1000", "10000"]) + "Mbps",
            "duplex": random.choice(["Full", "Half", "Auto"])
        })
    
    # Remove None values
    event = {k: v for k, v in event.items() if v is not None}
    
    return event

if __name__ == "__main__":
    # Generate sample events
    print("Sample Extreme Networks Events:")
    print("=" * 50)
    for i in range(3):
        print(f"\nEvent {i+1}:")
        print(extreme_networks_log())