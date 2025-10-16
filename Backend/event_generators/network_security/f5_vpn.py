#!/usr/bin/env python3
"""
F5 VPN event generator
Generates synthetic F5 VPN session events in syslog format
"""
import random
from datetime import datetime, timezone, timedelta

# VPN events
EVENTS = ["SESSION_START", "SESSION_END", "LOGIN", "LOGOUT", "CONNECTION_FAILED", "AUTH_SUCCESS", "AUTH_FAILURE"]

# Users
USERS = ["alice", "bob", "charlie", "diana", "admin", "vpnuser1", "vpnuser2", "remote_worker"]

# Devices
DEVICES = ["Windows10", "MacOS", "iPhone", "Android", "Linux", "iPad", "Chrome"]

# Messages
MESSAGES = [
    "VPN session established", "VPN session terminated", "User authenticated successfully",
    "Authentication failed", "Connection timeout", "SSL handshake completed", "Tunnel created",
    "Session expired", "Policy applied"
]

def generate_ip() -> str:
    """Generate IP address"""
    return f"{random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"

def f5_vpn_log() -> dict:
    """Generate a single F5 VPN event log in syslog format"""
    now = datetime.now(timezone.utc)
    event_time = now - timedelta(minutes=random.randint(0, 1440))
    
    timestamp = event_time.strftime("%Y-%m-%dT%H:%M:%SZ")
    session_id = f"sid-{random.randint(100, 999):03d}"
    user = random.choice(USERS)
    client_ip = generate_ip()
    start_time = timestamp
    event = random.choice(EVENTS)
    device = random.choice(DEVICES)
    message = random.choice(MESSAGES)
    
    # Generate syslog format matching the original test event
    log = (f'{timestamp} F5VPN session_id="{session_id}" user="{user}" '
           f'client_ip="{client_ip}" start_time="{start_time}" event="{event}" '
           f'device="{device}" message="{message}"')
    
    # Return dict with raw log and ATTR_FIELDS for HEC compatibility
    return {
        "raw": log
    }

# ATTR_FIELDS for AI-SIEM compatibility
if __name__ == "__main__":
    print("Sample F5 VPN Events:")
    print("=" * 50)
    for i in range(3):
        print(f"\nEvent {i+1}:")
        print(f5_vpn_log())