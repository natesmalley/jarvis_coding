#!/usr/bin/env python3
"""
ISC DHCP event generator
Generates synthetic ISC DHCP server logs
"""
import random
from datetime import datetime, timezone, timedelta

DHCP_TYPES = ["DHCPDISCOVER", "DHCPOFFER", "DHCPREQUEST", "DHCPACK", "DHCPRELEASE"]
INTERFACES = ["eth0", "eth1", "wlan0", "br0"]
HOSTNAMES = ["desktop01", "laptop02", "printer01", "phone03", "tablet01", None]

def generate_mac():
    """Generate a MAC address."""
    return f"{random.randint(0, 255):02x}:{random.randint(0, 255):02x}:{random.randint(0, 255):02x}:{random.randint(0, 255):02x}:{random.randint(0, 255):02x}:{random.randint(0, 255):02x}"

def generate_ip():
    """Generate an IP address in 192.168.1.x range."""
    return f"192.168.1.{random.randint(100, 200)}"

def isc_dhcp_log() -> dict:
    """Generate a single ISC DHCP server log"""
    now = datetime.now(timezone.utc)
    event_time = now - timedelta(seconds=random.randint(0, 3600))
    
    # Generate DHCP sequence (DISCOVER -> OFFER -> REQUEST -> ACK)
    dhcp_type = random.choice(DHCP_TYPES)
    pid = random.randint(700, 999)
    mac = generate_mac()
    ip = generate_ip()
    interface = random.choice(INTERFACES)
    hostname = random.choice(HOSTNAMES)
    
    # Build structured log entry
    log_entry = {
        "timestamp": event_time.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "process": "dhcpd",
        "process_id": pid,
        "dhcp_message_type": dhcp_type,
        "client_mac": mac,
        "client_ip": ip,
        "interface": interface,
        "client_hostname": hostname
    }
    
    # Add type-specific fields and message
    if dhcp_type == "DHCPDISCOVER":
        log_entry["message"] = f"{dhcp_type} from {mac} via {interface}"
    elif dhcp_type == "DHCPOFFER":
        log_entry["message"] = f"{dhcp_type} on {ip} to {mac} via {interface}"
    elif dhcp_type == "DHCPACK":
        lease_duration = random.choice([3600, 86400, 604800])  # 1 hour, 1 day, 1 week
        log_entry["lease_duration"] = lease_duration
        if hostname:
            log_entry["message"] = f"{dhcp_type} on {ip} to {mac} ({hostname}) via {interface} lease-duration {lease_duration}"
        else:
            log_entry["message"] = f"{dhcp_type} on {ip} to {mac} via {interface} lease-duration {lease_duration}"
    elif dhcp_type == "DHCPRELEASE":
        if hostname:
            log_entry["message"] = f"{dhcp_type} of {ip} from {mac} ({hostname}) via {interface}"
        else:
            log_entry["message"] = f"{dhcp_type} of {ip} from {mac} via {interface}"
    else:  # DHCPREQUEST
        log_entry["message"] = f"{dhcp_type} for {ip} from {mac} via {interface}"
    
    return log_entry

if __name__ == "__main__":
    import json
    print("Sample ISC DHCP Events:")
    print("=" * 50)
    for i in range(3):
        print(f"\nEvent {i+1}:")
        print(json.dumps(isc_dhcp_log(), indent=2))