#!/usr/bin/env python3
"""
Cisco IOS event generator
Generates synthetic Cisco IOS network device syslog events
"""
import json
import random
import time
from datetime import datetime, timezone, timedelta
from typing import Dict

# IOS device types
DEVICE_TYPES = ["Router", "Switch", "Firewall", "ASA"]

# Facility and severity levels
FACILITIES = ["LOCAL0", "LOCAL1", "LOCAL2", "LOCAL3", "LOCAL4", "LOCAL5", "LOCAL6", "LOCAL7"]
SEVERITIES = ["emerg", "alert", "crit", "err", "warning", "notice", "info", "debug"]

# Common IOS events
IOS_EVENTS = [
    {"facility": "SYS", "mnemonic": "CONFIG_I", "severity": "info", "message": "Configured from console by {user}"},
    {"facility": "LINK", "mnemonic": "UPDOWN", "severity": "info", "message": "Interface {interface}, changed state to {state}"},
    {"facility": "LINEPROTO", "mnemonic": "UPDOWN", "severity": "info", "message": "Line protocol on Interface {interface}, changed state to {state}"},
    {"facility": "BGP", "mnemonic": "ADJCHANGE", "severity": "notice", "message": "neighbor {ip} {state}"},
    {"facility": "OSPF", "mnemonic": "ADJCHG", "severity": "info", "message": "Process {process_id}, Nbr {ip} on {interface} from {old_state} to {new_state}"},
    {"facility": "SEC_LOGIN", "mnemonic": "SUCCESS", "severity": "info", "message": "Login Success [user: {user}] [Source: {ip}] [localport: 22]"},
    {"facility": "SEC_LOGIN", "mnemonic": "QUIET_MODE_ON", "severity": "warning", "message": "Quiet Mode is activated. Denying login attempts for {duration} seconds"},
    {"facility": "CRYPTO", "mnemonic": "IKMP_SA_REQ_SUCC", "severity": "info", "message": "ISAKMP SA request profile {profile} Accepted local:{local_ip} remote:{remote_ip}"},
    {"facility": "TRACKING", "mnemonic": "STATE", "severity": "info", "message": "1 ip sla 1 reachability Up->Down"},
    {"facility": "DUAL", "mnemonic": "NBRCHANGE", "severity": "info", "message": "EIGRP-IPv4 1: Neighbor {ip} ({interface}) is {state}"},
    {"facility": "SFF8472", "mnemonic": "THRESHOLD_VIOLATION", "severity": "warning", "message": "Te1/0/1: Temperature high warning; Operating value: 85.2 C, Threshold value: 85.0 C"},
    {"facility": "ENVIRONMENT", "mnemonic": "FAN_WARNING", "severity": "warning", "message": "Fan 1 operation status changed to warning"},
    {"facility": "C4K_HWACLMAN", "mnemonic": "CFGACE_COUNTER_WRAP", "severity": "info", "message": "Hardware counters wrapped for ACE number 10 in RACL Rule"}
]

# Interface types
INTERFACE_TYPES = [
    "GigabitEthernet0/0", "GigabitEthernet0/1", "GigabitEthernet1/0", "GigabitEthernet1/1",
    "TenGigabitEthernet0/0", "TenGigabitEthernet0/1", 
    "FastEthernet0/0", "FastEthernet0/1",
    "Serial0/0", "Serial0/1",
    "Loopback0", "Loopback1",
    "Tunnel0", "Tunnel1",
    "Vlan1", "Vlan10", "Vlan100"
]

# Users
USERS = ["admin", "netadmin", "cisco", "operator", "guest", "service"]

def generate_ip() -> str:
    """Generate a random IP address"""
    return f"{random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"

def cisco_ios_log() -> Dict:
    """Generate a single Cisco IOS syslog event"""
    now = datetime.now(timezone.utc)
    event_time = now - timedelta(minutes=random.randint(0, 1440))
    
    device_type = random.choice(DEVICE_TYPES)
    hostname = f"{device_type.lower()}-{random.randint(1, 50)}"
    event_info = random.choice(IOS_EVENTS)
    
    # Format message with dynamic values
    message = event_info["message"]
    replacements = {
        "user": random.choice(USERS),
        "interface": random.choice(INTERFACE_TYPES),
        "state": random.choice(["up", "down"]),
        "ip": generate_ip(),
        "process_id": random.randint(1, 65535),
        "old_state": random.choice(["LOADING", "FULL", "2WAY", "INIT"]),
        "new_state": random.choice(["LOADING", "FULL", "2WAY", "INIT"]),
        "profile": f"profile_{random.randint(1, 10)}",
        "local_ip": f"192.168.{random.randint(1, 10)}.{random.randint(1, 254)}",
        "remote_ip": generate_ip(),
        "duration": random.randint(60, 300)
    }
    
    for key, value in replacements.items():
        message = message.replace(f"{{{key}}}", str(value))
    
    # Create structured syslog event
    facility = random.choice(FACILITIES)
    severity = event_info["severity"]
    sequence_num = random.randint(1, 999999)
    
    event = {
        "timestamp": event_time.isoformat(),
        "hostname": hostname,
        "device_ip": generate_ip(),
        "facility": facility,
        "severity": severity,
        "mnemonic": event_info["mnemonic"],
        "facility_mnemonic": event_info["facility"],
        "sequence_number": sequence_num,
        "message": message,
        "raw_message": f"*{event_time.strftime('%b %d %H:%M:%S.%f')[:-3]}: %{event_info['facility']}-{severity.upper()}-{event_info['mnemonic']}: {message}",
        "process_name": event_info["facility"],
        "ios_version": f"{random.randint(12, 17)}.{random.randint(0, 9)}.{random.randint(0, 9)}",
        "hardware_platform": random.choice(["C9300", "C9400", "C2960", "ISR4321", "ASR1001", "Cat6500"]),
        "uptime": f"{random.randint(1, 365)} days, {random.randint(0, 23)} hours, {random.randint(0, 59)} minutes",
        "location": random.choice(["Building-A", "Building-B", "DataCenter-1", "Branch-Office", "Remote-Site"])
    }
    
    # Add event-specific fields
    if "Interface" in message:
        interface = next((i for i in INTERFACE_TYPES if i in message), random.choice(INTERFACE_TYPES))
        event.update({
            "interface_name": interface,
            "interface_status": "up" if "up" in message else "down",
            "interface_speed": random.choice(["10", "100", "1000", "10000"]) + "Mbps" if "Gigabit" in interface or "Fast" in interface else None,
            "interface_duplex": random.choice(["full", "half", "auto"]) if "Ethernet" in interface else None
        })
    
    # Add BGP specific fields
    if event_info["facility"] == "BGP":
        event.update({
            "bgp_peer": generate_ip(),
            "bgp_as": random.randint(64512, 65535),
            "bgp_state": random.choice(["Established", "Idle", "Active", "OpenSent", "OpenConfirm"])
        })
    
    # Add OSPF specific fields  
    if event_info["facility"] == "OSPF":
        event.update({
            "ospf_process_id": random.randint(1, 65535),
            "ospf_neighbor": generate_ip(),
            "ospf_area": f"0.0.0.{random.randint(0, 255)}",
            "ospf_state": random.choice(["Full", "2-Way", "ExStart", "Exchange", "Loading"])
        })
    
    # Add security event fields
    if "SEC_LOGIN" in event_info["facility"]:
        event.update({
            "source_ip": generate_ip(),
            "username": random.choice(USERS),
            "login_method": random.choice(["SSH", "Telnet", "Console", "VTY"]),
            "session_id": random.randint(1, 1000)
        })
    
    # Add crypto/VPN fields
    if event_info["facility"] == "CRYPTO":
        event.update({
            "crypto_map": f"crypto_map_{random.randint(1, 10)}",
            "ike_version": random.choice(["v1", "v2"]),
            "encryption": random.choice(["AES-256", "AES-128", "3DES"]),
            "authentication": random.choice(["SHA-256", "SHA-1", "MD5"])
        })
    
    # Remove None values
    event = {k: v for k, v in event.items() if v is not None}
    
    return event

if __name__ == "__main__":
    # Generate sample events
    print("Sample Cisco IOS Events:")
    print("=" * 50)
    for i in range(3):
        print(f"\nEvent {i+1}:")
        print(cisco_ios_log())