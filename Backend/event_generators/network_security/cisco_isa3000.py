#!/usr/bin/env python3
"""
Cisco ISA3000 Industrial Security Appliance event generator
Generates synthetic Cisco ISA3000 industrial network security events
"""
import json
import random
import time
from datetime import datetime, timezone, timedelta
from typing import Dict

# Event types specific to industrial environments
EVENT_TYPES = [
    {"type": "FIREWALL", "action": "ALLOW", "severity": "INFO"},
    {"type": "FIREWALL", "action": "DENY", "severity": "WARNING"},
    {"type": "IPS", "action": "ALERT", "severity": "HIGH"},
    {"type": "IPS", "action": "DROP", "severity": "CRITICAL"},
    {"type": "VPN", "action": "CONNECT", "severity": "INFO"},
    {"type": "VPN", "action": "DISCONNECT", "severity": "INFO"},
    {"type": "SYSTEM", "action": "BOOT", "severity": "NOTICE"},
    {"type": "SYSTEM", "action": "CONFIG_CHANGE", "severity": "WARNING"},
    {"type": "MODBUS", "action": "READ_COILS", "severity": "INFO"},
    {"type": "MODBUS", "action": "WRITE_REGISTERS", "severity": "WARNING"},
    {"type": "SCADA", "action": "HMI_ACCESS", "severity": "INFO"},
    {"type": "SCADA", "action": "UNAUTHORIZED_COMMAND", "severity": "CRITICAL"}
]

# Industrial protocols
INDUSTRIAL_PROTOCOLS = [
    "Modbus TCP", "DNP3", "EtherNet/IP", "PROFINET", "OPC UA",
    "BACnet", "IEC 61850", "S7", "CIP", "ControlNet"
]

# SCADA/ICS device types
DEVICE_TYPES = ["PLC", "HMI", "RTU", "SCADA Server", "Engineering Workstation", "Historian"]

# Modbus function codes
MODBUS_FUNCTIONS = [
    {"code": 1, "name": "Read Coils", "risk": "LOW"},
    {"code": 2, "name": "Read Discrete Inputs", "risk": "LOW"},
    {"code": 3, "name": "Read Holding Registers", "risk": "MEDIUM"},
    {"code": 4, "name": "Read Input Registers", "risk": "LOW"},
    {"code": 5, "name": "Write Single Coil", "risk": "HIGH"},
    {"code": 6, "name": "Write Single Register", "risk": "HIGH"},
    {"code": 15, "name": "Write Multiple Coils", "risk": "CRITICAL"},
    {"code": 16, "name": "Write Multiple Registers", "risk": "CRITICAL"}
]

def generate_ip() -> str:
    """Generate industrial network IP (typically 10.x.x.x or 192.168.x.x)"""
    if random.choice([True, False]):
        return f"10.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"
    else:
        return f"192.168.{random.randint(1, 10)}.{random.randint(1, 254)}"

def cisco_isa3000_log() -> Dict:
    """Generate a single Cisco ISA3000 event log"""
    now = datetime.now(timezone.utc)
    event_time = now - timedelta(minutes=random.randint(0, 1440))
    
    event_info = random.choice(EVENT_TYPES)
    
    event = {
        "timestamp": event_time.isoformat(),
        "hostname": f"ISA3000-{random.randint(1, 10)}",
        "device_ip": generate_ip(),
        "event_type": event_info["type"],
        "action": event_info["action"],
        "severity": event_info["severity"],
        "message_id": f"ISA-{random.randint(100000, 999999)}",
        "source_ip": generate_ip(),
        "destination_ip": generate_ip(),
        "source_port": random.randint(1024, 65535),
        "destination_port": random.choice([80, 102, 443, 502, 503, 2404, 20000, 44818]),
        "protocol": random.choice(["TCP", "UDP"]),
        "zone_from": random.choice(["TRUSTED", "UNTRUSTED", "DMZ", "SCADA", "CORPORATE"]),
        "zone_to": random.choice(["TRUSTED", "UNTRUSTED", "DMZ", "SCADA", "CORPORATE"]),
        "policy_name": f"ISA_Policy_{random.randint(1, 20)}",
        "rule_name": f"Rule_{random.randint(1, 100)}",
        "interface_in": f"GigabitEthernet0/{random.randint(0, 3)}",
        "interface_out": f"GigabitEthernet0/{random.randint(0, 3)}",
        "bytes_sent": random.randint(64, 10000),
        "bytes_received": random.randint(64, 10000),
        "duration": random.randint(1, 3600),  # seconds
    }
    
    # Add event-specific fields
    if event_info["type"] == "FIREWALL":
        event.update({
            "application": random.choice(["HTTP", "HTTPS", "Modbus", "DNP3", "SSH", "Telnet"]),
            "nat_source_ip": generate_ip() if random.choice([True, False]) else "",
            "nat_destination_ip": generate_ip() if random.choice([True, False]) else "",
            "connection_tag": random.randint(1000000, 9999999),
            "reason": random.choice([
                "Traffic allowed by policy",
                "Traffic denied by policy", 
                "Invalid packet format",
                "Connection limit exceeded"
            ]) if event_info["action"] == "DENY" else "Traffic allowed by policy"
        })
    
    elif event_info["type"] == "IPS":
        event.update({
            "signature_id": random.randint(1000, 9999),
            "signature_name": random.choice([
                "Industrial Protocol Anomaly",
                "Modbus Function Code Abuse",
                "SCADA Command Injection",
                "PLC Programming Attempt",
                "HMI Brute Force Attack",
                "DNP3 Protocol Violation",
                "Unauthorized Engineering Access"
            ]),
            "classification": random.choice([
                "Industrial System Attack",
                "SCADA Anomaly",
                "Protocol Violation",
                "Unauthorized Access"
            ]),
            "impact": random.choice(["Critical", "High", "Medium", "Low"]),
            "blocked": event_info["action"] == "DROP"
        })
    
    elif event_info["type"] == "VPN":
        event.update({
            "vpn_type": random.choice(["Site-to-Site", "Remote Access", "L2L"]),
            "tunnel_id": random.randint(1, 1000),
            "peer_ip": generate_ip(),
            "encryption": random.choice(["AES-256", "AES-128", "3DES"]),
            "authentication": random.choice(["SHA-256", "SHA-1", "MD5"]),
            "user": f"user{random.randint(1, 50)}@company.com" if event_info["action"] in ["CONNECT", "DISCONNECT"] else "",
            "bytes_transmitted": random.randint(1000, 1000000) if event_info["action"] == "DISCONNECT" else 0,
            "session_duration": random.randint(60, 28800) if event_info["action"] == "DISCONNECT" else 0
        })
    
    elif event_info["type"] == "MODBUS":
        modbus_func = random.choice(MODBUS_FUNCTIONS)
        event.update({
            "modbus_function_code": modbus_func["code"],
            "modbus_function_name": modbus_func["name"],
            "modbus_unit_id": random.randint(1, 247),
            "modbus_transaction_id": random.randint(1, 65535),
            "register_address": random.randint(0, 9999),
            "register_count": random.randint(1, 100),
            "risk_level": modbus_func["risk"],
            "device_type": random.choice(DEVICE_TYPES),
            "plc_model": random.choice(["Allen-Bradley", "Schneider", "Siemens", "GE Fanuc"])
        })
    
    elif event_info["type"] == "SCADA":
        event.update({
            "scada_protocol": random.choice(INDUSTRIAL_PROTOCOLS),
            "device_type": random.choice(DEVICE_TYPES),
            "operator": f"operator{random.randint(1, 20)}",
            "command": random.choice([
                "START_PROCESS",
                "STOP_PROCESS", 
                "RESET_ALARM",
                "CHANGE_SETPOINT",
                "OVERRIDE_SAFETY",
                "DOWNLOAD_PROGRAM"
            ]),
            "target_device": f"{random.choice(DEVICE_TYPES)}-{random.randint(1, 50)}",
            "authorization_level": random.choice(["Operator", "Engineer", "Administrator", "Unauthorized"]),
            "safety_impact": random.choice(["None", "Low", "Medium", "High", "Critical"])
        })
    
    elif event_info["type"] == "SYSTEM":
        event.update({
            "system_component": random.choice([
                "Firewall Engine",
                "IPS Engine", 
                "VPN Module",
                "Management Interface",
                "Industrial Protocol Inspector"
            ]),
            "config_section": random.choice([
                "Access Control",
                "IPS Signatures",
                "VPN Settings",
                "Industrial Protocols",
                "Zone Configuration"
            ]) if event_info["action"] == "CONFIG_CHANGE" else "",
            "admin_user": f"admin{random.randint(1, 5)}",
            "change_description": random.choice([
                "Policy rule modified",
                "Signature database updated",
                "Zone configuration changed",
                "VPN tunnel added",
                "Industrial protocol settings updated"
            ]) if event_info["action"] == "CONFIG_CHANGE" else ""
        })
    
    # Add industrial network context
    event.update({
        "industrial_zone": random.choice(["Level 0", "Level 1", "Level 2", "Level 3", "DMZ"]),
        "criticality": random.choice(["Critical", "High", "Medium", "Low"]),
        "safety_system": random.choice([True, False]),
        "process_area": random.choice([
            "Production Line 1",
            "Production Line 2", 
            "Quality Control",
            "Utilities",
            "Safety Systems",
            "Maintenance"
        ])
    })
    
    return event

if __name__ == "__main__":
    # Generate sample events
    print("Sample Cisco ISA3000 Events:")
    print("=" * 50)
    for i in range(3):
        print(f"\nEvent {i+1}:")
        print(cisco_isa3000_log())