#!/usr/bin/env python3
"""
F5 Networks event generator
Generates synthetic F5 BIG-IP load balancer and security events
"""
import json
import random
import time
from datetime import datetime, timezone, timedelta
from typing import Dict

# Module types
MODULES = ["LTM", "GTM", "ASM", "APM", "AFM", "AVR", "DNS"]

# Event types by module
EVENT_TYPES = {
    "LTM": [
        {"type": "POOL_MEMBER_UP", "severity": "INFO"},
        {"type": "POOL_MEMBER_DOWN", "severity": "ERROR"},
        {"type": "VIRTUAL_SERVER_UP", "severity": "INFO"},
        {"type": "VIRTUAL_SERVER_DOWN", "severity": "ERROR"},
        {"type": "CONNECTION_LIMIT_EXCEEDED", "severity": "WARNING"}
    ],
    "ASM": [
        {"type": "ATTACK_SIGNATURE_MATCHED", "severity": "CRITICAL"},
        {"type": "SQL_INJECTION_DETECTED", "severity": "CRITICAL"},
        {"type": "XSS_ATTACK_DETECTED", "severity": "CRITICAL"},
        {"type": "POLICY_VIOLATION", "severity": "WARNING"},
        {"type": "BLOCKED_REQUEST", "severity": "WARNING"}
    ],
    "APM": [
        {"type": "USER_LOGIN_SUCCESS", "severity": "INFO"},
        {"type": "USER_LOGIN_FAILURE", "severity": "WARNING"},
        {"type": "SESSION_CREATED", "severity": "INFO"},
        {"type": "SESSION_TERMINATED", "severity": "INFO"},
        {"type": "VPN_CONNECTION_ESTABLISHED", "severity": "INFO"}
    ],
    "AFM": [
        {"type": "FIREWALL_RULE_MATCHED", "severity": "INFO"},
        {"type": "DENIED_CONNECTION", "severity": "WARNING"},
        {"type": "DOS_ATTACK_DETECTED", "severity": "CRITICAL"},
        {"type": "RATE_LIMIT_EXCEEDED", "severity": "WARNING"},
        {"type": "INTRUSION_DETECTED", "severity": "CRITICAL"}
    ]
}

# HTTP methods
HTTP_METHODS = ["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS"]

# Attack types
ATTACK_TYPES = [
    "SQL Injection",
    "Cross-Site Scripting",
    "Command Injection",
    "Path Traversal",
    "LDAP Injection",
    "XML External Entity",
    "Server-Side Request Forgery"
]

def generate_ip() -> str:
    """Generate a random IP address"""
    return f"{random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"

def f5_networks_log() -> str:
    """Generate a single F5 Networks event log"""
    now = datetime.now(timezone.utc)
    event_time = now  # Use current time instead of random past time
    
    module = random.choice(list(EVENT_TYPES.keys()))
    event_info = random.choice(EVENT_TYPES[module])
    
    event = {
        "timestamp": event_time.isoformat(),
        "hostname": f"f5-bigip-{random.randint(1, 10)}",
        "device_ip": generate_ip(),
        "module": module,
        "event_type": event_info["type"],
        "severity": event_info["severity"],
        "facility": "LOCAL0",
        "priority": random.randint(16, 23),
        "slot": f"1.{random.randint(1, 4)}",
        "tmm": random.randint(0, 3),
        "virtual_server": f"vs_{random.choice(['web', 'api', 'app'])}_{random.randint(1, 5)}",
        "pool": f"pool_{random.choice(['web', 'api', 'app'])}_{random.randint(1, 5)}",
        "client_ip": generate_ip(),
        "server_ip": f"10.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}",
        "client_port": random.randint(32768, 65535),
        "server_port": random.choice([80, 443, 8080, 8443]),
        "protocol": random.choice(["TCP", "UDP", "HTTP", "HTTPS"])
    }
    
    # Add module-specific fields
    if module == "LTM":
        event.update({
            "pool_member_status": "up" if "UP" in event_info["type"] else "down",
            "connection_count": random.randint(0, 10000),
            "throughput_mbps": random.randint(1, 1000),
            "response_time_ms": random.randint(1, 5000)
        })
    
    elif module == "ASM":
        event.update({
            "http_method": random.choice(HTTP_METHODS),
            "uri": random.choice(["/", "/login", "/admin", "/api/v1/users", "/upload"]),
            "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "attack_type": random.choice(ATTACK_TYPES),
            "signature_id": random.randint(200000000, 299999999),
            "policy_name": f"asm_policy_{random.randint(1, 5)}",
            "violation_rating": random.randint(1, 5),
            "request_status": random.choice(["blocked", "alerted", "logged"]),
            "support_id": f"{random.randint(1000000000000000, 9999999999999999)}"
        })
    
    elif module == "APM":
        event.update({
            "username": f"user{random.randint(1, 100)}",
            "session_id": f"sess_{random.randint(100000000, 999999999)}",
            "access_profile": f"ap_{random.choice(['vpn', 'portal', 'federation'])}",
            "authentication_method": random.choice(["LDAP", "RADIUS", "Local", "SAML", "OAuth"]),
            "virtual_server_name": f"/Common/vs_{random.choice(['vpn', 'portal'])}",
            "client_type": random.choice(["Browser", "Mobile", "VPN Client"]),
            "geo_location": random.choice(["US", "CA", "GB", "DE", "FR", "JP"])
        })
    
    elif module == "AFM":
        event.update({
            "rule_name": f"rule_{random.randint(1, 100)}",
            "action": random.choice(["accept", "drop", "reject"]),
            "context_name": f"context_{random.randint(1, 10)}",
            "source_vlan": f"vlan_{random.randint(10, 100)}",
            "dest_vlan": f"vlan_{random.randint(10, 100)}",
            "packet_count": random.randint(1, 1000),
            "byte_count": random.randint(64, 1000000),
            "flow_id": random.randint(1000000, 9999999)
        })
    
    # Add common traffic details
    if random.choice([True, False]):
        event.update({
            "bytes_in": random.randint(100, 100000),
            "bytes_out": random.randint(100, 100000),
            "packets_in": random.randint(1, 1000),
            "packets_out": random.randint(1, 1000)
        })
    
    # Add OCSF compliance fields for parser
    event.update({
        "class_uid": 4001,
        "class_name": "Network Activity",
        "category_uid": 4,
        "category_name": "Network Activity",
        "activity_id": 6,
        "activity_name": "Traffic",
        "type_uid": 400106,
        "severity_id": 5 if event["severity"] == "CRITICAL" else 3 if event["severity"] in ["ERROR", "WARNING"] else 1,
        "status_id": 1 if any(x in event["event_type"] for x in ["UP", "SUCCESS", "ESTABLISHED", "ACCEPTED"]) else 2
    })
    
    # Return comma-separated key=value format for F5 parser
    # Parser expects: key1=value1,key2=value2,key3=value3
    pairs = []
    for key, value in event.items():
        # Clean key names - only alphanumeric and dots
        clean_key = ''.join(c for c in key if c.isalnum() or c in '._')
        pairs.append(f"{clean_key}={value}")
    
    return ",".join(pairs)

if __name__ == "__main__":
    # Generate sample events
    print("Sample F5 Networks Events:")
    print("=" * 50)
    for i in range(3):
        print(f"\nEvent {i+1}:")
        print(f5_networks_log())