#!/usr/bin/env python3
"""
Cisco Duo MFA event generator
"""
from __future__ import annotations
import json
import random
import time
from datetime import datetime, timezone
from typing import Dict

def cisco_duo_log() -> Dict:
    """Generate Cisco Duo MFA authentication event"""
    
    # Star Trek themed usernames
    usernames = [
        "jean.picard", "william.riker", "data.android", "geordi.laforge",
        "worf.security", "deanna.troi", "beverly.crusher", "wesley.crusher",
        "james.kirk", "spock.science", "leonard.mccoy", "montgomery.scott",
        "admin", "service_account", "external.vulcan", "contractor.ferengi"
    ]
    
    # Authentication factors
    factors = [
        {"name": "push", "id": 4, "desc": "Push notification"},
        {"name": "phone", "id": 3, "desc": "Phone call"},
        {"name": "sms", "id": 3, "desc": "SMS token"},
        {"name": "passcode", "id": 2, "desc": "TOTP token"},
        {"name": "token", "id": 2, "desc": "Hardware token"}
    ]
    
    # Result statuses
    results = [
        {"name": "SUCCESS", "status_id": 1, "severity": 1, "weight": 7},
        {"name": "DENIED", "status_id": 2, "severity": 3, "weight": 2},
        {"name": "FAILED", "status_id": 2, "severity": 3, "weight": 1},
        {"name": "PENDING", "status_id": 99, "severity": 2, "weight": 1}
    ]
    
    # Geographic locations
    locations = [
        "San Jose, US", "Seattle, US", "Chicago, US", "New York, US",
        "Los Angeles, US", "Austin, US", "Boston, US", "Denver, US",
        "London, UK", "Toronto, CA", "Sydney, AU"
    ]
    
    # Client IPs
    client_ips = [
        "198.51.100.150", "203.0.113.155", "192.0.2.160",
        "198.51.100.175", "203.0.113.180", "192.168.1.100"
    ]
    
    # Generate event data
    timestamp = datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
    username = random.choice(usernames)
    factor = random.choice(factors)
    result = random.choices(results, weights=[r["weight"] for r in results], k=1)[0]
    location = random.choice(locations)
    client_ip = random.choice(client_ips)
    
    # Generate appropriate messages based on factor and result
    messages = {
        ("push", "SUCCESS"): "User approved push notification",
        ("push", "DENIED"): "User denied push notification",
        ("push", "FAILED"): "Push notification failed to deliver",
        ("push", "PENDING"): "Push notification sent, awaiting response",
        
        ("phone", "SUCCESS"): "User approved phone call authentication",
        ("phone", "DENIED"): "User denied phone call authentication",
        ("phone", "FAILED"): "Phone call authentication failed",
        ("phone", "PENDING"): "Phone call in progress",
        
        ("sms", "SUCCESS"): "User successfully enrolled with SMS factor",
        ("sms", "DENIED"): "SMS authentication denied",
        ("sms", "FAILED"): "SMS delivery failed",
        ("sms", "PENDING"): "SMS token sent, awaiting entry",
        
        ("passcode", "SUCCESS"): "TOTP passcode verified successfully",
        ("passcode", "DENIED"): "Invalid TOTP passcode entered",
        ("passcode", "FAILED"): "TOTP passcode verification failed",
        ("passcode", "PENDING"): "Awaiting TOTP passcode entry",
        
        ("token", "SUCCESS"): "Hardware token verified successfully",
        ("token", "DENIED"): "Invalid hardware token code",
        ("token", "FAILED"): "Hardware token verification failed",
        ("token", "PENDING"): "Awaiting hardware token code"
    }
    
    message_key = (factor["name"], result["name"])
    message = messages.get(message_key, f"MFA authentication {result['name'].lower()}")
    
    # Create OCSF-compliant event
    event = {
        "timestamp": timestamp,
        "time": int(time.time() * 1000),
        "class_uid": 3002,
        "class_name": "Authentication",
        "category_uid": 3,
        "category_name": "Identity & Access Management",
        "activity_id": 1,
        "activity_name": "Logon",
        "type_uid": 300201,
        "severity_id": result["severity"],
        "status_id": result["status_id"],
        
        "user": {
            "name": username,
            "account_uid": username,
            "account_type": "User"
        },
        
        "src_endpoint": {
            "ip": client_ip,
            "location": {
                "desc": location,
                "city": location.split(", ")[0],
                "country": location.split(", ")[1] if ", " in location else "US"
            }
        },
        
        "auth_protocol": factor["name"],
        "auth_protocol_id": factor["id"],
        "status": result["name"],
        "message": message,
        
        "mfa_factors": [
            {
                "factor_type": factor["name"],
                "factor_result": result["name"],
                "factor_desc": factor["desc"]
            }
        ],
        
        "metadata": {
            "version": "1.0.0",
            "product": {
                "vendor_name": "Cisco",
                "name": "Cisco Duo Security"
            }
        },
        
        "observables": [
            {
                "name": "user",
                "type": "User",
                "value": username
            },
            {
                "name": "src_ip",
                "type": "IP Address", 
                "value": client_ip
            },
            {
                "name": "auth_factor",
                "type": "Other",
                "value": factor["name"]
            }
        ]
    }
    
    return event

if __name__ == "__main__":
    # Generate sample events
    print("Sample Cisco Duo MFA Events:")
    print("=" * 50)
    for i in range(3):
        print(f"\nEvent {i+1}:")
        print(json.dumps(cisco_duo_log(), indent=2))