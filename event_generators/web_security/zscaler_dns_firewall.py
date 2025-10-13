#!/usr/bin/env python3
"""
Zscaler DNS Firewall event generator
Generates synthetic Zscaler Internet Access DNS firewall logs
"""
import json
import random
import time
from datetime import datetime, timezone, timedelta
from typing import Dict

# DNS query types
QUERY_TYPES = ["A", "AAAA", "MX", "NS", "PTR", "SOA", "TXT", "CNAME", "SRV"]

# Response codes
RESPONSE_CODES = ["NOERROR", "NXDOMAIN", "SERVFAIL", "REFUSED"]

# Actions
ACTIONS = ["ALLOWED", "BLOCKED", "REDIRECTED"]

# Policy IDs
POLICY_IDS = [
    "MALWARE-DOMAIN", "PHISHING-PROTECTION", "BOTNET-DETECTION",
    "DATA-LOSS-PREVENTION", "SECURITY-POLICY", "CONTENT-FILTER"
]

# Threat categories
THREAT_CATEGORIES = [
    "Malware", "Phishing", "Botnet", "Command & Control",
    "Suspicious", "Adult Content", "Gambling", "Social Media"
]

# Star Trek themed domains
DOMAINS = [
    "starfleet.corp", "memory-alpha.org", "vulcan-academy.org", "betazed-council.net",
    "earth-starfleet.gov", "starfleet-academy.edu", "engineering.starfleet.corp",
    "romulan-empire.com", "ferengi-commerce.net", "borg-collective.net",
    "cardassian-union.org", "dominion-command.net", "suspicious-space-station.com"
]

# Star Trek themed users
USERS = [
    "jean.picard@starfleet.corp", "william.riker@starfleet.corp", "data.android@starfleet.corp",
    "jordy.laforge@starfleet.corp", "worf.security@starfleet.corp", "beverly.crusher@starfleet.corp",
    "deanna.troi@starfleet.corp", "starfleet-admin@enterprise.starfleet.corp"
]

# Star Trek themed device IDs
DEVICE_IDS = [
    "ENTERPRISE-BRIDGE-01", "ENTERPRISE-BRIDGE-02", "ENTERPRISE-ENG-01", "ENTERPRISE-SEC-01", 
    "ENTERPRISE-MED-01", "VOYAGER-BRIDGE-01", "DS9-OPS-01", "DEFIANT-TACTICAL-01"
]

def generate_ip() -> str:
    """Generate source IP address"""
    return f"{random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"

def generate_answer_ip() -> str:
    """Generate DNS answer IP address"""
    return f"{random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"

def zscaler_dns_firewall_log() -> Dict:
    """Generate a single Zscaler DNS Firewall event log"""
    now = datetime.now(timezone.utc)
    # Use recent timestamps (last 10 minutes)
    event_time = now - timedelta(minutes=random.randint(0, 10))
    
    query = random.choice(DOMAINS)
    query_type = random.choice(QUERY_TYPES)
    response_code = random.choice(RESPONSE_CODES)
    user_name = random.choice(USERS)
    source_ip = generate_ip()
    device_id = random.choice(DEVICE_IDS)
    
    # Determine if this is a threat (Star Trek themed)
    is_threat = any(threat in query for threat in ["romulan-empire", "ferengi-commerce", "borg-collective", "cardassian-union", "dominion-command", "suspicious"])
    
    # Set action and other fields based on threat status
    if is_threat:
        action = "BLOCKED"
        policy_id = random.choice(POLICY_IDS)
        threat_category = random.choice(THREAT_CATEGORIES)
        answer = ""  # No answer for blocked queries
    else:
        action = "ALLOWED"
        policy_id = None
        threat_category = None
        if response_code == "NOERROR" and query_type == "A":
            answer = generate_answer_ip()
        elif response_code == "NOERROR" and query_type == "AAAA":
            answer = f"2001:db8::{random.randint(1, 65535):x}"
        else:
            answer = ""
    
    event = {
        "timestamp": event_time.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "userName": user_name,
        "sourceIp": source_ip,
        "deviceId": device_id,
        "query": query,
        "queryType": query_type,
        "responseCode": response_code,
        "answer": answer,
        "action": action,
        "bytes_sent": random.randint(50, 1000),
        "bytes_received": random.randint(50, 1000),
        "response_time_ms": random.randint(1, 500)
    }
    
    # Add threat-related fields if applicable
    if is_threat:
        event["policyId"] = policy_id
        event["threatCategory"] = threat_category
        event["risk_score"] = random.randint(7, 10)
        event["blocked_reason"] = "Domain blocked by security policy"
    
    return event

if __name__ == "__main__":
    # Generate sample events
    #print("Sample Zscaler DNS Firewall Events:")
    #print("=" * 50)
    for i in range(100):
        #print(f"\nEvent {i+1}:")
        event_string = json.dumps(zscaler_dns_firewall_log())
        #perfect_event_string = event_string.replace("'",'"')
        print(event_string)
        #print(perfect_event_string)