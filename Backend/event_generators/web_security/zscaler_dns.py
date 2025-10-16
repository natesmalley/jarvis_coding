#!/usr/bin/env python3
"""
Zscaler Firewall event generator  
Generates synthetic Zscaler firewall and security events
"""
import json
import random
import time
from datetime import datetime, timezone, timedelta
from typing import Dict

# Actions taken by firewall
ACTIONS = ["Allow", "Block", "Drop", "Redirect"]

# DNS Record types
DNSRECORD = ["A","AAAA","SRV","HTTPS"]

# Protocols
PROTOCOLS = ["TCP", "UDP", "ICMP", "GRE", "ESP"]

# Applications detected
APPLICATIONS = [
    "HTTP", "HTTPS", "SSH", "FTP", "DNS", "SMTP", "POP3", "IMAP",
    "Facebook", "YouTube", "Twitter", "WhatsApp", "Skype", "Zoom",
    "Dropbox", "OneDrive", "GoogleDrive", "Box", "Slack", "Teams"
]

# Threat categories
THREAT_CATEGORIES = [
    "Malware",
    "Phishing", 
    "Botnet",
    "Command & Control",
    "Cryptocurrency Mining",
    "Adware",
    "Spyware",
    "Ransomware",
    "Data Theft",
    "DNS Tunneling"
]

# Countries
COUNTRIES = ["US", "CA", "GB", "DE", "FR", "CN", "RU", "IN", "BR", "JP", "AU", "IT"]

# Departments  
DEPARTMENTS = ["IT", "Sales", "Marketing", "Finance", "HR", "Engineering", "Legal", "Operations"]

# DNS Requests 
REQUESTS = ["google.com","linkedin.com","amazon.com","cloudflare.com"]

# DNS RESPONSES
RESPONSES = ["1.1.1.1","2.2.2.2","3.3.3.3","4.4.4.4"]

# Categories
CATEGORIES = ["Internet Services","Social Networking","Ecommerce","Internet Infrastructure"]

def generate_ip() -> str:
    """Generate a random IP address"""
    return f"{random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"

def zscaler_firewall_log() -> str:
    """Generate a single Zscaler Firewall event log"""
    now = datetime.now(timezone.utc)
    event_time = now - timedelta(minutes=random.randint(0, 5))
    
    action = random.choice(ACTIONS)
    protocol = random.choice(PROTOCOLS)
    app = random.choice(APPLICATIONS)
    dns = random.choice(DNSRECORD)
    request = random.choice(REQUESTS)
    response = random.choice(RESPONSES)
    category = random.choice(CATEGORIES)
    
    event = {
        "datetime": event_time.isoformat(),
        "user": f"user{random.randint(1, 100)}@company.com",
        "department": random.choice(DEPARTMENTS),
        "location": random.choice(["San Jose", "New York", "London", "Frankfurt", "Tokyo"]),
        "reqaction": action,
        "resaction": action,
        "reqrulelabel":"Default Firewall DNS Rule",
        "resrulelabel":"Default Firewall DNS Rule",
        "dns_reqtype": dns,
        "dns_req": request,
        "dns_resp": response,
        "srv_dport":"53",
        "durationms":"2",
        "clt_sip":f"10.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}",
        "srv_dip":f"{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}"
        "category": category,
        "respipcategory":"Professional Services",
        "deviceowner":"test_owner",
        "devicehostname":"test_hostname"
    }
    
    # Add OCSF compliance fields
    event.update({
        "class_uid": 4001,
        "class_name": "Network Activity",
        "category_uid": 4,
        "category_name": "Network Activity", 
        "activity_id": 6,
        "activity_name": "Traffic",
        "type_uid": 400106,
        "severity_id": 4 if action == "Block" else 2 if action == "Drop" else 1,
        "status_id": 2 if action in ["Block", "Drop"] else 1
    })
    
    # Return JSON for the proven Cisco Duo-style parser
    return json.dumps(event)

if __name__ == "__main__":
    # Generate sample events
   # print("Sample Zscaler Firewall Events:")
    #print("=" * 50)
    for i in range(100):
       #print(f"\nEvent {i+1}:")
        print(zscaler_firewall_log())