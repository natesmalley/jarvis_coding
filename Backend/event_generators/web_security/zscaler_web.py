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

# Protocols
PROTOCOLS = ["TCP", "UDP", "ICMP", "GRE", "ESP"]

# Applications detected
APPLICATIONS = [
    "HTTP", "HTTPS", "SSH", "FTP", "DNS", "SMTP", "POP3", "IMAP",
    "Facebook", "YouTube", "Twitter", "WhatsApp", "Skype", "Zoom",
    "Dropbox", "OneDrive", "GoogleDrive", "Box", "Slack", "Teams", "QUIC"
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

#Rules
RULES = ["Recommended Firewall Rule", "Default Firewall Filtering Rule", "Block QUIC", "Proxy Bypass"]

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
    user = f"user{random.randint(1, 100)}@company.com",
    
    event = {
    "datetime": event_time.isoformat(),
    "reason":"Allowed",
    "event_id": random.randint(1000000000000000000,9999999999999999999 ),
    "protocol":"HTTP",
    "action":"Allowed"
    "transactionsize":random.randint(1,1000),
    "responsesize":random.randint(1,1000),
    "requestsize":random.randint(1,1000),
    "urlcategory":"Internet Services",
    "serverip": generate_ip(),
    "requestmethod":"GET",
    "refererURL":"None",
    "useragent":"Mozilla/5.0",
    "product":"NSS",
    "location": random.choice(COUNTRIES)
    "ClientIP":f"10.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}",
    "status":"200",
    "user": user
    "url":"www.msftconnecttest.com/connecttest.txt",
    "vendor":"Zscaler",
    "hostname":"www.msftconnecttest.com",
    "clientpublicIP":generate_ip(),
    "threatcategory":"None",
    "threatname":"None",
    "filetype":"None",
    "appname":"General Browsing",
    "app_status":"N/A",
    "pagerisk":"0",
    "threatseverity":"None",
    "department": random.choice(DEPARTMENTS),
    "urlsupercategory":"Internet Communication",
    "appclass":"General Browsing",
    "dlpengine":"None",
    "urlclass":"Business Use",
    "threatclass":"None",
    "dlpdictionaries":"None",
    "fileclass":"None",
    "bwthrottle":"NO",
    "contenttype":"text/plain",
    "unscannabletype":"None",
    "deviceowner": user,
    "devicehostname":f"DEVICE{random.randint(1, 100)}",
    "keyprotectiontype":"N/A"
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