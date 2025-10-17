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
        "user": user,
        "department": random.choice(DEPARTMENTS),
        "locationname": random.choice(["San Jose", "New York", "London", "Frankfurt", "Tokyo"]),
        "cdport": random.choice([22, 23, 25, 53, 80, 143, 443, 993, 995, 8080]),
        "csport": random.randint(32768, 65535),
        "sdport":"0",
        "ssport":"0",
        "csip":f"10.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}",
        "cdip": generate_ip(),
        "ssip":"0.0.0.0",
        "sdip":"0.0.0.0",
        "tsip": generate_ip(),
        "tunsport":"0",
        "tuntype":"ZscalerClientConnector",
        "action": action,
        "dnat":"No",
        "stateful":"Yes",
        "aggregate":"No",
        "nwsvc": app,
        "nwapp":"udp",
        "proto":"UDP",
        "ipcat":"Miscellaneous or Unknown",
        "destcountry": random.choice(COUNTRIES),
        "avgduration":random.randint(1000, 5000),
        "rulelabel": random.choice(RULES),
        "inbytes":random.randint(0, 5000),
        "outbytes":random.randint(0, 5000),
        "duration":random.randint(0, 10),
        "durationms":random.randint(0, 5000),
        "numsessions":"1",
        "ipsrulelabel":"None",
        "threatcat":"None",
        "threatname":"None",
        "deviceowner":"user",
        "devicehostname": f"DEVICE{random.randint(1, 100)}",
        "threat_score":"0",
        "threat_severity":"None"
    }
    
    # Add threat detection fields for blocked traffic
    if action in ["Block", "Drop"]:
        if random.choice([True, False]):  # 50% chance of threat detection
            event.update({
                "threatcat": random.choice(THREAT_CATEGORIES),
                "threatnam": random.choice([
                    "Trojan.GenKryptik",
                    "Adware.Bundler",
                    "Phishing.Generic",
                    "Botnet.Zeus",
                    "Ransomware.WannaCry",
                    "Cryptominer.Generic"
                ]),
                "threat_score": random.randint(1, 100),
                "file_hash": f"{''.join(random.choices('abcdef0123456789', k=64))}",
                "file_name": random.choice([
                    "document.pdf.exe",
                    "invoice.zip", 
                    "update.exe",
                    "photo.jpg.scr"
                ])
            })
    
    # Add URL category for web traffic
    if app in ["HTTP", "HTTPS"] or "Web" in event.get("nwapp", ""):
        event.update({
            "url": random.choice([
                "http://malicious-site.com/payload",
                "https://phishing-bank.net/login",
                "http://c2-server.org/beacon",
                "https://legitimate-site.com/page"
            ]),
            "url_category": random.choice([
                "Business", "Social Networking", "News/Media", "Shopping",
                "Malware", "Phishing", "Command & Control", "Adult/Mature"
            ]),
            "referer": random.choice([
                "https://google.com/search",
                "https://company.com/",
                "https://malicious-redirect.com/"
            ]),
            "http_method": random.choice(["GET", "POST", "PUT", "DELETE"]),
            "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "response_code": random.choice([200, 302, 403, 404, 500])
        })
    
    # Add tunnel information for VPN traffic
    if random.choice([True, False]):  # 30% chance of tunnel traffic
        event.update({
            "tunnel_type": random.choice(["GRE", "IPSec", "SSL", "L2TP"]),
            "tunnel_id": f"tunnel_{random.randint(1000, 9999)}",
            "encrypted": "Yes"
        })
    
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