#!/usr/bin/env python3

"""
Generates synthetic Zscaler firewall and security events
"""
import json
import random
import time
from datetime import datetime, timezone, timedelta
from typing import Dict

# Actions taken by firewall
ACTIONS = ["Allow"]

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
    "Command & Control",
    "Ransomware",

]

# Countries
COUNTRIES = ["US", "CA", "GB", "DE", "FR", "CN", "RU", "IN", "BR", "JP", "AU", "IT"]

# Departments  
DEPARTMENTS = ["IT", "Sales", "Marketing", "Finance", "HR", "Engineering", "Legal", "Operations"]

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
    
    event = {
        "datetime": event_time.isoformat(),
        "timestamp": int(event_time.timestamp()),
        "recordtype": "FirewallLogs",
        "recordid": f"fw_{random.randint(1000000000, 9999999999)}",
        "action": action,
        "aggregate": "Yes" if random.choice([True, False]) else "No",
        "bandwidth_throttle": random.choice(["Yes", "No"]),
        "client_ip": f"10.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}",
        "client_publicip": generate_ip(),
        "client_country": random.choice(COUNTRIES),
        "client_latitude": round(random.uniform(-90, 90), 6),
        "client_longitude": round(random.uniform(-180, 180), 6),
        "department": random.choice(DEPARTMENTS),
        "dest_ip": generate_ip(),
        "dest_port": random.choice([22, 23, 25, 53, 80, 143, 443, 993, 995, 8080]),
        "dest_country": random.choice(COUNTRIES),
        "device_owner": f"user{random.randint(1, 100)}@company.com",
        "device_hostname": f"PC-{random.randint(1000, 9999)}",
        "dnat_ip": generate_ip() if action == "Allow" else "",
        "dnat_port": random.randint(1024, 65535) if action == "Allow" else 0,
        "duration": random.randint(1, 3600),  # seconds
        "inbound_bytes": random.randint(0, 1000000),
        "outbound_bytes": random.randint(0, 1000000),
        "app": app,
        "nwapp": random.choice(["Web Browsing", "SSL", "SSH", "DNS", "Email"]),
        "nwsvc": random.choice(["HTTP", "HTTPS", "DNS", "SMTP", "IMAP"]),
        "proto": protocol,
        "src_ip": f"10.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}",
        "src_port": random.randint(32768, 65535),
        "stateful": "Yes",
        "aggregate_session": random.choice(["Yes", "No"]),
        "policy": f"FW_Policy_{random.randint(1, 20)}",
        "rule": f"Rule_{random.randint(100, 999)}",
        "nat_rule": f"NAT_Rule_{random.randint(10, 99)}" if action == "Allow" else "",
        "locationname": random.choice(["San Jose", "New York", "London", "Frankfurt", "Tokyo"]),
        "numsessions": random.randint(1, 100),
        "user": f"user{random.randint(1, 100)}@company.com",
        "vendor": "Zscaler",
        "product": "ZIA",
        "version": "1.0"
    }
    
    # Add threat detection fields for blocked traffic
    if action in ["Allow"]:
        if random.choice([True, False]):  # 50% chance of threat detection
            event.update({
                "threatcat": random.choice(THREAT_CATEGORIES),
                "threatname": random.choice([
                    "cobaltstrike",
                    "8base",
                    "abyss",
                    "akira",
                    "alphv",
                    "babuk",
                    "bashe",
                    "bianlian",
                    "blackbasta",
                    "blackout",
                    "blacksuit",
                    "braincipher",
                    "cactus",
                    "ciphbit",
                    "clop",
                    "everest",
                    "hunters",
                    "kairos",
                    "killsecurity",
                    "lockbit",
                    "lynx",
                    "medusa",
                    "moneymessage",
                    "nitrogen",
                    "ragroup",
                    "revil",
                    "ransom",
                    "rhysida",
                    "qilin",
                    "spacebears",
                    "termite"  
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
    #print("Sample Zscaler Firewall Events:")
    print("=" * 50)
    for i in range(5):
        #print(f"\nEvent {i+1}:")
        print(zscaler_firewall_log())