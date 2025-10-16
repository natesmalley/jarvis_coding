#!/usr/bin/env python3
"""
Palo Alto Prisma SASE event generator  
Generates synthetic Palo Alto Prisma SASE security and network events
"""
import json
import random
import time
from datetime import datetime, timezone, timedelta
from typing import Dict

# Event types
EVENT_TYPES = [
    {"type": "TRAFFIC", "subtype": "end", "action": "allow"},
    {"type": "TRAFFIC", "subtype": "end", "action": "deny"},  
    {"type": "TRAFFIC", "subtype": "start", "action": "allow"},
    {"type": "THREAT", "subtype": "vulnerability", "action": "alert"},
    {"type": "THREAT", "subtype": "spyware", "action": "block"},
    {"type": "THREAT", "subtype": "virus", "action": "block"},
    {"type": "THREAT", "subtype": "wildfire", "action": "alert"},
    {"type": "URL", "subtype": "block", "action": "block"},
    {"type": "URL", "subtype": "allow", "action": "allow"},
    {"type": "DATA", "subtype": "file", "action": "block"},
    {"type": "TUNNEL", "subtype": "ipsec", "action": "up"},
    {"type": "TUNNEL", "subtype": "ipsec", "action": "down"},
    {"type": "AUTH", "subtype": "login", "action": "success"},
    {"type": "AUTH", "subtype": "login", "action": "failed"}
]

# Applications
APPLICATIONS = [
    "web-browsing", "ssl", "dns", "ssh", "ftp", "smtp", "pop3", "imap",
    "facebook", "youtube", "twitter", "skype", "zoom", "teams",
    "salesforce", "office365", "gmail", "dropbox", "onedrive"
]

# URL categories
URL_CATEGORIES = [
    "business-and-economy", "computer-and-internet-info", "content-delivery-networks",
    "education", "entertainment-and-arts", "financial-services", "government",
    "health-and-medicine", "home-and-garden", "hunting-and-fishing", "insufficient-content",
    "internet-communications-and-telephony", "internet-portals", "job-search", "legal",
    "military", "motor-vehicles", "music", "news", "not-resolved", "nudity", "online-storage-and-backup",
    "parked", "personal-sites-and-blogs", "philosophy-and-political-advocacy", "private-ip-addresses",
    "proxy-avoidance-and-anonymizers", "real-estate", "recreation-and-hobbies", "reference-and-research",
    "religion", "search-engines", "sex-education", "shareware-and-freeware", "shopping", "social-networking",
    "society", "sports", "stock-advice-and-tools", "streaming-media", "swimsuits-and-intimate-apparel",
    "training-and-tools", "translation", "travel", "unknown", "weapons", "web-advertisements",
    "malware", "phishing", "command-and-control", "hacking", "malicious"
]

# Threat names
THREAT_NAMES = [
    "Generic.Malware", "Trojan.GenKryptik", "Adware.Generic", "Spyware.Keylogger",
    "Backdoor.Generic", "Virus.Win32", "Rootkit.Generic", "Ransomware.Generic",
    "Botnet.Zeus", "Phishing.Generic", "Exploit.Kit", "Command.Control"
]

# Countries
COUNTRIES = ["US", "CA", "GB", "DE", "FR", "CN", "RU", "IN", "BR", "JP", "AU", "IT"]

def generate_ip() -> str:
    """Generate a random IP address"""
    return f"{random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"

def paloalto_prismasase_log() -> Dict:
    """Generate a single Palo Alto Prisma SASE event log"""
    now = datetime.now(timezone.utc)
    event_time = now - timedelta(minutes=random.randint(0, 1440))
    
    event_info = random.choice(EVENT_TYPES)
    
    # Base event structure
    event = {
        "time_generated": event_time.isoformat(),
        "serial": f"PA-SASE-{random.randint(100000, 999999)}",
        "type": event_info["type"],
        "subtype": event_info["subtype"],
        "config_version": f"{random.randint(1, 10)}.{random.randint(0, 9)}.{random.randint(0, 9)}",
        "time_received": event_time.isoformat(),
        "src": generate_ip(),
        "dst": generate_ip(),
        "natsrc": generate_ip() if random.choice([True, False]) else "",
        "natdst": generate_ip() if random.choice([True, False]) else "",
        "rule": f"Rule-{random.randint(1, 100)}",
        "srcuser": f"user{random.randint(1, 100)}@company.com",
        "dstuser": "",
        "app": random.choice(APPLICATIONS),
        "vsys": "vsys1",
        "from": random.choice(["trust", "untrust", "dmz", "internal", "external"]),
        "to": random.choice(["trust", "untrusted", "dmz", "internal", "external"]),
        "inbound_if": f"ethernet1/{random.randint(1, 8)}",
        "outbound_if": f"ethernet1/{random.randint(1, 8)}",
        "logset": "LSet1",
        "sessionid": random.randint(100000, 999999),
        "repeatcnt": 1,
        "sport": random.randint(1024, 65535),
        "dport": random.choice([22, 23, 25, 53, 80, 135, 139, 443, 445, 993, 995, 3389]),
        "natsport": random.randint(1024, 65535) if random.choice([True, False]) else 0,
        "natdport": random.choice([22, 23, 25, 53, 80, 443]) if random.choice([True, False]) else 0,
        "flags": f"0x{random.randint(1000, 9999):x}",
        "proto": random.choice(["tcp", "udp", "icmp"]),
        "action": event_info["action"],
        "bytes": random.randint(64, 1048576),
        "bytes_sent": random.randint(64, 524288),
        "bytes_received": random.randint(64, 524288),
        "packets": random.randint(1, 1000),
        "start": int(event_time.timestamp()),
        "elapsed": random.randint(1, 3600),
        "category": random.choice(["any", "business-and-economy", "computer-and-internet-info"]),
        "srcloc": random.choice(COUNTRIES),
        "dstloc": random.choice(COUNTRIES),
        "pkts_sent": random.randint(1, 500),
        "pkts_received": random.randint(1, 500)
    }
    
    # Add event-specific fields
    if event_info["type"] == "THREAT":
        event.update({
            "threatid": f"threat_{random.randint(1000, 9999)}",
            "threat": random.choice(THREAT_NAMES),
            "tname": random.choice(THREAT_NAMES),
            "tid": random.randint(10000, 99999),
            "severity": random.choice(["informational", "low", "medium", "high", "critical"]),
            "direction": random.choice(["client-to-server", "server-to-client"]),
            "seqno": random.randint(1000000, 9999999),
            "actionflags": f"0x{random.randint(1000, 9999):x}",
            "pcap_id": random.randint(1000000, 9999999),
            "reportid": random.randint(1000000000, 9999999999)
        })
        
        if event_info["subtype"] == "wildfire":
            event.update({
                "filedigest": ''.join(random.choices('abcdef0123456789', k=64)),
                "cloud": random.choice(["wildfire", "local"]),
                "filetype": random.choice(["pe", "pdf", "ms-office", "jar", "apk"]),
                "sender": f"user{random.randint(1, 50)}@company.com",
                "subject": "Suspicious attachment detected",
                "recipient": f"user{random.randint(51, 100)}@company.com"
            })
    
    elif event_info["type"] == "URL":
        event.update({
            "url": random.choice([
                "https://www.google.com/search?q=test",
                "https://malicious-site.com/payload", 
                "https://phishing-bank.net/login",
                "https://facebook.com/", 
                "https://youtube.com/watch?v=abc123"
            ]),
            "category": random.choice(URL_CATEGORIES),
            "referer": random.choice([
                "https://google.com/",
                "https://company.com/",
                "https://malicious-redirect.com/"
            ]),
            "http_method": random.choice(["GET", "POST", "PUT", "DELETE"]),
            "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "xff": generate_ip() if random.choice([True, False]) else "",
            "misc": f"url-category={random.choice(URL_CATEGORIES)}"
        })
    
    elif event_info["type"] == "DATA":
        event.update({
            "filename": random.choice([
                "confidential_document.pdf", "customer_database.xlsx", 
                "financial_report.docx", "source_code.zip", "employee_data.csv"
            ]),
            "filetype": random.choice(["pdf", "xlsx", "docx", "zip", "csv"]),
            "category": random.choice([
                "Credit Card Numbers", "Social Security Numbers", "Intellectual Property",
                "Financial Information", "Personal Health Information", "Customer Data"
            ]),
            "severity": random.choice(["informational", "low", "medium", "high", "critical"]),
            "direction": random.choice(["upload", "download"]),
            "justification": random.choice(["business-use", "false-positive", "approved"])
        })
    
    elif event_info["type"] == "TUNNEL":
        event.update({
            "tunnelid": f"tunnel_{random.randint(1, 100)}",
            "tunnel_type": event_info["subtype"],
            "stage": random.choice(["phase1", "phase2", "established", "terminated"]),
            "auth_method": random.choice(["psk", "certificate", "radius"]),
            "tunnel_ip": generate_ip(),
            "peer_ip": generate_ip(),
            "monitor_tag": f"monitor_{random.randint(1, 50)}",
            "parent_session_id": random.randint(100000, 999999),
            "parent_start_time": int((event_time - timedelta(seconds=random.randint(60, 3600))).timestamp()),
            "tunnel_inspect": random.choice(["enable", "disable"])
        })
    
    elif event_info["type"] == "AUTH":
        event.update({
            "authpolicy": f"auth_policy_{random.randint(1, 10)}",
            "server": random.choice(["LDAP", "RADIUS", "Local", "SAML", "Kerberos"]),
            "description": f"Authentication {event_info['action']} for user",
            "clienttype": random.choice(["Agent", "Browser", "Mobile App"]),
            "factor_no": random.randint(1, 3),
            "factor_type": random.choice(["password", "certificate", "token", "biometric"]),
            "factor_completion_time": random.randint(1, 30),
            "ugflags": f"0x{random.randint(1000, 9999):x}",
            "user_by_source": f"user{random.randint(1, 100)}@company.com"
        })
    
    # Add SASE-specific fields
    event.update({
        "device_name": f"PA-SASE-{random.randint(1, 10)}",
        "virtual_sys": "vsys1",
        "cmd": "show",
        "admin": f"admin{random.randint(1, 5)}",
        "client": "Web UI",
        "result": "Successful",
        "configuration_path": f"/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']",
        "dg_hier_level_1": random.randint(11, 15),
        "dg_hier_level_2": random.randint(0, 5),
        "dg_hier_level_3": 0,
        "dg_hier_level_4": 0,
        "vsys_name": "vsys1",
        "device_name": f"PA-SASE-{random.randint(1, 10)}",
        "vsys_id": 1
    })
    
    # Add cloud and edge-specific information
    event.update({
        "cloud_hostname": f"sase-{random.choice(['east', 'west', 'central'])}-{random.randint(1, 10)}.prismaaccess.com",
        "edge_location": random.choice([
            "us-east-1", "us-west-2", "eu-west-1", "ap-southeast-1", 
            "eu-central-1", "ap-northeast-1", "us-central-1"
        ]),
        "tenant_id": f"tenant_{random.randint(100000, 999999)}",
        "service_type": random.choice(["Prisma Access", "Cloud SWG", "CASB", "SWG"]),
        "connection_method": random.choice(["Mobile Users", "Remote Networks", "Service Connections"])
    })
    
    # Remove empty values
    event = {k: v for k, v in event.items() if v != ""}
    
    return event

if __name__ == "__main__":
    # Generate sample events
    print("Sample Palo Alto Prisma SASE Events:")
    print("=" * 50)
    for i in range(3):
        print(f"\nEvent {i+1}:")
        print(paloalto_prismasase_log())