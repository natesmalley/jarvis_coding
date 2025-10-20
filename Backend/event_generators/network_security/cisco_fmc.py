#!/usr/bin/env python3
"""
Cisco Firepower Management Center (FMC) event generator
Generates synthetic Cisco FMC security and management events
"""
import json
import random
import time
from datetime import datetime, timezone, timedelta
from typing import Dict

# Event types
EVENT_TYPES = [
    {"type": "Intrusion", "subtype": "IPS_EVENT", "severity": "High"},
    {"type": "Malware", "subtype": "MALWARE_EVENT", "severity": "Critical"},
    {"type": "Connection", "subtype": "CONNECTION_EVENT", "severity": "Info"},
    {"type": "File", "subtype": "FILE_EVENT", "severity": "Medium"},
    {"type": "System", "subtype": "SYSTEM_EVENT", "severity": "Warning"},
    {"type": "User", "subtype": "USER_EVENT", "severity": "Info"},
    {"type": "Policy", "subtype": "POLICY_EVENT", "severity": "Warning"},
    {"type": "URL", "subtype": "URL_EVENT", "severity": "Medium"},
    {"type": "DNS", "subtype": "DNS_EVENT", "severity": "Info"},
    {"type": "DLP", "subtype": "DLP_EVENT", "severity": "High"}
]

# Actions
ACTIONS = ["Allow", "Block", "Drop", "Alert", "Log", "Reset", "Redirect"]

# Protocols
PROTOCOLS = ["TCP", "UDP", "ICMP", "GRE", "ESP", "AH"]

# Malware types
MALWARE_TYPES = [
    "Trojan", "Virus", "Worm", "Rootkit", "Backdoor", "Adware", 
    "Spyware", "Ransomware", "Botnet", "Cryptominer"
]

# IPS signatures
IPS_SIGNATURES = [
    "SQL Injection Attack",
    "Cross-Site Scripting",
    "Buffer Overflow Attempt", 
    "Port Scan Detected",
    "Brute Force Login",
    "Command Injection",
    "Directory Traversal",
    "Shellcode Detected"
]

def generate_ip() -> str:
    """Generate a random IP address"""
    return f"{random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"

def cisco_fmc_log(overrides: dict = None) -> Dict:
    """Generate a single Cisco FMC event log"""
    now = datetime.now(timezone.utc)
    event_time = now - timedelta(minutes=random.randint(0, 10))
    
    event_info = random.choice(EVENT_TYPES)
    action = random.choice(ACTIONS)
    
    event = {
        "timestamp": event_time.isoformat(),
        "event_id": random.randint(1000000, 9999999),
        "event_type": event_info["type"],
        "event_subtype": event_info["subtype"],
        "severity": event_info["severity"],
        "action": action,
        "device_name": f"ENTERPRISE-FTD-{random.choice(['BRIDGE', 'ENGINEERING', 'SECURITY', 'MEDICAL'])}-{random.randint(1, 5)}",
        "device_ip": generate_ip(),
        "policy_name": f"StarfleetSecurityPolicy_{random.randint(1, 5)}",
        "rule_name": f"Directive_{random.randint(1, 100)}",
        "source_ip": generate_ip(),
        "destination_ip": generate_ip(),
        "source_port": random.randint(1024, 65535),
        "destination_port": random.choice([22, 23, 25, 53, 80, 135, 139, 443, 445, 993, 995, 3389]),
        "protocol": random.choice(PROTOCOLS),
        "source_country": random.choice(["US", "CA", "GB", "DE", "FR", "CN", "RU", "IN", "BR", "JP"]),
        "destination_country": random.choice(["US", "CA", "GB", "DE", "FR", "CN", "RU", "IN", "BR", "JP"]),
        "application_protocol": random.choice(["HTTP", "HTTPS", "SSH", "FTP", "DNS", "SMTP", "SMB", "RDP"]),
        "client_application": random.choice(["Chrome", "Firefox", "Safari", "Edge", "curl", "wget"]),
        "web_application": random.choice(["Apache", "Nginx", "IIS", "Tomcat", "Unknown"]),
        "bytes_sent": random.randint(64, 100000),
        "bytes_received": random.randint(64, 100000),
        "packets_sent": random.randint(1, 1000),
        "packets_received": random.randint(1, 1000),
        "duration": random.randint(1, 7200),  # seconds
    }
    
    # Add event-specific fields
    if event_info["type"] == "Intrusion":
        event.update({
            "signature_id": random.randint(1000, 9999),
            "signature_name": random.choice(IPS_SIGNATURES),
            "classification": random.choice(["Attempted Reconnaissance", "Web Application Attack", "Trojan Activity"]),
            "priority": random.randint(1, 4),
            "impact": random.choice(["Vulnerable", "Not Vulnerable", "Unknown"]),
            "blocked": action == "Block"
        })
    
    elif event_info["type"] == "Malware":
        event.update({
            "malware_name": f"{random.choice(MALWARE_TYPES)}.{random.choice(['Win32', 'Generic', 'Trojan'])}.{random.randint(1000, 9999)}",
            "malware_type": random.choice(MALWARE_TYPES),
            "file_name": random.choice(["malware.exe", "trojan.dll", "virus.scr", "backdoor.bat"]),
            "file_sha256": ''.join(random.choices('abcdef0123456789', k=64)),
            "file_size": random.randint(1024, 10485760),
            "detection_name": f"Malware_{random.randint(1000, 9999)}",
            "cloud_lookup": random.choice(["Clean", "Malware", "Unknown", "Timeout"])
        })
    
    elif event_info["type"] == "Connection":
        event.update({
            "connection_id": random.randint(100000, 999999),
            "initiator_ip": event["source_ip"],
            "responder_ip": event["destination_ip"],
            "tcp_flags": random.choice(["SYN", "ACK", "FIN", "RST", "SYN+ACK"]),
            "connection_counter": random.randint(1, 100),
            "first_packet_second": int(event_time.timestamp()),
            "last_packet_second": int(event_time.timestamp()) + event["duration"]
        })
    
    elif event_info["type"] == "File":
        event.update({
            "file_name": random.choice(["document.pdf", "image.jpg", "archive.zip", "executable.exe"]),
            "file_type": random.choice(["PDF", "JPEG", "ZIP", "PE"]),
            "file_sha256": ''.join(random.choices('abcdef0123456789', k=64)),
            "file_size": random.randint(1024, 52428800),
            "disposition": random.choice(["Clean", "Malware", "Custom Detection", "Unavailable"]),
            "spero_disposition": random.choice(["Clean", "Malware", "Unknown"]),
            "threat_score": random.randint(0, 100),
            "upload_destination": random.choice(["Cloud Analysis", "Dynamic Analysis", "Local Analysis"])
        })
    
    elif event_info["type"] == "URL":
        event.update({
            "url": random.choice([
                "http://romulan-spy.net/payload",
                "https://ferengi-phishing.com/login", 
                "http://borg-collective.net/assimilate",
                "https://starfleet.corp/bridge",
                "https://memory-alpha.org/library"
            ]),
            "url_category": random.choice([
                "Business", "Social Networking", "News/Media", "Shopping",
                "Malware", "Phishing", "Command & Control", "Adult Content"
            ]),
            "url_reputation": random.choice(["Trusted", "Untrusted", "Neutral", "Unknown"]),
            "referer": random.choice([
                "https://starfleet.corp/search",
                "https://enterprise.starfleet.corp/",
                "https://dominion-redirect.net/"
            ]),
            "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        })
    
    elif event_info["type"] == "DNS":
        event.update({
            "dns_query": random.choice([
                "starfleet.corp", "memory-alpha.org", "borg-collective.net", 
                "romulan-spy.org", "enterprise.starfleet.corp"
            ]),
            "dns_record_type": random.choice(["A", "AAAA", "MX", "NS", "TXT", "CNAME"]),
            "dns_response_type": random.choice(["No Error", "Format Error", "Server Failure", "Name Error"]),
            "dns_ttl": random.randint(60, 86400)
        })
    
    # Add geolocation for external IPs
    if not event["source_ip"].startswith("10.") and not event["source_ip"].startswith("192.168."):
        event.update({
            "source_latitude": round(random.uniform(-90, 90), 6),
            "source_longitude": round(random.uniform(-180, 180), 6)
        })
    
    if not event["destination_ip"].startswith("10.") and not event["destination_ip"].startswith("192.168."):
        event.update({
            "destination_latitude": round(random.uniform(-90, 90), 6),
            "destination_longitude": round(random.uniform(-180, 180), 6)
        })
    
    # Apply overrides if provided (for scenario customization)
    if overrides:
        event.update(overrides)
    
    return event

if __name__ == "__main__":
    # Generate sample events
    print("Sample Cisco FMC Events:")
    print("=" * 50)
    for i in range(3):
        print(f"\nEvent {i+1}:")
        print(json.dumps(cisco_fmc_log(), indent=2))