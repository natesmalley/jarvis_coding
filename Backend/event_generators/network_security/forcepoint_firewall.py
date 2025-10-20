#!/usr/bin/env python3
"""
ForcePoint Firewall event generator 
Generates firewall security events in CEF format
"""
from __future__ import annotations
import random
import time
from datetime import datetime, timezone, timedelta
from typing import Dict

# Firewall actions and verdicts
ACTIONS = ["Allow", "Block", "Drop", "Reject", "Deny", "Permit"]
VERDICTS = ["Allowed", "Blocked", "Dropped", "Rejected", "Denied", "Permitted"]

# Protocols and services
PROTOCOLS = ["TCP", "UDP", "ICMP", "GRE", "ESP", "AH"]
SERVICES = [
    ("HTTP", 80), ("HTTPS", 443), ("SSH", 22), ("FTP", 21), ("SMTP", 25),
    ("DNS", 53), ("DHCP", 67), ("SNMP", 161), ("LDAP", 389), ("RDP", 3389),
    ("SMB", 445), ("Telnet", 23), ("POP3", 110), ("IMAP", 143), ("NTP", 123)
]

# Security signatures and events
SIGNATURES = [
    (1001, "Port Scan Detected", 8),
    (1002, "Brute Force Attack", 9),
    (1003, "SQL Injection Attempt", 10),
    (1004, "Cross-Site Scripting", 7),
    (1005, "Malware Download Blocked", 10),
    (1006, "Suspicious DNS Query", 6),
    (1007, "Data Exfiltration Attempt", 9),
    (1008, "Unauthorized Access Attempt", 8),
    (1009, "DDoS Attack Detected", 10),
    (1010, "Intrusion Attempt", 8),
    (1011, "Policy Violation", 5),
    (1012, "Geo-Location Block", 4),
    (1013, "Application Control Block", 6),
    (1014, "URL Filtering Block", 5),
    (1015, "Threat Intelligence Match", 9)
]

# URLs and applications
BLOCKED_URLS = [
    "malicious-site.com/payload.exe",
    "phishing-bank.net/login.php", 
    "suspicious-domain.org/script.js",
    "blocked-social.com/content",
    "gaming-site.net/downloads",
    "streaming-site.org/videos",
    "torrent-site.com/files",
    "proxy-site.net/browse"
]

ALLOWED_URLS = [
    "company.com/portal",
    "microsoft.com/updates",
    "google.com/search",
    "github.com/repository",
    "stackoverflow.com/questions",
    "office365.com/login",
    "amazonaws.com/api",
    "cloudflare.com/cdn"
]

APPLICATIONS = [
    "HTTP", "HTTPS", "SSH", "FTP", "SMTP", "DNS", "Web Browsing",
    "Email", "File Transfer", "Remote Access", "Database", "Cloud Storage",
    "Social Media", "Streaming", "Gaming", "P2P", "VPN", "Proxy"
]

# User agents and device info
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36", 
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
    "curl/7.68.0",
    "python-requests/2.25.1",
    "Go-http-client/2.0"
]

def _generate_ip(internal: bool = True) -> str:
    """Generate IP address"""
    if internal:
        return random.choice([
            f"10.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}",
            f"172.{random.randint(16, 31)}.{random.randint(0, 255)}.{random.randint(1, 254)}",
            f"192.168.{random.randint(0, 255)}.{random.randint(1, 254)}"
        ])
    else:
        return f"{random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"

def forcepoint_firewall_log(overrides: dict | None = None) -> str:
    """
    Return a single ForcePoint Firewall event in CEF format.
    
    Pass `overrides` to force any field to a specific value:
        forcepoint_firewall_log({"act": "Block"})
    """
    now = datetime.now(timezone.utc)
    event_time = now - timedelta(seconds=random.randint(0, 300))
    
    # Select signature and determine action
    signature_id, signature_name, severity = random.choice(SIGNATURES)
    
    # Determine action based on signature
    if "Block" in signature_name or "Attempt" in signature_name or "Attack" in signature_name:
        action = random.choice(["Block", "Drop", "Deny"])
        verdict = action + "ed"
    else:
        action = random.choice(["Allow", "Permit"])
        verdict = action + "ed" if action == "Allow" else "Permitted"
    
    # Generate network details
    src_ip = _generate_ip(internal=True)
    dst_ip = _generate_ip(internal=False) if action in ["Block", "Drop", "Deny"] else _generate_ip(internal=random.random() < 0.7)
    
    service_name, default_port = random.choice(SERVICES)
    src_port = random.randint(1024, 65535)
    dst_port = default_port if random.random() < 0.7 else random.randint(1, 65535)
    protocol = random.choice(PROTOCOLS)
    
    # Select URL based on action
    if action in ["Block", "Drop", "Deny"]:
        url = random.choice(BLOCKED_URLS)
    else:
        url = random.choice(ALLOWED_URLS)
    
    # CEF header fields
    cef_version = "0"
    device_vendor = "Forcepoint"
    device_product = "NGFW"
    device_version = "6.8.1"
    
    # CEF extensions
    extensions = {
        "act": action,
        "app": random.choice(APPLICATIONS),
        "deviceDirection": random.choice(["0", "1"]),  # 0=inbound, 1=outbound
        "rt": int(event_time.timestamp() * 1000),
        "src": src_ip,
        "spt": src_port,
        "dst": dst_ip,
        "dpt": dst_port,
        "proto": protocol,
        "request": f"/{random.choice(['api', 'web', 'content', 'data'])}/{random.choice(['v1', 'v2', 'latest'])}/",
        "requestMethod": random.choice(["GET", "POST", "PUT", "DELETE", "HEAD"]),
        "cs1": url,
        "cs1Label": "URL",
        "cs2": random.choice(USER_AGENTS),
        "cs2Label": "UserAgent", 
        "cs3": f"Rule_{random.randint(1000, 9999)}",
        "cs3Label": "PolicyRule",
        "cs4": random.choice(["Internal", "External", "DMZ", "Guest"]),
        "cs4Label": "SourceZone",
        "cs5": random.choice(["Internal", "External", "DMZ", "Internet"]),
        "cs5Label": "DestinationZone",
        "cs6": random.choice(["High", "Medium", "Low", "Critical"]),
        "cs6Label": "ThreatLevel",
        "cnt": random.randint(1, 100),
        "in": random.randint(100, 100000),
        "out": random.randint(100, 100000),
        "cat": random.choice(["Firewall", "IPS", "Application Control", "URL Filtering", "Anti-Malware"]),
        "reason": f"{signature_name} - {verdict}",
        "outcome": verdict,
        "dvchost": f"FP-FW-{random.randint(1, 10):02d}",
        "dvc": _generate_ip(internal=True),
        "deviceInboundInterface": f"eth{random.randint(0, 3)}",
        "deviceOutboundInterface": f"eth{random.randint(0, 3)}",
        "externalId": str(random.randint(100000, 999999)),
        "fileSize": str(random.randint(1024, 1048576)) if "Download" in signature_name else "",
        "fileType": random.choice(["exe", "pdf", "doc", "zip", "js"]) if "Download" in signature_name else "",
        "fname": f"suspicious_file.{random.choice(['exe', 'pdf', 'doc'])}" if "Download" in signature_name else "",
        "fsize": str(random.randint(1024, 1048576)) if "Download" in signature_name else "",
        "msg": f"ForcePoint Firewall: {signature_name}",
        "spriv": random.choice(["Administrator", "User", "Guest"]) if random.random() < 0.5 else "",
        "dpriv": random.choice(["Administrator", "User", "Guest"]) if random.random() < 0.5 else "",
        "suser": f"user_{random.randint(1, 100)}" if random.random() < 0.4 else "",
        "duser": f"target_user_{random.randint(1, 100)}" if random.random() < 0.3 else "",
        "smac": f"{random.randint(0, 255):02x}:{random.randint(0, 255):02x}:{random.randint(0, 255):02x}:{random.randint(0, 255):02x}:{random.randint(0, 255):02x}:{random.randint(0, 255):02x}",
        "dmac": f"{random.randint(0, 255):02x}:{random.randint(0, 255):02x}:{random.randint(0, 255):02x}:{random.randint(0, 255):02x}:{random.randint(0, 255):02x}:{random.randint(0, 255):02x}",
        "cn1": random.randint(1, 1000000),
        "cn1Label": "ConnectionCount",
        "cn2": random.randint(1, 3600),
        "cn2Label": "Duration",
        "cn3": random.randint(0, 100),
        "cn3Label": "ThreatScore"
    }
    
    # Apply overrides
    if overrides:
        extensions.update(overrides)
    
    # Build CEF message
    timestamp = event_time.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + event_time.strftime("%z")[:3] + ":" + event_time.strftime("%z")[3:]
    
    # Build CEF header
    cef_header = f"CEF:{cef_version}|{device_vendor}|{device_product}|{device_version}|{signature_id}|{signature_name}|{severity}"
    
    # Build extensions string - only include non-empty values
    extension_pairs = []
    for key, value in extensions.items():
        if value:  # Only include non-empty values
            # Escape special characters in CEF extensions
            if isinstance(value, str):
                value = value.replace("\\", "\\\\").replace("=", "\\=").replace("|", "\\|")
            extension_pairs.append(f"{key}={value}")
    
    extensions_str = "|" + " ".join(extension_pairs)
    
    return f"{timestamp} {cef_header}{extensions_str}"

if __name__ == "__main__":
    # Generate sample logs
    print("Sample ForcePoint Firewall events:")
    for action in ["Allow", "Block", "Drop"]:
        print(f"\n{action} event:")
        print(forcepoint_firewall_log({"act": action}))
        print()