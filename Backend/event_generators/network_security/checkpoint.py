#!/usr/bin/env python3
"""Generate synthetic Check Point Firewall logs in JSON format for marketplace parser."""
import json
import random
from datetime import datetime, timezone
import time
import uuid

# SentinelOne AI-SIEM specific field attributes
# Check Point log fields and values
ACTIONS = ["Accept", "Drop", "Reject", "Encrypt", "Decrypt", "Monitor", "Block", "Allow"]
SERVICES = ["http", "https", "ssh", "ftp", "smtp", "dns", "telnet", "rdp", "smb", "ldap", "ntp", "snmp"]
PROTOCOLS = ["tcp", "udp", "icmp", "esp", "ah", "gre"]
RULES = ["Clean_Traffic", "Block_Malware", "Allow_VPN", "Monitor_Suspicious", "Default_Drop", "Allow_Internal", "Block_External_Threats"]
PRODUCTS = ["VPN-1 & FireWall-1", "Threat Prevention", "URL Filtering", "Application Control", "IPS", "Anti-Bot", "Anti-Virus"]
BLADES = ["fw", "ips", "urlf", "appi", "av", "ab", "dlp", "vpn"]
ORIGINS = ["fw01", "fw02", "cluster-1", "sg80", "sg5000", "mgmt-server"]
THREAT_TYPES = ["Malware", "Trojan", "Botnet", "Phishing", "SQL Injection", "XSS", "DDoS", "Ransomware"]

def get_random_ip(internal_probability=0.5):
    """Generate a random IP address."""
    if random.random() < internal_probability:
        # Internal IP
        return random.choice([
            f"10.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}",
            f"172.{random.randint(16, 31)}.{random.randint(0, 255)}.{random.randint(1, 254)}",
            f"192.168.{random.randint(0, 255)}.{random.randint(1, 254)}"
        ])
    else:
        # External IP
        return f"{random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"

def get_port_for_service(service):
    """Get standard port for a service."""
    port_map = {
        "http": 80, "https": 443, "ssh": 22, "ftp": 21, "smtp": 25,
        "dns": 53, "telnet": 23, "rdp": 3389, "smb": 445, "ldap": 389,
        "ntp": 123, "snmp": 161
    }
    return port_map.get(service, random.randint(1024, 65535))

def checkpoint_log(overrides: dict | None = None) -> dict:
    """Generate a single Check Point Firewall log entry in JSON format."""
    now = datetime.now(timezone.utc)
    
    # Determine action and related fields
    action = random.choice(ACTIONS)
    is_allowed = action in ["Accept", "Allow", "Encrypt", "Monitor"]
    
    # Generate source and destination IPs
    src_ip = get_random_ip(internal_probability=0.7 if is_allowed else 0.3)
    dst_ip = get_random_ip(internal_probability=0.3 if is_allowed else 0.7)
    
    # Select service and protocol
    service = random.choice(SERVICES)
    proto = "tcp" if service in ["http", "https", "ssh", "ftp", "smtp", "rdp", "smb", "ldap"] else random.choice(PROTOCOLS)
    
    # Generate ports
    if proto in ["tcp", "udp"]:
        dst_port = get_port_for_service(service)
        src_port = random.randint(1024, 65535)
    else:
        dst_port = 0
        src_port = 0
    
    # Build the JSON log entry for marketplace parser
    log_entry = {
        "time": now.isoformat(),
        "timestamp": int(now.timestamp() * 1000),  # milliseconds
        "orig": src_ip,
        "origin": random.choice(ORIGINS),
        "action": action,
        "src": src_ip,
        "dst": dst_ip,
        "proto": proto,
        "service": service,
        "service_id": str(dst_port) if dst_port else "",
        "s_port": src_port,
        "d_port": dst_port if dst_port else 0,
        "rule": random.choice(RULES),
        "rule_uid": f"{uuid.uuid4()}",
        "rule_name": random.choice(RULES),
        "product": random.choice(PRODUCTS),
        "blade": random.choice(BLADES),
        "ifdir": random.choice(["inbound", "outbound"]),
        "ifname": random.choice(["eth0", "eth1", "eth2", "bond0", "Internal", "External"]),
        "loguid": f"{uuid.uuid4()}",
        "version": "5",
        "fw_subproduct": "VPN-1",
        "policy_id_tag": "Standard",
        "nat_rulenum": random.randint(1, 100) if random.random() < 0.3 else 0,
        "nat_addtnl_rulenum": 0,
        "bytes": random.randint(100, 1000000) if is_allowed else random.randint(40, 1500),
        "packets": random.randint(1, 1000) if is_allowed else random.randint(1, 10),
        "elapsed": random.randint(0, 300) if is_allowed else 0,
        "hostname": f"checkpoint-{random.randint(1, 5)}.company.com",
        "sequencenum": random.randint(1, 1000000),
        "type": "log",
        "vendor": "Check Point",
        "product_family": "Network Security"
    }
    
    # Add threat-specific fields for certain actions
    if action in ["Drop", "Block", "Reject"] and random.random() < 0.5:
        log_entry.update({
            "attack": random.choice([
                "Malformed Packet", "Port Scan", "SQL Injection", 
                "Cross Site Scripting", "Buffer Overflow", "Malware",
                "Trojan", "Botnet Communication", "Brute Force"
            ]),
            "severity": random.choice(["Critical", "High", "Medium", "Low"]),
            "confidence_level": random.randint(1, 5),
            "protection_type": "IPS",
            "malware_action": "Blocked",
            "threat_prevention": True,
            "threat_name": random.choice(THREAT_TYPES)
        })
    
    # Apply overrides if provided
    if overrides:
        log_entry.update(overrides)
    
    return log_entry

if __name__ == "__main__":
    # Generate sample logs in JSON format
    print("Check Point NGFW JSON Format Examples:")
    print("=" * 60)
    for i in range(5):
        log = checkpoint_log()
        print(f"\nEvent {i+1}:")
        print(json.dumps(log, indent=2))