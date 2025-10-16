#!/usr/bin/env python3
"""
AWS VPC DNS event generator
Generates synthetic AWS VPC DNS query logs
"""
import json
import random
import time
from datetime import datetime, timezone, timedelta
from typing import Dict

# DNS query types
QUERY_TYPES = ["A", "AAAA", "MX", "NS", "PTR", "SOA", "TXT", "CNAME", "SRV"]

# Response codes
RESPONSE_CODES = [
    "NOERROR",
    "NXDOMAIN", 
    "SERVFAIL",
    "REFUSED",
    "TIMEOUT"
]

# Common domains for corporate environments
DOMAINS = [
    "company.corp",
    "internal.company.corp",
    "services.company.corp", 
    "portal.company.corp",
    "google.com",
    "amazonaws.com",
    "microsoft.com",
    "cloudflare.com",
    "github.com",
    "stackoverflow.com",
    "suspicious-domain.org",
    "threat-actor.net",
    "malware-c2.com"
]

def generate_vpc_ip() -> str:
    """Generate VPC IP address"""
    return f"10.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"

def aws_vpc_dns_log() -> Dict:
    """Generate a single AWS VPC DNS event log"""
    now = datetime.now(timezone.utc)
    event_time = now - timedelta(minutes=random.randint(0, 1440))
    
    domain = random.choice(DOMAINS)
    query_type = random.choice(QUERY_TYPES)
    response_code = random.choice(RESPONSE_CODES)
    
    # Determine if suspicious
    is_suspicious = domain in ["suspicious-domain.com", "malware-c2.net", "phishing-site.org"]
    
    event = {
        "version": "1.100000",
        "account_id": f"{random.randint(100000000000, 999999999999)}",
        "interface_id": f"eni-{random.randint(10000000, 99999999):08x}",
        "srcaddr": generate_vpc_ip(),
        "dstaddr": f"169.254.169.253",  # VPC DNS resolver
        "srcport": random.randint(32768, 65535),
        "dstport": 53,
        "protocol": 17,  # UDP
        "packets": 1,
        "bytes": random.randint(60, 512),
        "windowstart": int(event_time.timestamp()),
        "windowend": int(event_time.timestamp()) + 60,
        "action": "ACCEPT",
        "flowlogstatus": "OK",
        "query_name": domain,
        "query_type": query_type,
        "query_class": "IN",
        "rcode": response_code,
        "rdata": f"{random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}" if response_code == "NOERROR" and query_type == "A" else "",
        "answers": random.randint(0, 5) if response_code == "NOERROR" else 0,
        "transport": "UDP",
        "vpc_id": f"vpc-{random.randint(10000000, 99999999):08x}",
        "subnet_id": f"subnet-{random.randint(10000000, 99999999):08x}",
        "instance_id": f"i-{random.randint(10000000, 99999999):08x}",
        "query_timestamp": event_time.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "firewall_rule_action": "PASS",
        "threat_list_name": "malware-domains" if is_suspicious else "",
        "threat_list_id": f"tl-{random.randint(10000000, 99999999):08x}" if is_suspicious else ""
    }
    
    return event

if __name__ == "__main__":
    # Generate sample events
    print("Sample AWS VPC DNS Events:")
    print("=" * 50)
    for i in range(3):
        print(f"\nEvent {i+1}:")
        print(aws_vpc_dns_log())