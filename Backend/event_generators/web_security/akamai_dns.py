#!/usr/bin/env python3
"""
Akamai DNS query log event generator
Generates synthetic Akamai DNS logs in syslog format
"""
import random
from datetime import datetime, timezone, timedelta

# DNS record types
RECORD_TYPES = ["A", "AAAA", "CNAME", "MX", "NS", "TXT", "SRV"]

# DNS response codes
RESPONSE_CODES = ["NOERROR", "NXDOMAIN", "SERVFAIL", "FORMERR", "REFUSED"]

# Common domains
DOMAINS = [
    "www.example.com", "api.example.com", "mail.example.com",
    "cdn.example.com", "blog.example.com", "shop.example.com", 
    "nonexistent.example.com", "test.example.org", "app.example.net"
]

# Edge servers
EDGE_SERVERS = [
    "edge-ldn", "edge-sfo", "edge-nyc", "edge-fra", 
    "edge-nrt", "edge-syd", "edge-ams", "edge-mia"
]

def generate_client_ip() -> str:
    """Generate client IP address"""
    return f"{random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"

def generate_resolver_ip() -> str:
    """Generate resolver IP address"""
    resolvers = ["203.0.113.200", "203.0.113.201", "8.8.8.8", "1.1.1.1", "9.9.9.9"]
    return random.choice(resolvers)

def generate_answer(record_type: str, response_code: str, domain: str) -> str:
    """Generate DNS answer based on record type and response code"""
    if response_code != "NOERROR":
        return ""
    
    if record_type == "A":
        return f"192.0.2.{random.randint(1, 254)}"
    elif record_type == "AAAA":
        return f"2001:db8::{random.randint(1, 255):x}"
    elif record_type == "CNAME":
        return f"alias.{domain}"
    elif record_type == "MX":
        return f"{random.randint(10, 50)} mail.{domain}"
    elif record_type == "TXT":
        return "v=spf1 include:_spf.example.com ~all"
    else:
        return f"ns1.{domain}"

def akamai_dns_log() -> str:
    """Generate a single Akamai DNS query log in syslog format"""
    now = datetime.now(timezone.utc)
    event_time = now - timedelta(minutes=random.randint(0, 1440))
    
    timestamp = event_time.strftime("%Y-%m-%dT%H:%M:%SZ")
    stream_id = f"dns-{random.randint(100, 999)}"
    client_ip = generate_client_ip()
    resolver_ip = generate_resolver_ip()
    domain = random.choice(DOMAINS)
    record_type = random.choice(RECORD_TYPES)
    response_code = random.choice(RESPONSE_CODES)
    edge_server = random.choice(EDGE_SERVERS)
    answer = generate_answer(record_type, response_code, domain)
    
    # TTL based on response
    ttl = random.choice([300, 600, 1800, 3600]) if response_code == "NOERROR" else 0
    bytes_size = random.choice([64, 96, 128, 192, 256])
    
    # Generate syslog format matching the original test event
    # 2025-08-06T22:30:01Z AkamaiDNS streamId="dns-123" cliIP="198.51.100.30" resolverIP="203.0.113.200" domain="www.example.com" recordType="A" responseCode="NOERROR" answer="192.0.2.5" edge="edge-ldn" ttl=300 bytes=128
    log = (f'{timestamp} AkamaiDNS streamId="{stream_id}" cliIP="{client_ip}" '
           f'resolverIP="{resolver_ip}" domain="{domain}" recordType="{record_type}" '
           f'responseCode="{response_code}" answer="{answer}" edge="{edge_server}" '
           f'ttl={ttl} bytes={bytes_size}')
    
    return log

# ATTR_FIELDS for AI-SIEM compatibility
if __name__ == "__main__":
    # Generate sample events
    print("Sample Akamai DNS Events:")
    print("=" * 50)
    for i in range(3):
        print(f"\nEvent {i+1}:")
        print(akamai_dns_log())