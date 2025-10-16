#!/usr/bin/env python3
"""
ISC BIND DNS event generator
Generates synthetic ISC BIND DNS query logs
"""
import random
from datetime import datetime, timezone, timedelta

HOSTNAMES = [
    "www.akamai.com", "mail.example.org", "update.example.org", 
    "api.github.com", "cdn.jsdelivr.net", "dns.google.com",
    "secure.login.yahoo.com", "download.mozilla.org"
]

QUERY_TYPES = ["A", "AAAA", "MX", "CNAME", "PTR", "TXT", "NS"]
OPCODES = ["E", "T", "D", "U"]  # EDNS, TCP, DNSSEC, UDP

def get_random_ip():
    """Generate a random IP address."""
    ranges = [
        f"10.155.105.{random.randint(1, 255)}",
        f"192.0.2.{random.randint(1, 255)}",
        f"203.0.113.{random.randint(1, 255)}"
    ]
    return random.choice(ranges)

def generate_connection_uid():
    """Generate connection UID."""
    return f"0x7f{random.randint(10000000, 99999999):08x}"

def isc_bind_log() -> dict:
    """Generate a single ISC BIND DNS query log"""
    now = datetime.now(timezone.utc)
    event_time = now - timedelta(seconds=random.randint(0, 3600))
    
    # Generate log components
    hostname = random.choice(HOSTNAMES)
    src_ip = get_random_ip()
    src_port = random.randint(1024, 65535)
    query_type = random.choice(QUERY_TYPES)
    opcode = random.choice(OPCODES)
    conn_uid = generate_connection_uid()
    
    # Build structured log entry
    log_entry = {
        "timestamp": event_time.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z",
        "log_level": "info",
        "log_type": "queries",
        "client_uid": conn_uid,
        "client_ip": src_ip,
        "client_port": src_port,
        "query_hostname": hostname,
        "query_name": hostname,
        "query_class": "IN",
        "query_type": query_type,
        "query_opcode": opcode,
        "message": f"client @{conn_uid} {src_ip}#{src_port} ({hostname}): query: {hostname} IN {query_type} + ({opcode})"
    }
    
    return log_entry

if __name__ == "__main__":
    import json
    print("Sample ISC BIND DNS Events:")
    print("=" * 50)
    for i in range(3):
        print(f"\nEvent {i+1}:")
        print(json.dumps(isc_bind_log(), indent=2))