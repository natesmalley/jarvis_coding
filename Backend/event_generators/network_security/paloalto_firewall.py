#!/usr/bin/env python3
"""Generate synthetic Palo Alto Networks firewall logs (CSV format)."""
import json
import random
from datetime import datetime, timezone, timedelta
import time

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'shared'))
from randomization import Randomizer

# Palo Alto log types
LOG_TYPES = ["TRAFFIC", "THREAT", "SYSTEM", "CONFIG", "HIP-MATCH", "GLOBALPROTECT", "USERID", "URL"]

# Common fields
ACTIONS = ["allow", "deny", "drop", "reset-client", "reset-server", "reset-both"]
APPLICATIONS = ["ssl", "web-browsing", "dns", "ssh", "ftp", "smtp", "ping", "ms-rdp", "unknown-tcp", "unknown-udp"]
ZONES = ["trust", "untrust", "dmz", "guest", "vpn", "internal", "external", "internet", "datacenter"]
PROTOCOLS = ["tcp", "udp", "icmp", "esp", "ah", "gre"]
THREAT_CATEGORIES = ["brute-force", "sql-injection", "command-injection", "code-execution", "directory-traversal", 
                     "cross-site-scripting", "vulnerability", "spyware", "virus", "botnet"]
SEVERITIES = ["critical", "high", "medium", "low", "informational"]

def get_random_ip(internal_probability=0.5):
    """Generate a random IP address."""
    internal = random.random() < internal_probability
    return _R.ip(internal=internal)


def get_random_username(domain_probability: float = 0.7, empty_probability: float = 0.2) -> str:
    if random.random() < empty_probability:
        return ""

    username = _R.person(domain="corp.local").username
    if random.random() < domain_probability:
        return f"corp\\{username}"
    return username

def generate_serial_number():
    """Generate a firewall serial number."""
    return f"{random.randint(100000000000000, 999999999999999)}"

def generate_session_id():
    """Generate a session ID."""
    return str(random.randint(10000, 999999))


_R = Randomizer()

def generate_traffic_log():
    """Generate a TRAFFIC log entry."""
    now = datetime.now(timezone.utc)
    start_time = now - timedelta(seconds=random.randint(1, 300))
    
    # Generate IPs and ports
    src_ip = get_random_ip(internal_probability=0.7)
    dst_ip = get_random_ip(internal_probability=0.3)
    src_port = random.randint(1024, 65535)
    dst_port = random.choice([80, 443, 22, 21, 25, 53, 3389, 8080, 8443, random.randint(1024, 65535)])
    
    # Determine protocol based on port
    if dst_port in [80, 443, 8080, 8443]:
        protocol = "tcp"
        app = "web-browsing" if dst_port in [80, 8080] else "ssl"
    elif dst_port == 22:
        protocol = "tcp"
        app = "ssh"
    elif dst_port == 53:
        protocol = random.choice(["tcp", "udp"])
        app = "dns"
    else:
        protocol = random.choice(["tcp", "udp"])
        app = random.choice(APPLICATIONS)
    
    # Generate action
    action = random.choice(["allow", "allow", "allow", "deny", "drop"])  # More allows than denies
    
    # Calculate bytes and packets
    if action == "allow":
        bytes_total = random.randint(1000, 10000000)
        packets = random.randint(10, 10000)
    else:
        bytes_total = random.randint(0, 1500)
        packets = random.randint(1, 10)
    
    bytes_sent = int(bytes_total * random.uniform(0.3, 0.7))
    bytes_recv = bytes_total - bytes_sent
    
    # CSV fields for TRAFFIC log (PAN-OS 10.x format)
    fields = [
        "",  # future_use_1
        now.strftime("%Y/%m/%d %H:%M:%S"),  # receive_time
        generate_serial_number(),  # serial_number
        "TRAFFIC",  # type
        random.choice(["start", "end", "drop", "deny"]),  # subtype
        "",  # future_use_2
        start_time.strftime("%Y/%m/%d %H:%M:%S"),  # time_generated
        src_ip,  # src
        dst_ip,  # dst
        src_ip,  # natsrc
        dst_ip,  # natdst
        f"allow-{app}" if action == "allow" else f"block-{random.choice(['threats', 'malware', 'default'])}",  # rule
        get_random_username(),  # srcuser
        "",  # dstuser
        app,  # app
        "vsys1",  # vsys
        random.choice(ZONES),  # from
        random.choice(ZONES),  # to
        f"ethernet1/{random.randint(1, 8)}",  # inbound_if
        f"ethernet1/{random.randint(1, 8)}",  # outbound_if
        "FORWARD",  # logset
        "",  # future_use_3
        generate_session_id(),  # sessionid
        "1",  # repeatcnt
        str(src_port),  # sport
        str(dst_port),  # dport
        str(src_port),  # natsport
        str(dst_port),  # natdport
        "0x0",  # flags
        protocol,  # proto
        action,  # action
        str(bytes_total),  # bytes
        str(bytes_sent),  # bytes_sent
        str(bytes_recv),  # bytes_received
        str(packets),  # packets
        start_time.strftime("%Y/%m/%d %H:%M:%S"),  # start
        str(random.randint(1, 300)),  # elapsed
        random.choice(["internet-communications", "business-systems", "networking", ""]),  # category
        "",  # future_use_4
        str(random.randint(1, 1000000)),  # seqno
        "0x0",  # actionflags
        random.choice(["US", "CN", "RU", "DE", "GB", "FR", ""]),  # srcloc
        random.choice(["US", "CN", "RU", "DE", "GB", "FR", ""]),  # dstloc
        "",  # future_use_5
        str(int(packets * 0.6)),  # pkts_sent
        str(int(packets * 0.4)),  # pkts_received
        random.choice(["aged-out", "tcp-fin", "tcp-rst", "policy-deny", ""]) if action != "allow" else "aged-out",  # session_end_reason
    ]

    # The marketplace Palo Alto firewall parser expects a fixed number of CSV columns.
    # If we stop emitting fields early, the line will not match even if the earlier
    # fields are correct (because required delimiters/columns are missing).
    expected_fields = 115
    if len(fields) < expected_fields:
        fields.extend([""] * (expected_fields - len(fields)))

    return ",".join(fields)

def generate_threat_log():
    """Generate a THREAT log entry."""
    now = datetime.now(timezone.utc)
    
    # Generate IPs and ports
    src_ip = get_random_ip(internal_probability=0.3)  # More external threats
    dst_ip = get_random_ip(internal_probability=0.7)
    src_port = random.randint(1024, 65535)
    dst_port = random.choice([80, 443, 22, 21, 25, 53, 3389, 8080])
    
    threat_cat = random.choice(THREAT_CATEGORIES)
    severity = random.choice(SEVERITIES)
    
    # CSV fields for THREAT log
    fields = [
        "",  # future_use_1
        now.strftime("%Y/%m/%d %H:%M:%S"),  # receive_time
        generate_serial_number(),  # serial_number
        "THREAT",  # type
        random.choice(["url", "virus", "spyware", "vulnerability", "file"]),  # subtype
        "",  # future_use_2
        now.strftime("%Y/%m/%d %H:%M:%S"),  # time_generated
        src_ip,  # src
        dst_ip,  # dst
        src_ip,  # natsrc
        dst_ip,  # natdst
        "block-threats",  # rule
        get_random_username(),  # srcuser
        "",  # dstuser
        random.choice(["web-browsing", "ssl", "ftp", "smtp"]),  # app
        "vsys1",  # vsys
        random.choice(ZONES),  # from
        random.choice(ZONES),  # to
        f"ethernet1/{random.randint(1, 8)}",  # inbound_if
        f"ethernet1/{random.randint(1, 8)}",  # outbound_if
        "FORWARD",  # logset
        "",  # future_use_3
        generate_session_id(),  # sessionid
        "1",  # repeatcnt
        str(src_port),  # sport
        str(dst_port),  # dport
        str(src_port),  # natsport
        str(dst_port),  # natdport
        "0x80000000",  # flags
        "tcp",  # proto
        random.choice(["alert", "block", "continue"]),  # action
        f"(9999)",  # threat/content name
        threat_cat,  # category
        severity,  # severity
        "client-to-server",  # direction
        str(random.randint(1, 1000000)),  # seqno
        "0x0",  # actionflags
        random.choice(["US", "CN", "RU", "DE", "GB", "FR"]),  # srcloc
        random.choice(["US", "CN", "RU", "DE", "GB", "FR"]),  # dstloc
        "",  # future_use_5
        "",  # contenttype
        "",  # pcap_id
        "",  # filedigest
        "",  # cloud
        "",  # url_idx
        "",  # user_agent
        "",  # filetype
        "",  # xff
        "",  # referer
        "",  # sender
        "",  # subject
        "",  # recipient
        "",  # reportid
    ]

    expected_fields = 120
    if len(fields) < expected_fields:
        fields.extend([""] * (expected_fields - len(fields)))

    return ",".join(fields)

def paloalto_firewall_log(overrides: dict | None = None) -> str:
    """Generate a single Palo Alto Networks firewall log entry."""
    
    # Determine log type
    log_type = random.choices(
        ["TRAFFIC", "THREAT"],
        weights=[80, 20]  # 80% traffic, 20% threat
    )[0]
    
    if log_type == "TRAFFIC":
        log_line = generate_traffic_log()
    else:
        log_line = generate_threat_log()
    
    # Apply overrides if provided (limited support for CSV format)
    if overrides:
        # For CSV format, overrides are more complex to implement
        # This is a simplified version
        if "action" in overrides:
            parts = log_line.split(",")
            if len(parts) > 29:  # Action field position
                parts[29] = overrides["action"]
                log_line = ",".join(parts)
    
    return log_line

# OCSF-style attributes for HEC
if __name__ == "__main__":
    # Generate sample logs
    print("Sample Palo Alto firewall logs:")
    print("\nTraffic logs:")
    for _ in range(3):
        print(paloalto_firewall_log())
    
    print("\nThreat log:")
    # Force a threat log by generating multiple times
    for _ in range(10):
        log = paloalto_firewall_log()
        if "THREAT" in log:
            print(log)
            break