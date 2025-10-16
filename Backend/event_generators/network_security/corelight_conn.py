#!/usr/bin/env python3
"""
Corelight Connection Logs event generator (JSON format)
Generates Zeek/Corelight network connection events
"""
from __future__ import annotations
import json
import random
import time
import uuid
from datetime import datetime, timezone, timedelta
from typing import Dict, List

# Connection states
CONN_STATES = [
    "S0",  # Connection attempt seen, no reply
    "S1",  # Connection established, not terminated
    "SF",  # Normal establishment and termination
    "REJ", # Connection attempt rejected
    "S2",  # Connection established and close attempt by originator seen
    "S3",  # Connection established and close attempt by responder seen
    "RSTO", # Connection established, originator aborted
    "RSTR", # Responder sent a RST
    "RSTOS0", # Originator sent a SYN followed by a RST
    "RSTRH", # Responder sent a SYN ACK followed by a RST
    "SH",  # Originator sent a SYN followed by a FIN
    "SHR", # Responder sent a SYN ACK followed by a FIN
    "OTH"  # No SYN seen, just midstream traffic
]

# Common services
SERVICES = [
    "http", "https", "dns", "ssh", "ftp", "smtp", "pop3", "imap",
    "telnet", "rdp", "smb", "ntp", "dhcp", "snmp", "ldap", "kerberos",
    "mysql", "postgresql", "mongodb", "redis", "elasticsearch", "kafka",
    "-"  # No service identified
]

# Common protocols
PROTOCOLS = ["tcp", "udp", "icmp"]

# Common ports
COMMON_PORTS = {
    "http": 80,
    "https": 443,
    "dns": 53,
    "ssh": 22,
    "ftp": 21,
    "smtp": 25,
    "pop3": 110,
    "imap": 143,
    "telnet": 23,
    "rdp": 3389,
    "smb": 445,
    "ntp": 123,
    "dhcp": 67,
    "snmp": 161,
    "ldap": 389,
    "kerberos": 88,
    "mysql": 3306,
    "postgresql": 5432,
    "mongodb": 27017,
    "redis": 6379,
    "elasticsearch": 9200,
    "kafka": 9092
}

def _generate_ip(internal: bool = True) -> str:
    """Generate an IP address"""
    if internal:
        # Internal IPs
        return random.choice([
            f"10.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}",
            f"172.{random.randint(16, 31)}.{random.randint(0, 255)}.{random.randint(1, 254)}",
            f"192.168.{random.randint(0, 255)}.{random.randint(1, 254)}"
        ])
    else:
        # External IPs
        return f"{random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"

def _generate_uid() -> str:
    """Generate a Zeek connection UID"""
    chars = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
    return 'C' + ''.join(random.choices(chars, k=17))

def corelight_conn_log(overrides: dict | None = None) -> Dict:
    """
    Return a single Corelight connection log event as JSON string.
    
    Pass `overrides` to force any field to a specific value:
        corelight_conn_log({"service": "ssh"})
    """
    # Generate timestamps
    now = datetime.now(timezone.utc)
    start_time = now - timedelta(seconds=random.randint(0, 300))
    duration = random.uniform(0.001, 120.0)  # Connection duration in seconds
    
    # Select service and protocol
    service = random.choice(SERVICES)
    if service == "-":
        protocol = random.choice(PROTOCOLS)
        src_port = random.randint(1024, 65535)
        dst_port = random.randint(1, 65535)
    else:
        protocol = "tcp" if service not in ["dns", "dhcp", "ntp", "snmp"] else "udp"
        src_port = random.randint(1024, 65535)
        dst_port = COMMON_PORTS.get(service, random.randint(1, 65535))
    
    # Determine connection state based on service
    if service in ["http", "https", "dns"]:
        # These usually complete successfully
        conn_state = random.choices(
            ["SF", "S1", "S0", "REJ"],
            weights=[0.8, 0.1, 0.05, 0.05]
        )[0]
    elif service == "ssh":
        # SSH might have more failed attempts
        conn_state = random.choices(
            ["SF", "S1", "S0", "REJ", "RSTO"],
            weights=[0.6, 0.1, 0.1, 0.15, 0.05]
        )[0]
    else:
        conn_state = random.choice(CONN_STATES)
    
    # Generate byte counts based on service and state
    if conn_state in ["S0", "REJ", "RSTOS0"]:
        # Failed connections have minimal data
        orig_bytes = random.randint(40, 200)
        resp_bytes = 0 if conn_state == "S0" else random.randint(0, 100)
    elif service in ["http", "https"]:
        # Web traffic can be large
        orig_bytes = random.randint(200, 5000)
        resp_bytes = random.randint(500, 500000)
    elif service == "dns":
        # DNS is typically small
        orig_bytes = random.randint(40, 200)
        resp_bytes = random.randint(60, 500)
    else:
        # General traffic
        orig_bytes = random.randint(40, 50000)
        resp_bytes = random.randint(40, 50000)
    
    # Generate packet counts (roughly proportional to bytes)
    orig_pkts = max(1, orig_bytes // random.randint(40, 1500))
    resp_pkts = max(0 if resp_bytes == 0 else 1, resp_bytes // random.randint(40, 1500))
    
    # Determine if internal or external connection
    is_internal = random.random() < 0.3
    
    event = {
        "ts": start_time.timestamp(),
        "uid": _generate_uid(),
        "id": {
            "orig_h": _generate_ip(internal=True),
            "orig_p": src_port,
            "resp_h": _generate_ip(internal=is_internal),
            "resp_p": dst_port
        },
        "proto": protocol,
        "service": service if service != "-" else None,
        "duration": round(duration, 6),
        "orig_bytes": orig_bytes,
        "resp_bytes": resp_bytes,
        "conn_state": conn_state,
        "local_orig": True,
        "local_resp": is_internal,
        "missed_bytes": 0,
        "history": _generate_history(conn_state),
        "orig_pkts": orig_pkts,
        "orig_ip_bytes": orig_bytes + (orig_pkts * 40),  # Add IP header overhead
        "resp_pkts": resp_pkts,
        "resp_ip_bytes": resp_bytes + (resp_pkts * 40),
        "tunnel_parents": []
    }
    
    # Add optional fields
    if protocol == "tcp" and conn_state == "SF":
        event["orig_l2_addr"] = f"{random.randint(0, 255):02x}:{random.randint(0, 255):02x}:{random.randint(0, 255):02x}:{random.randint(0, 255):02x}:{random.randint(0, 255):02x}:{random.randint(0, 255):02x}"
        event["resp_l2_addr"] = f"{random.randint(0, 255):02x}:{random.randint(0, 255):02x}:{random.randint(0, 255):02x}:{random.randint(0, 255):02x}:{random.randint(0, 255):02x}:{random.randint(0, 255):02x}"
    
    # Apply any overrides
    if overrides:
        event.update(overrides)
    
    return event

def _generate_history(conn_state: str) -> str:
    """Generate connection history string based on state"""
    history_map = {
        "S0": "S",
        "S1": "Sh",
        "SF": "ShADfaF",
        "REJ": "Sr",
        "S2": "ShADf",
        "S3": "ShADfa",
        "RSTO": "ShADR",
        "RSTR": "ShAr",
        "RSTOS0": "SR",
        "RSTRH": "SHr",
        "SH": "SF",
        "SHR": "SHR",
        "OTH": "A"
    }
    return history_map.get(conn_state, "Sh")

if __name__ == "__main__":
    # Generate sample logs
    print("Sample Corelight connection logs:")
    for i in range(3):
        print(corelight_conn_log())
        print()