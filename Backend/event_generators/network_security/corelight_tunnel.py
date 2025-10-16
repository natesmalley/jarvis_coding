#!/usr/bin/env python3
"""
Corelight Tunnel Logs event generator (JSON format)
Generates Zeek/Corelight tunnel (VPN/encapsulation) activity events
"""
from __future__ import annotations
import json
import random
import time
import uuid
from datetime import datetime, timezone, timedelta
from typing import Dict, List

# Tunnel types
TUNNEL_TYPES = [
    "Tunnel::VXLAN",
    "Tunnel::GRE",
    "Tunnel::IP",
    "Tunnel::AYIYA",
    "Tunnel::TEREDO",
    "Tunnel::GTPv1",
    "Tunnel::ESP",
    "Tunnel::L2TP"
]

# Tunnel actions
TUNNEL_ACTIONS = [
    "Tunnel::DISCOVER",
    "Tunnel::CLOSE",
    "Tunnel::EXPIRE"
]

# Common VPN/tunnel ports
TUNNEL_PORTS = {
    "Tunnel::VXLAN": 4789,
    "Tunnel::GRE": 0,  # GRE doesn't use ports
    "Tunnel::IP": 0,   # IP-in-IP doesn't use ports
    "Tunnel::AYIYA": 5072,
    "Tunnel::TEREDO": 3544,
    "Tunnel::GTPv1": 2152,
    "Tunnel::ESP": 0,  # ESP is IP protocol 50
    "Tunnel::L2TP": 1701
}

def _generate_ip(internal: bool = True) -> str:
    """Generate an IP address"""
    if internal:
        return random.choice([
            f"10.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}",
            f"172.{random.randint(16, 31)}.{random.randint(0, 255)}.{random.randint(1, 254)}",
            f"192.168.{random.randint(0, 255)}.{random.randint(1, 254)}"
        ])
    else:
        return f"{random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"

def _generate_uid() -> str:
    """Generate a Zeek connection UID"""
    chars = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
    return 'C' + ''.join(random.choices(chars, k=17))

def corelight_tunnel_log(overrides: dict | None = None) -> Dict:
    """
    Return a single Corelight tunnel log event as JSON string.
    
    Pass `overrides` to force any field to a specific value:
        corelight_tunnel_log({"tunnel_type": "Tunnel::VXLAN", "action": "Tunnel::DISCOVER"})
    """
    # Generate timestamps
    now = datetime.now(timezone.utc)
    timestamp = now - timedelta(seconds=random.randint(0, 300))
    
    # Select tunnel type
    tunnel_type = random.choice(TUNNEL_TYPES)
    
    # Select action based on realistic patterns
    if random.random() < 0.6:
        action = "Tunnel::DISCOVER"  # Most common - new tunnels discovered
    elif random.random() < 0.7:
        action = "Tunnel::CLOSE"     # Normal closure
    else:
        action = "Tunnel::EXPIRE"    # Timeout/expiration
    
    # Determine ports based on tunnel type
    default_port = TUNNEL_PORTS.get(tunnel_type, 0)
    if default_port == 0:
        # For protocols without standard ports
        src_port = 0
        dst_port = 0
    else:
        src_port = random.randint(1024, 65535)
        dst_port = default_port
    
    # Determine if this is a VPN or internal tunnel
    is_vpn = tunnel_type in ["Tunnel::ESP", "Tunnel::L2TP", "Tunnel::GRE"]
    is_internal = not is_vpn and random.random() < 0.4
    
    # Generate inner IPs (what's inside the tunnel)
    inner_src_ip = _generate_ip(internal=True)
    inner_dst_ip = _generate_ip(internal=True) if is_internal else _generate_ip(internal=False)
    
    event = {
        "ts": timestamp.timestamp(),
        "uid": _generate_uid(),
        "id": {
            "orig_h": _generate_ip(internal=True),
            "orig_p": src_port,
            "resp_h": _generate_ip(internal=is_internal),
            "resp_p": dst_port
        },
        "tunnel_type": tunnel_type,
        "action": action
    }
    
    # Add inner tunnel information for DISCOVER events
    if action == "Tunnel::DISCOVER":
        # Inner connection details
        inner_proto = random.choice(["tcp", "udp", "icmp"])
        
        if inner_proto == "icmp":
            inner_src_port = 0
            inner_dst_port = 0
        else:
            inner_src_port = random.randint(1024, 65535)
            # Common destination ports for tunneled traffic
            inner_dst_port = random.choice([80, 443, 22, 3389, 445, 3306, 5432, 6379])
        
        event["inner"] = {
            "id": {
                "orig_h": inner_src_ip,
                "orig_p": inner_src_port,
                "resp_h": inner_dst_ip,
                "resp_p": inner_dst_port
            },
            "proto": inner_proto,
            "service": _get_service_from_port(inner_dst_port) if inner_proto != "icmp" else None
        }
    
    # Add metadata for specific tunnel types
    if tunnel_type == "Tunnel::VXLAN":
        event["vni"] = random.randint(1, 16777215)  # VXLAN Network Identifier
    elif tunnel_type == "Tunnel::GTPv1":
        event["teid"] = random.randint(1, 4294967295)  # Tunnel Endpoint Identifier
    elif tunnel_type == "Tunnel::ESP":
        event["spi"] = f"0x{random.randint(256, 4294967295):08x}"  # Security Parameter Index
    
    # Apply any overrides
    if overrides:
        event.update(overrides)
    
    return event

def _get_service_from_port(port: int) -> str:
    """Get service name from port number"""
    port_services = {
        80: "http",
        443: "https",
        22: "ssh",
        3389: "rdp",
        445: "smb",
        3306: "mysql",
        5432: "postgresql",
        6379: "redis",
        21: "ftp",
        25: "smtp",
        53: "dns",
        110: "pop3",
        143: "imap"
    }
    return port_services.get(port, "-")

if __name__ == "__main__":
    # Generate sample logs
    print("Sample Corelight tunnel logs:")
    for i in range(3):
        print(corelight_tunnel_log())
        print()