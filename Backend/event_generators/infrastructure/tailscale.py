#!/usr/bin/env python3
"""
Tailscale event generator (JSON format)
Generates Tailscale VPN audit and network flow logs
"""
from __future__ import annotations
import json
import random
import time
import uuid
from datetime import datetime, timezone, timedelta
from typing import Dict, List

# Event types
EVENT_TYPES = ["configuration", "network"]

# Configuration actions
CONFIG_ACTIONS = [
    "UPDATE",
    "CREATE",
    "DELETE",
    "ENABLE",
    "DISABLE",
    "APPROVE",
    "REJECT"
]

# Target types for configuration changes
TARGET_TYPES = [
    "machine",
    "user",
    "acl",
    "dns",
    "derp_map",
    "domain",
    "log_config",
    "log_stream_endpoint",
    "posture_integration",
    "tailnet_settings",
    "webhook_endpoint",
    "ssh_rule",
    "exit_node"
]

# Properties that can be changed
PROPERTIES = [
    "authorized",
    "keyExpiryDisabled",
    "name",
    "tags",
    "routes",
    "advertisedRoutes",
    "enabledRoutes",
    "acl",
    "dnsConfig",
    "sshEnabled",
    "magicDNS",
    "deviceApprovalRequired",
    "userApprovalRequired"
]

# Actor types
ACTOR_TYPES = ["user", "apikey", "tagged-device"]

# Node OS types
OS_TYPES = ["linux", "windows", "darwin", "ios", "android", "freebsd"]

# Common protocols and ports
PROTOCOLS = [
    {"proto": 6, "name": "tcp"},
    {"proto": 17, "name": "udp"},
    {"proto": 1, "name": "icmp"}
]

COMMON_PORTS = {
    22: "ssh",
    80: "http",
    443: "https",
    3389: "rdp",
    5432: "postgresql",
    3306: "mysql",
    6379: "redis",
    8080: "http-alt",
    9090: "prometheus",
    53: "dns"
}

def _generate_ip(internal: bool = True) -> str:
    """Generate an IP address"""
    if internal:
        # Tailscale CGNAT range
        return f"100.{random.randint(64, 127)}.{random.randint(0, 255)}.{random.randint(1, 254)}"
    else:
        return f"{random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"

def _generate_node_id() -> str:
    """Generate a Tailscale node ID"""
    return f"n{uuid.uuid4().hex[:16]}CNTRL"

def _generate_user_id() -> str:
    """Generate a Tailscale user ID"""
    return f"u{uuid.uuid4().hex[:16]}CNTRL"

def _generate_tailnet() -> str:
    """Generate a tailnet name"""
    domains = ["company.com", "example.org", "corp.net", "internal.io"]
    return f"tailnet-{random.choice(domains)}"

def tailscale_log(overrides: dict | None = None) -> Dict:
    """
    Return a single Tailscale event as JSON string.
    
    Pass `overrides` to force any field to a specific value:
        tailscale_log({"action": "UPDATE", "target.type": "machine"})
    """
    # Determine event type
    event_type = random.choice(EVENT_TYPES)
    
    if event_type == "configuration":
        event = _generate_config_event()
    else:  # network
        event = _generate_network_event()
    
    # Apply any overrides
    if overrides:
        event.update(overrides)
    
    return event

def _generate_config_event() -> Dict:
    """Generate a configuration/audit event"""
    now = datetime.now(timezone.utc)
    event_time = now - timedelta(seconds=random.randint(0, 300))
    
    # Select action and target
    action = random.choice(CONFIG_ACTIONS)
    target_type = random.choice(TARGET_TYPES)
    
    # Generate actor
    actor_type = random.choice(ACTOR_TYPES)
    if actor_type == "user":
        actor = {
            "id": _generate_user_id(),
            "loginName": f"user{random.randint(1, 100)}@company.com",
            "displayName": f"User {random.randint(1, 100)}",
            "type": "user"
        }
    elif actor_type == "apikey":
        actor = {
            "id": f"api_{uuid.uuid4().hex[:8]}",
            "loginName": "API Key",
            "displayName": f"API Key - {random.choice(['CI/CD', 'Monitoring', 'Automation'])}",
            "type": "apikey"
        }
    else:  # tagged-device
        actor = {
            "id": _generate_node_id(),
            "loginName": f"tag:server",
            "displayName": f"server-{random.randint(1, 50)}",
            "type": "tagged-device"
        }
    
    # Generate target based on type
    target = {
        "id": _generate_node_id() if target_type == "machine" else str(uuid.uuid4()),
        "name": _generate_target_name(target_type),
        "type": target_type
    }
    
    # Add property for UPDATE actions
    if action == "UPDATE":
        target["property"] = random.choice(PROPERTIES)
    
    event = {
        "eventGroupID": str(uuid.uuid4()),
        "tailnet": _generate_tailnet(),
        "action": action,
        "actor": actor,
        "target": target,
        "new": event_time.isoformat() + "Z",
        "origin": random.choice(["control-plane", "admin-console", "api", "cli"])
    }
    
    # Add old timestamp for updates
    if action == "UPDATE":
        event["old"] = (event_time - timedelta(hours=random.randint(1, 72))).isoformat() + "Z"
    
    # Add additional fields based on target type
    if target_type == "machine" and action in ["CREATE", "UPDATE"]:
        event["info"] = {
            "nodeKey": f"nodekey:{uuid.uuid4().hex}",
            "machineKey": f"mkey:{uuid.uuid4().hex}",
            "discoKey": f"discokey:{uuid.uuid4().hex}",
            "ephemeral": random.random() < 0.1,
            "tags": _generate_tags()
        }
    
    return event

def _generate_network_event() -> Dict:
    """Generate a network flow log event"""
    now = datetime.now(timezone.utc)
    start_time = now - timedelta(seconds=random.randint(0, 300))
    
    # Determine if this is exit traffic or regular traffic
    is_exit_traffic = random.random() < 0.3
    
    if is_exit_traffic:
        # Exit node traffic
        event = {
            "exitTraffic": True,
            "nodeId": _generate_node_id(),
            "physicalTraffic": {
                "src": _generate_ip(internal=False),
                "dst": _generate_ip(internal=False)
            },
            "subnetTraffic": {
                "src": _generate_ip(internal=True),
                "dst": _generate_ip(internal=False)
            },
            "proto": random.choice(PROTOCOLS)["proto"],
            "start": start_time.isoformat() + "Z",
            "end": (start_time + timedelta(seconds=random.randint(1, 300))).isoformat() + "Z",
            "bytesIn": random.randint(100, 10000000),
            "bytesOut": random.randint(100, 10000000),
            "packetsIn": random.randint(10, 10000),
            "packetsOut": random.randint(10, 10000)
        }
    else:
        # Regular inter-node traffic
        src_port = random.randint(1024, 65535)
        dst_port = random.choice(list(COMMON_PORTS.keys()))
        protocol = random.choice(PROTOCOLS)
        
        event = {
            "start": start_time.isoformat() + "Z",
            "end": (start_time + timedelta(seconds=random.randint(1, 300))).isoformat() + "Z",
            "virtualTraffic": {
                "src": _generate_ip(internal=True),
                "dst": _generate_ip(internal=True),
                "srcPort": src_port,
                "dstPort": dst_port,
                "proto": protocol["proto"]
            },
            "physicalTraffic": {
                "src": _generate_ip(internal=False),
                "dst": _generate_ip(internal=False)
            },
            "subnetTraffic": {
                "src": _generate_ip(internal=True),
                "dst": _generate_ip(internal=True),
                "srcPort": src_port,
                "dstPort": dst_port,
                "proto": protocol["proto"]
            },
            "proto": protocol["proto"],
            "bytesIn": random.randint(100, 50000000),
            "bytesOut": random.randint(100, 50000000),
            "packetsIn": random.randint(10, 50000),
            "packetsOut": random.randint(10, 50000),
            "nodeId": _generate_node_id(),
            "userId": _generate_user_id(),
            "srcNodeId": _generate_node_id(),
            "dstNodeId": _generate_node_id()
        }
        
        # Add service info if known port
        if dst_port in COMMON_PORTS:
            event["service"] = COMMON_PORTS[dst_port]
        
        # Add connection info
        event["connections"] = [{
            "src": event["virtualTraffic"]["src"],
            "dst": event["virtualTraffic"]["dst"],
            "srcPort": src_port,
            "dstPort": dst_port,
            "proto": protocol["name"]
        }]
    
    return event

def _generate_target_name(target_type: str) -> str:
    """Generate a name based on target type"""
    if target_type == "machine":
        return f"{random.choice(['laptop', 'desktop', 'server', 'vm'])}-{random.randint(1, 999)}"
    elif target_type == "user":
        return f"user{random.randint(1, 100)}@company.com"
    elif target_type == "acl":
        return "tailnet-acl-policy"
    elif target_type == "dns":
        return "tailnet-dns-config"
    elif target_type == "exit_node":
        return f"exit-{random.choice(['us-east', 'us-west', 'eu-west', 'ap-south'])}-{random.randint(1, 10)}"
    elif target_type == "ssh_rule":
        return f"ssh-rule-{random.choice(['admin', 'developer', 'ops'])}"
    elif target_type == "log_stream_endpoint":
        return f"https://siem.company.com/tailscale-logs"
    else:
        return f"{target_type}-{random.randint(1, 100)}"

def _generate_tags() -> List[str]:
    """Generate Tailscale ACL tags"""
    all_tags = [
        "tag:server",
        "tag:dev",
        "tag:prod",
        "tag:staging",
        "tag:corp",
        "tag:contractor",
        "tag:exit-node",
        "tag:subnet-router",
        "tag:k8s",
        "tag:database"
    ]
    num_tags = random.randint(0, 3)
    return random.sample(all_tags, num_tags) if num_tags > 0 else []

if __name__ == "__main__":
    # Generate sample logs
    print("Sample Tailscale events:")
    
    # Configuration event
    print("\nConfiguration event:")
    print(tailscale_log({"action": "UPDATE", "target": {"type": "machine"}}))
    
    # Network flow event
    print("\nNetwork flow event:")
    print(tailscale_log({"exitTraffic": False}))
    
    print()