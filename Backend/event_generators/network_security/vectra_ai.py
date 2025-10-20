#!/usr/bin/env python3
"""
Vectra AI event generator (JSON format)
Generates Vectra AI detection and scoring events in syslog JSON format
"""
from __future__ import annotations
import json
import random
import time
import uuid
from datetime import datetime, timezone, timedelta
from typing import Dict, List

# Detection categories
DETECTION_CATEGORIES = [
    "Command & Control",
    "Botnet Activity", 
    "Lateral Movement",
    "Exfiltration",
    "Reconnaissance",
    "Info Stealer",
    "Ransomware",
    "Hidden DNS Tunnel",
    "Hidden HTTPS Tunnel",
    "External Remote Access",
    "Suspicious Admin",
    "Brute-Force",
    "Port Scan",
    "Suspicious File Activity",
    "Data Smuggler",
    "Account Takeover"
]

# Detection types
DETECTION_TYPES = [
    "Hidden DNS Tunnel",
    "Hidden HTTPS Tunnel", 
    "Suspicious HTTP",
    "External Remote Access",
    "RDP Recon",
    "SMB Brute-Force",
    "Port Scan",
    "Port Sweep",
    "Shell Knocker",
    "Automated Replication",
    "File Share Enumeration",
    "Ransomware File Activity",
    "Data Smuggler",
    "Large Outbound Transfer"
]

# Account types
ACCOUNT_TYPES = [
    "o365",
    "aws", 
    "azure",
    "gcp",
    "salesforce",
    "box",
    "dropbox"
]

# Host categories
HOST_CATEGORIES = [
    "server",
    "client",
    "domain_controller",
    "gateway",
    "printer",
    "mobile",
    "iot"
]

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

def _generate_detection_id() -> int:
    """Generate a detection ID"""
    return random.randint(1000, 99999)

def _generate_account_uid() -> str:
    """Generate an account UID"""
    account_type = random.choice(ACCOUNT_TYPES)
    email = f"user{random.randint(100, 999)}@company.com"
    return f"{account_type}:{email}"

def _generate_host_id() -> str:
    """Generate a host ID"""
    return f"host-{uuid.uuid4().hex[:8]}"

def vectra_ai_log(overrides: dict | None = None) -> str:
    """
    Return a single Vectra AI event as JSON string.
    
    Pass `overrides` to force any field to a specific value:
        vectra_ai_log({"category": "Exfiltration", "threat": 90})
    """
    # Generate timestamps
    now = datetime.now(timezone.utc)
    timestamp = now - timedelta(seconds=random.randint(0, 300))
    
    # Determine event type
    event_type = random.choice(["account", "account_detection", "host", "health", "audit"])
    
    if event_type == "account":
        event = _generate_account_event(timestamp)
    elif event_type == "account_detection":
        event = _generate_account_detection_event(timestamp)
    elif event_type == "host":
        event = _generate_host_event(timestamp)
    elif event_type == "health":
        event = _generate_health_event(timestamp)
    else:  # audit
        event = _generate_audit_event(timestamp)
    
    # Apply any overrides
    if overrides:
        event.update(overrides)
    
    # Format as syslog with JSON
    priority = 134  # local0.info
    syslog_timestamp = timestamp.strftime("%b %d %H:%M:%S")
    hostname = "vectra-brain"
    tag = f"vectra_json_{event_type}"
    
    json_data = json.dumps(event, separators=(",", ":"))
    return f"<{priority}>{syslog_timestamp} {hostname} {tag} -: {json_data}"

def _generate_account_event(timestamp: datetime) -> Dict:
    """Generate an account scoring event"""
    account_uid = _generate_account_uid()
    threat = random.randint(0, 100)
    certainty = random.randint(0, 100)
    
    # Higher threat/certainty means more detections
    num_detections = 0
    if threat > 80 or certainty > 80:
        num_detections = random.randint(5, 15)
    elif threat > 50 or certainty > 50:
        num_detections = random.randint(2, 5)
    elif threat > 20 or certainty > 20:
        num_detections = random.randint(1, 3)
    
    event = {
        "version": "v3.3",
        "account_uid": account_uid,
        "category": "account",
        "certainty": certainty,
        "threat": threat,
        "score": threat * certainty // 100,
        "severity": _get_severity(threat, certainty),
        "account_id": random.randint(1000, 9999),
        "href": f"https://vectra.company.com/accounts/{account_uid.split(':')[1]}",
        "is_prioritized": threat > 70 or certainty > 70,
        "last_detection_timestamp": timestamp.isoformat() + "Z",
        "detection_count": num_detections,
        "detection_categories": random.sample(DETECTION_CATEGORIES, min(num_detections, 5)) if num_detections > 0 else [],
        "tags": _generate_tags(),
        "service_access_history": {
            "last_30_days": random.randint(50, 500),
            "last_7_days": random.randint(10, 100),
            "last_day": random.randint(1, 20)
        },
        "vectra_timestamp": timestamp.isoformat() + "Z",
        "ts": timestamp.timestamp()
    }
    
    return event

def _generate_account_detection_event(timestamp: datetime) -> Dict:
    """Generate an account detection event"""
    account_uid = _generate_account_uid()
    detection_type = random.choice(DETECTION_TYPES)
    detection_id = _generate_detection_id()
    
    event = {
        "version": "v3.3",
        "account_uid": account_uid,
        "category": "account_detection",
        "detection": detection_type,
        "detection_id": detection_id,
        "detection_category": _get_detection_category(detection_type),
        "detection_type": detection_type,
        "certainty": random.randint(0, 100),
        "threat": random.randint(0, 100),
        "created_timestamp": (timestamp - timedelta(hours=random.randint(0, 24))).isoformat() + "Z",
        "first_timestamp": (timestamp - timedelta(days=random.randint(0, 7))).isoformat() + "Z",
        "last_timestamp": timestamp.isoformat() + "Z",
        "state": random.choice(["active", "inactive"]),
        "is_triaged": random.random() < 0.3,
        "assigned_to": f"analyst{random.randint(1, 5)}@company.com" if random.random() < 0.2 else None,
        "tags": _generate_tags(),
        "summary": _generate_detection_summary(detection_type),
        "grouped_details": _generate_grouped_details(detection_type),
        "href": f"https://vectra.company.com/detections/{detection_id}",
        "vectra_timestamp": timestamp.isoformat() + "Z",
        "ts": timestamp.timestamp()
    }
    
    return event

def _generate_host_event(timestamp: datetime) -> Dict:
    """Generate a host scoring event"""
    host_id = _generate_host_id()
    host_ip = _generate_ip()
    threat = random.randint(0, 100)
    certainty = random.randint(0, 100)
    
    event = {
        "version": "v3.3",
        "host_id": host_id,
        "category": "host",
        "certainty": certainty,
        "threat": threat,
        "score": threat * certainty // 100,
        "severity": _get_severity(threat, certainty),
        "host_ip": host_ip,
        "host_name": f"WORKSTATION-{random.randint(100, 999)}",
        "host_type": random.choice(HOST_CATEGORIES),
        "is_key_asset": random.random() < 0.2,
        "detection_count": random.randint(0, 10),
        "tags": _generate_tags(),
        "last_detection_timestamp": timestamp.isoformat() + "Z",
        "last_source": _generate_ip(),
        "href": f"https://vectra.company.com/hosts/{host_id}",
        "vectra_timestamp": timestamp.isoformat() + "Z",
        "ts": timestamp.timestamp()
    }
    
    return event

def _generate_health_event(timestamp: datetime) -> Dict:
    """Generate a health monitoring event"""
    event = {
        "version": "v3.3",
        "category": "health",
        "health_status": random.choice(["healthy", "warning", "critical"]),
        "cpu_usage": random.randint(10, 90),
        "memory_usage": random.randint(20, 85),
        "disk_usage": random.randint(30, 80),
        "capture_rate": random.uniform(0.95, 1.0),
        "active_hosts": random.randint(100, 5000),
        "active_accounts": random.randint(50, 1000),
        "detections_per_hour": random.randint(10, 200),
        "brain_version": "7.5.0",
        "sensor_version": "7.5.0",
        "uptime_hours": random.randint(100, 8760),
        "vectra_timestamp": timestamp.isoformat() + "Z",
        "ts": timestamp.timestamp()
    }
    
    return event

def _generate_audit_event(timestamp: datetime) -> Dict:
    """Generate an audit log event"""
    audit_actions = [
        "user_login", "user_logout", "detection_triaged", "detection_fixed",
        "rule_created", "rule_modified", "rule_deleted", "settings_changed",
        "user_created", "user_deleted", "role_assigned", "api_key_created"
    ]
    
    event = {
        "version": "v3.3",
        "category": "audit",
        "action": random.choice(audit_actions),
        "user": f"admin{random.randint(1, 5)}@company.com",
        "source_ip": _generate_ip(),
        "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "result": random.choice(["success", "failure"]),
        "object_type": random.choice(["detection", "account", "host", "rule", "user"]),
        "object_id": str(random.randint(1000, 9999)),
        "message": "Audit action completed",
        "vectra_timestamp": timestamp.isoformat() + "Z",
        "ts": timestamp.timestamp()
    }
    
    return event

def _get_severity(threat: int, certainty: int) -> str:
    """Calculate severity based on threat and certainty"""
    score = threat * certainty // 100
    if score >= 80:
        return "critical"
    elif score >= 60:
        return "high"
    elif score >= 40:
        return "medium"
    else:
        return "low"

def _get_detection_category(detection_type: str) -> str:
    """Map detection type to category"""
    category_map = {
        "Hidden DNS Tunnel": "Command & Control",
        "Hidden HTTPS Tunnel": "Command & Control",
        "Suspicious HTTP": "Command & Control",
        "External Remote Access": "Command & Control",
        "RDP Recon": "Reconnaissance",
        "SMB Brute-Force": "Lateral Movement",
        "Port Scan": "Reconnaissance",
        "Port Sweep": "Reconnaissance",
        "Shell Knocker": "Command & Control",
        "Automated Replication": "Lateral Movement",
        "File Share Enumeration": "Reconnaissance",
        "Ransomware File Activity": "Ransomware",
        "Data Smuggler": "Exfiltration",
        "Large Outbound Transfer": "Exfiltration"
    }
    return category_map.get(detection_type, "Unknown")

def _generate_tags() -> List[str]:
    """Generate random tags"""
    all_tags = [
        "production", "development", "critical_asset", "finance", "hr",
        "engineering", "sales", "executive", "contractor", "vpn_user",
        "privileged", "service_account", "legacy_system"
    ]
    num_tags = random.randint(0, 3)
    return random.sample(all_tags, num_tags) if num_tags > 0 else []

def _generate_detection_summary(detection_type: str) -> Dict:
    """Generate detection summary based on type"""
    if "Tunnel" in detection_type:
        return {
            "domains_queried": random.randint(10, 1000),
            "bytes_sent": random.randint(1000000, 100000000),
            "suspicious_domains": random.randint(1, 50)
        }
    elif "Brute-Force" in detection_type:
        return {
            "attempts": random.randint(100, 10000),
            "targets": random.randint(1, 50),
            "success_rate": random.uniform(0, 0.1)
        }
    elif "Transfer" in detection_type or "Exfiltration" in detection_type:
        return {
            "bytes_transferred": random.randint(10000000, 10000000000),
            "files_accessed": random.randint(10, 10000),
            "destinations": random.randint(1, 5)
        }
    else:
        return {
            "events": random.randint(10, 1000),
            "severity_score": random.randint(1, 100)
        }

def _generate_grouped_details(detection_type: str) -> List[Dict]:
    """Generate grouped details for detections"""
    num_groups = random.randint(1, 5)
    details = []
    
    for _ in range(num_groups):
        detail = {
            "first_timestamp": (datetime.now(timezone.utc) - timedelta(hours=random.randint(1, 72))).isoformat() + "Z",
            "last_timestamp": datetime.now(timezone.utc).isoformat() + "Z",
            "count": random.randint(1, 100),
            "source_ip": _generate_ip(),
            "destination": _generate_ip(internal=False) if random.random() < 0.5 else f"external-site-{random.randint(1, 100)}.com"
        }
        details.append(detail)
    
    return details

if __name__ == "__main__":
    # Generate sample logs
    print("Sample Vectra AI events:")
    for event_type in ["account", "account_detection", "host"]:
        print(f"\n{event_type.upper()} event:")
        print(vectra_ai_log({"category": event_type}))
        print()