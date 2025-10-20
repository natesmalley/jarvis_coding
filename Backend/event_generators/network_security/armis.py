#!/usr/bin/env python3
"""
Armis event generator (JSON format)
Generates Armis security finding and device activity events
"""
from __future__ import annotations
import json
import random
import time
import uuid
from datetime import datetime, timezone, timedelta
from typing import Dict, List

# Event types
EVENT_TYPES = [
    "Alert",
    "Activity",
    "PolicyViolation",
    "DeviceFirstSeen",
    "DeviceRiskChange",
    "VulnerabilityDetected",
    "AnomalousActivity",
    "UnmanagedDevice",
    "NetworkThreat"
]

# Alert classifications
ALERT_CLASSIFICATIONS = [
    "Suspicious Activity",
    "Policy Violation",
    "Vulnerability",
    "Unmanaged Device",
    "Risk Score Change",
    "Anomalous Behavior",
    "Network Threat",
    "Configuration Issue",
    "Compliance Violation"
]

# Device types
DEVICE_TYPES = [
    "Computer",
    "Mobile",
    "IoT",
    "Medical",
    "Industrial",
    "NetworkInfrastructure",
    "Printer",
    "Camera",
    "SmartTV",
    "VoIP",
    "AccessPoint",
    "Switch",
    "Router",
    "Firewall",
    "Server"
]

# Device manufacturers
MANUFACTURERS = [
    "Apple", "Samsung", "Microsoft", "Dell", "HP", "Cisco", "Juniper",
    "Philips", "GE Healthcare", "Siemens", "Honeywell", "Canon", "Epson",
    "Axis", "Hikvision", "Polycom", "Yealink", "Ubiquiti", "Aruba"
]

# Risk factors
RISK_FACTORS = [
    "Unencrypted Traffic",
    "Weak Authentication",
    "Known Vulnerability",
    "End of Life",
    "Default Credentials",
    "Suspicious Connections",
    "Anomalous Behavior",
    "Policy Violation",
    "Missing Patches",
    "Exposed Services"
]

# Policy action types
ACTION_TYPES = ["Email", "Alert", "Block", "Quarantine", "Tag", "Webhook"]

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

def _generate_mac() -> str:
    """Generate a MAC address"""
    return ":".join([f"{random.randint(0, 255):02x}" for _ in range(6)])

def _generate_device_id() -> str:
    """Generate an Armis device ID"""
    return str(random.randint(1000000, 9999999))

def armis_log(overrides: dict | None = None) -> str:
    """
    Return a single Armis event as JSON string with syslog prefix.
    
    Pass `overrides` to force any field to a specific value:
        armis_log({"type": "Alert", "severity": "Critical"})
    """
    # Generate timestamps
    now = datetime.now(timezone.utc)
    timestamp = now - timedelta(seconds=random.randint(0, 300))
    
    # Select event type
    event_type = random.choice(EVENT_TYPES)
    
    # Generate base event
    event = {
        "id": str(uuid.uuid4()),
        "type": event_type,
        "_time": timestamp.isoformat() + "Z",
        "time": int(timestamp.timestamp()),
        "description": _generate_description(event_type),
        "severity": _calculate_severity(event_type),
        "content": {}
    }
    
    # Add type-specific fields
    if event_type == "Alert":
        event.update(_generate_alert_fields(timestamp))
    elif event_type == "PolicyViolation":
        event.update(_generate_policy_violation_fields(timestamp))
    elif event_type in ["DeviceFirstSeen", "UnmanagedDevice"]:
        event.update(_generate_device_discovery_fields(timestamp))
    elif event_type == "DeviceRiskChange":
        event.update(_generate_risk_change_fields(timestamp))
    elif event_type == "VulnerabilityDetected":
        event.update(_generate_vulnerability_fields(timestamp))
    elif event_type in ["AnomalousActivity", "NetworkThreat"]:
        event.update(_generate_threat_fields(timestamp))
    else:  # Activity
        event.update(_generate_activity_fields(timestamp))
    
    # Apply any overrides
    if overrides:
        event.update(overrides)
    
    # Format as syslog with JSON (similar to parser format)
    priority = 134  # local0.info
    syslog_timestamp = timestamp.strftime("%b %d %H:%M:%S")
    hostname = "armis-sensor"
    
    # Format as syslog with JSON payload for parser compatibility
    # Parser expects: .*- - .${parse=dottedEscapedJson}
    json_data = json.dumps(event, separators=(",", ":"))
    
    return f"<{priority}>{syslog_timestamp} {hostname} armis - - .{json_data}"

def _generate_description(event_type: str) -> str:
    """Generate description based on event type"""
    descriptions = {
        "Alert": "Security alert triggered by anomalous device behavior",
        "Activity": "Device activity logged",
        "PolicyViolation": "Device violated configured security policy",
        "DeviceFirstSeen": "New device discovered on network",
        "DeviceRiskChange": "Device risk score changed significantly",
        "VulnerabilityDetected": "Known vulnerability detected on device",
        "AnomalousActivity": "Anomalous behavior detected for device",
        "UnmanagedDevice": "Unmanaged device detected on network",
        "NetworkThreat": "Network-based threat detected"
    }
    return descriptions.get(event_type, "Security event detected")

def _calculate_severity(event_type: str) -> str:
    """Calculate severity based on event type"""
    if event_type in ["NetworkThreat", "VulnerabilityDetected"]:
        return random.choice(["Critical", "High"])
    elif event_type in ["PolicyViolation", "AnomalousActivity"]:
        return random.choice(["High", "Medium"])
    elif event_type in ["DeviceRiskChange", "UnmanagedDevice"]:
        return random.choice(["Medium", "Low"])
    else:
        return random.choice(["Low", "Info"])

def _generate_alert_fields(timestamp: datetime) -> Dict:
    """Generate alert-specific fields"""
    device = _generate_device_info()
    
    return {
        "policy": {
            "actionType": random.choice(ACTION_TYPES),
            "actionTypeDisplay": "Send Alert",
            "alertClassificationId": random.randint(1, 50),
            "description": random.choice(ALERT_CLASSIFICATIONS),
            "isActive": True,
            "creationTime": (timestamp - timedelta(days=random.randint(1, 365))).isoformat() + "Z",
            "labels": _generate_labels(),
            "actionParams": {
                "alertClassificationId": random.randint(1, 50),
                "alertDescription": random.choice(ALERT_CLASSIFICATIONS),
                "emailRecipients": ["security-team@company.com"] if random.random() < 0.5 else []
            }
        },
        "content": {
            "device": device,
            "riskScore": random.randint(1, 100),
            "riskFactors": random.sample(RISK_FACTORS, random.randint(1, 3))
        },
        "relatedDevices": [_generate_device_id() for _ in range(random.randint(0, 3))]
    }

def _generate_policy_violation_fields(timestamp: datetime) -> Dict:
    """Generate policy violation fields"""
    device = _generate_device_info()
    
    return {
        "policy": {
            "name": random.choice([
                "No IoT in Corporate Network",
                "Block Unencrypted Traffic",
                "Enforce Device Authentication",
                "Vulnerability Remediation SLA",
                "Network Segmentation Policy"
            ]),
            "actionType": "Alert",
            "violationType": random.choice([
                "Unauthorized Device",
                "Insecure Configuration",
                "Missing Updates",
                "Network Violation"
            ])
        },
        "content": {
            "device": device,
            "violationDetails": {
                "detected": timestamp.isoformat() + "Z",
                "rule": "Device type not allowed in network segment",
                "action": random.choice(["Alert", "Block", "Quarantine"])
            }
        }
    }

def _generate_device_discovery_fields(timestamp: datetime) -> Dict:
    """Generate device discovery fields"""
    device = _generate_device_info()
    device["firstSeen"] = timestamp.isoformat() + "Z"
    device["lastSeen"] = timestamp.isoformat() + "Z"
    
    return {
        "content": {
            "device": device,
            "discoveryMethod": random.choice([
                "Network Scan",
                "Traffic Analysis",
                "DHCP",
                "DNS",
                "Active Probe"
            ]),
            "networkLocation": {
                "vlan": random.randint(1, 4094),
                "switchPort": f"gi1/0/{random.randint(1, 48)}",
                "accessPoint": f"AP-{random.randint(1, 100)}" if device["type"] in ["Mobile", "IoT"] else None
            }
        }
    }

def _generate_risk_change_fields(timestamp: datetime) -> Dict:
    """Generate risk score change fields"""
    device = _generate_device_info()
    old_score = random.randint(1, 100)
    new_score = random.randint(1, 100)
    
    return {
        "content": {
            "device": device,
            "riskChange": {
                "oldScore": old_score,
                "newScore": new_score,
                "delta": new_score - old_score,
                "reason": random.choice([
                    "New vulnerability detected",
                    "Suspicious network activity",
                    "Device behavior changed",
                    "Security update applied",
                    "Configuration changed"
                ])
            },
            "riskFactors": random.sample(RISK_FACTORS, random.randint(1, 4))
        }
    }

def _generate_vulnerability_fields(timestamp: datetime) -> Dict:
    """Generate vulnerability detection fields"""
    device = _generate_device_info()
    
    return {
        "content": {
            "device": device,
            "vulnerability": {
                "cve": f"CVE-{random.randint(2020, 2024)}-{random.randint(1000, 99999)}",
                "cvss": round(random.uniform(4.0, 10.0), 1),
                "severity": random.choice(["Critical", "High", "Medium"]),
                "description": "Remote code execution vulnerability",
                "affected": f"{device['manufacturer']} {device['model']} < {device['osVersion']}",
                "remediation": "Apply security patch or upgrade firmware",
                "exploitAvailable": random.random() < 0.3
            }
        }
    }

def _generate_threat_fields(timestamp: datetime) -> Dict:
    """Generate threat detection fields"""
    device = _generate_device_info()
    
    return {
        "content": {
            "device": device,
            "threat": {
                "type": random.choice([
                    "C2 Communication",
                    "Data Exfiltration",
                    "Lateral Movement",
                    "Port Scanning",
                    "Malware Activity"
                ]),
                "confidence": random.randint(70, 99),
                "indicators": {
                    "suspiciousConnections": random.randint(1, 10),
                    "bytesTransferred": random.randint(1000000, 1000000000),
                    "duration": random.randint(60, 3600),
                    "destinationIPs": [_generate_ip(internal=False) for _ in range(random.randint(1, 3))]
                }
            }
        },
        "relatedDevices": [_generate_device_id() for _ in range(random.randint(1, 5))]
    }

def _generate_activity_fields(timestamp: datetime) -> Dict:
    """Generate general activity fields"""
    device = _generate_device_info()
    
    return {
        "content": {
            "device": device,
            "activity": {
                "type": random.choice([
                    "Network Connection",
                    "Service Started",
                    "Configuration Change",
                    "Software Update",
                    "User Login"
                ]),
                "details": {
                    "connections": random.randint(1, 100),
                    "protocols": random.sample(["HTTP", "HTTPS", "SSH", "RDP", "SMB"], random.randint(1, 3)),
                    "dataTransferred": random.randint(1000, 10000000)
                }
            }
        }
    }

def _generate_device_info() -> Dict:
    """Generate device information"""
    device_type = random.choice(DEVICE_TYPES)
    manufacturer = random.choice(MANUFACTURERS)
    
    return {
        "id": _generate_device_id(),
        "name": f"{device_type.lower()}-{random.randint(100, 999)}",
        "type": device_type,
        "ip": _generate_ip(),
        "mac": _generate_mac(),
        "manufacturer": manufacturer,
        "model": f"{manufacturer} {device_type} {random.choice(['Pro', 'Plus', 'X', ''])}".strip(),
        "osName": _get_os_for_device_type(device_type),
        "osVersion": f"{random.randint(1, 15)}.{random.randint(0, 9)}.{random.randint(0, 99)}",
        "category": _get_category_for_device_type(device_type),
        "isManaged": random.random() < 0.7,
        "tags": _generate_tags()
    }

def _get_os_for_device_type(device_type: str) -> str:
    """Get OS based on device type"""
    os_map = {
        "Computer": random.choice(["Windows", "macOS", "Ubuntu", "CentOS"]),
        "Mobile": random.choice(["iOS", "Android"]),
        "Server": random.choice(["Windows Server", "Ubuntu Server", "RHEL", "VMware ESXi"]),
        "NetworkInfrastructure": random.choice(["Cisco IOS", "JunOS", "FortiOS"]),
        "IoT": random.choice(["Embedded Linux", "RTOS", "Custom"]),
        "Medical": random.choice(["Windows Embedded", "QNX", "Custom"]),
        "Industrial": random.choice(["Windows CE", "VxWorks", "Custom"])
    }
    return os_map.get(device_type, "Unknown")

def _get_category_for_device_type(device_type: str) -> str:
    """Get category based on device type"""
    category_map = {
        "Computer": "IT",
        "Mobile": "BYOD",
        "Server": "IT",
        "NetworkInfrastructure": "Network",
        "IoT": "IoT",
        "Medical": "IoMT",
        "Industrial": "OT",
        "Printer": "IT",
        "Camera": "Physical Security"
    }
    return category_map.get(device_type, "Other")

def _generate_labels() -> List[str]:
    """Generate policy labels"""
    all_labels = [
        "critical-assets", "production", "development", "guest-network",
        "corporate", "dmz", "internet-facing", "pci-compliance",
        "hipaa-compliance", "high-risk"
    ]
    return random.sample(all_labels, random.randint(1, 3))

def _generate_tags() -> List[str]:
    """Generate device tags"""
    all_tags = [
        "monitored", "exception", "critical", "vulnerable",
        "eol", "unpatched", "guest", "contractor", "managed"
    ]
    return random.sample(all_tags, random.randint(0, 3))

if __name__ == "__main__":
    # Generate sample logs
    print("Sample Armis events:")
    for event_type in ["Alert", "PolicyViolation", "VulnerabilityDetected"]:
        print(f"\n{event_type} event:")
        print(armis_log({"type": event_type}))
        print()