#!/usr/bin/env python3
"""
Darktrace event generator (JSON format)
"""
from __future__ import annotations
import json
import random
import time
import uuid
from datetime import datetime, timezone, timedelta
from typing import Dict, List

# Model breach types and descriptions
MODEL_BREACHES = [
    {
        "name": "Anomalous Connection / Data Sent to Rare Domain",
        "description": "A device has been observed sending data to a domain that has rarely been seen across the network",
        "category": "data_exfiltration",
        "base_score": 0.75
    },
    {
        "name": "Device / Large Number of Model Breaches",
        "description": "Multiple anomalous behaviors detected from a single device in a short time period",
        "category": "suspicious_activity",
        "base_score": 0.85
    },
    {
        "name": "Compliance / SMB Version 1 Usage",
        "description": "Device observed using deprecated and vulnerable SMB v1 protocol",
        "category": "compliance",
        "base_score": 0.35
    },
    {
        "name": "Anomalous File / Internet Facing System File Download",
        "description": "An internet-facing system has downloaded an unusual file type",
        "category": "malware",
        "base_score": 0.65
    },
    {
        "name": "Device / Suspicious Domain",
        "description": "Device connected to a domain with suspicious characteristics",
        "category": "c2_communication",
        "base_score": 0.70
    },
    {
        "name": "User / New Admin Credentials on Client",
        "description": "Administrative credentials used on a device for the first time",
        "category": "credential_access",
        "base_score": 0.60
    },
    {
        "name": "Anomalous Server Activity / Rare External from Server",
        "description": "Server initiated unusual outbound connection to external IP",
        "category": "lateral_movement",
        "base_score": 0.80
    },
    {
        "name": "Device / New User Agent",
        "description": "Device observed using a previously unseen user agent string",
        "category": "evasion",
        "base_score": 0.45
    },
    {
        "name": "Anomalous Connection / Application Protocol on Unusual Port",
        "description": "Standard protocol detected on non-standard port",
        "category": "evasion",
        "base_score": 0.55
    },
    {
        "name": "Compliance / Crypto Currency Mining Activity",
        "description": "Patterns consistent with cryptocurrency mining detected",
        "category": "resource_hijacking",
        "base_score": 0.90
    }
]

# AI Analyst incident types
AI_INCIDENTS = [
    {
        "title": "Possible Ransomware Attack Chain",
        "category": "ransomware",
        "group_severity": 95,
        "summary": "Multiple stages of a potential ransomware attack detected"
    },
    {
        "title": "Suspicious Remote Access Pattern",
        "category": "remote_access",
        "group_severity": 75,
        "summary": "Unusual remote access activity detected from external source"
    },
    {
        "title": "Potential Data Exfiltration",
        "category": "exfiltration",
        "group_severity": 85,
        "summary": "Large data transfer to unusual external destination"
    },
    {
        "title": "Lateral Movement Detected",
        "category": "lateral_movement",
        "group_severity": 80,
        "summary": "Device accessing multiple internal systems in unusual pattern"
    },
    {
        "title": "Command and Control Communication",
        "category": "c2",
        "group_severity": 90,
        "summary": "Persistent communication with known malicious infrastructure"
    }
]

# Device types and hostnames
DEVICE_TYPES = ["laptop", "desktop", "server", "mobile", "iot", "printer", "router"]
HOSTNAMES = [
    "CORP-LAPTOP-", "DESKTOP-", "SERVER-", "MOBILE-", "PRINTER-", 
    "ROUTER-", "IOT-", "WORKSTATION-", "DEV-", "PROD-"
]

# Domains and IPs
INTERNAL_DOMAINS = ["corp.local", "internal.company.com", "office.local", "datacenter.local"]
SUSPICIOUS_DOMAINS = [
    "suspicious-domain-{}.com", "malware-c2-{}.net", "phishing-site-{}.org",
    "crypto-miner-{}.io", "data-exfil-{}.com", "suspicious-cdn-{}.net"
]

def _generate_ip(internal=True):
    """Generate an IP address"""
    if internal:
        return f"10.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"
    else:
        return f"{random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"

def _generate_device():
    """Generate device information"""
    device_type = random.choice(DEVICE_TYPES)
    hostname_prefix = random.choice(HOSTNAMES)
    hostname = f"{hostname_prefix}{random.randint(100, 999)}"
    
    return {
        "hostname": hostname,
        "ip": _generate_ip(internal=True),
        "mac": ":".join([f"{random.randint(0, 255):02x}" for _ in range(6)]),
        "type": device_type,
        "os": random.choice(["Windows 10", "Windows 11", "Ubuntu 20.04", "macOS 12.0", "Unknown"])
    }

def _generate_triggered_components(breach_type):
    """Generate triggered component details based on breach type"""
    components = []
    
    base_component = {
        "time": int(time.time() * 1000),
        "uid": str(uuid.uuid4()),
        "pid": random.randint(1000, 9999),
        "detail": {}
    }
    
    if breach_type["category"] == "data_exfiltration":
        component = base_component.copy()
        component["detail"] = {
            "bytesOut": random.randint(1000000, 1000000000),
            "destination": random.choice(SUSPICIOUS_DOMAINS).format(random.randint(1, 100)),
            "protocol": random.choice(["HTTPS", "HTTP", "FTP", "SSH"]),
            "port": random.choice([443, 80, 21, 22, 8080, 8443])
        }
        components.append(component)
    
    elif breach_type["category"] == "malware":
        component = base_component.copy()
        component["detail"] = {
            "fileName": random.choice(["update.exe", "svchost_new.exe", "chrome_update.exe", "document.exe"]),
            "fileHash": uuid.uuid4().hex,
            "fileSize": random.randint(50000, 5000000),
            "downloadSource": f"http://{random.choice(SUSPICIOUS_DOMAINS).format(random.randint(1, 100))}/download"
        }
        components.append(component)
    
    elif breach_type["category"] == "credential_access":
        component = base_component.copy()
        component["detail"] = {
            "username": random.choice(["admin", "administrator", "sa", "root", "service_account"]),
            "authType": random.choice(["NTLM", "Kerberos", "Basic", "Digest"]),
            "sourceIP": _generate_ip(internal=random.choice([True, False])),
            "successful": random.choice([True, False])
        }
        components.append(component)
    
    elif breach_type["category"] == "lateral_movement":
        component = base_component.copy()
        target_device = _generate_device()
        component["detail"] = {
            "targetHost": target_device["hostname"],
            "targetIP": target_device["ip"],
            "method": random.choice(["SMB", "RDP", "SSH", "WMI", "PSExec"]),
            "service": random.choice(["admin$", "c$", "ipc$", "ssh", "rdp"])
        }
        components.append(component)
    
    # Add generic network component for all types
    if random.random() > 0.3:
        network_component = base_component.copy()
        network_component["detail"] = {
            "connections": random.randint(1, 100),
            "bytesIn": random.randint(1000, 10000000),
            "bytesOut": random.randint(1000, 10000000),
            "duration": random.randint(1, 3600)
        }
        components.append(network_component)
    
    return components

def darktrace_log(overrides: dict | None = None) -> Dict:
    """
    Return a single Darktrace event as JSON string.
    
    Pass `overrides` to force any field to a specific value:
        darktrace_log({"score": 0.95})
    """
    event_type = random.choice(["model_breach", "ai_analyst"])
    
    if event_type == "model_breach":
        return _generate_model_breach(overrides)
    else:
        return _generate_ai_analyst(overrides)

def _generate_model_breach(overrides: dict | None = None) -> str:
    """Generate a Darktrace model breach event"""
    breach = random.choice(MODEL_BREACHES)
    device = _generate_device()
    
    # Calculate score with some randomness
    score = breach["base_score"] + random.uniform(-0.15, 0.15)
    score = max(0.0, min(1.0, score))  # Clamp between 0 and 1
    
    # Generate timestamps
    now = datetime.now(timezone.utc)
    creation_time = now - timedelta(seconds=random.randint(0, 300))
    
    event = {
        "time": int(now.timestamp() * 1000),
        "creationTime": int(creation_time.timestamp() * 1000),
        "model": {
            "name": breach["name"],
            "description": breach["description"],
            "id": random.randint(100, 999),
            "version": random.randint(1, 5),
            "uuid": str(uuid.uuid4())
        },
        "breachUrl": f"https://darktrace-{uuid.uuid4().hex[:8]}-0001-01/#modelbreach/{random.randint(10000, 99999)}",
        "pbid": random.randint(1000000, 9999999),
        "score": round(score, 3),
        "device": device,
        "triggeredComponents": _generate_triggered_components(breach),
        "commentCount": random.randint(0, 5),
        "acknowledged": random.choice([True, False]),
        "category": breach["category"],
        "mitreTactics": _get_mitre_tactics(breach["category"]),
        "tags": _get_tags(breach["category"])
    }
    
    # Add additional context fields
    if breach["category"] in ["data_exfiltration", "c2_communication"]:
        event["externalIP"] = _generate_ip(internal=False)
        event["externalDomain"] = random.choice(SUSPICIOUS_DOMAINS).format(random.randint(1, 100))
    
    if breach["category"] == "compliance":
        event["complianceViolation"] = {
            "standard": random.choice(["PCI-DSS", "HIPAA", "GDPR", "SOC2"]),
            "requirement": f"Section {random.randint(1, 12)}.{random.randint(1, 10)}",
            "severity": random.choice(["Low", "Medium", "High"])
        }
    
    # Apply any overrides
    if overrides:
        event.update(overrides)
    
    return event

def _generate_ai_analyst(overrides: dict | None = None) -> str:
    """Generate a Darktrace AI Analyst incident"""
    incident = random.choice(AI_INCIDENTS)
    
    # Generate multiple related breaches
    num_breaches = random.randint(2, 6)
    related_breaches = []
    devices = [_generate_device() for _ in range(random.randint(1, 3))]
    
    for i in range(num_breaches):
        breach_time = int((time.time() - random.randint(0, 3600)) * 1000)
        related_breaches.append({
            "modelName": random.choice(MODEL_BREACHES)["name"],
            "pbid": random.randint(1000000, 9999999),
            "time": breach_time,
            "score": round(random.uniform(0.5, 0.95), 3),
            "device": random.choice(devices)
        })
    
    # Sort breaches by time
    related_breaches.sort(key=lambda x: x["time"])
    
    now = datetime.now(timezone.utc)
    
    event = {
        "time": int(now.timestamp() * 1000),
        "incidentId": str(uuid.uuid4()),
        "title": incident["title"],
        "summary": incident["summary"],
        "category": incident["category"],
        "groupSeverity": incident["group_severity"],
        "incidentUrl": f"https://darktrace-{uuid.uuid4().hex[:8]}-0001-01/saas#aiincident/{random.randint(10000, 99999)}",
        "startTime": related_breaches[0]["time"],
        "endTime": related_breaches[-1]["time"],
        "devices": devices,
        "relatedBreaches": related_breaches,
        "mitreTactics": _get_mitre_tactics(incident["category"]),
        "mitreAttacks": _get_mitre_attacks(incident["category"]),
        "status": random.choice(["new", "investigating", "resolved", "false_positive"]),
        "assignee": random.choice(["unassigned", "soc_analyst_1", "soc_analyst_2", "incident_response"]),
        "comments": []
    }
    
    # Add incident-specific details
    if incident["category"] == "ransomware":
        event["ransomwareIndicators"] = {
            "encryptionDetected": True,
            "shadowCopyDeletion": random.choice([True, False]),
            "ransomNoteDetected": random.choice([True, False]),
            "affectedFiles": random.randint(10, 10000),
            "fileExtensions": [".locked", ".encrypted", ".crypto"]
        }
    
    elif incident["category"] == "exfiltration":
        total_bytes = sum(random.randint(1000000, 100000000) for _ in range(num_breaches))
        event["exfiltrationDetails"] = {
            "totalBytesTransferred": total_bytes,
            "destinations": [random.choice(SUSPICIOUS_DOMAINS).format(i) for i in range(random.randint(1, 3))],
            "protocols": ["HTTPS", "SSH", "FTP"],
            "duration": related_breaches[-1]["time"] - related_breaches[0]["time"]
        }
    
    elif incident["category"] == "lateral_movement":
        event["lateralMovementDetails"] = {
            "sourceSystems": [d["hostname"] for d in devices[:1]],
            "targetSystems": [f"SERVER-{random.randint(100, 999)}" for _ in range(random.randint(2, 5))],
            "techniques": ["PSExec", "WMI", "RDP"],
            "credentialsUsed": [f"CORP\\{random.choice(['admin', 'svc_account', 'backup_admin'])}"]
        }
    
    # Add investigation notes
    if event["status"] != "new":
        event["investigationNotes"] = random.choice([
            "Initial analysis shows legitimate administrative activity",
            "Confirmed malicious activity, containment in progress",
            "User confirmed unusual but authorized activity",
            "Awaiting additional context from endpoint team"
        ])
    
    # Apply any overrides
    if overrides:
        event.update(overrides)
    
    return event

def _get_mitre_tactics(category: str) -> List[str]:
    """Get MITRE ATT&CK tactics for a category"""
    tactics_map = {
        "data_exfiltration": ["Collection", "Exfiltration"],
        "malware": ["Execution", "Defense Evasion"],
        "c2_communication": ["Command and Control"],
        "credential_access": ["Credential Access", "Privilege Escalation"],
        "lateral_movement": ["Lateral Movement", "Discovery"],
        "compliance": ["Discovery"],
        "ransomware": ["Impact", "Defense Evasion"],
        "remote_access": ["Initial Access", "Persistence"],
        "resource_hijacking": ["Impact", "Resource Development"],
        "evasion": ["Defense Evasion"],
        "suspicious_activity": ["Discovery", "Collection"]
    }
    return tactics_map.get(category, ["Unknown"])

def _get_mitre_attacks(category: str) -> List[str]:
    """Get MITRE ATT&CK techniques for a category"""
    attacks_map = {
        "ransomware": ["T1486", "T1490", "T1489"],
        "exfiltration": ["T1041", "T1048", "T1567"],
        "lateral_movement": ["T1021", "T1570", "T1563"],
        "c2": ["T1071", "T1095", "T1571"],
        "remote_access": ["T1133", "T1078", "T1021"]
    }
    return attacks_map.get(category, [])

def _get_tags(category: str) -> List[str]:
    """Get relevant tags for a breach category"""
    base_tags = ["darktrace", "anomaly", "security"]
    category_tags = {
        "data_exfiltration": ["exfiltration", "data_loss"],
        "malware": ["malware", "trojan", "virus"],
        "c2_communication": ["c2", "botnet", "backdoor"],
        "credential_access": ["credentials", "authentication"],
        "lateral_movement": ["lateral", "internal_recon"],
        "compliance": ["compliance", "policy_violation"],
        "ransomware": ["ransomware", "encryption"],
        "resource_hijacking": ["cryptomining", "resource_abuse"],
        "evasion": ["evasion", "obfuscation"]
    }
    
    return base_tags + category_tags.get(category, [])

if __name__ == "__main__":
    # Generate a few sample logs
    print("Model Breach Events:")
    for _ in range(2):
        print(darktrace_log({"eventType": "model_breach"}))
        print()
    
    print("\nAI Analyst Events:")
    for _ in range(2):
        print(darktrace_log({"eventType": "ai_analyst"}))
        print()