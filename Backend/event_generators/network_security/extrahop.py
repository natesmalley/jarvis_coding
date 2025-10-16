#!/usr/bin/env python3
"""
ExtraHop Reveal(x) 360 event generator (JSON format)
Generates ExtraHop detection and network activity events
"""
from __future__ import annotations
import json
import random
import time
import uuid
from datetime import datetime, timezone, timedelta
from typing import Dict, List

# Detection types
DETECTION_TYPES = [
    "suspicious_connection",
    "sql_injection",
    "dns_tunneling",
    "data_exfiltration",
    "privilege_escalation",
    "lateral_movement",
    "brute_force_attack",
    "ransomware_activity",
    "cryptocurrency_mining",
    "vulnerability_exploit",
    "web_shell_activity",
    "suspicious_authentication",
    "port_scan",
    "ddos_attack",
    "insider_threat"
]

# Detection titles  
DETECTION_TITLES = {
    "suspicious_connection": "Suspicious External Connection Detected",
    "sql_injection": "SQL Injection Attack Attempt",
    "dns_tunneling": "DNS Tunneling Activity",
    "data_exfiltration": "Potential Data Exfiltration",
    "privilege_escalation": "Privilege Escalation Attempt",
    "lateral_movement": "Lateral Movement Detected",
    "brute_force_attack": "Brute Force Authentication Attack",
    "ransomware_activity": "Ransomware Behavior Detected",
    "cryptocurrency_mining": "Cryptocurrency Mining Activity",
    "vulnerability_exploit": "Vulnerability Exploitation Attempt",
    "web_shell_activity": "Web Shell Command Execution",
    "suspicious_authentication": "Anomalous Authentication Pattern",
    "port_scan": "Network Port Scanning",
    "ddos_attack": "Distributed Denial of Service Attack",
    "insider_threat": "Insider Threat Behavior"
}

# MITRE ATT&CK tactics
MITRE_TACTICS = [
    "Initial Access",
    "Execution",
    "Persistence",
    "Privilege Escalation",
    "Defense Evasion",
    "Credential Access",
    "Discovery",
    "Lateral Movement",
    "Collection",
    "Command and Control",
    "Exfiltration",
    "Impact"
]

# MITRE ATT&CK techniques (subset)
MITRE_TECHNIQUES = {
    "Initial Access": ["T1190", "T1133", "T1566"],
    "Execution": ["T1059", "T1203", "T1053"],
    "Persistence": ["T1098", "T1136", "T1543"],
    "Privilege Escalation": ["T1068", "T1055", "T1134"],
    "Defense Evasion": ["T1070", "T1036", "T1562"],
    "Credential Access": ["T1110", "T1003", "T1558"],
    "Discovery": ["T1057", "T1018", "T1083"],
    "Lateral Movement": ["T1021", "T1570", "T1080"],
    "Collection": ["T1005", "T1039", "T1074"],
    "Command and Control": ["T1071", "T1105", "T1095"],
    "Exfiltration": ["T1041", "T1048", "T1567"],
    "Impact": ["T1486", "T1489", "T1499"]
}

# Detection categories
CATEGORIES = [
    "sec",  # Security
    "sec.attack",
    "sec.command",
    "sec.exploit",
    "sec.lateral",
    "sec.recon"
]

# Status values
STATUS_VALUES = ["new", "in_progress", "closed", "suppressed"]

# Resolution values
RESOLUTION_VALUES = ["action_taken", "false_positive", "no_action_needed", "escalated", None]

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

def _generate_device_id() -> str:
    """Generate a device ID"""
    return f"{random.randint(1000, 99999)}"

def _generate_detection_id() -> int:
    """Generate a detection ID"""
    return random.randint(1000000, 9999999)

def extrahop_log(overrides: dict | None = None) -> Dict:
    """
    Return a single ExtraHop event as JSON string.
    
    Pass `overrides` to force any field to a specific value:
        extrahop_log({"type": "sql_injection", "risk_score": 90})
    """
    # Generate timestamps
    now = datetime.now(timezone.utc)
    start_time = now - timedelta(minutes=random.randint(5, 300))
    update_time = start_time + timedelta(minutes=random.randint(1, 60))
    mod_time = update_time
    
    # Select detection type
    detection_type = random.choice(DETECTION_TYPES)
    
    # Calculate risk score based on detection type
    if detection_type in ["ransomware_activity", "data_exfiltration", "vulnerability_exploit"]:
        risk_score = random.randint(70, 99)
    elif detection_type in ["sql_injection", "privilege_escalation", "lateral_movement"]:
        risk_score = random.randint(50, 85)
    else:
        risk_score = random.randint(20, 70)
    
    # Generate participants
    participants = _generate_participants(detection_type)
    
    # Select MITRE tactics and techniques
    if detection_type == "lateral_movement":
        tactics = ["Lateral Movement"]
    elif detection_type == "data_exfiltration":
        tactics = ["Exfiltration", "Collection"]
    elif detection_type == "privilege_escalation":
        tactics = ["Privilege Escalation"]
    elif detection_type == "ransomware_activity":
        tactics = ["Impact", "Defense Evasion"]
    else:
        tactics = random.sample(MITRE_TACTICS, random.randint(1, 3))
    
    techniques = []
    for tactic in tactics:
        technique_list = MITRE_TECHNIQUES.get(tactic, [])
        if technique_list:
            techniques.extend(random.sample(technique_list, min(2, len(technique_list))))
    
    # Generate properties based on detection type
    properties = _generate_properties(detection_type, participants)
    
    # Status and resolution
    status = random.choice(STATUS_VALUES)
    resolution = None
    if status == "closed":
        resolution = random.choice(RESOLUTION_VALUES)
    
    event = {
        "id": _generate_detection_id(),
        "start_time": int(start_time.timestamp() * 1000),  # milliseconds
        "update_time": int(update_time.timestamp() * 1000),
        "mod_time": int(mod_time.timestamp() * 1000),
        "title": DETECTION_TITLES.get(detection_type, "Unknown Detection"),
        "description": _generate_description(detection_type, participants),
        "risk_score": risk_score,
        "type": detection_type,
        "categories": _select_categories(detection_type),
        "participants": participants,
        "properties": properties,
        "mitre_tactics": tactics,
        "mitre_techniques": techniques,
        "ticket_id": f"INC{random.randint(100000, 999999)}" if random.random() < 0.3 else None,
        "assignee": f"analyst{random.randint(1, 10)}@company.com" if status != "new" else None,
        "status": status,
        "resolution": resolution,
        "appliance_id": random.randint(1, 5),
        "is_user_created": False
    }
    
    # Add optional fields
    if random.random() < 0.4:
        event["end_time"] = int((start_time + timedelta(minutes=random.randint(1, 120))).timestamp() * 1000)
    
    # Apply any overrides
    if overrides:
        event.update(overrides)
    
    return event

def _generate_participants(detection_type: str) -> List[Dict]:
    """Generate participants based on detection type"""
    participants = []
    
    # Always have at least one offender
    offender_ip = _generate_ip(internal=random.random() < 0.3)
    participants.append({
        "object_id": _generate_device_id(),
        "object_type": "device",
        "role": "offender",
        "hostname": f"host-{random.randint(100, 999)}" if "." not in offender_ip else None,
        "ipaddr": offender_ip,
        "port": random.randint(1024, 65535) if detection_type != "port_scan" else None
    })
    
    # Add victims
    num_victims = 1 if detection_type not in ["port_scan", "ddos_attack", "lateral_movement"] else random.randint(2, 10)
    
    for _ in range(num_victims):
        victim_ip = _generate_ip(internal=True)
        victim = {
            "object_id": _generate_device_id(),
            "object_type": "device",
            "role": "victim",
            "hostname": f"srv-{random.choice(['web', 'db', 'app', 'file'])}-{random.randint(1, 50)}",
            "ipaddr": victim_ip
        }
        
        # Add port for specific detection types
        if detection_type in ["sql_injection", "web_shell_activity"]:
            victim["port"] = random.choice([80, 443, 8080, 8443])
        elif detection_type == "brute_force_attack":
            victim["port"] = random.choice([22, 3389, 445])
        elif detection_type == "data_exfiltration":
            victim["port"] = random.choice([443, 22, 21])
        
        participants.append(victim)
    
    return participants

def _generate_properties(detection_type: str, participants: List[Dict]) -> Dict:
    """Generate properties based on detection type"""
    properties = {
        "detection_id": str(uuid.uuid4()),
        "severity": _get_severity_label(detection_type),
        "confidence": random.randint(70, 99)
    }
    
    if detection_type == "sql_injection":
        properties.update({
            "query_string": "' OR '1'='1' --",
            "database_type": random.choice(["MySQL", "PostgreSQL", "MSSQL", "Oracle"]),
            "affected_tables": random.randint(1, 10)
        })
    elif detection_type == "data_exfiltration":
        properties.update({
            "bytes_transferred": random.randint(10000000, 10000000000),
            "duration_minutes": random.randint(5, 120),
            "files_accessed": random.randint(10, 1000),
            "protocol": random.choice(["HTTPS", "SSH", "FTP", "DNS"])
        })
    elif detection_type == "brute_force_attack":
        properties.update({
            "attempts": random.randint(100, 10000),
            "unique_usernames": random.randint(1, 100),
            "success_rate": round(random.uniform(0, 0.1), 3),
            "protocol": random.choice(["SSH", "RDP", "SMB"])
        })
    elif detection_type == "ransomware_activity":
        properties.update({
            "files_encrypted": random.randint(100, 10000),
            "encryption_rate": f"{random.randint(10, 100)} files/sec",
            "ransom_note_detected": random.random() < 0.8,
            "file_extensions": [".locked", ".encrypted", ".crypto"]
        })
    elif detection_type == "port_scan":
        properties.update({
            "ports_scanned": random.randint(100, 65535),
            "scan_type": random.choice(["TCP SYN", "TCP Connect", "UDP", "Xmas"]),
            "open_ports_found": random.randint(0, 20)
        })
    elif detection_type == "dns_tunneling":
        properties.update({
            "queries_count": random.randint(1000, 50000),
            "unique_domains": random.randint(1, 10),
            "avg_query_length": random.randint(50, 200),
            "suspicious_domain": f"tunnel{random.randint(1, 100)}.{random.choice(['tk', 'ml', 'ga'])}"
        })
    
    return properties

def _generate_description(detection_type: str, participants: List[Dict]) -> str:
    """Generate detailed description based on detection type"""
    offender = next(p for p in participants if p["role"] == "offender")
    victims = [p for p in participants if p["role"] == "victim"]
    
    if detection_type == "suspicious_connection":
        return f"Device {offender['ipaddr']} established suspicious connection to {victims[0]['ipaddr']}"
    elif detection_type == "sql_injection":
        return f"SQL injection attempt detected from {offender['ipaddr']} targeting database server {victims[0]['hostname']}"
    elif detection_type == "data_exfiltration":
        return f"Large data transfer detected from {victims[0]['hostname']} to external IP {offender['ipaddr']}"
    elif detection_type == "lateral_movement":
        return f"Lateral movement detected from {offender.get('hostname', offender['ipaddr'])} to {len(victims)} internal systems"
    elif detection_type == "ransomware_activity":
        return f"Ransomware behavior detected on {victims[0]['hostname']} - rapid file encryption observed"
    else:
        return f"{DETECTION_TITLES[detection_type]} involving {offender['ipaddr']} and {len(victims)} target(s)"

def _select_categories(detection_type: str) -> List[str]:
    """Select appropriate categories for detection type"""
    if detection_type in ["sql_injection", "vulnerability_exploit"]:
        return ["sec", "sec.exploit"]
    elif detection_type in ["lateral_movement", "privilege_escalation"]:
        return ["sec", "sec.lateral"]
    elif detection_type in ["port_scan", "dns_tunneling"]:
        return ["sec", "sec.recon"]
    elif detection_type in ["web_shell_activity", "cryptocurrency_mining"]:
        return ["sec", "sec.command"]
    else:
        return ["sec", "sec.attack"]

def _get_severity_label(detection_type: str) -> str:
    """Get severity label based on detection type"""
    if detection_type in ["ransomware_activity", "data_exfiltration", "vulnerability_exploit"]:
        return "critical"
    elif detection_type in ["sql_injection", "privilege_escalation", "lateral_movement"]:
        return "high"
    elif detection_type in ["brute_force_attack", "suspicious_authentication"]:
        return "medium"
    else:
        return "low"

if __name__ == "__main__":
    # Generate sample logs
    print("Sample ExtraHop events:")
    for detection in ["sql_injection", "data_exfiltration", "lateral_movement"]:
        print(f"\n{detection.upper()} detection:")
        print(extrahop_log({"type": detection}))
        print()