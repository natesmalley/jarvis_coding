#!/usr/bin/env python3
"""
Manchester SIEM event generator
Generates synthetic Manchester SIEM security events and alerts
"""
import json
import random
import time
from datetime import datetime, timezone, timedelta
from typing import Dict

# Event types
EVENT_TYPES = [
    {"type": "CORRELATION_ALERT", "severity": "HIGH", "category": "Detection"},
    {"type": "ANOMALY_DETECTION", "severity": "MEDIUM", "category": "Analytics"},
    {"type": "THREAT_INTELLIGENCE", "severity": "HIGH", "category": "Intelligence"},
    {"type": "BEHAVIORAL_ANALYSIS", "severity": "MEDIUM", "category": "Analytics"},
    {"type": "RULE_MATCH", "severity": "LOW", "category": "Detection"},
    {"type": "DATA_LOSS_PREVENTION", "severity": "HIGH", "category": "DLP"},
    {"type": "COMPLIANCE_VIOLATION", "severity": "MEDIUM", "category": "Compliance"},
    {"type": "INSIDER_THREAT", "severity": "CRITICAL", "category": "Detection"},
    {"type": "NETWORK_ANOMALY", "severity": "MEDIUM", "category": "Network"},
    {"type": "USER_BEHAVIOR_ANOMALY", "severity": "MEDIUM", "category": "User"}
]

# Alert statuses
ALERT_STATUSES = ["New", "Open", "Investigating", "Resolved", "False Positive", "Closed"]

# Risk scores
RISK_LEVELS = ["Low", "Medium", "High", "Critical"]

# Attack tactics (MITRE ATT&CK)
ATTACK_TACTICS = [
    "Initial Access", "Execution", "Persistence", "Privilege Escalation",
    "Defense Evasion", "Credential Access", "Discovery", "Lateral Movement",
    "Collection", "Command and Control", "Exfiltration", "Impact"
]

# Attack techniques
ATTACK_TECHNIQUES = [
    "T1566.001 - Spearphishing Attachment",
    "T1078 - Valid Accounts", 
    "T1055 - Process Injection",
    "T1021.001 - RDP",
    "T1110 - Brute Force",
    "T1003 - OS Credential Dumping",
    "T1083 - File and Directory Discovery",
    "T1090 - Proxy",
    "T1041 - Exfiltration Over C2 Channel",
    "T1486 - Data Encrypted for Impact"
]

# Data sources
DATA_SOURCES = [
    "Windows Event Logs", "Syslog", "Firewall Logs", "Proxy Logs",
    "DNS Logs", "Endpoint Detection", "Network Traffic", "Email Logs",
    "Cloud Audit Logs", "Database Logs", "Application Logs", "IDS/IPS"
]

def generate_ip() -> str:
    """Generate a random IP address"""
    return f"{random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"

def manch_siem_log() -> Dict:
    """Generate a single Manchester SIEM event log"""
    now = datetime.now(timezone.utc)
    event_time = now - timedelta(minutes=random.randint(0, 1440))
    
    event_info = random.choice(EVENT_TYPES)
    
    event = {
        "timestamp": event_time.isoformat(),
        "event_id": f"MSIEM-{random.randint(1000000, 9999999)}",
        "alert_id": f"ALERT-{random.randint(100000, 999999)}",
        "event_type": event_info["type"],
        "severity": event_info["severity"],
        "category": event_info["category"],
        "status": random.choice(ALERT_STATUSES),
        "risk_score": random.randint(1, 100),
        "risk_level": event_info["severity"],
        "confidence": random.randint(50, 100),
        "title": f"{event_info['type'].replace('_', ' ').title()} Detected",
        "description": f"Manchester SIEM detected {event_info['type'].replace('_', ' ').lower()} activity",
        "source_ip": generate_ip(),
        "destination_ip": generate_ip(),
        "source_hostname": f"host-{random.randint(1, 1000)}",
        "destination_hostname": f"server-{random.randint(1, 100)}",
        "user_name": f"user{random.randint(1, 100)}@company.com",
        "source_country": random.choice(["US", "CA", "GB", "DE", "FR", "CN", "RU", "IN", "BR", "JP"]),
        "destination_country": random.choice(["US", "CA", "GB", "DE", "FR", "CN", "RU", "IN", "BR", "JP"]),
        "data_source": random.choice(DATA_SOURCES),
        "rule_name": f"SIEM_Rule_{random.randint(1, 500)}",
        "rule_description": f"Detection rule for {event_info['type'].replace('_', ' ').lower()}",
        "asset_criticality": random.choice(["Low", "Medium", "High", "Critical"]),
        "analyst_assigned": f"analyst{random.randint(1, 20)}@company.com",
        "investigation_notes": ""
    }
    
    # Add event-specific fields
    if event_info["type"] == "CORRELATION_ALERT":
        event.update({
            "correlated_events": random.randint(3, 50),
            "correlation_rule": f"Correlation_Rule_{random.randint(1, 100)}",
            "time_window": f"{random.randint(5, 60)} minutes",
            "attack_tactic": random.choice(ATTACK_TACTICS),
            "attack_technique": random.choice(ATTACK_TECHNIQUES),
            "kill_chain_phase": random.choice([
                "Reconnaissance", "Weaponization", "Delivery", "Exploitation",
                "Installation", "Command & Control", "Actions on Objectives"
            ])
        })
    
    elif event_info["type"] == "ANOMALY_DETECTION":
        event.update({
            "anomaly_type": random.choice([
                "Traffic Volume", "Login Pattern", "Data Access", "Network Behavior",
                "User Activity", "System Performance", "Application Usage"
            ]),
            "baseline_value": random.randint(10, 1000),
            "current_value": random.randint(1500, 5000),
            "deviation_percentage": random.randint(150, 500),
            "ml_model": f"AnomalyDetection_v{random.randint(1, 5)}.{random.randint(0, 9)}",
            "confidence_score": random.randint(70, 95)
        })
    
    elif event_info["type"] == "THREAT_INTELLIGENCE":
        event.update({
            "ioc_type": random.choice(["IP", "Domain", "URL", "Hash", "Email"]),
            "ioc_value": random.choice([
                generate_ip(),
                "malicious-domain.com",
                "http://c2-server.net/beacon",
                "5d41402abc4b2a76b9719d911017c592",
                "attacker@malicious.com"
            ]),
            "threat_actor": random.choice([
                "APT28", "APT29", "Lazarus Group", "FIN7", "Carbanak",
                "Cozy Bear", "Fancy Bear", "Dark Halo", "Unknown"
            ]),
            "threat_campaign": f"Campaign_{random.randint(2020, 2025)}_{random.randint(1, 100)}",
            "feed_source": random.choice([
                "VirusTotal", "AlienVault OTX", "ThreatConnect", "MISP",
                "Commercial Feed", "Internal Intelligence", "Government Feed"
            ]),
            "first_seen": (event_time - timedelta(days=random.randint(1, 365))).isoformat()
        })
    
    elif event_info["type"] == "BEHAVIORAL_ANALYSIS":
        event.update({
            "behavior_type": random.choice([
                "Unusual Login Time", "Excessive File Access", "Privilege Escalation",
                "Lateral Movement", "Data Hoarding", "Off-Hours Activity"
            ]),
            "user_risk_score": random.randint(1, 100),
            "peer_group": f"Peer_Group_{random.randint(1, 20)}",
            "peer_group_average": random.randint(10, 50),
            "behavior_duration": f"{random.randint(1, 24)} hours",
            "affected_resources": random.randint(1, 20)
        })
    
    elif event_info["type"] == "DATA_LOSS_PREVENTION":
        event.update({
            "dlp_policy": f"DLP_Policy_{random.randint(1, 50)}",
            "data_type": random.choice([
                "Credit Card", "SSN", "Personal Health Info", "Intellectual Property",
                "Financial Data", "Customer Data", "Employee Data"
            ]),
            "data_classification": random.choice(["Public", "Internal", "Confidential", "Restricted"]),
            "violation_count": random.randint(1, 100),
            "file_name": random.choice([
                "customer_database.xlsx", "financial_report.pdf", "employee_records.csv",
                "source_code.zip", "contracts.docx", "medical_records.xlsx"
            ]),
            "file_size": random.randint(1024, 104857600),  # bytes
            "action_taken": random.choice(["Block", "Quarantine", "Alert", "Encrypt"])
        })
    
    elif event_info["type"] == "INSIDER_THREAT":
        event.update({
            "insider_risk_score": random.randint(70, 100),
            "risk_indicators": random.sample([
                "After Hours Access", "Unusual Data Access", "Policy Violations",
                "Performance Issues", "Financial Stress", "Access to Sensitive Data",
                "Recent Termination Notice", "Privilege Abuse"
            ], random.randint(2, 5)),
            "employee_status": random.choice(["Active", "Terminated", "On Leave", "Contractor"]),
            "department": random.choice(["IT", "Finance", "HR", "Sales", "Operations", "Executive"]),
            "manager": f"manager{random.randint(1, 10)}@company.com",
            "investigation_priority": random.choice(["Low", "Medium", "High", "Critical"])
        })
    
    elif event_info["type"] == "NETWORK_ANOMALY":
        event.update({
            "network_segment": random.choice(["DMZ", "Internal", "Guest", "Management", "Production"]),
            "protocol": random.choice(["TCP", "UDP", "ICMP", "HTTP", "HTTPS", "DNS"]),
            "port": random.choice([22, 23, 25, 53, 80, 135, 139, 443, 445, 993, 995, 3389]),
            "bytes_transferred": random.randint(1024, 1073741824),  # bytes
            "packets_count": random.randint(100, 100000),
            "connection_duration": random.randint(1, 86400),  # seconds
            "geographic_anomaly": random.choice([True, False])
        })
    
    # Add timeline and workflow information
    event.update({
        "created_time": event_time.isoformat(),
        "last_updated": event_time.isoformat(),
        "escalation_level": random.randint(0, 3),
        "sla_breach": random.choice([True, False]),
        "time_to_detection": random.randint(1, 1440),  # minutes
        "time_to_acknowledgment": random.randint(5, 60) if event["status"] != "New" else None,
        "time_to_resolution": random.randint(30, 2880) if event["status"] in ["Resolved", "Closed"] else None
    })
    
    # Add compliance and regulatory information
    event.update({
        "compliance_frameworks": random.sample([
            "SOX", "PCI-DSS", "HIPAA", "GDPR", "SOC2", "ISO27001", "NIST"
        ], random.randint(1, 3)),
        "regulatory_impact": random.choice(["None", "Low", "Medium", "High"]),
        "notification_required": random.choice([True, False])
    })
    
    # Remove None values
    event = {k: v for k, v in event.items() if v is not None}
    
    return event

if __name__ == "__main__":
    # Generate sample events
    print("Sample Manchester SIEM Events:")
    print("=" * 50)
    for i in range(3):
        print(f"\nEvent {i+1}:")
        print(manch_siem_log())