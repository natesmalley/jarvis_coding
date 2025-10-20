#!/usr/bin/env python3
"""Generate synthetic Aruba ClearPass Policy Manager logs."""
import json
import random
from datetime import datetime, timezone

# ClearPass log types and categories
LOG_TYPES = [
    "Common Session Logs",
    "Insight Logs", 
    "Audit Records",
    "System Logs",
    "Authentication Logs"
]

AUTH_METHODS = ["EAP-TLS", "EAP-PEAP", "EAP-TTLS", "MAC-Auth", "Web-Auth", "802.1X"]
AUTH_SOURCES = ["Active Directory", "Local User Repository", "Guest User Repository", "LDAP"]
ENFORCEMENT_PROFILES = ["Employee Access", "Guest Access", "BYOD Access", "IoT Devices", "Contractor Access", "Quarantine"]
NAS_TYPES = ["Aruba Controller", "Aruba Switch", "Aruba AP", "Third-party Switch"]

def get_random_ip():
    """Generate a random IP address."""
    if random.random() < 0.7:  # 70% internal IPs
        return f"10.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"
    else:
        return f"192.168.{random.randint(1, 254)}.{random.randint(1, 254)}"

def get_random_mac():
    """Generate a random MAC address."""
    return ":".join([f"{random.randint(0, 255):02x}" for _ in range(6)])

def generate_session_log():
    """Generate a Common Session Log entry."""
    success = random.random() < 0.85
    
    return {
        "auth_status": "Success" if success else "Failed",
        "username": f"user{random.randint(1, 500)}@company.com" if random.random() < 0.8 else f"guest{random.randint(1, 100)}",
        "mac_address": get_random_mac(),
        "ip_address": get_random_ip(),
        "auth_method": random.choice(AUTH_METHODS),
        "auth_source": random.choice(AUTH_SOURCES),
        "enforcement_profile": random.choice(ENFORCEMENT_PROFILES) if success else "Deny Access",
        "nas_ip": f"10.{random.randint(1, 10)}.{random.randint(1, 50)}.{random.randint(1, 254)}",
        "nas_port": f"GigabitEthernet0/0/{random.randint(1, 48)}",
        "nas_type": random.choice(NAS_TYPES),
        "session_id": f"5{random.randint(10000000, 99999999)}",
        "error_code": 0 if success else random.choice([601, 602, 603, 604, 605])
    }

def generate_insight_log():
    """Generate an Insight Log entry."""
    categories = ["Device Profiling", "Posture Assessment", "Anomaly Detection", "Compliance Check"]
    
    return {
        "category": random.choice(categories),
        "device_mac": get_random_mac(),
        "device_ip": get_random_ip(),
        "device_type": random.choice(["Windows PC", "MacBook", "iPhone", "Android", "Printer", "VoIP Phone", "IoT Device"]),
        "os_version": random.choice(["Windows 10", "Windows 11", "macOS 12", "iOS 15", "Android 12", "Unknown"]),
        "compliance_status": random.choice(["Compliant", "Non-Compliant", "Unknown"]),
        "risk_score": random.randint(0, 100),
        "anomalies_detected": random.randint(0, 5)
    }

def generate_audit_log():
    """Generate an Audit Record entry."""
    actions = [
        "Configuration Change", "User Login", "User Logout", "Policy Update",
        "Certificate Issued", "Guest Account Created", "Device Onboarded",
        "Service Restart", "Backup Created", "License Updated"
    ]
    
    return {
        "action": random.choice(actions),
        "admin_user": random.choice(["admin", "netops", "security_admin", f"admin{random.randint(1, 10)}"]),
        "admin_ip": get_random_ip(),
        "target_object": random.choice(["Policy", "Service", "User", "Device", "Certificate", "System"]),
        "result": random.choice(["Success", "Failed"]),
        "description": f"Action performed via {random.choice(['Web UI', 'CLI', 'API'])}"
    }

def aruba_clearpass_log(overrides: dict | None = None) -> str:
    """Generate a single Aruba ClearPass log entry in expected syslog format."""
    now = datetime.now(timezone.utc)
    log_type = random.choice(LOG_TYPES)
    
    # Generate syslog format matching parser expectations
    # Format: timestamp hostname process_name ip log_type log_number field1 field2
    timestamp = now.strftime("%Y-%m-%d %H:%M:%S,%f")[:-3]
    hostname = f"clearpass-{random.randint(1, 5)}.company.com"
    process = "clearpass-server"
    ip = f"10.100.{random.randint(1, 10)}.{random.randint(1, 254)}"
    log_number = random.randint(1000, 9999)
    
    # Generate type-specific fields
    if log_type == "Common Session Logs":
        session = generate_session_log()
        field1 = f"user={session['username']}"
        field2 = f"status={session['auth_status']}"
    elif log_type == "Insight Logs":
        insight = generate_insight_log()
        field1 = f"category={insight['category']}"
        field2 = f"risk_score={insight['risk_score']}"
    elif log_type == "Audit Records":
        audit = generate_audit_log()
        field1 = f"action={audit['action']}"
        field2 = f"admin_user={audit['admin_user']}"
    else:
        field1 = "component=Policy_Engine"
        field2 = "severity=INFO"
    
    # Build syslog format matching parser pattern
    # $timestamp$ \S+ \S+ $ip=ipv4Pat$ Common Session Logs $log_number$ $field1$ $field2$
    log_entry = f"{timestamp} {hostname} {process} {ip} {log_type} {log_number} {field1} {field2}"
    
    # Apply simple overrides
    if overrides:
        if "log_type" in overrides:
            log_entry = log_entry.replace(log_type, overrides["log_type"])
        if "ip" in overrides:
            log_entry = log_entry.replace(ip, overrides["ip"])
    
    return log_entry

# OCSF-style attributes for HEC
if __name__ == "__main__":
    # Generate sample logs
    for _ in range(5):
        print(aruba_clearpass_log())