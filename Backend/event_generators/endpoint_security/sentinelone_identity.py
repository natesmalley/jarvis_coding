#!/usr/bin/env python3
"""
SentinelOne Identity (Ranger AD) event generator
Generates realistic SentinelOne identity and authentication events based on 
Active Directory monitoring and user behavior analytics.
"""
from __future__ import annotations
import json
import random
import time
import hashlib
import uuid
from datetime import datetime, timezone, timedelta
from typing import Dict, List

# Identity event types
IDENTITY_EVENT_TYPES = [
    {
        "eventType": "User Login",
        "category": "Authentication",
        "severity": "INFO"
    },
    {
        "eventType": "Failed Login",
        "category": "Authentication", 
        "severity": "MEDIUM"
    },
    {
        "eventType": "Privilege Escalation",
        "category": "Authorization",
        "severity": "HIGH"
    },
    {
        "eventType": "Account Lockout",
        "category": "Account Management",
        "severity": "MEDIUM"
    },
    {
        "eventType": "Password Change",
        "category": "Account Management",
        "severity": "INFO"
    },
    {
        "eventType": "Group Membership Change",
        "category": "Account Management",
        "severity": "MEDIUM"
    },
    {
        "eventType": "Suspicious Login Pattern",
        "category": "Behavioral Analytics",
        "severity": "HIGH"
    },
    {
        "eventType": "Service Account Activity",
        "category": "Service Accounts",
        "severity": "INFO"
    },
    {
        "eventType": "Admin Console Access",
        "category": "Administrative",
        "severity": "MEDIUM"
    },
    {
        "eventType": "Kerberos Ticket Anomaly",
        "category": "Kerberos",
        "severity": "HIGH"
    }
]

# Users and service accounts
USERS = [
    {"username": "john.doe", "displayName": "John Doe", "department": "Finance", "isAdmin": False},
    {"username": "jane.smith", "displayName": "Jane Smith", "department": "IT", "isAdmin": True},
    {"username": "bob.jones", "displayName": "Bob Jones", "department": "HR", "isAdmin": False},
    {"username": "alice.williams", "displayName": "Alice Williams", "department": "Operations", "isAdmin": False},
    {"username": "charlie.brown", "displayName": "Charlie Brown", "department": "Security", "isAdmin": True},
    {"username": "admin", "displayName": "Administrator", "department": "IT", "isAdmin": True},
    {"username": "svc_backup", "displayName": "Backup Service", "department": "IT", "isAdmin": False},
    {"username": "svc_sql", "displayName": "SQL Service", "department": "IT", "isAdmin": False}
]

# Login types and methods
LOGIN_TYPES = [
    {"type": "Interactive", "method": "Password"},
    {"type": "Network", "method": "NTLM"},
    {"type": "NetworkCleartext", "method": "Password"},
    {"type": "Service", "method": "Service"},
    {"type": "RemoteInteractive", "method": "RDP"},
    {"type": "Batch", "method": "Scheduled Task"},
    {"type": "Unlock", "method": "Password"},
    {"type": "CachedInteractive", "method": "Cached Credentials"}
]

# Common security groups
SECURITY_GROUPS = [
    "Domain Admins",
    "Enterprise Admins", 
    "Local Administrators",
    "Backup Operators",
    "Account Operators",
    "Print Operators",
    "Server Operators",
    "Remote Desktop Users",
    "Finance Users",
    "IT Staff",
    "HR Team",
    "Operations Team"
]

# Domain controllers and servers
DOMAIN_CONTROLLERS = [
    "DC01.financorp.local",
    "DC02.financorp.local",
    "DC03.financorp.local"
]

def generate_ip_address() -> str:
    """Generate internal or external IP addresses"""
    if random.random() < 0.8:  # 80% internal IPs for identity events
        return f"10.{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(1, 254)}"
    else:  # 20% external IPs
        return f"{random.randint(1, 223)}.{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(1, 254)}"

def generate_workstation_name() -> str:
    """Generate realistic workstation names"""
    prefixes = ["WS", "PC", "DESK", "LT", "NB"]
    return f"{random.choice(prefixes)}-{random.randint(100, 999)}"

def format_timestamp(dt: datetime) -> int:
    """Convert datetime to epoch timestamp (milliseconds) for SentinelOne events"""
    return int(dt.timestamp() * 1000)

def sentinelone_identity_log(custom_fields: Dict = None) -> Dict:
    """Generate a SentinelOne Ranger AD identity event"""
    
    # Select random configurations
    event_info = random.choice(IDENTITY_EVENT_TYPES)
    user_info = random.choice(USERS)
    login_info = random.choice(LOGIN_TYPES)
    domain_controller = random.choice(DOMAIN_CONTROLLERS)
    
    # Generate base event structure
    event_time = datetime.now(timezone.utc) - timedelta(minutes=random.randint(0, 1440))
    
    event = {
        "event.id": str(uuid.uuid4()),
        "event.time": format_timestamp(event_time),
        "event.category": event_info["category"],
        "event.type": event_info["eventType"],
        
        # Login specific fields
        "event.login.type": login_info["type"],
        "event.login.userName": user_info["username"],
        "event.login.loginIsSuccessful": True,  # Will be overridden for failed logins
        
        # Endpoint information
        "endpoint.name": generate_workstation_name(),
        "endpoint.os": random.choice(["Windows 10", "Windows 11", "Windows Server 2019", "Windows Server 2022"]),
        "endpoint.type": random.choice(["workstation", "server", "domain_controller"]),
        
        # Source process (for login events)
        "src.process.name": random.choice(["winlogon.exe", "lsass.exe", "svchost.exe", "explorer.exe"]),
        "src.process.pid": random.randint(1000, 65535),
        "src.process.user": user_info["username"],
        "src.process.cmdline": "",
        "src.process.uid": str(uuid.uuid4()),
        "src.process.parent.uid": str(uuid.uuid4()),
        
        # Network information
        "src.ip.address": generate_ip_address(),
        "src.port.number": random.randint(1024, 65535),
        "dst.ip.address": generate_ip_address(),
        "dst.port.number": random.choice([139, 445, 135, 3389, 88, 389, 636]),
        
        # Agent and site information
        "agent.uuid": str(uuid.uuid4()),
        "agent.version": f"22.{random.randint(1,4)}.{random.randint(1,10)}.{random.randint(100,999)}",
        "site.id": str(uuid.uuid4()),
        "site.name": "FinanceCorp Main Site",
        "account.id": str(uuid.uuid4()),
        "account.name": "FinanceCorp",
        
        # Data source information
        "dataSource.category": "security",
        "dataSource.vendor": "SentinelOne",
        
        # Session information
        "session": random.randint(1, 100),
        "process.unique.key": f"{random.randint(1000000000, 9999999999)}",
        
        # Windows Event Log fields (for Windows events)
        "winEventLog.id": random.choice([4624, 4625, 4634, 4648, 4672, 4720, 4740, 4767]),
        "winEventLog.level": random.choice(["Information", "Warning", "Error"]),
        "winEventLog.channel": "Security",
        "winEventLog.providerName": "Microsoft-Windows-Security-Auditing",
        "winEventLog.description": "",
        "winEventLog.description.userid": user_info["username"],
        "winEventLog.description.securityId": f"S-1-5-21-{random.randint(100000000,999999999)}-{random.randint(100000000,999999999)}-{random.randint(100000000,999999999)}-{random.randint(1000,9999)}"
    }
    
    # Customize based on event type
    if event_info["eventType"] == "Failed Login":
        event["event.login.loginIsSuccessful"] = False
        event["winEventLog.id"] = 4625  # Failed logon
        event["winEventLog.level"] = "Warning"
        event["winEventLog.description"] = f"An account failed to log on. Subject: Security ID: {event['winEventLog.description.securityId']} Account Name: {user_info['username']}"
        
    elif event_info["eventType"] == "User Login":
        event["event.login.loginIsSuccessful"] = True
        event["winEventLog.id"] = 4624  # Successful logon
        event["winEventLog.level"] = "Information"
        event["winEventLog.description"] = f"An account was successfully logged on. Subject: Security ID: {event['winEventLog.description.securityId']} Account Name: {user_info['username']}"
        
    elif event_info["eventType"] == "Privilege Escalation":
        event["winEventLog.id"] = 4672  # Special privileges assigned
        event["winEventLog.description"] = f"Special privileges assigned to new logon. Subject: Security ID: {event['winEventLog.description.securityId']} Account Name: {user_info['username']}"
        
    elif event_info["eventType"] == "Account Lockout":
        event["winEventLog.id"] = 4740  # Account locked out
        event["winEventLog.level"] = "Warning"
        event["winEventLog.description"] = f"A user account was locked out. Subject: Account Name: {user_info['username']}"
        
    elif event_info["eventType"] == "Password Change":
        event["winEventLog.id"] = 4724  # Password reset
        event["winEventLog.description"] = f"An attempt was made to reset an account's password. Subject: Account Name: {user_info['username']}"
        
    elif event_info["eventType"] == "Group Membership Change":
        group = random.choice(SECURITY_GROUPS)
        event["winEventLog.id"] = 4728  # Member added to security group
        event["winEventLog.description"] = f"A member was added to a security-enabled global group. Subject: Account Name: {user_info['username']} Group: {group}"
        
    elif event_info["eventType"] == "Kerberos Ticket Anomaly":
        event["winEventLog.id"] = 4768  # Kerberos TGT requested
        event["winEventLog.description"] = f"A Kerberos authentication ticket (TGT) was requested. Account Name: {user_info['username']}"
        
    # Add threat intelligence indicators for suspicious events
    if event_info["severity"] in ["HIGH", "CRITICAL"]:
        event["indicator.category"] = "Suspicious Activity"
        event["indicator.name"] = f"Suspicious {event_info['eventType']}"
        event["indicator.description"] = f"Detected suspicious {event_info['eventType'].lower()} for user {user_info['username']}"
        event["indicator.metadata"] = json.dumps({
            "confidence": random.randint(70, 95),
            "severity": event_info["severity"],
            "user_risk_score": random.randint(60, 90) if not user_info["isAdmin"] else random.randint(80, 100),
            "behavioral_anomaly": True,
            "mitre_tactics": ["Credential Access", "Privilege Escalation", "Persistence"]
        })
        
        # Add threat intelligence source
        if random.random() < 0.3:  # 30% chance of TI indicator
            event["tiIndicator.source"] = "SentinelOne Threat Intelligence"
            event["tiIndicator.value"] = event["src.ip.address"]
    
    # Add OS-specific details
    if "Windows" in event["endpoint.os"]:
        event["os.name"] = event["endpoint.os"]
        
    # Apply custom fields if provided
    if custom_fields:
        event.update(custom_fields)
    
    return event

if __name__ == "__main__":
    # Generate sample events
    print("Sample SentinelOne Identity Events:")
    print("=" * 50)
    
    for i in range(3):
        print(f"\nEvent {i+1}:")
        print(sentinelone_identity_log())