#!/usr/bin/env python3
"""
ManageEngine General event generator
Generates synthetic ManageEngine IT management and security events
"""
import json
import random
import time
from datetime import datetime, timezone, timedelta
from typing import Dict

# ManageEngine products
PRODUCTS = [
    "ADManager Plus",
    "ADAudit Plus", 
    "ADSelfService Plus",
    "AssetExplorer",
    "ServiceDesk Plus",
    "Desktop Central",
    "Patch Manager Plus",
    "OS Deployer",
    "Remote Access Plus",
    "Key Manager Plus",
    "Password Manager Pro",
    "Access Manager Plus"
]

# Event types by category
EVENT_CATEGORIES = {
    "USER_MANAGEMENT": [
        {"action": "USER_CREATED", "severity": "INFO"},
        {"action": "USER_DELETED", "severity": "WARNING"},
        {"action": "USER_MODIFIED", "severity": "INFO"},
        {"action": "PASSWORD_RESET", "severity": "INFO"},
        {"action": "ACCOUNT_LOCKED", "severity": "WARNING"},
        {"action": "ACCOUNT_UNLOCKED", "severity": "INFO"}
    ],
    "GROUP_MANAGEMENT": [
        {"action": "GROUP_CREATED", "severity": "INFO"},
        {"action": "GROUP_DELETED", "severity": "WARNING"},
        {"action": "GROUP_MODIFIED", "severity": "INFO"},
        {"action": "MEMBER_ADDED", "severity": "INFO"},
        {"action": "MEMBER_REMOVED", "severity": "INFO"}
    ],
    "SYSTEM_MANAGEMENT": [
        {"action": "PATCH_INSTALLED", "severity": "INFO"},
        {"action": "SOFTWARE_INSTALLED", "severity": "INFO"},
        {"action": "SOFTWARE_UNINSTALLED", "severity": "INFO"},
        {"action": "SYSTEM_REBOOT", "severity": "WARNING"},
        {"action": "SERVICE_STARTED", "severity": "INFO"},
        {"action": "SERVICE_STOPPED", "severity": "WARNING"}
    ],
    "SECURITY": [
        {"action": "LOGIN_FAILED", "severity": "WARNING"},
        {"action": "LOGIN_SUCCESS", "severity": "INFO"},
        {"action": "PRIVILEGE_ESCALATION", "severity": "CRITICAL"},
        {"action": "UNAUTHORIZED_ACCESS", "severity": "HIGH"},
        {"action": "POLICY_VIOLATION", "severity": "WARNING"},
        {"action": "MALWARE_DETECTED", "severity": "CRITICAL"}
    ],
    "ASSET_MANAGEMENT": [
        {"action": "ASSET_DISCOVERED", "severity": "INFO"},
        {"action": "ASSET_MODIFIED", "severity": "INFO"},
        {"action": "ASSET_RETIRED", "severity": "INFO"},
        {"action": "LICENSE_EXPIRED", "severity": "WARNING"},
        {"action": "COMPLIANCE_VIOLATION", "severity": "WARNING"}
    ],
    "HELPDESK": [
        {"action": "TICKET_CREATED", "severity": "INFO"},
        {"action": "TICKET_RESOLVED", "severity": "INFO"},
        {"action": "TICKET_ESCALATED", "severity": "WARNING"},
        {"action": "SLA_BREACH", "severity": "HIGH"},
        {"action": "TICKET_REOPENED", "severity": "WARNING"}
    ]
}

# User roles
USER_ROLES = [
    "Administrator", "IT Manager", "Help Desk", "Technician", 
    "Asset Manager", "Security Analyst", "Auditor", "End User"
]

# Operating systems
OPERATING_SYSTEMS = [
    "Windows 10", "Windows 11", "Windows Server 2019", "Windows Server 2022",
    "macOS Monterey", "macOS Ventura", "Ubuntu 20.04", "Ubuntu 22.04",
    "CentOS 7", "CentOS 8", "RHEL 8", "RHEL 9"
]

def generate_ip() -> str:
    """Generate a random IP address"""
    return f"10.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"

def manageengine_general_log() -> Dict:
    """Generate a single ManageEngine event log"""
    now = datetime.now(timezone.utc)
    event_time = now - timedelta(minutes=random.randint(0, 1440))
    
    product = random.choice(PRODUCTS)
    category = random.choice(list(EVENT_CATEGORIES.keys()))
    event_info = random.choice(EVENT_CATEGORIES[category])
    
    event = {
        "timestamp": event_time.isoformat(),
        "event_id": f"ME-{random.randint(100000, 999999)}",
        "product": product,
        "event_category": category,
        "action": event_info["action"],
        "severity": event_info["severity"],
        "description": f"{event_info['action'].replace('_', ' ').title()} event occurred",
        "source_ip": generate_ip(),
        "user_name": f"user{random.randint(1, 100)}",
        "domain": "company.local",
        "workstation": f"WS-{random.randint(1000, 9999)}",
        "computer_name": f"PC-{random.randint(100, 999)}",
        "operating_system": random.choice(OPERATING_SYSTEMS),
        "agent_version": f"{random.randint(10, 14)}.{random.randint(0, 9)}.{random.randint(0, 9)}.{random.randint(1000, 9999)}",
        "location": random.choice(["HQ", "Branch-A", "Branch-B", "Remote", "Data Center"]),
        "department": random.choice(["IT", "Finance", "HR", "Sales", "Marketing", "Operations"])
    }
    
    # Add category-specific fields
    if category == "USER_MANAGEMENT":
        target_user = f"user{random.randint(1, 100)}"
        event.update({
            "target_user": target_user,
            "target_user_dn": f"CN={target_user},OU=Users,DC=company,DC=local",
            "organizational_unit": random.choice(["Users", "Admins", "ServiceAccounts", "Contractors"]),
            "user_role": random.choice(USER_ROLES),
            "group_membership": [f"Group-{random.randint(1, 20)}" for _ in range(random.randint(1, 5))]
        })
        
        if "PASSWORD" in event_info["action"]:
            event.update({
                "password_policy": "Default Domain Policy",
                "password_complexity": random.choice(["Met", "Not Met"]),
                "password_age": random.randint(0, 90)
            })
    
    elif category == "GROUP_MANAGEMENT":
        group_name = f"Group-{random.randint(1, 50)}"
        event.update({
            "group_name": group_name,
            "group_type": random.choice(["Security", "Distribution", "Universal"]),
            "group_scope": random.choice(["Global", "Domain Local", "Universal"]),
            "group_dn": f"CN={group_name},OU=Groups,DC=company,DC=local",
            "member_count": random.randint(1, 100)
        })
    
    elif category == "SYSTEM_MANAGEMENT":
        event.update({
            "patch_kb": f"KB{random.randint(1000000, 9999999)}" if "PATCH" in event_info["action"] else "",
            "software_name": random.choice([
                "Microsoft Office 365", "Adobe Reader", "Google Chrome", 
                "Mozilla Firefox", "Java Runtime", "VLC Media Player"
            ]) if "SOFTWARE" in event_info["action"] else "",
            "software_version": f"{random.randint(1, 100)}.{random.randint(0, 9)}.{random.randint(0, 9)}" if "SOFTWARE" in event_info["action"] else "",
            "service_name": random.choice([
                "Windows Update", "DHCP Client", "DNS Client", "Print Spooler", "Task Scheduler"
            ]) if "SERVICE" in event_info["action"] else "",
            "installation_status": random.choice(["Success", "Failed", "Pending"]) if "INSTALLED" in event_info["action"] else "",
            "reboot_required": random.choice([True, False]) if "PATCH" in event_info["action"] else False
        })
    
    elif category == "SECURITY":
        event.update({
            "authentication_method": random.choice(["NTLM", "Kerberos", "Local", "LDAP"]),
            "logon_type": random.choice(["Interactive", "Network", "Service", "RemoteInteractive"]),
            "failure_reason": random.choice([
                "Invalid credentials", "Account locked", "Account disabled", 
                "Password expired", "Logon time restriction"
            ]) if "FAILED" in event_info["action"] else "",
            "privilege_level": random.choice(["User", "Administrator", "System", "Service"]),
            "policy_name": f"Security_Policy_{random.randint(1, 10)}" if "POLICY" in event_info["action"] else "",
            "malware_name": f"Trojan.Win32.Generic.{random.randint(1000, 9999)}" if "MALWARE" in event_info["action"] else ""
        })
    
    elif category == "ASSET_MANAGEMENT":
        event.update({
            "asset_id": f"ASSET-{random.randint(10000, 99999)}",
            "asset_type": random.choice(["Desktop", "Laptop", "Server", "Mobile", "Printer", "Network Device"]),
            "manufacturer": random.choice(["Dell", "HP", "Lenovo", "Apple", "Cisco", "Microsoft"]),
            "model": f"Model-{random.randint(1000, 9999)}",
            "serial_number": f"SN{''.join(random.choices('ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789', k=10))}",
            "purchase_date": (event_time - timedelta(days=random.randint(30, 1095))).date().isoformat(),
            "warranty_expiry": (event_time + timedelta(days=random.randint(30, 730))).date().isoformat(),
            "cost": random.randint(500, 5000),
            "license_key": f"{''.join(random.choices('ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789', k=25))}" if "LICENSE" in event_info["action"] else ""
        })
    
    elif category == "HELPDESK":
        ticket_id = f"TKT-{random.randint(10000, 99999)}"
        event.update({
            "ticket_id": ticket_id,
            "ticket_subject": random.choice([
                "Password reset request", "Software installation", "Hardware issue",
                "Network connectivity", "Email problem", "System performance"
            ]),
            "priority": random.choice(["Low", "Medium", "High", "Critical"]),
            "category": random.choice(["Hardware", "Software", "Network", "Security", "Access"]),
            "subcategory": random.choice(["Desktop", "Laptop", "Printer", "Application", "Email"]),
            "assigned_to": f"tech{random.randint(1, 20)}",
            "requester": f"user{random.randint(1, 100)}",
            "resolution_time": random.randint(15, 480) if "RESOLVED" in event_info["action"] else None,  # minutes
            "sla_hours": random.choice([4, 8, 24, 48]),
            "satisfaction_rating": random.randint(1, 5) if "RESOLVED" in event_info["action"] else None
        })
    
    # Add compliance and audit fields
    event.update({
        "compliance_status": random.choice(["Compliant", "Non-Compliant", "Partial", "Unknown"]),
        "audit_trail": f"audit_{random.randint(1000000, 9999999)}",
        "change_request_id": f"CR-{random.randint(10000, 99999)}" if random.choice([True, False]) else "",
        "approver": f"manager{random.randint(1, 10)}" if random.choice([True, False]) else ""
    })
    
    # Remove None values and empty strings
    event = {k: v for k, v in event.items() if v is not None and v != ""}
    
    return event

if __name__ == "__main__":
    # Generate sample events
    print("Sample ManageEngine Events:")
    print("=" * 50)
    for i in range(3):
        print(f"\nEvent {i+1}:")
        print(manageengine_general_log())