#!/usr/bin/env python3
"""
BeyondTrust Password Safe event generator (syslog + JSON format)
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
    "AccountCheckout", "AccountCheckin", "AccountView", "AccountPasswordChange",
    "SessionStart", "SessionEnd", "AssetAccess", "PasswordGeneration",
    "PolicyViolation", "UserLogin", "UserLogout", "AdminAction",
    "ApprovalRequest", "ApprovalGranted", "ApprovalDenied", "AuditReport"
]

# Account types
ACCOUNT_TYPES = [
    "Windows Domain", "Windows Local", "Unix/Linux", "Database", "Network Device",
    "Web Application", "Cloud Service", "SSH Key", "Certificate", "API Key"
]

# Asset types
ASSET_TYPES = [
    "Windows Server", "Linux Server", "Network Switch", "Router", "Firewall",
    "Database Server", "Web Server", "Cloud Instance", "Application Server"
]

# Actions
ACTIONS = [
    "checkout", "checkin", "view", "password_change", "session_launch",
    "session_terminate", "approve", "deny", "create", "delete", "modify"
]

# Approval reasons
APPROVAL_REASONS = [
    "Routine maintenance", "Emergency access", "Troubleshooting", "Compliance audit",
    "Security incident response", "System upgrade", "Configuration change", "Backup restore"
]

# Users and groups
USERS = [
    ("John Doe", "jdoe", "IT Administrator"),
    ("Jane Smith", "jsmith", "Database Administrator"), 
    ("Bob Johnson", "bjohnson", "Network Administrator"),
    ("Alice Williams", "awilliams", "Security Analyst"),
    ("Charlie Brown", "cbrown", "System Administrator"),
    ("Admin User", "admin", "System Administrator"),
    ("Service Account", "svc_backup", "Service Account")
]

# Privileged accounts
PRIVILEGED_ACCOUNTS = [
    ("administrator", "Windows Domain", "CORP\\administrator"),
    ("root", "Unix/Linux", "root@server01.company.com"),
    ("sa", "Database", "SQL Server SA"),
    ("admin", "Network Device", "cisco_admin"),
    ("postgres", "Database", "PostgreSQL Admin"),
    ("oracle", "Database", "Oracle DBA"),
    ("svc_sql", "Windows Domain", "CORP\\svc_sql"),
    ("backup_admin", "Unix/Linux", "backup@backup-server")
]

# Systems and assets
SYSTEMS = [
    ("DC01", "Domain Controller", "Windows Server 2019"),
    ("SQL01", "Database Server", "SQL Server 2019"),
    ("WEB01", "Web Server", "IIS/Windows Server"),
    ("LINUX01", "File Server", "Ubuntu 20.04"),
    ("SWITCH01", "Network Switch", "Cisco Catalyst"),
    ("FIREWALL01", "Firewall", "Palo Alto Networks"),
    ("BACKUP01", "Backup Server", "Veeam Backup"),
    ("ORACLE01", "Database Server", "Oracle 19c")
]

def _generate_ip():
    """Generate an IP address"""
    return f"10.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"

def _generate_session_id():
    """Generate a session ID"""
    return f"sess_{uuid.uuid4().hex[:16]}"

def _generate_request_id():
    """Generate a request ID"""
    return f"req_{random.randint(100000, 999999)}"

def beyondtrust_passwordsafe_log(overrides: dict | None = None) -> str:
    """
    Return a single BeyondTrust Password Safe event as syslog + JSON string.
    
    Pass `overrides` to force any field to a specific value:
        beyondtrust_passwordsafe_log({"EventType": "AccountCheckout"})
    """
    # Generate timestamps
    now = datetime.now(timezone.utc)
    event_time = now - timedelta(seconds=random.randint(0, 300))
    
    # Select event details
    event_type = random.choice(EVENT_TYPES)
    user_name, user_id, user_role = random.choice(USERS)
    account_name, account_type, account_full_name = random.choice(PRIVILEGED_ACCOUNTS)
    system_name, system_desc, system_os = random.choice(SYSTEMS)
    
    # Base event structure
    event = {
        "EventTime": event_time.strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
        "EventType": event_type,
        "EventId": str(uuid.uuid4()),
        "UserId": user_id,
        "UserName": user_name,
        "UserDisplayName": user_name,
        "UserRole": user_role,
        "UserDomain": "CORP",
        "SourceIP": _generate_ip(),
        "UserAgent": random.choice([
            "BeyondTrust Password Safe Client 21.2",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "BeyondTrust Mobile App 3.1"
        ]),
        "SessionId": _generate_session_id(),
        "AccountId": str(uuid.uuid4()),
        "AccountName": account_name,
        "AccountType": account_type,
        "AccountDescription": account_full_name,
        "SystemId": str(uuid.uuid4()),
        "SystemName": system_name,
        "SystemDescription": system_desc,
        "SystemType": system_os,
        "SystemAddress": _generate_ip(),
        "Action": random.choice(ACTIONS),
        "Result": random.choice(["Success", "Failed", "Partial"]),
        "Severity": random.choice(["Low", "Medium", "High", "Critical"]),
        "Category": random.choice(["Access", "Administration", "Audit", "Security"]),
        "RequestId": _generate_request_id(),
        "WorkflowId": str(uuid.uuid4()) if random.random() > 0.5 else None,
        "Duration": random.randint(1, 3600),  # seconds
        "BytesTransferred": random.randint(0, 1000000) if event_type in ["SessionStart", "AssetAccess"] else 0,
        "RecordsAffected": random.randint(1, 100) if "password" in event_type.lower() else 1,
        "PolicyName": random.choice([
            "Standard Access Policy", "Emergency Access Policy", "Privileged Access Policy",
            "Database Access Policy", "Network Device Policy", "Service Account Policy"
        ]),
        "RuleName": random.choice([
            "Require Approval", "Dual Authorization", "Time-based Access", 
            "IP Restriction", "Role-based Access", "Emergency Override"
        ]),
        "ComplianceState": random.choice(["Compliant", "Non-Compliant", "Unknown"]),
        "RiskScore": random.randint(0, 100),
        "Tags": random.sample(["production", "critical", "database", "domain_admin", "service", "backup"], random.randint(1, 3))
    }
    
    # Add event-specific details
    if event_type == "AccountCheckout":
        event.update({
            "CheckoutReason": random.choice(APPROVAL_REASONS),
            "CheckoutDuration": random.randint(30, 480),  # minutes
            "AutoCheckinEnabled": random.choice([True, False]),
            "PasswordRevealed": random.choice([True, False]),
            "ConflictResolution": random.choice(["Queue", "Override", "Deny"])
        })
        
    elif event_type == "AccountCheckin":
        event.update({
            "CheckinType": random.choice(["Manual", "Automatic", "Forced"]),
            "PasswordChanged": random.choice([True, False]),
            "SessionClosed": random.choice([True, False])
        })
        
    elif event_type in ["SessionStart", "SessionEnd"]:
        event.update({
            "SessionType": random.choice(["RDP", "SSH", "Console", "Web", "Database"]),
            "Protocol": random.choice(["RDP", "SSH", "HTTPS", "Telnet", "Console"]),
            "Port": random.choice([22, 3389, 443, 23, 1433, 1521]),
            "ConnectionMethod": random.choice(["Direct", "Jump Server", "Gateway"]),
            "RecordingEnabled": random.choice([True, False]),
            "MonitoringEnabled": random.choice([True, False])
        })
        
    elif event_type == "ApprovalRequest":
        event.update({
            "RequestReason": random.choice(APPROVAL_REASONS),
            "ApproverRequired": random.choice(USERS)[1],  # User ID
            "ApprovalPolicy": random.choice([
                "Single Approver", "Dual Authorization", "Manager Approval", "Security Team Approval"
            ]),
            "RequestExpiration": (event_time + timedelta(hours=random.randint(1, 24))).strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
            "Priority": random.choice(["Low", "Normal", "High", "Emergency"])
        })
        
    elif event_type in ["ApprovalGranted", "ApprovalDenied"]:
        approver_name, approver_id, approver_role = random.choice(USERS)
        event.update({
            "ApproverName": approver_name,
            "ApproverId": approver_id,
            "ApproverRole": approver_role,
            "ApprovalReason": random.choice([
                "Approved - routine maintenance", "Approved - emergency access",
                "Denied - insufficient justification", "Denied - policy violation",
                "Approved - manager authorization", "Denied - security concern"
            ]),
            "ApprovalTime": event_time.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        })
        
    elif event_type == "AccountPasswordChange":
        event.update({
            "PasswordComplexity": random.choice(["High", "Medium", "Low"]),
            "PasswordLength": random.randint(12, 32),
            "PasswordPolicy": random.choice([
                "Corporate Standard", "High Security", "Database Policy", "Service Account Policy"
            ]),
            "RotationType": random.choice(["Scheduled", "Manual", "Emergency", "Policy-driven"]),
            "PreviousPasswordAge": random.randint(1, 90)  # days
        })
        
    elif event_type == "PolicyViolation":
        event.update({
            "ViolationType": random.choice([
                "Unauthorized Access Attempt", "Password Policy Violation", 
                "Session Time Exceeded", "Concurrent Session Limit",
                "IP Address Restriction", "Time-based Access Violation"
            ]),
            "ViolationSeverity": random.choice(["Low", "Medium", "High", "Critical"]),
            "PolicyViolated": random.choice([
                "Access Control Policy", "Password Policy", "Session Policy", "Network Policy"
            ]),
            "AutoRemediation": random.choice([True, False]),
            "NotificationSent": random.choice([True, False])
        })
        
    elif event_type in ["UserLogin", "UserLogout"]:
        event.update({
            "AuthenticationMethod": random.choice([
                "Username/Password", "Multi-Factor Authentication", "Certificate", 
                "Active Directory", "SAML", "OAuth", "API Key"
            ]),
            "AuthenticationResult": random.choice(["Success", "Failed", "Partial"]),
            "FailureReason": random.choice([
                "Invalid Credentials", "Account Locked", "Account Disabled",
                "MFA Failed", "Network Error", "Policy Violation"
            ]) if random.random() > 0.7 else None,
            "LoginAttempts": random.randint(1, 5)
        })
        
    elif event_type == "AdminAction":
        event.update({
            "AdminAction": random.choice([
                "User Creation", "User Deletion", "Policy Modification", 
                "System Configuration", "Account Import", "Report Generation",
                "Backup Configuration", "License Management"
            ]),
            "TargetObject": random.choice([
                "User Account", "System Account", "Policy", "Configuration",
                "Asset", "Group", "Role", "Permission"
            ]),
            "ConfigurationChange": random.choice([True, False]),
            "BackupCreated": random.choice([True, False])
        })
    
    # Add audit trail information
    event.update({
        "AuditTrail": {
            "CreatedBy": user_id,
            "CreatedTime": event_time.strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
            "ModifiedBy": user_id,
            "ModifiedTime": event_time.strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
            "Version": "1.0",
            "Hash": f"sha256:{uuid.uuid4().hex + uuid.uuid4().hex}"
        },
        "Metadata": {
            "TenantId": str(uuid.uuid4()),
            "OrganizationId": str(uuid.uuid4()),
            "ProductVersion": "21.2.5",
            "ApiVersion": "v1.0",
            "CorrelationId": str(uuid.uuid4()),
            "TraceId": str(uuid.uuid4())
        }
    })
    
    # Apply any overrides
    if overrides:
        event.update(overrides)
    
    # Format as syslog + JSON (timestamp IP JSON)
    # Parser expects: $access_activity.time$ $access_activity.syslog_ip$ ${parse=dottedJson}$
    timestamp = event_time.strftime("%Y-%m-%d %H:%M:%S")
    syslog_ip = "10.0.0.150"  # BeyondTrust appliance IP
    
    return f"{timestamp} {syslog_ip} {json.dumps(event, separators=(',', ':'))}"

if __name__ == "__main__":
    # Generate sample logs
    print("Sample BeyondTrust Password Safe events:")
    for event_type in ["AccountCheckout", "SessionStart", "ApprovalRequest", "PolicyViolation"]:
        print(f"\n{event_type} event:")
        print(beyondtrust_passwordsafe_log({"EventType": event_type}))
        print()