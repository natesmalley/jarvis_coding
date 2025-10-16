#!/usr/bin/env python3
"""
Mimecast email security event generator (JSON format)
"""
from __future__ import annotations
import json
import random
import time
import uuid
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional

# Mimecast log types
LOG_TYPES = {
    "audit": "Audit",
    "dlp": "DLP Logs", 
    "ttp_attachment": "TTP Attachment Protection",
    "ttp_url": "TTP URL",
    "siem": "SIEM",
    "ttp_impersonation": "TTP Impersonation Protection"
}

# Audit log categories and types
AUDIT_CATEGORIES = [
    "Administration Logs", "Authentication Logs", "Email Security Logs",
    "Archive Logs", "Data Retention Logs", "Policy Logs", "Gateway Logs"
]

AUDIT_TYPES = [
    "logon", "logoff", "failed logon", "policy change", "user creation",
    "user deletion", "configuration change", "password change", "rule creation",
    "rule deletion", "admin action", "bulk operation", "api access"
]

# DLP policies and actions
DLP_POLICIES = [
    "Credit Card Protection", "SSN Protection", "Financial Data Protection", 
    "Healthcare Data Protection", "Personal Information Protection",
    "Source Code Protection", "Customer Data Protection", "Employee Data Protection"
]

DLP_ACTIONS = ["block", "hold", "quarantine", "warn", "notify", "allow"]

# TTP (Targeted Threat Protection) results and actions
TTP_RESULTS = ["clean", "malicious", "suspicious", "timeout", "error", "skipped"]
TTP_ACTIONS = ["block", "allow", "quarantine", "warn", "strip", "replace"]

# File types and names
MALICIOUS_FILE_TYPES = [".exe", ".scr", ".bat", ".cmd", ".com", ".pif", ".vbs", ".js"]
SUSPICIOUS_FILE_TYPES = [".zip", ".rar", ".7z", ".doc", ".docx", ".xls", ".xlsx", ".pdf"]
SAFE_FILE_TYPES = [".txt", ".jpg", ".png", ".gif", ".pdf", ".docx", ".xlsx"]

FILE_NAMES = [
    "invoice", "receipt", "document", "report", "presentation", "image", 
    "backup", "update", "installer", "patch", "scan", "fax"
]

MALWARE_NAMES = [
    "Emotet", "TrickBot", "Dridex", "IcedID", "Qakbot", "BazarLoader",
    "Agent Tesla", "FormBook", "Lokibot", "NetWire", "AsyncRAT", "RedLine"
]

# Email domains and users
INTERNAL_DOMAINS = ["company.com", "corp.com", "enterprise.com", "business.com"]
EXTERNAL_DOMAINS = [
    "gmail.com", "outlook.com", "yahoo.com", "hotmail.com", "protonmail.com",
    "suspicious-domain.com", "phishing-site.net", "malware-host.org"
]

USERS = [
    "jean.picard", "william.riker", "data.android", "geordi.laforge", "worf.security", 
    "deanna.troi", "beverly.crusher", "wesley.crusher", "tasha.yar", "guinan.bartender",
    "james.kirk", "spock.science", "leonard.mccoy", "montgomery.scott", "nyota.uhura",
    "pavel.chekov", "hikaru.sulu", "benjamin.sisko", "kira.nerys", "julian.bashir",
    "jadzia.dax", "miles.obrien", "odo.security", "kathryn.janeway", "chakotay.commander",
    "tuvok.security", "tom.paris", "belanna.torres", "harry.kim", "seven.of.nine", "admin"
]

# Subject lines by category
SUBJECT_TEMPLATES = {
    "phishing": [
        "Urgent: Account verification required",
        "Security alert - immediate action needed", 
        "Your account has been suspended",
        "RE: Invoice payment overdue",
        "DocuSign: Document ready for signature",
        "CEO: Quick question"
    ],
    "malware": [
        "Invoice #{}.pdf",
        "Delivery notification",
        "Scan from printer",
        "Fax received",
        "Voice message attached"
    ],
    "legitimate": [
        "Meeting tomorrow",
        "Q3 Financial Report",
        "Project update",
        "Weekly newsletter",
        "Your receipt"
    ]
}

# Routes and directions
ROUTES = ["inbound", "outbound", "internal", "external"]
DIRECTIONS = ["Inbound", "Outbound", "Internal"]

def _generate_email_address(internal=True, suspicious=False):
    """Generate an email address"""
    user = random.choice(USERS)
    if suspicious:
        domain = random.choice([d for d in EXTERNAL_DOMAINS if "suspicious" in d or "phishing" in d or "malware" in d])
    elif internal:
        domain = random.choice(INTERNAL_DOMAINS)
    else:
        domain = random.choice(EXTERNAL_DOMAINS)
    return f"{user}@{domain}"

def _generate_message_id():
    """Generate a message ID"""
    domain = random.choice(INTERNAL_DOMAINS + EXTERNAL_DOMAINS)
    return f"<{uuid.uuid4()}@{domain}>"

def _generate_file_info(malicious=False):
    """Generate file information"""
    if malicious:
        file_type = random.choice(MALICIOUS_FILE_TYPES + SUSPICIOUS_FILE_TYPES)
    else:
        file_type = random.choice(SAFE_FILE_TYPES)
    
    file_name = random.choice(FILE_NAMES)
    return {
        "fileName": f"{file_name}_{random.randint(1000, 9999)}{file_type}",
        "fileType": file_type[1:],  # Remove the dot
        "fileSize": random.randint(1024, 50000000)  # 1KB to 50MB
    }

def mimecast_log(overrides: dict | None = None) -> Dict:
    """
    Return a single Mimecast event as JSON string.
    
    Pass `overrides` to force any field to a specific value:
        mimecast_log({"logType": "dlp"})
    """
    # Select log type
    log_type = random.choice(list(LOG_TYPES.keys()))
    
    if log_type == "audit":
        return _generate_audit_log(overrides)
    elif log_type == "dlp":
        return _generate_dlp_log(overrides)
    elif log_type == "ttp_attachment":
        return _generate_ttp_attachment_log(overrides)
    elif log_type == "ttp_url":
        return _generate_ttp_url_log(overrides)
    elif log_type == "ttp_impersonation":
        return _generate_ttp_impersonation_log(overrides)
    else:  # siem
        return _generate_siem_log(overrides)

def _generate_audit_log(overrides: dict | None = None) -> str:
    """Generate Mimecast audit log"""
    now = datetime.now(timezone.utc)
    
    event = {
        "identifier": LOG_TYPES["audit"],
        "mimecastEvent": {
            "eventTime": now.strftime("%Y-%m-%dT%H:%M:%S%z"),
            "auditType": random.choice(AUDIT_TYPES),
            "category": random.choice(AUDIT_CATEGORIES),
            "eventInfo": f"User {random.choice(USERS)} performed {random.choice(AUDIT_TYPES)} action",
            "id": str(uuid.uuid4()),
            "user": _generate_email_address(internal=True),
            "source": random.choice(["Web UI", "API", "Mobile App", "Outlook Plugin"]),
            "sourceIp": f"10.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}",
            "userAgent": random.choice([
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                "Mimecast Mobile App 3.2.1",
                "Mimecast API Client 1.0"
            ]),
            "ingestType": "audit"
        }
    }
    
    if overrides:
        event["mimecastEvent"].update(overrides)
    
    return event

def _generate_dlp_log(overrides: dict | None = None) -> str:
    """Generate Mimecast DLP log"""
    now = datetime.now(timezone.utc)
    policy = random.choice(DLP_POLICIES)
    action = random.choice(DLP_ACTIONS)
    
    # Generate subject based on policy type
    if "Credit Card" in policy or "Financial" in policy:
        subject = f"Invoice #{random.randint(10000, 99999)}"
    elif "Healthcare" in policy:
        subject = "Patient records update"
    else:
        subject = random.choice(SUBJECT_TEMPLATES["legitimate"])
    
    event = {
        "identifier": LOG_TYPES["dlp"],
        "mimecastEvent": {
            "eventTime": now.strftime("%Y-%m-%dT%H:%M:%S%z"),
            "senderAddress": _generate_email_address(internal=random.choice([True, False])),
            "recipientAddress": _generate_email_address(internal=True),
            "subject": subject,
            "messageId": _generate_message_id(),
            "policy": policy,
            "action": action,
            "route": random.choice(ROUTES),
            "direction": random.choice(DIRECTIONS),
            "triggerType": random.choice(["content", "attachment", "header"]),
            "definition": f"DLP rule triggered: {policy}",
            "hits": random.randint(1, 10),
            "ingestType": "dlp"
        }
    }
    
    # Add file info if attachment triggered
    if event["mimecastEvent"]["triggerType"] == "attachment":
        file_info = _generate_file_info()
        event["mimecastEvent"].update(file_info)
    
    if overrides:
        event["mimecastEvent"].update(overrides)
    
    return event

def _generate_ttp_attachment_log(overrides: dict | None = None) -> str:
    """Generate Mimecast TTP Attachment Protection log"""
    now = datetime.now(timezone.utc)
    result = random.choice(TTP_RESULTS)
    action = random.choice(TTP_ACTIONS)
    
    # Generate malicious content based on result
    is_malicious = result in ["malicious", "suspicious"]
    file_info = _generate_file_info(malicious=is_malicious)
    
    event = {
        "identifier": LOG_TYPES["ttp_attachment"],
        "mimecastEvent": {
            "date": now.strftime("%Y-%m-%dT%H:%M:%S%z"),
            "senderAddress": _generate_email_address(internal=False, suspicious=is_malicious),
            "recipientAddress": _generate_email_address(internal=True),
            "subject": random.choice(SUBJECT_TEMPLATES["malware" if is_malicious else "legitimate"]),
            "messageId": _generate_message_id(),
            "result": result,
            "actionTriggered": action,
            "route": random.choice(ROUTES),
            "direction": random.choice(DIRECTIONS),
            "details": f"File attachment scanned with result: {result}",
            "ingestType": "ttp_attachment",
            **file_info
        }
    }
    
    # Add threat details for malicious files
    if is_malicious:
        event["mimecastEvent"].update({
            "threatName": random.choice(MALWARE_NAMES),
            "sandboxResult": random.choice(["malicious", "suspicious", "timeout"]),
            "confidence": random.randint(70, 100),
            "category": random.choice(["Trojan", "Backdoor", "Worm", "Ransomware"])
        })
    
    if overrides:
        event["mimecastEvent"].update(overrides)
    
    return event

def _generate_ttp_url_log(overrides: dict | None = None) -> str:
    """Generate Mimecast TTP URL Protection log"""
    now = datetime.now(timezone.utc)
    result = random.choice(TTP_RESULTS)
    action = random.choice(TTP_ACTIONS)
    
    is_malicious = result in ["malicious", "suspicious"]
    
    # Generate URL based on threat level
    if is_malicious:
        domain = random.choice(["suspicious-site.com", "phishing-domain.net", "malware-host.org"])
        url = f"https://{domain}/click?id={uuid.uuid4()}"
    else:
        domain = random.choice(["microsoft.com", "google.com", "github.com", "stackoverflow.com"])
        url = f"https://{domain}/path/to/resource"
    
    event = {
        "identifier": LOG_TYPES["ttp_url"],
        "mimecastEvent": {
            "date": now.strftime("%Y-%m-%dT%H:%M:%S%z"),
            "senderAddress": _generate_email_address(internal=False, suspicious=is_malicious),
            "recipientAddress": _generate_email_address(internal=True),
            "subject": random.choice(SUBJECT_TEMPLATES["phishing" if is_malicious else "legitimate"]),
            "messageId": _generate_message_id(),
            "url": url,
            "result": result,
            "actionTriggered": action,
            "route": random.choice(ROUTES),
            "direction": random.choice(DIRECTIONS),
            "userAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "details": f"URL clicked with result: {result}",
            "ingestType": "ttp_url"
        }
    }
    
    # Add threat details for malicious URLs
    if is_malicious:
        event["mimecastEvent"].update({
            "category": random.choice(["Phishing", "Malware", "Spam", "Suspicious"]),
            "reputation": random.choice(["Poor", "Suspicious", "Unknown"]),
            "confidence": random.randint(60, 100),
            "clickTime": (now + timedelta(minutes=random.randint(1, 60))).strftime("%Y-%m-%dT%H:%M:%S%z")
        })
    
    if overrides:
        event["mimecastEvent"].update(overrides)
    
    return event

def _generate_ttp_impersonation_log(overrides: dict | None = None) -> str:
    """Generate Mimecast TTP Impersonation Protection log"""
    now = datetime.now(timezone.utc)
    
    # Impersonation types
    impersonation_types = ["Display Name", "Similar Domain", "Newly Observed Domain", "Internal Name"]
    impersonation_type = random.choice(impersonation_types)
    
    # Generate spoofed sender based on type
    if impersonation_type == "Display Name":
        sender = f"CEO <ceo@fake-{random.choice(INTERNAL_DOMAINS)}>"
        target = "CEO"
    elif impersonation_type == "Similar Domain":
        # Create typosquatted domain
        real_domain = random.choice(INTERNAL_DOMAINS)
        fake_domain = real_domain.replace("o", "0").replace("e", "3")
        sender = f"{random.choice(USERS)}@{fake_domain}"
        target = real_domain
    else:
        sender = _generate_email_address(internal=False, suspicious=True)
        target = random.choice(USERS)
    
    event = {
        "identifier": LOG_TYPES["ttp_impersonation"],
        "mimecastEvent": {
            "date": now.strftime("%Y-%m-%dT%H:%M:%S%z"),
            "senderAddress": sender,
            "recipientAddress": _generate_email_address(internal=True),
            "subject": random.choice(SUBJECT_TEMPLATES["phishing"]),
            "messageId": _generate_message_id(),
            "impersonationType": impersonation_type,
            "targetedUser": target,
            "actionTriggered": random.choice(["block", "quarantine", "warn", "tag"]),
            "route": "inbound",
            "direction": "Inbound",
            "confidence": random.randint(75, 100),
            "details": f"Impersonation attempt detected: {impersonation_type}",
            "ingestType": "ttp_impersonation"
        }
    }
    
    if overrides:
        event["mimecastEvent"].update(overrides)
    
    return event

def _generate_siem_log(overrides: dict | None = None) -> str:
    """Generate Mimecast SIEM log"""
    now = datetime.now(timezone.utc)
    
    # SIEM events are typically security-focused aggregations
    event_types = ["Email Security Alert", "Policy Violation", "Threat Detection", "User Activity"]
    event_type = random.choice(event_types)
    
    event = {
        "identifier": LOG_TYPES["siem"],
        "mimecastEvent": {
            "eventTime": now.strftime("%Y-%m-%dT%H:%M:%S%z"),
            "eventType": event_type,
            "severity": random.choice(["Low", "Medium", "High", "Critical"]),
            "source": "Mimecast Email Security",
            "description": f"SIEM alert: {event_type} detected",
            "affectedUsers": random.randint(1, 10),
            "emailsProcessed": random.randint(1, 1000),
            "threatsBlocked": random.randint(0, 50),
            "policies": random.sample(DLP_POLICIES, random.randint(1, 3)),
            "timeWindow": "1 hour",
            "ingestType": "siem"
        }
    }
    
    if overrides:
        event["mimecastEvent"].update(overrides)
    
    return event

if __name__ == "__main__":
    # Generate sample logs for different types
    print("Sample Mimecast events:")
    log_types = ["audit", "dlp", "ttp_attachment", "ttp_url", "ttp_impersonation", "siem"]
    
    for log_type in log_types:
        print(f"\n{log_type.upper()} event:")
        if log_type == "audit":
            print(_generate_audit_log())
        elif log_type == "dlp":
            print(_generate_dlp_log())
        elif log_type == "ttp_attachment":
            print(_generate_ttp_attachment_log())
        elif log_type == "ttp_url":
            print(_generate_ttp_url_log())
        elif log_type == "ttp_impersonation":
            print(_generate_ttp_impersonation_log())
        else:
            print(_generate_siem_log())
        print()