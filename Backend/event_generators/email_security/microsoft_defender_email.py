#!/usr/bin/env python3
"""
Microsoft Defender for Email logs generator (JSON format)
"""
from __future__ import annotations
import json
import random
import time
import uuid
from datetime import datetime, timezone, timedelta
from typing import Dict, List

# Threat types and verdicts
THREAT_TYPES = ["Phish", "Malware", "Spam", "Bulk", "None"]
DETECTION_METHODS = ["ATP Safe Attachments", "ATP Safe Links", "Anti-phishing", "Anti-malware", "Anti-spam", "User reported"]

# Email actions
EMAIL_ACTIONS = ["Allow", "Block", "Quarantine", "Replace", "Redirect", "Delete", "MoveToJmf"]
DELIVERY_ACTIONS = ["Delivered", "Blocked", "Replaced", "Quarantined"]

# Malware families
MALWARE_FAMILIES = ["Emotet", "TrickBot", "Dridex", "IcedID", "Qakbot", "BazarLoader", "Agent Tesla", "FormBook"]

# Phishing techniques
PHISHING_TECHNIQUES = [
    "Brand impersonation", "CEO fraud", "Credential harvesting", "Display name spoofing",
    "Domain impersonation", "Mailbox intelligence", "Mixed analysis", "Spoof intelligence"
]

# File types and names
FILE_TYPES = [".pdf", ".docx", ".xlsx", ".zip", ".exe", ".js", ".html", ".txt", ".jpg"]
MALICIOUS_FILE_TYPES = [".exe", ".scr", ".bat", ".js", ".vbs", ".wsf", ".jar"]

# Email subjects
PHISHING_SUBJECTS = [
    "Urgent: Account verification required",
    "Security alert from IT department", 
    "Your account will be suspended",
    "Invoice payment overdue",
    "DocuSign document ready",
    "CEO: Quick question"
]

MALWARE_SUBJECTS = [
    "Invoice attached",
    "Delivery notification",
    "Scan from printer",
    "Voice message",
    "Payment receipt"
]

# Users and domains
USERS = ["john.doe", "jane.smith", "bob.jones", "alice.williams", "admin", "support"]
INTERNAL_DOMAINS = ["company.com", "corp.com", "enterprise.local"]
EXTERNAL_DOMAINS = ["gmail.com", "outlook.com", "suspicious-domain.com", "phishing-site.net"]

def _generate_ip(internal=False):
    """Generate IP address"""
    if internal:
        return f"10.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"
    else:
        return f"{random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"

def _generate_email_address(internal=True, suspicious=False):
    """Generate email address"""
    user = random.choice(USERS)
    if suspicious:
        domain = random.choice([d for d in EXTERNAL_DOMAINS if "suspicious" in d or "phishing" in d])
    elif internal:
        domain = random.choice(INTERNAL_DOMAINS)
    else:
        domain = random.choice(EXTERNAL_DOMAINS)
    return f"{user}@{domain}"

def microsoft_defender_email_log(overrides: dict | None = None) -> Dict:
    """
    Return a single Microsoft Defender for Email event as JSON string.
    
    Pass `overrides` to force any field to a specific value:
        microsoft_defender_email_log({"ThreatTypes": "Phish"})
    """
    now = datetime.now(timezone.utc)
    timestamp = now - timedelta(seconds=random.randint(0, 300))
    
    # Determine threat type and associated details
    threat_type = random.choice(THREAT_TYPES)
    is_malicious = threat_type != "None"
    
    # Generate email addresses
    sender_email = _generate_email_address(internal=False, suspicious=is_malicious)
    recipient_email = _generate_email_address(internal=True)
    
    # Generate subject based on threat type
    if threat_type == "Phish":
        subject = random.choice(PHISHING_SUBJECTS)
    elif threat_type == "Malware":
        subject = random.choice(MALWARE_SUBJECTS)
    else:
        subject = f"Regular email - {random.choice(['Meeting', 'Report', 'Update', 'Newsletter'])}"
    
    # Base record structure
    record = {
        "time": now.strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
        "resourceId": f"/subscriptions/{uuid.uuid4()}/resourcegroups/rg-security/providers/microsoft.operationalinsights/workspaces/security-workspace",
        "operationName": "EmailEvents",
        "operationVersion": "1.0",
        "category": "EmailEvents",
        "tenantId": str(uuid.uuid4()),
        "resultType": "Success",
        "resultSignature": "EmailProcessed",
        "callerIpAddress": _generate_ip(internal=False),
        "correlationId": str(uuid.uuid4()),
        "identity": "System",
        "Level": 4,
        "location": "Global",
        "Tenant": "company.onmicrosoft.com",
        "properties": {
            "ReportId": str(uuid.uuid4()),
            "NetworkMessageId": f"<{uuid.uuid4()}@{sender_email.split('@')[1]}>",
            "InternetMessageId": f"<{uuid.uuid4()}@mail.protection.outlook.com>",
            "Timestamp": timestamp.strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
            "EmailClusterId": str(uuid.uuid4()),
            "SenderIPv4": _generate_ip(internal=False),
            "SenderIPv6": None,
            "SenderMailFromAddress": sender_email,
            "SenderFromAddress": sender_email,
            "SenderDisplayName": sender_email.split('@')[0].replace('.', ' ').title(),
            "SenderObjectId": str(uuid.uuid4()) if random.random() > 0.5 else None,
            "SenderMailFromDomain": sender_email.split('@')[1],
            "SenderFromDomain": sender_email.split('@')[1],
            "Subject": subject,
            "EmailDirection": random.choice(["Inbound", "Outbound", "Intra-org"]),
            "DeliveryAction": random.choice(DELIVERY_ACTIONS),
            "DeliveryLocation": random.choice(["Inbox", "JunkEmailFolder", "DeletedItems", "Quarantine", "External", "Failed", "Dropped", "Forwarded"]),
            "RecipientEmailAddress": recipient_email,
            "RecipientObjectId": str(uuid.uuid4()),
            "AuthenticationDetails": json.dumps({
                "SPF": random.choice(["Pass", "Fail", "SoftFail", "Neutral", "None"]),
                "DKIM": random.choice(["Pass", "Fail", "None"]),
                "DMARC": random.choice(["Pass", "Fail", "None"]),
                "CompAuth": random.choice(["Pass", "Fail", "SoftPass", "None"])
            }),
            "ConnectorIndex": random.randint(0, 10),
            "EmailActionPolicy": random.choice(["Standard preset security policy", "Strict preset security policy", "Custom policy"]),
            "EmailActionPolicyGuid": str(uuid.uuid4()),
            "EmailLanguage": random.choice(["en", "es", "fr", "de", "zh", "ja"]),
            "ThreatTypes": threat_type,
            "DetectionMethods": random.choice(DETECTION_METHODS) if is_malicious else None,
            "ActionType": random.choice(EMAIL_ACTIONS) if is_malicious else "Allow",
            "ActionTrigger": random.choice(["User", "Admin", "Automated"]) if is_malicious else None,
            "ActionResult": "Success",
            "PolicyAction": random.choice(["Allow", "Block", "Quarantine"]),
            "UserLevelAction": random.choice(["Allow", "Block", "MoveToJmf"]) if random.random() > 0.7 else None,
            "UserLevelPolicy": random.choice(["Standard", "Strict", "Custom"]) if random.random() > 0.7 else None,
            "BulkComplaintLevel": str(random.randint(0, 9)) if threat_type == "Bulk" else None,
            "ConfidenceLevel": random.choice(["Low", "Normal", "High"]),
            "EmailSize": random.randint(1024, 5000000),  # 1KB to 5MB
            "AttachmentCount": random.randint(0, 5),
            "UrlCount": random.randint(0, 10),
            "SizeInBytes": random.randint(1024, 5000000),
            "Directionality": random.choice(["Inbound", "Outbound", "Intra-org"]),
            "ThreatsAndDetectionTech": threat_type if is_malicious else None,
            "AdditionalFields": json.dumps({
                "CustomDomain": random.choice([True, False]),
                "IsReadReceiptRequested": random.choice([True, False]),
                "HasAttachments": random.choice([True, False]),
                "MessageTraceId": str(uuid.uuid4())
            })
        }
    }
    
    # Add threat-specific details
    if threat_type == "Malware":
        record["properties"]["MalwareFamily"] = random.choice(MALWARE_FAMILIES)
        record["properties"]["MalwareFilterVerdict"] = "Malware"
        record["properties"]["FileName"] = f"document_{random.randint(1000, 9999)}{random.choice(MALICIOUS_FILE_TYPES)}"
        record["properties"]["FileType"] = random.choice(MALICIOUS_FILE_TYPES)[1:]
        record["properties"]["SHA256"] = uuid.uuid4().hex + uuid.uuid4().hex
        record["properties"]["ThreatNames"] = [random.choice(MALWARE_FAMILIES)]
        
    elif threat_type == "Phish":
        record["properties"]["PhishFilterVerdict"] = "Phish"
        record["properties"]["PhishConfidenceLevel"] = random.choice(["Low", "Normal", "High"])
        record["properties"]["PhishDetectionMethod"] = random.choice(PHISHING_TECHNIQUES)
        record["properties"]["UrlsInfo"] = json.dumps([{
            "Url": f"https://phishing-site-{random.randint(1, 100)}.com/login",
            "UrlVerdict": "Malicious",
            "UrlDomain": f"phishing-site-{random.randint(1, 100)}.com"
        }])
        
    elif threat_type == "Spam":
        record["properties"]["SpamFilterVerdict"] = "Spam"
        record["properties"]["SpamConfidenceLevel"] = random.choice(["Low", "Normal", "High"])
        record["properties"]["BulkComplaintLevel"] = str(random.randint(5, 9))
        
    # Add organizational details
    record["properties"]["OrgLevelAction"] = random.choice(["Allow", "Block", "Quarantine"])
    record["properties"]["OrgLevelPolicy"] = random.choice(["Default", "AntiPhishing", "AntiMalware", "AntiSpam"])
    record["properties"]["SystemOverrides"] = json.dumps([]) if random.random() > 0.8 else None
    record["properties"]["UserOverrides"] = json.dumps([]) if random.random() > 0.9 else None
    
    # Add latest delivery details
    record["properties"]["LatestDeliveryAction"] = record["properties"]["DeliveryAction"]
    record["properties"]["LatestDeliveryLocation"] = record["properties"]["DeliveryLocation"]
    
    # Wrap in EventHub format
    event = {
        "records": [record]
    }
    
    # Apply any overrides
    if overrides:
        record["properties"].update(overrides)
    
    return event

if __name__ == "__main__":
    # Generate sample logs
    print("Sample Microsoft Defender for Email events:")
    for threat in ["Phish", "Malware", "Spam", "None"]:
        print(f"\n{threat} event:")
        print(microsoft_defender_email_log({"ThreatTypes": threat}))
        print()