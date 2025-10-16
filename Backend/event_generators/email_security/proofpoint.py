#!/usr/bin/env python3
"""
Proofpoint email security event generator (JSON format)
"""
from __future__ import annotations
import json
import random
import time
import uuid
import base64
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional

# Email domains
SAFE_DOMAINS = ["starfleet.corp", "gmail.com", "outlook.com", "yahoo.com", "federation.gov", "enterprise.starfleet"]
SUSPICIOUS_DOMAINS = [
    "phishing-site-{}.com", "malware-host-{}.net", "suspicious-domain-{}.org",
    "fake-company-{}.com", "phish-{}.net", "malicious-{}.io",
    "scam-site-{}.com", "fraud-{}.net", "imposter-{}.org"
]

# Common names and email prefixes - Star Trek characters
FIRST_NAMES = ["Jean", "Jordy", "Haxorsaurus", "Worf", "Data", "Deanna", "Beverly", "Wesley", "James", "Spock"]
LAST_NAMES = ["Picard", "LaForge", "", "Security", "Android", "Troi", "Crusher", "Crusher", "Kirk", "Science"]
EMAIL_PREFIXES = ["info", "support", "admin", "contact", "sales", "help", "service", "noreply", "billing", "security"]

# Subject line templates
SUBJECT_TEMPLATES = {
    "phishing": [
        "Urgent: Verify your account",
        "Security Alert: Immediate action required",
        "Your account has been suspended",
        "Re: Invoice #{} is overdue",
        "Important: Update your payment information",
        "CEO: Quick question",
        "Wire transfer confirmation needed",
        "DocuSign: Please review and sign",
    ],
    "malware": [
        "Invoice #{}.pdf",
        "Delivery notification",
        "Your order has shipped",
        "Resume - {}.doc",
        "Scan from printer",
        "Fax received",
        "Voice message attached",
        "Photos from last night",
    ],
    "spam": [
        "You've won!",
        "Limited time offer",
        "Hot singles in your area",
        "Miracle weight loss solution",
        "Make money from home",
        "Congratulations!",
        "Free gift card",
        "Click here for amazing deals",
    ],
    "legitimate": [
        "Meeting tomorrow at 2pm",
        "Q3 Financial Report",
        "Project update",
        "Team lunch Friday",
        "Re: Contract review",
        "Monthly newsletter",
        "Your receipt from Amazon",
        "GitHub: New pull request",
    ]
}

# Threat types
THREAT_TYPES = ["phish", "malware", "spam", "impostor", "none"]
THREAT_NAMES = {
    "phish": ["Credential Phishing", "Spear Phishing", "Business Email Compromise", "Account Takeover"],
    "malware": ["Emotet", "TrickBot", "Dridex", "AgentTesla", "FormBook", "Lokibot", "Ursnif", "IcedID"],
    "spam": ["Generic Spam", "Pharmacy Spam", "Dating Spam", "Lottery Scam"],
    "impostor": ["CEO Fraud", "Vendor Impersonation", "Employee Impersonation", "Brand Impersonation"]
}

# Policy actions
POLICY_ACTIONS = ["deliver", "quarantine", "block", "continue", "discard"]
MODULES_RUN = ["av", "spam", "dkimv", "spf", "dmarc", "urldefense", "attachment_defense", "impostor"]

def _generate_email_address(malicious=False):
    """Generate an email address"""
    if malicious and random.random() > 0.3:
        # Suspicious email
        domain = random.choice(SUSPICIOUS_DOMAINS).format(random.randint(1, 100))
        if random.random() > 0.5:
            # Typosquatting
            name = random.choice(FIRST_NAMES).lower() + "." + random.choice(LAST_NAMES).lower()
            name = name.replace("o", "0").replace("i", "1") if random.random() > 0.5 else name
        else:
            name = random.choice(EMAIL_PREFIXES) + str(random.randint(1, 999))
    else:
        # Normal email
        domain = random.choice(SAFE_DOMAINS)
        if random.random() > 0.5:
            name = random.choice(FIRST_NAMES).lower() + "." + random.choice(LAST_NAMES).lower()
        else:
            name = random.choice(EMAIL_PREFIXES)
    
    return f"{name}@{domain}"

def _generate_ip():
    """Generate an IP address"""
    if random.random() > 0.7:
        # Internal IP
        return f"10.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"
    else:
        # External IP
        return f"{random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"

def _generate_message_parts(threat_type):
    """Generate message parts based on threat type"""
    parts = []
    
    if threat_type in ["phish", "malware"]:
        # Add malicious content
        if random.random() > 0.5:
            # Malicious attachment
            parts.append({
                "disposition": "attached",
                "sha256": uuid.uuid4().hex + uuid.uuid4().hex,
                "md5": uuid.uuid4().hex,
                "filename": random.choice([
                    "invoice.pdf.exe", "document.doc", "scan.pdf", 
                    "payment_details.xlsx", "urgent.docm", "report.zip"
                ]),
                "contentType": "application/octet-stream",
                "sandboxStatus": "threat"
            })
        
        if random.random() > 0.3:
            # Malicious URL
            parts.append({
                "disposition": "inline",
                "contentType": "text/html",
                "oContentType": "text/html",
                "isUnsupported": False,
                "urls": [
                    {
                        "url": f"http://{random.choice(SUSPICIOUS_DOMAINS).format(random.randint(1, 100))}/click?id={uuid.uuid4()}",
                        "isRewritten": True,
                        "threatStatus": "malicious"
                    }
                ]
            })
    else:
        # Normal content
        parts.append({
            "disposition": "inline",
            "contentType": "text/plain",
            "oContentType": "text/plain",
            "isUnsupported": False
        })
    
    return parts

def _calculate_scores(threat_type):
    """Calculate threat scores based on threat type"""
    scores = {
        "spamScore": 0,
        "phishScore": 0,
        "malwareScore": 0,
        "impostorScore": 0
    }
    
    if threat_type == "phish":
        scores["phishScore"] = random.randint(75, 100)
        scores["spamScore"] = random.randint(30, 70)
    elif threat_type == "malware":
        scores["malwareScore"] = random.randint(80, 100)
        scores["spamScore"] = random.randint(40, 80)
    elif threat_type == "spam":
        scores["spamScore"] = random.randint(85, 100)
    elif threat_type == "impostor":
        scores["impostorScore"] = random.randint(70, 100)
        scores["phishScore"] = random.randint(50, 80)
    else:  # legitimate
        scores["spamScore"] = random.randint(0, 30)
        scores["phishScore"] = random.randint(0, 20)
        scores["malwareScore"] = 0
        scores["impostorScore"] = random.randint(0, 10)
    
    return scores

def proofpoint_log(overrides: dict | None = None) -> Dict:
    """
    Return a single Proofpoint email security event as JSON string.
    
    Pass `overrides` to force any field to a specific value:
        proofpoint_log({"phishScore": 95})
    """
    # Determine threat type
    threat_type = random.choice(THREAT_TYPES)
    is_malicious = threat_type != "none"
    
    # Generate sender and recipient
    sender_email = _generate_email_address(malicious=is_malicious)
    sender_name = f"{random.choice(FIRST_NAMES)} {random.choice(LAST_NAMES)}"
    recipient_email = _generate_email_address(malicious=False)
    
    # Generate timestamps
    now = datetime.now(timezone.utc)
    message_time = now - timedelta(seconds=random.randint(0, 300))
    
    # Calculate scores
    scores = _calculate_scores(threat_type)
    
    # Determine policy action based on scores
    max_score = max(scores.values())
    if max_score >= 80:
        policy_action = random.choice(["quarantine", "block"])
    elif max_score >= 50:
        policy_action = random.choice(["quarantine", "deliver"])
    else:
        policy_action = "deliver"
    
    # Select subject based on threat type
    subject_mapping = {
        "phish": "phishing",
        "malware": "malware", 
        "spam": "spam",
        "impostor": "phishing",  # Impostor attacks often use phishing-style subjects
        "none": "legitimate"
    }
    subject_category = subject_mapping.get(threat_type, "legitimate")
    subject_template = random.choice(SUBJECT_TEMPLATES[subject_category])
    subject = subject_template.format(random.randint(10000, 99999), random.choice(FIRST_NAMES))
    
    # Build event
    event = {
        "GUID": str(uuid.uuid4()),
        "QID": f"Q{random.randint(100000, 999999)}",
        "id": str(uuid.uuid4()),
        "messageID": f"<{uuid.uuid4()}@{sender_email.split('@')[1]}>",
        "messageTime": message_time.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z",
        "messageSize": random.randint(1024, 1048576),  # 1KB to 1MB
        "subject": subject,
        "sender": sender_email,
        "fromAddress": [sender_email],
        "headerFrom": f'"{sender_name}" <{sender_email}>',
        "senderIP": _generate_ip(),
        "recipient": [recipient_email],
        "toAddresses": [recipient_email],
        "ccAddresses": [],
        "replyToAddress": [sender_email],
        "headerReplyTo": sender_email,
        "completelyRewritten": random.choice(["true", "false"]),
        "cluster": f"proofpoint-cluster-{random.randint(1, 10)}",
        "policyRoutes": [policy_action],
        "modulesRun": random.sample(MODULES_RUN, random.randint(3, len(MODULES_RUN))),
        **scores
    }
    
    # Add threat info if malicious
    if is_malicious:
        threat_info = {
            "threat": random.choice(THREAT_NAMES.get(threat_type, ["Unknown"])),
            "threatType": threat_type,
            "threatID": str(uuid.uuid4()),
            "threatStatus": "active",
            "classification": threat_type,
            "threatTime": message_time.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
        }
        
        event["threatsInfo"] = [threat_info]
        
        # Add quarantine info if quarantined
        if policy_action == "quarantine":
            event["quarantineFolder"] = "Quarantine"
            event["quarantineRule"] = f"Rule_{threat_type}_quarantine"
    
    # Add message parts
    event["messageParts"] = _generate_message_parts(threat_type)
    
    # Add SPF, DKIM, DMARC results
    event["spf"] = random.choice(["pass", "fail", "softfail", "neutral", "none"])
    event["dkimv"] = random.choice(["pass", "fail", "none"])
    event["dmarc"] = random.choice(["pass", "fail", "none"])
    
    # Add additional metadata
    event["xmailer"] = random.choice([
        "Microsoft Outlook 16.0", "Thunderbird", "Apple Mail", 
        "Gmail Web", "Unknown", "PHPMailer 6.5", "SwiftMailer"
    ])
    
    if is_malicious and random.random() > 0.5:
        event["campaignId"] = f"campaign_{uuid.uuid4().hex[:8]}"
    
    # Apply any overrides
    if overrides:
        event.update(overrides)
    
    return event

if __name__ == "__main__":
    # Generate a few sample logs
    print("Sample Proofpoint events:")
    for threat in ["phish", "malware", "spam", "impostor", "none"]:
        print(f"\n{threat.upper()} event:")
        print(proofpoint_log({"threatType": threat}))