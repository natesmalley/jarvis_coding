#!/usr/bin/env python3
"""
Abnormal Security event generator
Generates synthetic Abnormal Security email security events
"""
import json
import random
import time
from datetime import datetime, timezone, timedelta
from typing import Dict

# Threat types detected by Abnormal
THREAT_TYPES = [
    "Credential Phishing",
    "Invoice Fraud",
    "Business Email Compromise",
    "Malware",
    "Spam",
    "Graymail",
    "Account Takeover",
    "Vendor Fraud",
    "Payroll Diversion",
    "Gift Card Scam"
]

# Remediation actions
REMEDIATION_ACTIONS = [
    "Quarantined",
    "Deleted",
    "Moved to Junk",
    "Released",
    "Under Review",
    "No Action Required"
]

# Attack strategies
ATTACK_STRATEGIES = [
    "Name Impersonation",
    "Domain Impersonation", 
    "Reply-To Mismatch",
    "Lookalike Domain",
    "Social Engineering",
    "Urgency Tactics",
    "Authority Impersonation"
]

def abnormal_security_log() -> Dict:
    """Generate a single Abnormal Security event log"""
    now = datetime.now(timezone.utc)
    # Use recent timestamps (last 10 minutes)
    event_time = now - timedelta(minutes=random.randint(0, 10))
    
    # Star Trek themed sender names and domains
    starfleet_officers = ["jean.picard", "william.riker", "data.android", "jordy.laforge", "worf.security", "beverly.crusher", "deanna.troi"]
    suspicious_domains = ["romulan-empire.com", "ferengi-commerce.net", "borg-collective.net", "cardassian-union.org"]
    
    # Generate event data
    threat_type = random.choice(THREAT_TYPES)
    severity = "high" if threat_type in ["Credential Phishing", "Business Email Compromise", "Account Takeover"] else random.choice(["low", "medium", "high"])
    
    event = {
        "event_id": f"abn-{random.randint(100000, 999999)}",
        "timestamp": event_time.isoformat(),
        "threat_type": threat_type,
        "severity": severity,
        "sender_email": f"{random.choice(['admin', 'noreply', 'support', 'finance'])}@{random.choice(suspicious_domains)}",
        "recipient_email": f"{random.choice(starfleet_officers)}@starfleet.corp",
        "subject": random.choice([
            "Urgent: Verify Your Starfleet Credentials",
            "Starfleet Command Invoice #" + str(random.randint(10000, 99999)) + " - Payment Required",
            "Re: Diplomatic Transfer Request",
            "Your Replicator Order Could Not Be Delivered", 
            "Starfleet IT Security Alert - Action Required",
            "Updated Starfleet Benefits Information"
        ]),
        "attack_strategy": random.sample(ATTACK_STRATEGIES, random.randint(1, 3)),
        "remediation_action": random.choice(REMEDIATION_ACTIONS),
        "confidence_score": round(random.uniform(0.7, 0.99), 2),
        "impersonated_party": random.choice(["Captain Picard", "Commander Riker", "Starfleet Command", "Starfleet Academy", "Engineering", None]),
        "attack_vector": random.choice(["email", "link", "attachment"]),
        "is_internal": random.choice([True, False]),
        "messages_delivered": random.randint(0, 10),
        "messages_remediated": random.randint(0, 10),
        "first_seen": (event_time - timedelta(hours=random.randint(1, 72))).isoformat(),
        "last_seen": event_time.isoformat()
    }
    
    return event

if __name__ == "__main__":
    # Generate sample events
    print("Sample Abnormal Security Events:")
    print("=" * 50)
    for i in range(3):
        print(f"\nEvent {i+1}:")
        print(abnormal_security_log())