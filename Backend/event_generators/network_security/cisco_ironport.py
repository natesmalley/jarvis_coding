#!/usr/bin/env python3
"""
Cisco IronPort Email Security Appliance event generator
Generates synthetic Cisco IronPort ESA security logs in JSON format
"""
import json
import random
from datetime import datetime, timezone, timedelta

# Anti-spam verdicts
ANTISPAM_VERDICTS = ["Negative", "Positive", "Suspected spam", "Bulk mail", "Marketing"]

# Anti-virus verdicts
ANTIVIRUS_VERDICTS = ["Clean", "Infected", "Quarantined", "Repaired", "Encrypted"]

# Email subjects (Star Trek themed)
SUBJECTS = [
    "Starfleet Quarterly Report - USS Enterprise",
    "Bridge crew meeting notes",
    "Engineering invoice #NCC-1701",
    "Starfleet Academy password reset request", 
    "Urgent: Romulan activity detected",
    "Your replicator order has shipped",
    "Red alert: Security breach",
    "Starfleet Command verification required",
    "Congratulations! You won the Academy Award!",
    "Free holodeck program download"
]

# Domains (Star Trek themed)
DOMAINS = [
    "starfleet.corp",
    "enterprise.starfleet.corp",
    "memory-alpha.org",
    "vulcan-academy.org", 
    "romulan-empire.com",
    "ferengi-commerce.net",
    "borg-collective.net"
]

# Hostnames (Star Trek themed)
HOSTNAMES = ["ENTERPRISE-MAIL-01", "ENTERPRISE-MAIL-02", "STARFLEET-ESA-01", "VOYAGER-ESA-PROD"]

# Star Trek characters for email generation
STARFLEET_OFFICERS = [
    "jean.picard", "william.riker", "data.android", "jordy.laforge",
    "worf.security", "beverly.crusher", "deanna.troi", "miles.obrien"
]

def generate_email() -> str:
    """Generate Star Trek themed email address"""
    officer = random.choice(STARFLEET_OFFICERS)
    domain = random.choice(DOMAINS)
    return f"{officer}@{domain}"

def generate_ip() -> str:
    """Generate IP address"""
    return f"{random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"

def generate_message_id() -> str:
    """Generate message ID"""
    return f"{random.randint(1000000, 9999999)}"

def cisco_ironport_log() -> dict:
    """Generate a single Cisco IronPort email security event log in JSON format"""
    now = datetime.now(timezone.utc) 
    # Use recent timestamps (last 10 minutes)
    event_time = now - timedelta(minutes=random.randint(0, 10))
    
    timestamp = event_time.strftime("%Y-%m-%dT%H:%M:%SZ")
    hostname = random.choice(HOSTNAMES)
    message_id = generate_message_id()
    from_addr = generate_email()
    to_addr = generate_email()
    subject = random.choice(SUBJECTS)
    src_ip = generate_ip()
    dst_ip = generate_ip()
    antispam_verdict = random.choice(ANTISPAM_VERDICTS)
    antivirus_verdict = random.choice(ANTIVIRUS_VERDICTS)
    
    # Determine if this is a threat
    is_threat = "romulan" in from_addr or "borg" in from_addr or "ferengi" in from_addr
    
    severity = "warn" if is_threat else "info"
    verdict = "BLOCKED" if is_threat or antispam_verdict == "Positive" or antivirus_verdict == "Infected" else "ACCEPTED"
    message_size = random.randint(1024, 10485760)
    attachment_count = random.randint(0, 5)
    connection_id = random.randint(1000, 9999)
    reputation_score = round(random.uniform(-10.0, 10.0), 1) if random.random() > 0.5 else None
    
    # Generate JSON format
    log_event = {
        "timestamp": timestamp,
        "hostname": hostname,
        "facility": "mail",
        "severity": severity,
        "message_id": message_id,
        "from_address": from_addr,
        "to_address": to_addr,
        "subject": subject,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "antispam_verdict": antispam_verdict,
        "antivirus_verdict": antivirus_verdict,
        "verdict": verdict,
        "message_size": message_size,
        "attachment_count": attachment_count,
        "connection_id": connection_id,
        "reputation_score": reputation_score,
        "vendor": "cisco",
        "product": "ironport",
        "log_type": "email_security"
    }
    
    return log_event

# ATTR_FIELDS for AI-SIEM compatibility
if __name__ == "__main__":
    # Generate sample events
    print("Sample Cisco IronPort Email Security Events (JSON):")
    print("=" * 50)
    for i in range(3):
        print(f"\nEvent {i+1}:")
        event = cisco_ironport_log()
        print(json.dumps(event, indent=2))