#!/usr/bin/env python3
"""
Imperva WAF event generator
Generates synthetic Imperva Web Application Firewall security events
"""
import json
import random
import time
from datetime import datetime, timezone, timedelta
from typing import Dict

# HTTP methods
HTTP_METHODS = ["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH"]

# Attack types
ATTACK_TYPES = [
    "SQL Injection",
    "Cross Site Scripting",
    "Command Injection", 
    "Path Traversal",
    "Remote File Inclusion",
    "Local File Inclusion",
    "LDAP Injection",
    "XML Injection",
    "Buffer Overflow",
    "Protocol Anomaly"
]

# Actions taken
ACTIONS = ["Block", "Alert", "Pass", "Redirect"]

# Violation categories
VIOLATION_CATEGORIES = [
    "Security",
    "Protocol",
    "Data Loss Prevention",
    "Compliance",
    "Bot Protection"
]

# Countries
COUNTRIES = ["US", "CA", "GB", "DE", "FR", "CN", "RU", "IN", "BR", "JP"]

def generate_ip() -> str:
    """Generate a random IP address"""
    return f"{random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"

def imperva_waf_log() -> Dict:
    """Generate a single Imperva WAF event log"""
    now = datetime.now(timezone.utc)
    event_time = now - timedelta(minutes=random.randint(0, 1440))
    
    client_ip = generate_ip()
    attack_type = random.choice(ATTACK_TYPES)
    action = random.choice(ACTIONS)
    
    event = {
        "timestamp": event_time.isoformat(),
        "eventId": f"imp_{random.randint(1000000000, 9999999999)}",
        "clientIP": client_ip,
        "serverIP": f"10.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}",
        "httpMethod": random.choice(HTTP_METHODS),
        "uri": random.choice([
            "/",
            "/login",
            "/admin",
            "/api/v1/users",
            "/upload",
            "/search",
            "/contact",
            "/admin/config.php",
            "/wp-admin/admin-ajax.php",
            "/../../../etc/passwd"
        ]),
        "userAgent": random.choice([
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15",
            "curl/7.68.0",
            "python-requests/2.25.1",
            "sqlmap/1.4.7",
            "Nikto/2.1.6"
        ]),
        "referer": random.choice([
            "",
            "https://google.com/",
            "https://example.com/",
            "https://malicious-site.com/"
        ]),
        "host": random.choice(["example.com", "www.example.com", "api.example.com"]),
        "protocol": random.choice(["HTTP/1.1", "HTTP/2.0"]),
        "responseCode": random.choice([200, 403, 404, 500, 503]),
        "responseSize": random.randint(100, 50000),
        "requestSize": random.randint(100, 10000),
        "processingTime": random.randint(1, 1000),
        "action": action,
        "attackType": attack_type,
        "violationCategory": random.choice(VIOLATION_CATEGORIES),
        "severity": random.choice(["High", "Medium", "Low", "Informational"]),
        "policyName": f"policy_{random.randint(1, 10)}",
        "ruleName": f"rule_{random.randint(100, 999)}",
        "ruleId": random.randint(10000, 99999),
        "confidenceLevel": random.randint(1, 10),
        "riskScore": random.randint(0, 100),
        "sessionId": f"sess_{random.randint(100000000, 999999999)}",
        "sourceCountry": random.choice(COUNTRIES),
        "sourceASN": random.randint(1000, 99999),
        "destinationPort": random.choice([80, 443, 8080, 8443]),
        "sourcePort": random.randint(32768, 65535),
        "applicationName": random.choice(["WebApp1", "API Gateway", "Admin Portal", "Customer Portal"]),
        "siteName": f"site_{random.randint(1, 5)}",
        "serverGroup": f"group_{random.randint(1, 3)}"
    }
    
    # Add attack-specific details
    if "SQL" in attack_type:
        event.update({
            "sqlPattern": random.choice([
                "UNION SELECT",
                "DROP TABLE",
                "' OR 1=1",
                "'; INSERT INTO",
                "EXEC xp_cmdshell"
            ]),
            "dbType": random.choice(["MySQL", "PostgreSQL", "MSSQL", "Oracle"])
        })
    
    elif "XSS" in attack_type or "Cross Site" in attack_type:
        event.update({
            "xssPattern": random.choice([
                "<script>alert('xss')</script>",
                "javascript:alert(1)",
                "<img src=x onerror=alert(1)>",
                "<svg onload=alert(1)>"
            ])
        })
    
    elif "Command" in attack_type:
        event.update({
            "commandPattern": random.choice([
                "; ls -la",
                "| cat /etc/passwd",
                "&& whoami",
                "`id`"
            ])
        })
    
    # Add DLP details for data loss prevention
    if event["violationCategory"] == "Data Loss Prevention":
        event.update({
            "dataType": random.choice(["Credit Card", "SSN", "Email", "Phone", "Custom Pattern"]),
            "matchCount": random.randint(1, 10),
            "maskedData": "****-****-****-1234" if "Credit Card" in event.get("dataType", "") else "***-**-****"
        })
    
    # Add bot protection details
    if event["violationCategory"] == "Bot Protection":
        event.update({
            "botType": random.choice(["Good Bot", "Bad Bot", "Suspicious", "Human"]),
            "botScore": random.randint(0, 100),
            "challengeResult": random.choice(["Passed", "Failed", "Not Challenged"])
        })
    
    return event

if __name__ == "__main__":
    # Generate sample events
    print("Sample Imperva WAF Events:")
    print("=" * 50)
    for i in range(3):
        print(f"\nEvent {i+1}:")
        print(imperva_waf_log())