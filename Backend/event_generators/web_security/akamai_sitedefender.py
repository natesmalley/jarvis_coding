#!/usr/bin/env python3
"""
Akamai SiteDefender WAF event generator
Generates synthetic Akamai SiteDefender WAF security events
"""
import json
import random
from datetime import datetime, timezone, timedelta
from typing import Dict

# WAF rule types and messages
WAF_RULES = [
    {"rule": "981176", "ruleAction": "BLOCK", "ruleMessage": "SQL Injection Detected", "ruleTag": "SQL_Injection"},
    {"rule": "941130", "ruleAction": "ALERT", "ruleMessage": "Cross Site Scripting", "ruleTag": "XSS"},
    {"rule": "932100", "ruleAction": "BLOCK", "ruleMessage": "Command Injection Attack", "ruleTag": "Command_Injection"},
    {"rule": "933100", "ruleAction": "BLOCK", "ruleMessage": "PHP Injection Attack", "ruleTag": "PHP_Injection"},
    {"rule": "920100", "ruleAction": "ALERT", "ruleMessage": "Invalid HTTP Request Line", "ruleTag": "Protocol_Violation"},
    {"rule": "921110", "ruleAction": "ALERT", "ruleMessage": "HTTP Request Smuggling Attack", "ruleTag": "Request_Smuggling"},
    {"rule": "930100", "ruleAction": "BLOCK", "ruleMessage": "Path Traversal Attack", "ruleTag": "Path_Traversal"},
    {"rule": "942100", "ruleAction": "BLOCK", "ruleMessage": "SQL Injection Attack", "ruleTag": "SQLi"},
]

HTTP_METHODS = ["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH"]
HTTP_HOSTS = ["www.example.com", "api.example.com", "cdn.example.com", "shop.example.com"]
HTTP_PATHS = ["/", "/login", "/api/v1/users", "/search", "/checkout", "/admin", "/health"]
HTTP_STATUS_CODES = [200, 301, 302, 403, 404, 500, 503]

CITIES = ["Los Angeles", "San Francisco", "New York", "Chicago", "Miami", "Seattle"]
COUNTRIES = ["US", "CA", "UK", "DE", "FR", "JP"]

def get_random_ip():
    """Generate a random IP address."""
    if random.random() < 0.3:  # 30% suspicious IPs
        return f"203.0.113.{random.randint(1, 255)}"
    elif random.random() < 0.5:  # Some other suspicious ranges
        return f"198.51.100.{random.randint(1, 255)}"
    else:  # Normal IPs
        return f"{random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"

def akamai_sitedefender_log() -> Dict:
    """Generate a single Akamai SiteDefender WAF event log"""
    now = datetime.now(timezone.utc)
    event_time = now - timedelta(minutes=random.randint(0, 60))
    
    # Determine if this is an attack or clean traffic
    is_attack = random.random() < 0.4  # 40% attacks
    
    rules = []
    if is_attack:
        # Select 1-2 rules for attack
        rules = random.sample(WAF_RULES, random.randint(1, 2))
    
    # Generate client data
    client_ip = get_random_ip()
    config_id = str(random.randint(10000, 99999))
    policy_id = f"p_{random.randint(10000, 99999)}"
    
    # Generate HTTP message details
    method = random.choice(HTTP_METHODS)
    host = random.choice(HTTP_HOSTS)
    path = random.choice(HTTP_PATHS)
    
    # Status code based on whether it's an attack
    if is_attack and any(rule["ruleAction"] == "BLOCK" for rule in rules):
        status = 403  # Blocked
    else:
        status = random.choice(HTTP_STATUS_CODES)
    
    # Bot score (higher = more likely bot/attack)
    if is_attack:
        bot_score = random.randint(60, 95)
    else:
        bot_score = random.randint(5, 30)
    
    # Geo data
    city = random.choice(CITIES)
    country = random.choice(COUNTRIES)
    
    event = {
        "type": "akamai_siem",
        "attackData": {
            "clientIP": client_ip,
            "configId": config_id,
            "policyId": policy_id,
            "rules": rules
        },
        "httpMessage": {
            "method": method,
            "host": host,
            "path": path,
            "status": status
        },
        "botData": None,
        "geo": {
            "city": city,
            "country": country
        },
        "userRiskData": {
            "botScore": bot_score
        },
        "time": event_time.isoformat().replace('+00:00', 'Z')
    }
    
    return event

if __name__ == "__main__":
    # Generate sample events
    print("Sample Akamai SiteDefender WAF Events:")
    print("=" * 50)
    for i in range(3):
        print(f"\nEvent {i+1}:")
        print(akamai_sitedefender_log())