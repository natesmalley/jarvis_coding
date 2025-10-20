#!/usr/bin/env python3
"""
Incapsula WAF event generator
Generates synthetic Imperva Incapsula web application firewall events
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
    "Remote File Inclusion",
    "Local File Inclusion",
    "Command Injection",
    "LDAP Injection",
    "XML Injection",
    "Path Traversal",
    "Buffer Overflow",
    "Backdoor Access",
    "Bot Access",
    "DDoS Attack"
]

# Actions taken
ACTIONS = ["Pass", "Block", "Challenge", "Alert", "Monitor"]

# Bot types
BOT_TYPES = [
    "Search Engine Bot",
    "Social Media Bot", 
    "Monitoring Bot",
    "Malicious Bot",
    "Unknown Bot",
    "Scraping Bot",
    "Attack Bot"
]

# Countries
COUNTRIES = ["US", "CA", "GB", "DE", "FR", "CN", "RU", "IN", "BR", "JP", "AU", "IT", "ES", "NL"]

# User agents
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "curl/7.68.0",
    "python-requests/2.25.1",
    "sqlmap/1.4.7",
    "Nikto/2.1.6"
]

def generate_ip() -> str:
    """Generate a random IP address"""
    return f"{random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"

def incapsula_log() -> Dict:
    """Generate a single Incapsula WAF event log"""
    now = datetime.now(timezone.utc)
    event_time = now - timedelta(minutes=random.randint(0, 1440))
    
    client_ip = generate_ip()
    action = random.choice(ACTIONS)
    attack_type = random.choice(ATTACK_TYPES)
    
    event = {
        "timestamp": event_time.isoformat(),
        "log_id": f"inc_{random.randint(1000000000, 9999999999)}",
        "account_id": f"{random.randint(100000, 999999)}",
        "site_id": f"{random.randint(10000000, 99999999)}",
        "request_id": f"{random.randint(1000000000000000, 9999999999999999)}",
        "client_ip": client_ip,
        "client_country": random.choice(COUNTRIES),
        "client_country_code": random.choice(COUNTRIES),
        "client_asn": random.randint(1000, 99999),
        "client_asn_name": random.choice([
            "Amazon.com Inc.",
            "Google LLC",
            "Microsoft Corporation", 
            "Cloudflare Inc.",
            "Digital Ocean",
            "Suspicious Provider Inc."
        ]),
        "server_ip": f"10.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}",
        "host": random.choice(["example.com", "www.example.com", "api.example.com", "admin.example.com"]),
        "method": random.choice(HTTP_METHODS),
        "uri": random.choice([
            "/",
            "/login",
            "/admin", 
            "/api/v1/users",
            "/upload",
            "/search",
            "/wp-admin/admin-ajax.php",
            "/../../../etc/passwd",
            "/api/data?id=1' OR 1=1--"
        ]),
        "query_string": random.choice([
            "",
            "?search=test",
            "?id=123",
            "?user=admin&pass=password",
            "?file=../../../etc/passwd",
            "?cmd=cat /etc/passwd"
        ]),
        "user_agent": random.choice(USER_AGENTS),
        "referer": random.choice([
            "",
            "https://google.com/search",
            "https://example.com/",
            "https://malicious-site.com/",
            "https://attacker-domain.net/"
        ]),
        "request_size": random.randint(100, 50000),
        "response_code": random.choice([200, 302, 403, 404, 429, 500, 503]),
        "response_size": random.randint(100, 100000),
        "response_time": random.randint(1, 5000),  # milliseconds
        "action": action,
        "rule_name": f"rule_{random.randint(1, 1000)}",
        "rule_id": random.randint(10000, 99999),
        "policy_name": f"policy_{random.randint(1, 50)}",
        "attack_type": attack_type if action in ["Block", "Challenge", "Alert"] else "",
        "severity": random.choice(["Low", "Medium", "High", "Critical"]) if action in ["Block", "Challenge", "Alert"] else "",
        "confidence": random.randint(1, 10) if action in ["Block", "Challenge", "Alert"] else None,
        "session_id": f"sess_{random.randint(100000000, 999999999)}",
        "visit_id": f"visit_{random.randint(100000000, 999999999)}"
    }
    
    # Add bot detection fields
    if random.choice([True, False]):  # 50% chance of bot detection
        event.update({
            "is_bot": True,
            "bot_type": random.choice(BOT_TYPES),
            "bot_classification": random.choice(["Good", "Bad", "Neutral", "Unknown"]),
            "bot_score": random.randint(0, 100)
        })
    else:
        event["is_bot"] = False
    
    # Add DDoS detection fields for high volume attacks
    if "DDoS" in attack_type or action == "Challenge":
        event.update({
            "is_ddos": True,
            "ddos_type": random.choice(["Volumetric", "Protocol", "Application"]),
            "request_rate": random.randint(100, 10000),  # requests per second
            "bandwidth_mbps": random.randint(1, 1000)
        })
    
    # Add specific attack details
    if "SQL" in attack_type:
        event.update({
            "sql_injection_pattern": random.choice([
                "UNION SELECT",
                "' OR 1=1",
                "'; DROP TABLE",
                "EXEC xp_cmdshell"
            ]),
            "database_type": random.choice(["MySQL", "PostgreSQL", "MSSQL", "Oracle"])
        })
    
    elif "XSS" in attack_type or "Cross Site" in attack_type:
        event.update({
            "xss_pattern": random.choice([
                "<script>alert('xss')</script>",
                "javascript:alert(1)",
                "<img src=x onerror=alert(1)>",
                "<svg onload=alert(1)>"
            ]),
            "xss_type": random.choice(["Reflected", "Stored", "DOM-based"])
        })
    
    elif "Command" in attack_type:
        event.update({
            "command_pattern": random.choice([
                "; cat /etc/passwd",
                "| whoami",
                "&& ls -la",
                "`id`"
            ])
        })
    
    elif "File" in attack_type:
        event.update({
            "file_path": random.choice([
                "../../../etc/passwd",
                "..\\..\\windows\\system32\\config\\sam", 
                "../../../../var/log/apache/access.log",
                "../config/database.yml"
            ])
        })
    
    # Add geolocation data
    event.update({
        "client_latitude": round(random.uniform(-90, 90), 6),
        "client_longitude": round(random.uniform(-180, 180), 6),
        "client_city": random.choice([
            "New York", "London", "Tokyo", "Moscow", "Beijing",
            "Los Angeles", "Paris", "Sydney", "Toronto", "Berlin"
        ])
    })
    
    # Add SSL/TLS information
    event.update({
        "ssl_protocol": random.choice(["TLSv1.2", "TLSv1.3", "TLSv1.1", "SSLv3"]),
        "ssl_cipher": random.choice([
            "ECDHE-RSA-AES256-GCM-SHA384",
            "ECDHE-RSA-AES128-GCM-SHA256", 
            "AES256-SHA256",
            "AES128-SHA"
        ]),
        "ssl_client_verify": random.choice(["SUCCESS", "NONE", "FAILED"])
    })
    
    # Add cache information
    event.update({
        "cache_status": random.choice(["HIT", "MISS", "BYPASS", "EXPIRED"]),
        "edge_location": random.choice([
            "us-east-1", "us-west-2", "eu-west-1", "ap-southeast-1",
            "eu-central-1", "ap-northeast-1", "us-central-1"
        ])
    })
    
    # Remove None values
    event = {k: v for k, v in event.items() if v is not None}
    
    return event

if __name__ == "__main__":
    # Generate sample events
    print("Sample Incapsula Events:")
    print("=" * 50)
    for i in range(3):
        print(f"\nEvent {i+1}:")
        print(incapsula_log())