#!/usr/bin/env python3
"""
Akamai Security event generator
Generates synthetic Akamai Security logs in syslog format
"""
import random
from datetime import datetime, timezone, timedelta

# Attack types
ATTACK_TYPES = [
    "SQL_Injection", "XSS", "CSRF", "Path_Traversal", "Command_Injection",
    "RFI", "LFI", "Brute_Force", "Rate_Limiting", "Bot_Detection"
]

# HTTP methods
HTTP_METHODS = ["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH"]

# HTTP status codes
STATUS_CODES = [200, 301, 302, 400, 401, 403, 404, 500, 502, 503]

# Actions
ACTIONS = ["blocked", "allowed", "challenged", "monitored", "rate_limited"]

# Hostnames
HOSTNAMES = [
    "www.example.com", "api.example.com", "login.example.com",
    "admin.example.com", "shop.example.com", "blog.example.com"
]

# Paths
PATHS = [
    "/login", "/admin", "/api/v1/users", "/search", "/upload",
    "/wp-admin", "/phpmyadmin", "/.env", "/config", "/backup"
]

# User agents
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36", 
    "curl/7.68.0", "python-requests/2.25.1", "Googlebot/2.1",
    "sqlmap/1.5", "Nikto/2.1", "OWASP ZAP/2.10"
]

# Messages
MESSAGES = [
    "Attempted SQL injection in login parameter detected and blocked",
    "Cross-site scripting attack prevented",
    "Path traversal attack blocked", 
    "Brute force login attempt detected",
    "Suspicious bot activity identified",
    "Rate limiting applied to client",
    "Malicious payload in request body"
]

def generate_client_ip() -> str:
    """Generate client IP address"""
    return f"{random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"

def akamai_general_log() -> str:
    """Generate a single Akamai Security log in syslog format"""
    now = datetime.now(timezone.utc)
    event_time = now - timedelta(minutes=random.randint(0, 1440))
    
    timestamp = event_time.strftime("%Y-%m-%dT%H:%M:%SZ")
    client_ip = generate_client_ip()
    host = random.choice(HOSTNAMES)
    path = random.choice(PATHS)
    rule_id = str(random.randint(900000, 999999))
    attack_type = random.choice(ATTACK_TYPES)
    action = random.choice(ACTIONS)
    http_method = random.choice(HTTP_METHODS)
    status = random.choice(STATUS_CODES)
    user_agent = random.choice(USER_AGENTS)
    message = random.choice(MESSAGES)
    
    # Generate syslog format matching the original test event
    log = (f'{timestamp} AkamaiSecurity clientIP="{client_ip}" host="{host}" '
           f'path="{path}" ruleId="{rule_id}" attackType="{attack_type}" '
           f'action="{action}" httpMethod="{http_method}" status={status} '
           f'userAgent="{user_agent}" message="{message}"')
    
    return log

# ATTR_FIELDS for AI-SIEM compatibility
if __name__ == "__main__":
    # Generate sample events
    print("Sample Akamai Security Events:")
    print("=" * 50)
    for i in range(3):
        print(f"\nEvent {i+1}:")
        print(akamai_general_log())