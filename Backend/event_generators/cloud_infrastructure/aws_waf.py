#!/usr/bin/env python3

import json
import random
from datetime import datetime, timedelta
import uuid

# SentinelOne AI-SIEM specific field attributes
def aws_waf_log():
    current_time = datetime.utcnow()
    
    actions = ["ALLOW", "BLOCK", "CAPTCHA", "COUNT"]
    rule_groups = ["Default", "SQLInjectionRules", "XSSRules", "BotControlRules", "RateLimitRules", "CustomRules"]
    terminating_types = ["", "BLOCK", "CAPTCHA", "RATE_BASED", "CUSTOM"]
    http_methods = ["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH"]
    http_versions = ["HTTP/1.1", "HTTP/2", "HTTP/1.0"]
    countries = ["US", "CA", "GB", "DE", "FR", "JP", "CN", "RU", "BR", "IN", "AU", "MX"]
    
    uris = [
        "/index.html", "/login.php", "/api/v1/users", "/admin/dashboard",
        "/search", "/contact.php", "/products", "/checkout", "/api/data",
        "/wp-admin", "/phpmyadmin", "/.env", "/config.json", "/api/auth"
    ]
    
    user_agents = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
        "curl/7.68.0", "python-requests/2.25.1", "Googlebot/2.1",
        "bot/1.0", "scanner/2.0", "sqlmap/1.5"
    ]
    
    args_examples = [
        "",
        "id=123&category=products",
        "user=admin&password=' OR '1'='1",
        "search=<script>alert('XSS')</script>",
        "file=../../../../etc/passwd",
        "cmd=ls -la",
        "token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
    ]
    
    action = random.choice(actions)
    rule_group = random.choice(rule_groups)
    
    if action in ["BLOCK", "CAPTCHA"]:
        terminating_type = random.choice([t for t in terminating_types if t])
    else:
        terminating_type = ""
    
    headers = [
        {"name": "Host", "value": f"example{random.randint(1,10)}.com"},
        {"name": "User-Agent", "value": random.choice(user_agents)}
    ]
    
    if random.random() > 0.5:
        headers.append({"name": "Referer", "value": f"https://referrer{random.randint(1,5)}.com"})
    
    if random.random() > 0.7:
        headers.append({"name": "X-Forwarded-For", "value": f"{random.randint(1,255)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,255)}"})
    
    log_entry = {
        "timestamp": current_time.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "formatVersion": "1.0",
        "webaclId": f"arn:aws:wafv2:us-east-1:{random.randint(100000000000, 999999999999)}:regional/webacl/ExampleWebACL-{random.randint(1000,9999)}",
        "ruleGroupId": rule_group,
        "terminatingRuleType": terminating_type,
        "action": action,
        "httpRequest": {
            "clientIp": f"{random.randint(1,255)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,255)}",
            "country": random.choice(countries),
            "uri": random.choice(uris),
            "args": random.choice(args_examples),
            "httpVersion": random.choice(http_versions),
            "httpMethod": random.choice(http_methods),
            "headers": headers
        }
    }
    
    if random.random() > 0.8:
        log_entry["requestId"] = str(uuid.uuid4())
    
    if action == "BLOCK" and random.random() > 0.5:
        log_entry["labels"] = [
            {"name": "awswaf:managed:aws:sql-database:SQLi_QUERYARGUMENTS"}
        ]
    
    return log_entry

if __name__ == "__main__":
    print(json.dumps(aws_waf_log(), indent=2))