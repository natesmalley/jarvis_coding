#!/usr/bin/env python3
"""Generate synthetic Cloudflare WAF logs in GRON format."""
import json
import random
from datetime import datetime, timezone
import time

# Cloudflare WAF event types and fields
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
    "Python-urllib/3.8",
    "sqlmap/1.5.2#stable (http://sqlmap.org)",  # Attack tool
    "Nikto/2.1.6",  # Scanner
    "curl/7.68.0"
]

COUNTRIES = ["US", "CN", "RU", "DE", "GB", "FR", "JP", "BR", "IN", "CA", "AU", "NL", "SG", "KR"]

WAF_ACTIONS = ["challenge", "block", "skip", "allow", "log", "js_challenge", "managed_challenge"]

WAF_RULES = [
    {"id": "100001", "description": "SQL Injection Attack"},
    {"id": "100002", "description": "Cross-Site Scripting (XSS)"},
    {"id": "100003", "description": "Remote Code Execution"},
    {"id": "100004", "description": "Path Traversal"},
    {"id": "100005", "description": "Command Injection"},
    {"id": "100015A", "description": "PHP Code Injection"},
    {"id": "100021", "description": "Shellshock"},
    {"id": "100030", "description": "Apache Struts RCE"},
    {"id": "981176", "description": "OWASP CRS 3.0 - Restricted SQL Character Anomaly Detection"},
    {"id": "981243", "description": "OWASP CRS 3.0 - Detects classic SQL injection probings"}
]

REQUEST_METHODS = ["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH"]

PATHS = [
    "/", "/index.php", "/admin", "/login", "/api/v1/users", "/search",
    "/admin/config.php", "/phpmyadmin", "/.env", "/wp-admin",
    "/api/v1/data", "/checkout", "/payment", "/user/profile",
    "/?id=1' OR '1'='1", "/search?q=<script>alert(1)</script>",
    "/admin/backup.sql", "/../../etc/passwd", "/cmd.php?exec=whoami"
]

EDGE_COLOS = ["LAX", "SFO", "ORD", "JFK", "LHR", "FRA", "NRT", "SIN", "SYD", "GRU", "AMS", "CDG"]

def get_random_ip():
    """Generate a random IP address."""
    return f"{random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"

def generate_ray_id():
    """Generate a Cloudflare Ray ID."""
    return f"{random.randint(100000000000000, 999999999999999):x}-{random.choice(EDGE_COLOS)}"

def calculate_waf_scores(path, method, user_agent):
    """Calculate WAF attack scores based on request characteristics."""
    scores = {
        "WAFAttackScore": 0,
        "WAFSQLiAttackScore": 0,
        "WAFXSSAttackScore": 0,
        "WAFRCEAttackScore": 0
    }
    
    # Check for SQL injection patterns
    if any(pattern in path.lower() for pattern in ["' or", "union select", "drop table", "1=1", "' and"]):
        scores["WAFSQLiAttackScore"] = random.randint(70, 100)
        scores["WAFAttackScore"] = max(scores["WAFAttackScore"], scores["WAFSQLiAttackScore"])
    
    # Check for XSS patterns
    if any(pattern in path.lower() for pattern in ["<script", "javascript:", "onerror=", "onclick=", "alert("]):
        scores["WAFXSSAttackScore"] = random.randint(70, 100)
        scores["WAFAttackScore"] = max(scores["WAFAttackScore"], scores["WAFXSSAttackScore"])
    
    # Check for RCE patterns
    if any(pattern in path.lower() for pattern in ["../", "cmd=", "exec=", ".php?", "system(", "eval("]):
        scores["WAFRCEAttackScore"] = random.randint(60, 100)
        scores["WAFAttackScore"] = max(scores["WAFAttackScore"], scores["WAFRCEAttackScore"])
    
    # Check user agent for known attack tools
    if any(tool in user_agent for tool in ["sqlmap", "nikto", "nmap", "masscan"]):
        scores["WAFAttackScore"] = max(scores["WAFAttackScore"], random.randint(80, 100))
    
    # Random false positives
    if scores["WAFAttackScore"] == 0 and random.random() < 0.05:
        scores["WAFAttackScore"] = random.randint(20, 50)
    
    return scores

def json_to_gron(obj, prefix="json"):
    """Convert JSON object to GRON format."""
    lines = []
    
    def _process_value(value, path):
        if isinstance(value, dict):
            if not value:  # empty dict
                lines.append(f"{path} = {{}};")
            else:
                for key, val in value.items():
                    # Escape special characters in key names
                    safe_key = key.replace(".", "\\.")
                    _process_value(val, f"{path}.{safe_key}")
        elif isinstance(value, list):
            if not value:  # empty list
                lines.append(f"{path} = [];")
            else:
                for i, val in enumerate(value):
                    _process_value(val, f"{path}[{i}]")
        elif isinstance(value, str):
            # Escape quotes and backslashes in string values
            escaped = value.replace("\\", "\\\\").replace('"', '\\"')
            lines.append(f'{path} = "{escaped}";')
        elif isinstance(value, bool):
            lines.append(f"{path} = {str(value).lower()};")
        elif value is None:
            lines.append(f"{path} = null;")
        else:
            lines.append(f"{path} = {value};")
    
    _process_value(obj, prefix)
    return "\n".join(lines)

def cloudflare_waf_log(overrides: dict | None = None) -> str:
    """Generate a single Cloudflare WAF log entry in GRON format."""
    now = datetime.now(timezone.utc)
    timestamp = now.isoformat() + "Z"
    
    # Generate request details
    method = random.choice(REQUEST_METHODS)
    path = random.choice(PATHS)
    user_agent = random.choice(USER_AGENTS)
    client_ip = get_random_ip()
    
    # Calculate WAF scores
    waf_scores = calculate_waf_scores(path, method, user_agent)
    
    # Determine response based on WAF score
    if waf_scores["WAFAttackScore"] >= 80:
        action = random.choice(["block", "challenge", "managed_challenge"])
        response_status = 403
    elif waf_scores["WAFAttackScore"] >= 50:
        action = random.choice(["challenge", "js_challenge", "log"])
        response_status = 403 if action != "log" else 200
    else:
        action = random.choice(["allow", "skip", "log"])
        response_status = 200
    
    # Build the event
    event = {
        "Timestamp": timestamp,
        "CreatedAt": timestamp,
        "EdgeStartTimestamp": int(now.timestamp() * 1000000000),  # nanoseconds
        "ClientIP": client_ip,
        "ClientRequestHost": f"example-{random.randint(1, 10)}.com",
        "ClientRequestMethod": method,
        "ClientRequestURI": path,
        "ClientRequestProtocol": "HTTP/1.1" if random.random() < 0.7 else "HTTP/2",
        "ClientRequestUserAgent": user_agent,
        "EdgeResponseStatus": response_status,
        "OriginResponseStatus": response_status if action in ["allow", "log"] else 0,
        "EdgeServerIP": get_random_ip(),
        "RayID": generate_ray_id(),
        "EdgeColoCode": random.choice(EDGE_COLOS),
        "ClientCountry": random.choice(COUNTRIES),
        "ClientDeviceType": random.choice(["desktop", "mobile", "tablet", "bot"]),
        "ClientRequestBytes": random.randint(200, 2000),
        "EdgeResponseBytes": random.randint(500, 50000),
        "EdgeRequestHost": f"example-{random.randint(1, 10)}.com",
        "EdgePathingOp": "wl" if action == "allow" else "ban",
        "EdgePathingSrc": "filterBasedFirewall",
        "EdgePathingStatus": "nr" if action in ["allow", "log"] else "captchaNew",
        "FirewallMatchesActions": [action],
        "FirewallMatchesRuleIDs": [random.choice(WAF_RULES)["id"]] if waf_scores["WAFAttackScore"] > 0 else [],
        "SecurityLevel": random.choice(["low", "medium", "high", "essentially_off"]),
        "WAFAction": action,
        "WAFProfile": random.choice(["low", "high"]),
        "WorkerCPUTime": random.randint(1000, 50000),
        "WorkerStatus": "ok",
        "ZoneID": random.randint(100000000, 999999999),
        "ParentRayID": "00",
        "OriginIP": f"10.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}",
        "CacheCacheStatus": random.choice(["hit", "miss", "bypass", "dynamic"]),
        "CacheResponseBytes": random.randint(0, 50000) if response_status == 200 else 0,
        "ClientRequestReferer": f"https://google.com/search?q={random.choice(['test', 'example', 'demo'])}",
        "ClientSSLCipher": "ECDHE-RSA-AES128-GCM-SHA256",
        "ClientSSLProtocol": "TLSv1.3" if random.random() < 0.8 else "TLSv1.2",
        "EdgeResponseContentType": "text/html" if response_status == 200 else "text/plain",
        "EdgeResponseCompressionRatio": round(random.uniform(1.5, 3.5), 2),
        "EdgeServerTime": random.randint(10, 500),
        "dataSource": {
            "vendor": "Cloudflare",
            "category": "security",
            "name": "Cloudflare WAF"
        }
    }
    
    # Add WAF scores
    event.update(waf_scores)
    
    # Add matched rules descriptions if any
    if event["FirewallMatchesRuleIDs"]:
        rule_id = event["FirewallMatchesRuleIDs"][0]
        rule_desc = next((r["description"] for r in WAF_RULES if r["id"] == rule_id), "Unknown Rule")
        event["WAFRuleDescription"] = rule_desc
        event["WAFRuleID"] = rule_id
    
    # Apply overrides
    if overrides:
        event.update(overrides)
    
    # Convert to GRON format
    return json_to_gron(event)

# OCSF-style attributes for HEC
if __name__ == "__main__":
    # Generate sample logs
    print("Sample Cloudflare WAF logs:")
    
    # Normal traffic
    print("\nNormal traffic:")
    print(cloudflare_waf_log({"ClientRequestURI": "/api/v1/users", "WAFAttackScore": 0}))
    
    # SQL injection attempt
    print("\nSQL injection attempt:")
    print(cloudflare_waf_log({"ClientRequestURI": "/products?id=1' OR '1'='1"}))
    
    # XSS attempt
    print("\nXSS attempt:")
    print(cloudflare_waf_log({"ClientRequestURI": "/search?q=<script>alert('xss')</script>"}))