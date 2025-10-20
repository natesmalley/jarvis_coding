#!/usr/bin/env python3
"""
Cloudflare General event generator
Generates synthetic Cloudflare security and performance events
"""
import json
import random
import time
from datetime import datetime, timezone, timedelta
from typing import Dict

# HTTP methods
HTTP_METHODS = ["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH"]

# HTTP status codes
STATUS_CODES = [200, 301, 302, 304, 400, 401, 403, 404, 500, 502, 503]

# User agents
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
    "curl/7.68.0",
    "python-requests/2.25.1"
]

# Countries
COUNTRIES = ["US", "CA", "GB", "DE", "FR", "JP", "AU", "BR", "IN", "CN", "RU"]

# Actions taken by Cloudflare
ACTIONS = ["allow", "block", "challenge", "jschallenge", "managed_challenge", "log", "bypass"]

# Security rules
SECURITY_RULES = [
    "Rate Limiting",
    "DDoS Protection", 
    "Bot Management",
    "WAF Custom Rule",
    "WAF Managed Rule",
    "IP Reputation",
    "Geoblocking",
    "Browser Integrity Check"
]

def generate_ip() -> str:
    """Generate a random IP address"""
    return f"{random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"

def cloudflare_general_log() -> Dict:
    """Generate a single Cloudflare event log"""
    now = datetime.now(timezone.utc)
    # Use recent timestamps (last 10 minutes)
    event_time = now - timedelta(minutes=random.randint(0, 10))
    
    client_ip = generate_ip()
    action = random.choice(ACTIONS)
    status_code = random.choice(STATUS_CODES)
    
    # Adjust status code based on action
    if action == "block":
        status_code = random.choice([403, 429])
    elif action == "challenge":
        status_code = random.choice([403, 503])
    
    # Star Trek themed domains
    star_trek_hosts = ["starfleet.corp", "www.starfleet.corp", "api.starfleet.corp", "enterprise.starfleet.corp"]
    
    event = {
        "Datetime": int(event_time.timestamp() * 1000),  # Unix timestamp in milliseconds
        "ZoneID": random.randint(100000000000000000, 999999999999999999),
        "ZoneName": "starfleet.corp",
        "ClientIP": client_ip,
        "ClientRequestHost": random.choice(star_trek_hosts),
        "ClientRequestMethod": random.choice(HTTP_METHODS),
        "ClientRequestURI": random.choice(["/", "/api/v1/crew", "/starfleet/login", "/bridge/admin", "/engineering/console", "/api/ship-status"]),
        "ClientRequestUserAgent": random.choice(USER_AGENTS),
        "ClientCountry": random.choice(COUNTRIES),
        "ClientASN": random.randint(1000, 99999),
        "ClientIPClass": random.choice(["clean", "malicious", "searchEngine", "whitelist", "greylist"]),
        "EdgeResponseStatus": status_code,
        "EdgeResponseBytes": random.randint(100, 50000),
        "EdgeRequestHost": "starfleet.corp",
        "EdgeStartTimestamp": int(event_time.timestamp() * 1000000),  # Microseconds
        "EdgeEndTimestamp": int((event_time.timestamp() + random.uniform(0.001, 2.0)) * 1000000),
        "OriginIP": f"10.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}",
        "OriginResponseStatus": status_code if action == "allow" else 0,
        "OriginResponseTime": random.randint(10, 5000) if action == "allow" else 0,  # milliseconds
        "Action": action,
        "SecurityLevel": random.choice(["off", "essentially_off", "low", "medium", "high", "under_attack"]),
        "WAFProfile": random.choice(["low", "medium", "high"]),
        "WAFAction": action if action in ["allow", "block", "challenge"] else "unknown",
        "WAFFlags": random.randint(0, 255),
        "WAFMatchedVar": random.choice(["", "HTTP_USER_AGENT", "REQUEST_URI", "HTTP_HOST", "ARGS"]),
        "WAFRuleID": f"rule_{random.randint(1000, 9999)}" if action == "block" else "",
        "WAFRuleMessage": random.choice(SECURITY_RULES) if action in ["block", "challenge"] else "",
        "RayID": f"{random.randint(100000000000000000, 999999999999999999):016x}",
        "CacheCacheStatus": random.choice(["hit", "miss", "expired", "updating", "stale", "bypass", "revalidated"]),
        "CacheResponseBytes": random.randint(0, 10000),
        "CacheResponseStatus": random.choice([200, 304, 404, 0]),
        "BotScore": random.randint(1, 99),
        "BotScoreSrc": random.choice(["Not Computed", "Machine Learning", "Heuristics", "JS Fingerprinting"]),
        "BotTags": random.choice(["", "verified_bot", "likely_automated", "likely_human"]),
        "ThreatScore": random.randint(0, 100),
        "RequestHeaders": {
            "cf-ray": f"{random.randint(100000000000000000, 999999999999999999):016x}",
            "cf-visitor": '{"scheme":"https"}',
            "x-forwarded-proto": "https"
        }
    }
    
    # Add firewall events details
    if action in ["block", "challenge"]:
        event.update({
            "FirewallMatchesActions": [action],
            "FirewallMatchesSources": [random.choice(SECURITY_RULES)],
            "FirewallMatchesRuleIDs": [f"rule_{random.randint(1000, 9999)}"]
        })
    
    return event

if __name__ == "__main__":
    # Generate sample events
    print("Sample Cloudflare Events:")
    print("=" * 50)
    for i in range(3):
        print(f"\nEvent {i+1}:")
        print(cloudflare_general_log())