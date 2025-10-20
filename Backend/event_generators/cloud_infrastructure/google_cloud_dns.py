#!/usr/bin/env python3
"""
Google Cloud DNS event generator
Generates synthetic Google Cloud DNS query and audit events
"""
import json
import random
import time
from datetime import datetime, timezone, timedelta
from typing import Dict

# DNS query types
QUERY_TYPES = ["A", "AAAA", "MX", "NS", "PTR", "SOA", "TXT", "CNAME", "SRV", "CAA"]

# Response codes
RESPONSE_CODES = ["NOERROR", "NXDOMAIN", "SERVFAIL", "REFUSED", "TIMEOUT"]

# Query classes
QUERY_CLASSES = ["IN", "CH", "HS"]

# Common domains
DOMAINS = [
    "google.com",
    "youtube.com",
    "gmail.com",
    "googleapis.com",
    "gstatic.com",
    "doubleclick.net",
    "example.com",
    "malicious-domain.net",
    "phishing-site.org",
    "c2-server.com"
]

# Project IDs
PROJECT_IDS = ["prod-web-123456", "staging-api-789012", "dev-analytics-345678"]

# Locations
LOCATIONS = ["us-central1", "us-east1", "europe-west1", "asia-southeast1"]

def generate_ip() -> str:
    """Generate a random IP address"""
    return f"{random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"

def google_cloud_dns_log() -> Dict:
    """Generate a single Google Cloud DNS event log"""
    now = datetime.now(timezone.utc)
    event_time = now - timedelta(minutes=random.randint(0, 1440))
    
    query_name = random.choice(DOMAINS)
    query_type = random.choice(QUERY_TYPES)
    response_code = random.choice(RESPONSE_CODES)
    
    # Check if suspicious domain
    is_suspicious = query_name in ["malicious-domain.net", "phishing-site.org", "c2-server.com"]
    
    event = {
        "timestamp": event_time.isoformat() + "Z",
        "insertId": f"dns_{random.randint(1000000000000000, 9999999999999999)}",
        "resource": {
            "type": "gce_instance",
            "labels": {
                "project_id": random.choice(PROJECT_IDS),
                "instance_id": f"{random.randint(1000000000000000000, 9999999999999999999)}",
                "zone": random.choice(LOCATIONS) + "-a"
            }
        },
        "logName": f"projects/{random.choice(PROJECT_IDS)}/logs/dns.googleapis.com%2Fdns_queries",
        "severity": "INFO" if not is_suspicious else "WARNING",
        "jsonPayload": {
            "queryName": query_name,
            "queryType": query_type,
            "queryClass": random.choice(QUERY_CLASSES),
            "responseCode": response_code,
            "sourceIP": generate_ip(),
            "protocol": random.choice(["UDP", "TCP"]),
            "ednsClientSubnet": f"{generate_ip()}/24" if random.choice([True, False]) else "",
            "serverIP": "8.8.8.8",
            "querySize": random.randint(32, 512),
            "responseSize": random.randint(64, 1024) if response_code == "NOERROR" else random.randint(32, 128),
            "latency": f"{random.randint(1, 500)}ms",
            "cached": random.choice([True, False]),
            "dnssecValidated": random.choice([True, False]),
            "recursionAvailable": True,
            "recursionDesired": True,
            "authenticatedData": random.choice([True, False]),
            "checkingDisabled": False,
            "answersReturned": random.randint(0, 5) if response_code == "NOERROR" else 0,
            "authoritativeAnswer": random.choice([True, False])
        },
        "httpRequest": {
            "requestMethod": "POST",
            "requestUrl": f"https://dns.google/resolve?name={query_name}&type={query_type}",
            "userAgent": random.choice([
                "dns-over-https/1.0",
                "Mozilla/5.0 (DoH client)",
                "curl/7.68.0",
                "dig/9.16.1"
            ]),
            "remoteIp": generate_ip(),
            "status": 200 if response_code == "NOERROR" else 404,
            "responseSize": random.randint(100, 2000),
            "latency": f"{random.uniform(0.001, 0.5):.3f}s"
        },
        "sourceLocation": {
            "file": "dns_server.go",
            "line": random.randint(100, 500),
            "function": "handleDNSQuery"
        }
    }
    
    # Add threat intelligence data for suspicious domains
    if is_suspicious:
        event["jsonPayload"]["threatIntelligence"] = {
            "category": random.choice(["malware", "phishing", "command_control"]),
            "confidence": random.uniform(0.7, 0.99),
            "firstSeen": (event_time - timedelta(days=random.randint(1, 30))).isoformat() + "Z",
            "source": random.choice(["VirusTotal", "ThreatIntel", "Internal"])
        }
        event["labels"] = {
            "threat_detected": "true",
            "blocked": "true" if random.choice([True, False]) else "false"
        }
    
    # Add geolocation data
    event["jsonPayload"]["geoLocation"] = {
        "country": random.choice(["US", "CA", "GB", "DE", "FR", "JP", "AU"]),
        "region": random.choice(["California", "Texas", "London", "Tokyo"]),
        "city": random.choice(["San Francisco", "Austin", "London", "Tokyo"]),
        "latitude": round(random.uniform(-90, 90), 6),
        "longitude": round(random.uniform(-180, 180), 6)
    }
    
    return event

if __name__ == "__main__":
    # Generate sample events
    print("Sample Google Cloud DNS Events:")
    print("=" * 50)
    for i in range(3):
        print(f"\nEvent {i+1}:")
        print(google_cloud_dns_log())