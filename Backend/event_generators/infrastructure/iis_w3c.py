#!/usr/bin/env python3
"""
Microsoft IIS W3C Extended Log Format event generator
Generates synthetic IIS web server logs
"""
import json
import random
import time
from datetime import datetime, timezone, timedelta
from typing import Dict

# HTTP methods
HTTP_METHODS = ["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH"]

# HTTP status codes
STATUS_CODES = [200, 201, 204, 301, 302, 304, 400, 401, 403, 404, 500, 502, 503]

# URI stems
URI_STEMS = [
    "/",
    "/index.html",
    "/about.html",
    "/contact.html",
    "/login",
    "/logout",
    "/api/users",
    "/api/data",
    "/admin",
    "/uploads",
    "/downloads",
    "/images/logo.png",
    "/css/style.css",
    "/js/app.js"
]

# User agents
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
    "curl/7.68.0",
    "PostmanRuntime/7.28.4",
    "python-requests/2.25.1"
]

# Usernames
USERNAMES = ["alice", "bob", "charlie", "admin", "service", "-"]

# Site names
SITE_NAMES = ["www.contoso.com", "api.contoso.com", "intranet.contoso.com"]

# Computer names
COMPUTER_NAMES = ["WEB01", "WEB02", "IIS-PROD", "IIS-TEST"]

def generate_ip() -> str:
    """Generate IP address"""
    return f"{random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"

def generate_server_ip() -> str:
    """Generate server IP address (usually private)"""
    return f"192.0.2.{random.randint(10, 100)}"

def generate_query_string() -> str:
    """Generate query string"""
    if random.random() > 0.7:  # 30% chance of having query string
        params = []
        for _ in range(random.randint(1, 3)):
            key = random.choice(["id", "page", "user", "filter", "sort"])
            value = random.choice(["123", "home", "alice", "active", "desc"])
            params.append(f"{key}={value}")
        return "?" + "&".join(params)
    return "-"

def iis_w3c_log() -> Dict:
    """Generate a single Microsoft IIS W3C log event"""
    now = datetime.now(timezone.utc)
    event_time = now - timedelta(minutes=random.randint(0, 1440))
    
    method = random.choice(HTTP_METHODS)
    uri_stem = random.choice(URI_STEMS)
    query_string = generate_query_string()
    status_code = random.choice(STATUS_CODES)
    username = random.choice(USERNAMES)
    sitename = random.choice(SITE_NAMES)
    computername = random.choice(COMPUTER_NAMES)
    user_agent = random.choice(USER_AGENTS)
    
    # Generate appropriate byte sizes based on status and method
    if status_code >= 400:
        bytes_sent = random.randint(200, 1000)  # Error pages are smaller
    elif method == "GET":
        bytes_sent = random.randint(1024, 50000)  # Variable content size
    else:
        bytes_sent = random.randint(200, 2000)  # API responses
    
    bytes_received = random.randint(100, 5000) if method in ["POST", "PUT", "PATCH"] else random.randint(50, 500)
    
    event = {
        "timestamp": event_time.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "date": event_time.strftime("%Y-%m-%d"),
        "time": event_time.strftime("%H:%M:%S"),
        "client_ip": generate_ip(),
        "username": username,
        "sitename": sitename,
        "computername": computername,
        "server_ip": generate_server_ip(),
        "server_port": random.choice([80, 443, 8080]),
        "method": method,
        "uri_stem": uri_stem,
        "uri_query": query_string,
        "status_code": status_code,
        "bytes_sent": bytes_sent,
        "bytes_received": bytes_received,
        "user_agent": user_agent,
        "referer": random.choice(["-", "https://google.com", "https://contoso.com"]),
        "cookie": "-",
        "time_taken": random.randint(10, 5000),  # milliseconds
    }
    
    return event

if __name__ == "__main__":
    # Generate sample events
    print("Sample Microsoft IIS W3C Log Events:")
    print("=" * 50)
    for i in range(3):
        print(f"\nEvent {i+1}:")
        print(iis_w3c_log())