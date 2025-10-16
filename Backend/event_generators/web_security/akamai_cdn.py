#!/usr/bin/env python3
"""
Akamai CDN access log event generator
Generates synthetic Akamai CDN logs in syslog format
"""
import random
from datetime import datetime, timezone, timedelta

# SentinelOne AI-SIEM specific field attributes
# HTTP methods
HTTP_METHODS = ["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH"]

# Status codes
STATUS_CODES = [200, 301, 302, 304, 400, 401, 403, 404, 500, 502, 503]

# Cache statuses
CACHE_STATUSES = ["HIT", "MISS", "REFRESH_HIT", "REFRESH_MISS", "TCP_MISS", "TCP_HIT"]

# Hostnames
HOSTNAMES = [
    "www.example.com", "api.example.com", "cdn.example.com", 
    "assets.example.com", "static.example.com", "img.example.com"
]

# Paths
PATHS = [
    "/index.html", "/api/v1/users", "/images/logo.png", "/css/style.css",
    "/js/app.js", "/favicon.ico", "/robots.txt", "/sitemap.xml",
    "/assets/image.jpg", "/downloads/file.pdf"
]

# Countries
COUNTRIES = ["US", "CA", "GB", "DE", "FR", "JP", "AU", "BR", "IN", "MX"]

# Cities
CITIES = ["Seattle", "New York", "London", "Tokyo", "Sydney", "Berlin", "Paris", "Toronto"]

def generate_ip() -> str:
    """Generate client IP address"""
    return f"{random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"

def generate_edge_ip() -> str:
    """Generate edge server IP address"""
    return f"{random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"

def akamai_cdn_log() -> str:
    """Generate a single Akamai CDN access log in syslog format"""
    now = datetime.now(timezone.utc)
    event_time = now - timedelta(minutes=random.randint(0, 1440))
    
    timestamp = event_time.strftime("%Y-%m-%dT%H:%M:%SZ")
    stream_id = f"stream-{random.randint(100, 999)}"
    cp = str(random.randint(10000, 99999))
    req_id = f"{''.join(random.choices('abcdefghijklmnopqrstuvwxyz0123456789', k=10))}"
    status_code = random.choice(STATUS_CODES)
    client_ip = generate_ip()
    req_host = random.choice(HOSTNAMES)
    req_method = random.choice(HTTP_METHODS)
    req_path = random.choice(PATHS)
    byte_size = random.randint(1024, 1048576)  # 1KB to 1MB
    cache_status = random.choice(CACHE_STATUSES)
    turnaround_time = random.randint(10, 500)
    edge_ip = generate_edge_ip()
    country = random.choice(COUNTRIES)
    city = random.choice(CITIES)
    
    # Generate syslog format matching the original test event
    log = (f'{timestamp} AkamaiCDN streamId="{stream_id}" cp="{cp}" '
           f'reqId="{req_id}" statusCode={status_code} cliIP="{client_ip}" '
           f'reqHost="{req_host}" reqMethod="{req_method}" reqPath="{req_path}" '
           f'bytes={byte_size} cacheStatus="{cache_status}" '
           f'turnAroundTimeMSec={turnaround_time} edgeIP="{edge_ip}" '
           f'country="{country}" city="{city}"')
    
    return log

if __name__ == "__main__":
    # Generate sample events
    print("Sample Akamai CDN Events:")
    print("=" * 50)
    for i in range(3):
        print(f"\nEvent {i+1}:")
        print(akamai_cdn_log())