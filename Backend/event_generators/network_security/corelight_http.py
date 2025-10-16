#!/usr/bin/env python3
"""
Corelight HTTP Logs event generator (JSON format)
Generates Zeek/Corelight HTTP activity events
"""
from __future__ import annotations
import json
import random
import time
import uuid
from datetime import datetime, timezone, timedelta
from typing import Dict, List

# HTTP methods
HTTP_METHODS = ["GET", "POST", "HEAD", "PUT", "DELETE", "OPTIONS", "CONNECT", "PATCH"]

# HTTP versions
HTTP_VERSIONS = ["1.0", "1.1", "2.0"]

# Status codes
STATUS_CODES = [200, 301, 302, 304, 400, 401, 403, 404, 405, 500, 502, 503]

# User agents
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/91.0.864.59",
    "curl/7.68.0",
    "python-requests/2.25.1",
    "Go-http-client/2.0",
    "Java/11.0.11",
    "Wget/1.20.3 (linux-gnu)"
]

# Common hosts
HOSTS = [
    "www.example.com", "api.example.com", "cdn.example.com",
    "www.google.com", "www.github.com", "www.stackoverflow.com",
    "update.microsoft.com", "api.slack.com", "www.amazon.com",
    "internal.corp.local", "app.internal.local", "db.internal.local"
]

# Common URIs
URIS = [
    "/", "/index.html", "/api/v1/users", "/api/v1/login", "/api/v1/data",
    "/static/css/main.css", "/static/js/app.js", "/images/logo.png",
    "/search", "/products", "/cart", "/checkout", "/account/profile",
    "/admin/dashboard", "/wp-admin", "/phpmyadmin", "/.git/config",
    "/api/health", "/metrics", "/status", "/version"
]

# Referrers
REFERRERS = [
    "-",
    "https://www.google.com/",
    "https://www.bing.com/",
    "https://www.example.com/",
    "https://www.example.com/products",
    "https://internal.corp.local/dashboard"
]

def _generate_ip(internal: bool = True) -> str:
    """Generate an IP address"""
    if internal:
        return random.choice([
            f"10.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}",
            f"172.{random.randint(16, 31)}.{random.randint(0, 255)}.{random.randint(1, 254)}",
            f"192.168.{random.randint(0, 255)}.{random.randint(1, 254)}"
        ])
    else:
        return f"{random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"

def _generate_uid() -> str:
    """Generate a Zeek connection UID"""
    chars = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
    return 'C' + ''.join(random.choices(chars, k=17))

def corelight_http_log(overrides: dict | None = None) -> Dict:
    """
    Return a single Corelight HTTP log event as JSON string.
    
    Pass `overrides` to force any field to a specific value:
        corelight_http_log({"method": "POST", "status_code": 200})
    """
    # Generate timestamps
    now = datetime.now(timezone.utc)
    timestamp = now - timedelta(seconds=random.randint(0, 300))
    
    # Select method and URI
    method = random.choice(HTTP_METHODS)
    uri = random.choice(URIS)
    host = random.choice(HOSTS)
    
    # Determine status code based on URI
    if uri in ["/.git/config", "/wp-admin", "/phpmyadmin"] and random.random() < 0.8:
        # Suspicious URIs often get 404 or 403
        status_code = random.choice([403, 404])
    elif method == "POST" and "/api/" in uri:
        # API POSTs might fail sometimes
        status_code = random.choices(
            [200, 201, 400, 401, 500],
            weights=[0.6, 0.2, 0.1, 0.05, 0.05]
        )[0]
    else:
        # Normal traffic
        status_code = random.choices(
            STATUS_CODES,
            weights=[0.5, 0.05, 0.05, 0.1, 0.05, 0.02, 0.03, 0.1, 0.02, 0.03, 0.02, 0.03]
        )[0]
    
    # Generate request/response sizes based on method and URI
    if method == "GET":
        request_body_len = 0
        if uri.endswith(('.css', '.js', '.png', '.jpg')):
            response_body_len = random.randint(1000, 100000)
        else:
            response_body_len = random.randint(200, 50000)
    elif method == "POST":
        request_body_len = random.randint(50, 5000)
        response_body_len = random.randint(20, 1000) if status_code < 400 else random.randint(20, 500)
    else:
        request_body_len = random.randint(0, 500)
        response_body_len = random.randint(0, 1000)
    
    # Determine if internal or external
    is_internal = "internal" in host or random.random() < 0.3
    
    event = {
        "ts": timestamp.timestamp(),
        "uid": _generate_uid(),
        "id": {
            "orig_h": _generate_ip(internal=True),
            "orig_p": random.randint(1024, 65535),
            "resp_h": _generate_ip(internal=is_internal),
            "resp_p": 443 if "https" in host or random.random() < 0.7 else 80
        },
        "trans_depth": 1,
        "method": method,
        "host": host,
        "uri": uri,
        "referrer": random.choice(REFERRERS),
        "version": random.choice(HTTP_VERSIONS),
        "user_agent": random.choice(USER_AGENTS),
        "request_body_len": request_body_len,
        "response_body_len": response_body_len,
        "status_code": status_code,
        "status_msg": _get_status_msg(status_code),
        "tags": []
    }
    
    # Add optional fields
    if random.random() < 0.3:
        event["username"] = "-"
        event["password"] = "-"
    
    if random.random() < 0.2:
        event["orig_fuids"] = [f"F{_generate_uid()[1:]}"]
        event["orig_filenames"] = ["upload.txt"] if method == "POST" else []
    
    if random.random() < 0.2:
        event["resp_fuids"] = [f"F{_generate_uid()[1:]}"]
        event["resp_filenames"] = []
    
    # Add MIME types for responses
    if uri.endswith('.html') or uri == '/':
        event["resp_mime_types"] = ["text/html"]
    elif uri.endswith('.json') or '/api/' in uri:
        event["resp_mime_types"] = ["application/json"]
    elif uri.endswith('.css'):
        event["resp_mime_types"] = ["text/css"]
    elif uri.endswith('.js'):
        event["resp_mime_types"] = ["application/javascript"]
    elif uri.endswith('.png'):
        event["resp_mime_types"] = ["image/png"]
    elif uri.endswith('.jpg'):
        event["resp_mime_types"] = ["image/jpeg"]
    
    # Apply any overrides
    if overrides:
        event.update(overrides)
    
    return event

def _get_status_msg(status_code: int) -> str:
    """Get HTTP status message"""
    status_msgs = {
        200: "OK",
        201: "Created",
        301: "Moved Permanently",
        302: "Found",
        304: "Not Modified",
        400: "Bad Request",
        401: "Unauthorized",
        403: "Forbidden",
        404: "Not Found",
        405: "Method Not Allowed",
        500: "Internal Server Error",
        502: "Bad Gateway",
        503: "Service Unavailable"
    }
    return status_msgs.get(status_code, "Unknown")

if __name__ == "__main__":
    # Generate sample logs
    print("Sample Corelight HTTP logs:")
    for i in range(3):
        print(corelight_http_log())
        print()