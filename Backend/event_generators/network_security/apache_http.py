#!/usr/bin/env python3
"""Generate synthetic Apache HTTP Server access logs."""
import json
import random
from datetime import datetime, timezone

# Apache Common Log Format (CLF) / Combined Log Format

METHODS = ["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH"]
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0",
    "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
    "Python-urllib/3.8",
    "curl/7.68.0",
]

PATHS = [
    "/", "/index.html", "/about.html", "/contact.html", "/products", "/services",
    "/api/v1/users", "/api/v1/products", "/api/v1/orders", "/api/health",
    "/login", "/logout", "/dashboard", "/profile", "/settings",
    "/images/logo.png", "/css/style.css", "/js/app.js", "/favicon.ico",
    "/admin", "/wp-admin", "/phpmyadmin", "/.env", "/config.php",  # Common attack paths
    "/search?q=test", "/product?id=123", "/user?name=john",
]

STATUS_CODES = [
    (200, 70),  # OK - most common
    (301, 5),   # Moved Permanently
    (302, 5),   # Found
    (304, 10),  # Not Modified
    (400, 3),   # Bad Request
    (401, 2),   # Unauthorized
    (403, 2),   # Forbidden
    (404, 5),   # Not Found
    (500, 2),   # Internal Server Error
    (503, 1),   # Service Unavailable
]

def get_random_ip():
    """Generate a random IP address."""
    if random.random() < 0.8:  # 80% internal IPs
        return f"10.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"
    else:  # 20% external IPs
        return f"{random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"

def get_response_size(status_code, path):
    """Get appropriate response size based on status and path."""
    if status_code == 304:
        return 0
    elif status_code >= 400:
        return random.randint(200, 500)
    elif path.endswith(('.png', '.jpg', '.jpeg', '.gif')):
        return random.randint(10000, 500000)
    elif path.endswith(('.css', '.js')):
        return random.randint(1000, 50000)
    else:
        return random.randint(200, 10000)

def apache_http_log(overrides: dict | None = None) -> str:
    """Generate a single Apache HTTP access log entry in Common Log Format."""
    now = datetime.now(timezone.utc)
    
    # Select status code based on weights
    status_code = random.choices(
        [code for code, _ in STATUS_CODES],
        weights=[weight for _, weight in STATUS_CODES]
    )[0]
    
    method = random.choice(METHODS)
    path = random.choice(PATHS)
    
    # Generate Apache Common Log Format components
    src_ip = get_random_ip()
    user_name = "-" if random.random() < 0.95 else f"user{random.randint(1, 100)}"
    timestamp = now.strftime("%d/%b/%Y:%H:%M:%S +0000")
    http_version = "HTTP/1.1" if random.random() < 0.95 else "HTTP/2.0"
    response_size = get_response_size(status_code, path)
    
    # Build Apache Common Log Format
    # Format: IP - user [timestamp] "METHOD path HTTP/version" status size
    log_entry = f'{src_ip} - {user_name} [{timestamp}] "{method} {path} {http_version}" {status_code} {response_size}'
    
    # Apply simple overrides (limited for text format)
    if overrides:
        # For text format, we can only do simple string replacements
        if "status_code" in overrides:
            log_entry = log_entry.replace(str(status_code), str(overrides["status_code"]))
        if "method" in overrides:
            log_entry = log_entry.replace(method, overrides["method"])
    
    return log_entry

# OCSF-style attributes for HEC
if __name__ == "__main__":
    # Generate sample logs
    for _ in range(5):
        print(apache_http_log())