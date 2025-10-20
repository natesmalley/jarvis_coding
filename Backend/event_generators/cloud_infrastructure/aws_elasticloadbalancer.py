#!/usr/bin/env python3
"""
AWS Elastic Load Balancer Logs Event Generator
Generates synthetic AWS Application Load Balancer access logs for testing
Produces events compatible with SentinelOne AWS ELB parser
"""

import random
import time
import json
from datetime import datetime, timezone

def aws_elasticloadbalancer_log():
    """Generate a synthetic AWS Elastic Load Balancer access log event."""
    
    # Corporate client IPs
    client_ips = [
        "192.168.1.100",  # Corporate HQ
        "10.0.1.50",      # Branch Office
        "172.16.2.75",    # Data Center
        "192.168.10.200", # Remote Office
        "10.1.1.25"       # Mobile Users
    ]
    
    backend_ips = [
        "10.0.0.100",
        "10.0.0.101", 
        "10.0.0.102",
        "172.16.1.50",
        "172.16.1.51"
    ]
    
    user_agents = [
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Corporate-Browser/1.0",
        "Corporate-Mobile-App/2.3.1 (Business; Android 12)",
        "Corporate-API-Client/1.5.0",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) BusinessApp/3.0",
        "Corporate-Security-Scanner/4.2.1"
    ]
    
    http_methods = ["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS"]
    
    request_urls = [
        "https://company.corp/",
        "https://company.corp/api/employees/roster",
        "https://company.corp/systems/monitoring",
        "https://company.corp/security/alerts",
        "https://company.corp/hr/records",
        "https://company.corp/analytics/dashboard",
        "https://company.corp/communications/portal"
    ]
    
    status_codes = [200, 201, 204, 301, 302, 400, 401, 403, 404, 500, 502, 503]
    
    ssl_ciphers = [
        "ECDHE-RSA-AES128-GCM-SHA256",
        "ECDHE-RSA-AES256-GCM-SHA384", 
        "ECDHE-RSA-CHACHA20-POLY1305",
        "AES128-GCM-SHA256",
        "AES256-GCM-SHA384"
    ]
    
    # Generate timestamp in ISO format (recent)
    now = datetime.now(timezone.utc)
    timestamp = now.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    
    # Generate ALB-specific event
    event = {
        "type": random.choice(["http", "https"]),
        "time": timestamp,
        "alb": f"corporate-alb-{random.randint(1,3)}",
        "client_ip": random.choice(client_ips),
        "client_port": random.randint(32768, 65535),
        "backend_ip": random.choice(backend_ips),
        "backend_port": random.choice([80, 443, 8080, 8443, 9000]),
        "request_processing_time": round(random.uniform(0.001, 0.050), 6),
        "backend_processing_time": round(random.uniform(0.010, 0.500), 6),
        "response_processing_time": round(random.uniform(0.001, 0.020), 6),
        "alb_status_code": random.choice(status_codes),
        "backend_status_code": random.choice(status_codes),
        "received_bytes": random.randint(100, 5000),
        "sent_bytes": random.randint(200, 15000),
        "request_verb": random.choice(http_methods),
        "request_url": random.choice(request_urls),
        "request_proto": "HTTP/1.1",
        "user_agent": random.choice(user_agents),
        "ssl_cipher": random.choice(ssl_ciphers),
        "ssl_protocol": random.choice(["TLSv1.2", "TLSv1.3"]),
        "target_group_arn": f"arn:aws:elasticloadbalancing:us-east-1:123456789012:targetgroup/corporate-tg-{random.randint(1,5)}/{''.join(random.choices('abcdef0123456789', k=16))}",
        "trace_id": f"Root=1-{''.join(random.choices('abcdef0123456789', k=8))}-{''.join(random.choices('abcdef0123456789', k=24))}",
        "domain_name": "company.corp",
        "chosen_cert_arn": f"arn:aws:acm:us-east-1:123456789012:certificate/{''.join(random.choices('abcdef0123456789-', k=36))}",
        "matched_rule_priority": random.randint(1, 100),
        "request_creation_time": timestamp,
        "actions_executed": random.choice(["forward", "redirect", "fixed-response"]),
        "redirect_url": random.choice(["-", "https://company.corp/login"]),
        "error_reason": random.choice(["-", "TargetNotFound", "TargetTimeout", "LBConnectTimeout"]),
        "target:port_list": f"{random.choice(backend_ips)}:{random.choice([80, 443, 8080])}",
        "target_status_code_list": str(random.choice(status_codes)),
        "classification": random.choice(["Normal", "Desync"]),
        "classification_reason": random.choice(["-", "HeaderValueInvalid", "RequestLineInvalid"])
    }
    
    return event

if __name__ == "__main__":
    # Generate and print sample event
    event = aws_elasticloadbalancer_log()
    print(json.dumps(event, indent=2))
