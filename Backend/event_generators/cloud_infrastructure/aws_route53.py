#!/usr/bin/env python3
"""
AWS Route 53 event generator
Generates synthetic AWS Route 53 DNS query logs in JSON format
"""
import random
import json
from datetime import datetime, timezone, timedelta

# SentinelOne AI-SIEM specific field attributes
# DNS query types
QUERY_TYPES = ["A", "AAAA", "MX", "NS", "PTR", "SOA", "TXT", "CNAME", "SRV"]

# Response codes
RESPONSE_CODES = [
    "NOERROR",
    "NXDOMAIN", 
    "SERVFAIL",
    "REFUSED",
    "TIMEOUT"
]

# Common domains for corporate environments
DOMAINS = [
    "company.corp",
    "www.company.corp", 
    "api.company.corp",
    "internal.company.corp",
    "services.company.corp",
    "portal.company.corp",
    "google.com",
    "amazonaws.com",
    "microsoft.com",
    "cloudflare.com",
    "github.com",
    "stackoverflow.com",
    "suspicious-domain.org",
    "threat-actor.net",
    "malware-c2.com"
]

# AWS edge locations
EDGE_LOCATIONS = [
    "IAD79-P3", "DFW50-P2", "LAX3-P1", "SEA19-P4", 
    "ORD52-P3", "ATL56-P2", "SFO53-P1", "MIA50-P3"
]

def generate_client_ip() -> str:
    """Generate client IP address"""
    return f"{random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"

def aws_route53_log(overrides: dict = None) -> dict:
    """Generate a single AWS Route 53 DNS event log as dict that can be formatted for parser"""
    now = datetime.now(timezone.utc)
    event_time = now - timedelta(minutes=random.randint(0, 10))
    
    domain = random.choice(DOMAINS)
    query_type = random.choice(QUERY_TYPES)
    response_code = random.choice(RESPONSE_CODES)
    edge_location = random.choice(EDGE_LOCATIONS)
    client_ip = generate_client_ip()
    
    timestamp = event_time.strftime("%Y-%m-%dT%H:%M:%SZ")
    resolver_endpoint_id = f"rslvr-endpt-{random.randint(1000, 9999)}"
    
    # Generate structured event data that hec_sender can format appropriately
    event = {
        "timestamp": timestamp,
        "source": "Route53",
        "queryName": domain,
        "queryType": query_type,
        "clientIp": client_ip,
        "edgeLocation": edge_location,
        "responseCode": response_code,
        "resolverEndpointId": resolver_endpoint_id,
        "version": "1.0",
        "account": "123456789012",
        "region": "us-east-1",
        # Add raw syslog format for parser compatibility
        "_raw": f'{timestamp} Route53 queryName="{domain}" queryType="{query_type}" clientIp="{client_ip}" edgeLocation="{edge_location}" responseCode="{response_code}" resolverEndpointId="{resolver_endpoint_id}"'
    }
    
    # Apply overrides if provided (for scenario customization)
    if overrides:
        if "domain" in overrides:
            event["queryName"] = overrides["domain"]
            domain = overrides["domain"]
        if "query_type" in overrides:
            event["queryType"] = overrides["query_type"]
            query_type = overrides["query_type"]
        if "response_code" in overrides:
            event["responseCode"] = overrides["response_code"]
            response_code = overrides["response_code"]
        if "client_ip" in overrides:
            event["clientIp"] = overrides["client_ip"]
            client_ip = overrides["client_ip"]
        # Update raw format with overridden values
        event["_raw"] = f'{timestamp} Route53 queryName="{domain}" queryType="{query_type}" clientIp="{client_ip}" edgeLocation="{edge_location}" responseCode="{response_code}" resolverEndpointId="{resolver_endpoint_id}"'
    
    return event

if __name__ == "__main__":
    # Generate sample events
    print("Sample AWS Route 53 DNS Events:")
    print("=" * 50)
    for i in range(3):
        print(f"\nEvent {i+1}:")
        print(json.dumps(aws_route53_log(), indent=2))