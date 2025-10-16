#!/usr/bin/env python3
"""
Infoblox DDI Event Generator
Generates synthetic Infoblox DNS/DHCP/IP management events for testing
"""

import random
import time
import json
from datetime import datetime, timezone

# SentinelOne AI-SIEM specific field attributes
def infoblox_ddi_log():
    """Generate a synthetic Infoblox DDI log event."""
    
    # Infoblox supports DNS, DHCP, and IPAM events
    event_types = [
        {
            "type": "DNS_QUERY",
            "template": "client {client_ip}#{client_port}: query: {domain} IN {record_type} +{flags} ({server_ip})",
            "fields": {
                "record_type": ["A", "AAAA", "PTR", "MX", "CNAME", "TXT"],
                "flags": ["E", "T", "RD", "RA"],
                "domain": ["example.com", "malicious-domain.net", "internal.local", "cdn.amazonaws.com"]
            }
        },
        {
            "type": "DNS_RESPONSE", 
            "template": "client {client_ip}#{client_port}: query response: {domain} IN {record_type} {response_code} {response_ip}",
            "fields": {
                "response_code": ["NOERROR", "NXDOMAIN", "SERVFAIL", "REFUSED"],
                "record_type": ["A", "AAAA", "PTR", "MX"],
                "domain": ["example.com", "blocked-malware.org", "phishing-site.net"]
            }
        },
        {
            "type": "DHCP_LEASE",
            "template": "DHCPACK on {assigned_ip} to {mac_address} ({hostname}) via {interface}",
            "fields": {
                "hostname": ["workstation-01", "server-web", "laptop-user", "printer-hp"],
                "interface": ["eth0", "vlan100", "mgmt0"]
            }
        },
        {
            "type": "DHCP_RELEASE",
            "template": "DHCPRELEASE of {assigned_ip} from {mac_address} ({hostname}) via {interface}",
            "fields": {
                "hostname": ["workstation-01", "server-web", "laptop-user"],
                "interface": ["eth0", "vlan100"]
            }
        }
    ]
    
    # Select random event type
    event_type = random.choice(event_types)
    
    # Generate timestamp
    timestamp = datetime.now().strftime("%d-%b-%Y %H:%M:%S.%f")[:-3]
    
    # Generate common field values
    field_values = {
        "client_ip": f"192.168.{random.randint(1,254)}.{random.randint(1,254)}",
        "client_port": random.randint(32768, 65535),
        "server_ip": f"10.0.{random.randint(1,10)}.{random.randint(1,10)}",
        "assigned_ip": f"192.168.100.{random.randint(1,254)}",
        "mac_address": ":".join([f"{random.randint(0,255):02x}" for _ in range(6)]),
        "response_ip": f"203.0.113.{random.randint(1,254)}"
    }
    
    # Add event-specific field values
    if "fields" in event_type:
        for field, options in event_type["fields"].items():
            field_values[field] = random.choice(options)
    
    # Format the log message
    log_message = event_type["template"].format(**field_values)
    
    # Infoblox log format: timestamp hostname service[pid]: message
    hostname = f"infoblox-{random.randint(10,99)}"
    service = "named" if event_type["type"].startswith("DNS") else "dhcpd"
    pid = random.randint(1000, 9999)
    
    raw_log = f"{timestamp} {hostname} {service}[{pid}]: {log_message}"
    
    return {
        "raw": raw_log,
        "timestamp": datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z'),
        "vendor": "Infoblox",
        "product": "DDI",
        "event_type": event_type["type"],
        "service": service,
        "hostname": hostname,
        "client_ip": field_values.get("client_ip"),
        "server_ip": field_values.get("server_ip"),
        "domain": field_values.get("domain", ""),
        "assigned_ip": field_values.get("assigned_ip", "")
    }

if __name__ == "__main__":
    # Generate and print sample events
    print("Infoblox DDI Log Examples:")
    print("=" * 40)
    
    for i in range(4):
        event = infoblox_ddi_log()
        print(f"\nEvent {i+1} ({event['event_type']}):")
        print(f"Raw: {event['raw']}")
        print(f"Service: {event['service']}")
        if event.get('domain'):
            print(f"Domain: {event['domain']}")
        if event.get('assigned_ip'):
            print(f"IP: {event['assigned_ip']}")