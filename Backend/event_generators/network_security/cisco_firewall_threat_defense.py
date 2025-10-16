#!/usr/bin/env python3
"""
Cisco Firewall Threat Defense Event Generator
Generates synthetic Cisco FTD syslog events matching official SentinelOne parser format
"""

import random
import time
import json
import uuid
from datetime import datetime, timezone

# SentinelOne AI-SIEM specific field attributes
def cisco_firewall_threat_defense_log():
    """Generate a synthetic Cisco FTD syslog event matching official parser expectations."""
    
    # Official parser expects syslog format with specific event IDs (430001-430005)
    event_types = [
        {
            "id": "430001", 
            "name": "Intrusion event",
            "template": "EventPriority: {priority}, DeviceUUID: {device_uuid}, SrcIP: {src_ip}, DstIP: {dst_ip}, Classification: {classification}"
        },
        {
            "id": "430002",
            "name": "Open", 
            "template": "SrcIP: {src_ip}, DstIP: {dst_ip}, SrcPort: {src_port}, DstPort: {dst_port}, Protocol: {protocol}, User: {user}"
        },
        {
            "id": "430003",
            "name": "Close",
            "template": "SrcIP: {src_ip}, DstIP: {dst_ip}, ConnectionDuration: {duration}, InitiatorBytes: {init_bytes}, ResponderBytes: {resp_bytes}"
        },
        {
            "id": "430004", 
            "name": "File events",
            "template": "FileName: {filename}, FileAction: {action}, FileSHA256: {sha256}, User: {user}, SrcIP: {src_ip}"
        },
        {
            "id": "430005",
            "name": "File malware events", 
            "template": "ThreatName: {threat}, FileName: {filename}, SHA_Disposition: {disposition}, EventPriority: {priority}, SrcIP: {src_ip}"
        }
    ]
    
    # Select random event type
    event_type = random.choice(event_types)
    
    # Generate timestamp in syslog format
    timestamp = datetime.now().strftime("%b %d %H:%M:%S")
    
    # Generate hostname
    hostname = f"ftd-{random.randint(100,999)}"
    
    # Generate field values for template
    field_values = {
        "priority": random.choice(["High", "Medium", "Low"]),
        "device_uuid": str(uuid.uuid4()),
        "src_ip": f"192.168.{random.randint(1,254)}.{random.randint(1,254)}",
        "dst_ip": f"203.0.113.{random.randint(1,254)}",
        "src_port": random.randint(1024, 65535),
        "dst_port": random.choice([80, 443, 22, 25, 53, 993, 8080]),
        "protocol": random.choice(["TCP", "UDP", "ICMP"]),
        "user": f"user{random.randint(1000,9999)}",
        "duration": random.randint(1, 3600),
        "init_bytes": random.randint(100, 50000),
        "resp_bytes": random.randint(50, 25000),
        "filename": random.choice(["malware.exe", "document.pdf", "script.ps1", "payload.dll"]),
        "action": random.choice(["CREATE", "DELETE", "MODIFY", "EXECUTE"]),
        "sha256": f"{random.randint(10**63, 10**64-1):064x}",
        "threat": random.choice(["Trojan.Generic", "Malware.Detected", "Backdoor.Agent", "Virus.Win32"]),
        "disposition": random.choice(["MALICIOUS", "CLEAN", "UNKNOWN"]),
        "classification": random.choice(["trojan-activity", "policy-violation", "attempted-recon"])
    }
    
    # Format the event message
    event_message = event_type["template"].format(**field_values)
    
    # Generate proper Cisco FTD syslog format
    # Format: <priority>timestamp hostname : FTD-1-eventid: message
    priority = 165  # Local use facility (20) + Notice severity (5) = 20*8 + 5 = 165
    
    raw_log = f"<{priority}>{timestamp} {hostname} : FTD-1-{event_type['id']}: {event_message}"
    
    # Return in format expected by HEC sender
    return {
        "raw": raw_log,
        "timestamp": datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z'),
        "vendor": "Cisco",
        "product": "Firewall Threat Defense",
        "event_type": event_type["name"],
        "event_id": f"FTD-1-{event_type['id']}",
        "hostname": hostname,
        # Include some key fields for testing
        "src_ip": field_values["src_ip"],
        "dst_ip": field_values["dst_ip"],
        "user": field_values.get("user", ""),
        "device_uuid": field_values["device_uuid"]
    }

if __name__ == "__main__":
    # Generate and print sample events for each type
    print("Cisco FTD Official Parser Format Examples:")
    print("=" * 60)
    
    for i in range(5):
        event = cisco_firewall_threat_defense_log()
        print(f"\nEvent {i+1}:")
        print(f"Raw: {event['raw']}")
        print(f"Type: {event['event_type']}")
        print(f"ID: {event['event_id']}")