#!/usr/bin/env python3
"""
FortiManager Event Generator
Generates synthetic FortiManager management and audit events for testing
"""

import random
import time
import json
from datetime import datetime, timezone

# SentinelOne AI-SIEM specific field attributes
def fortimanager_log():
    """Generate a synthetic FortiManager log event."""
    
    # FortiManager event types
    event_types = [
        {
            "type": "CONFIG_CHANGE",
            "template": "user={user} ui={ui} action=config_changed object={object_type} objname={object_name} msg='{description}'",
            "objects": ["firewall.policy", "system.admin", "vpn.ipsec", "system.interface", "antivirus.profile"],
            "descriptions": [
                "Policy rule modified",
                "Administrator account updated", 
                "VPN tunnel configuration changed",
                "Interface settings updated",
                "Antivirus profile modified"
            ]
        },
        {
            "type": "LOGIN_ATTEMPT",
            "template": "user={user} ui={ui} action={action} status={status} reason='{reason}' srcip={src_ip}",
            "actions": ["login", "logout"],
            "statuses": ["success", "failed"],
            "reasons": [
                "Valid credentials",
                "Invalid password",
                "Account locked",
                "Session timeout",
                "Two-factor authentication required"
            ]
        },
        {
            "type": "POLICY_INSTALL",
            "template": "user={user} ui={ui} action=policy_install target={target_device} status={status} msg='Policy package {package_name} installed'",
            "statuses": ["success", "failed", "partial"],
            "packages": ["Standard_Policy", "Security_Policy", "Branch_Policy", "DMZ_Policy"]
        },
        {
            "type": "DEVICE_REGISTRATION",
            "template": "action=device_register device={device_name} serial={serial} status={status} ip={device_ip}",
            "statuses": ["registered", "unregistered", "pending"],
            "device_types": ["FortiGate", "FortiWiFi", "FortiSwitch", "FortiAP"]
        }
    ]
    
    # Select random event type
    event_type = random.choice(event_types)
    
    # Generate field values
    field_values = {
        "user": random.choice(["admin", "security_admin", "readonly_user", "policy_manager"]),
        "ui": random.choice(["GUI", "CLI", "API", "SSH"]),
        "src_ip": f"192.168.{random.randint(1,254)}.{random.randint(1,254)}",
        "target_device": f"FGT-{random.randint(100,999)}",
        "device_name": f"{random.choice(event_type.get('device_types', ['FortiGate']))}-{random.randint(10,99)}",
        "device_ip": f"10.0.{random.randint(1,254)}.{random.randint(1,254)}",
        "serial": f"FG{random.randint(100000, 999999)}",
        "object_type": random.choice(event_type.get("objects", ["system.config"])),
        "object_name": f"rule_{random.randint(1,100)}",
        "package_name": random.choice(event_type.get("packages", ["Default_Policy"])),
        "action": random.choice(event_type.get("actions", ["modify"])),
        "status": random.choice(event_type.get("statuses", ["success"])),
        "reason": random.choice(event_type.get("reasons", ["Operation completed"])),
        "description": random.choice(event_type.get("descriptions", ["Configuration updated"]))
    }
    
    # Format the log message
    log_message = event_type["template"].format(**field_values)
    
    # Generate FortiManager syslog format
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    hostname = f"FortiManager-{random.randint(10,99)}"
    
    # FortiManager log format: timestamp hostname FortiManager: log_message
    raw_log = f"{timestamp} {hostname} FortiManager: {log_message}"
    
    return {
        "raw": raw_log,
        "timestamp": datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z'),
        "vendor": "Fortinet",
        "product": "FortiManager",
        "event_type": event_type["type"],
        "user": field_values["user"],
        "ui": field_values["ui"],
        "src_ip": field_values["src_ip"],
        "status": field_values["status"],
        "hostname": hostname
    }

if __name__ == "__main__":
    # Generate and print sample events
    print("FortiManager Log Examples:")
    print("=" * 40)
    
    for i in range(4):
        event = fortimanager_log()
        print(f"\nEvent {i+1} ({event['event_type']}):")
        print(f"Raw: {event['raw']}")
        print(f"User: {event['user']} via {event['ui']}")
        print(f"Status: {event['status']}")