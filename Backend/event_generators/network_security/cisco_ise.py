#!/usr/bin/env python3
"""
Cisco ISE (Identity Services Engine) event generator
Generates synthetic Cisco ISE authentication and authorization events
"""
import json
import random
import time
import hashlib
from datetime import datetime, timezone, timedelta
from typing import Dict

# Authentication results
AUTH_RESULTS = [
    ("Passed", "User authentication succeeded"),
    ("Failed", "Authentication failed"),
    ("Failed", "User not found"),
    ("Failed", "Wrong password"),
    ("Failed", "Account disabled"),
    ("Failed", "Certificate expired"),
    ("Passed", "Guest authentication succeeded"),
    ("Passed", "Machine authentication succeeded")
]

# Endpoint types
ENDPOINT_TYPES = ["Windows", "Mac", "iPhone", "Android", "Linux", "Unknown"]

# Network access devices
NAD_TYPES = ["WirelessController", "Switch", "VPN", "Router"]

# Protocols
PROTOCOLS = ["RADIUS", "TACACS+", "802.1X", "MAB"]

# Posture statuses
POSTURE_STATUS = ["Compliant", "NonCompliant", "Unknown", "NotApplicable"]

# Locations
LOCATIONS = ["HQ-Building-A", "HQ-Building-B", "Branch-NYC", "Branch-LON", "Remote-VPN"]

def generate_mac_address() -> str:
    """Generate a random MAC address"""
    return ":".join([f"{random.randint(0, 255):02x}" for _ in range(6)])

def generate_ip() -> str:
    """Generate a random IP address"""
    return f"10.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"

def cisco_ise_log() -> str:
    """Generate a single Cisco ISE event log"""
    now = datetime.now(timezone.utc)
    event_time = now - timedelta(minutes=random.randint(0, 1440))
    
    # Select authentication result
    auth_result, failure_reason = random.choice(AUTH_RESULTS)
    
    # Generate event data
    event = {
        "EventTimestamp": event_time.isoformat(),
        "MessageCode": random.choice(["5200", "5201", "5231", "5400", "5401", "5440"]),
        "ACSServer": f"ise-psn-{random.randint(1, 3)}",
        "AccessService": random.choice(["Default Network Access", "Guest Access", "BYOD", "Device Admin"]),
        "UserName": f"user{random.randint(1, 100)}@company.com" if "Machine" not in failure_reason else f"host/{random.choice(['PC', 'LAPTOP'])}-{random.randint(100, 999)}",
        "IdentityGroup": random.choice(["Employees", "Contractors", "Guests", "IT-Admins", "Executives"]),
        "NetworkDeviceName": f"nad-{random.choice(NAD_TYPES).lower()}-{random.randint(1, 10)}",
        "NetworkDeviceGroups": f"Location#{random.choice(LOCATIONS)}#Device Type#{random.choice(NAD_TYPES)}",
        "AuthenticationMethod": random.choice(["PEAP(EAP-MSCHAPv2)", "EAP-TLS", "MAB", "PEAP(EAP-TLS)", "Web Authentication"]),
        "AuthenticationResult": auth_result,
        "FailureReason": failure_reason if auth_result == "Failed" else "",
        "Protocol": random.choice(PROTOCOLS),
        "FramedIPAddress": generate_ip(),
        "NASIPAddress": generate_ip(),
        "NASPortType": random.choice(["Wireless - IEEE 802.11", "Ethernet", "Virtual", "Async"]),
        "NASPortId": f"GigabitEthernet1/0/{random.randint(1, 48)}",
        "CallingStationID": generate_mac_address(),
        "CalledStationID": f"{generate_mac_address()}:CORP-WIFI",
        "AuthorizationPolicyMatchedRule": random.choice(["Corp-WiFi-Access", "Guest-Internet-Only", "Quarantine-Policy", "Full-Access"]) if auth_result == "Passed" else "",
        "PostureStatus": random.choice(POSTURE_STATUS) if auth_result == "Passed" else "Unknown",
        "EndpointProfile": random.choice(["Windows10-Workstation", "Apple-iPhone", "Apple-MacBookPro", "Android-Device", "Unknown"]),
        "DeviceType": random.choice(ENDPOINT_TYPES),
        "SSID": random.choice(["CORP-WIFI", "GUEST-WIFI", "BYOD-WIFI", "IOT-NETWORK"]),
        "SessionID": hashlib.md5(f"{event_time.timestamp()}".encode()).hexdigest(),
        "AuthenticationLatency": random.randint(10, 500),  # milliseconds
        "RadiusPacketType": random.choice(["Access-Request", "Access-Accept", "Access-Reject", "Access-Challenge"]),
        "ISEPolicySetName": random.choice(["Wired_802.1X", "Wireless_802.1X", "VPN_Access", "Guest_Access"]),
        "Location": random.choice(LOCATIONS),
        "DeviceRegistrationStatus": random.choice(["Registered", "NotRegistered", "Pending"]),
        "MDMServerName": random.choice(["", "Intune", "AirWatch", "MobileIron"]),
        "MDMComplianceStatus": random.choice(["Compliant", "NonCompliant", "NotApplicable"])
    }
    
    # Add VLAN assignment for successful authentications
    if auth_result == "Passed":
        event["VLAN"] = random.choice(["10", "20", "30", "99", "100"])
        event["DACLName"] = random.choice(["", "RESTRICT_ACCESS", "QUARANTINE_ACL", "EMPLOYEE_ACL"])
    
    # Add threat indicators for failed authentications
    if auth_result == "Failed":
        event["FailedAttempts"] = random.randint(1, 10)
        event["ThreatLevel"] = "High" if event["FailedAttempts"] > 5 else "Medium"
    
    return json.dumps(event)

if __name__ == "__main__":
    # Generate sample events
    print("Sample Cisco ISE Events:")
    print("=" * 50)
    for i in range(3):
        print(f"\nEvent {i+1}:")
        print(cisco_ise_log())