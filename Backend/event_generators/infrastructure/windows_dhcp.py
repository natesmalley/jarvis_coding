#!/usr/bin/env python3
"""
Windows DHCP Server event generator
Generates DHCP server log events in CSV format
"""
from __future__ import annotations
import random
import time
from datetime import datetime, timezone, timedelta
from typing import Dict, List

# DHCP Event IDs and descriptions
DHCP_EVENTS = {
    10: "DNS Update Request",
    11: "DNS Update Successful", 
    12: "DNS Update Failed",
    13: "DNS Update Not Requested",
    20: "Database Cleanup Begin",
    21: "Database Cleanup End", 
    22: "Database Cleanup Failed",
    23: "IP Address Cleanup Begin",
    24: "IP Address Cleanup End",
    30: "DNS Update Request (IPv6)",
    31: "DNS Update Successful (IPv6)",
    32: "DNS Update Failed (IPv6)",
    33: "Packet Drop",
    34: "Address Conflict",
    35: "Declined DHCP Request",
    36: "Address Release",
    50: "Unreachable Domain",
    51: "Authorized Server List Updated",
    52: "Unauthorized DHCP Server",
    53: "Authorization Successful",
    54: "Authorization Failed",
    55: "Authorization Revoked",
    56: "Address Already in Use",
    57: "Dynamic DNS Registration Failed - Full Zone",
    58: "Dynamic DNS Registration Successful - Full Zone", 
    59: "Dynamic DNS Registration Failed - Secure Zone",
    60: "Dynamic DNS Registration Successful - Secure Zone"
}

# DHCP lease operations
LEASE_OPERATIONS = [
    "Assign", "Renew", "Release", "Decline", "NAK", "Request", "Discover", "Offer", "Inform"
]

# Hostnames and device types
HOSTNAMES = [
    "DESKTOP-ABC123", "LAPTOP-XYZ789", "WORKSTATION-001", "SERVER-DB01", 
    "PRINTER-HP001", "PHONE-CISCO", "TABLET-IPAD", "IOT-SENSOR", "CAMERA-SEC",
    "SWITCH-CORE", "AP-WIFI001", "DEV-MACHINE", "TEST-CLIENT", "GUEST-DEVICE"
]

# Vendor classes
VENDOR_CLASSES = [
    ("MSFT 5.0", "4D534654203530"),  # Microsoft Windows
    ("PXEClient", "505845436C69656E74"),  # PXE Boot Client
    ("android-dhcp", "616E64726F69642D64686370"),  # Android
    ("iPhone", "6950686F6E65"),  # Apple iPhone
    ("Cisco Systems", "436973636F2053797374656D73"),  # Cisco
    ("HP JetDirect", "4850204A657444697265637420"),  # HP Printer
    ("DHCP Vendor Class", "4448435020456E64706F696E74")  # Generic
]

# User classes and DNS error codes
USER_CLASSES = ["User", "Employee", "Guest", "Admin", "Service", "Device"]
DNS_ERROR_CODES = [0, 1, 2, 5, 9, 10, 13, 14, 15]

def _generate_ip() -> str:
    """Generate internal IP address"""
    return f"192.168.{random.randint(1, 10)}.{random.randint(10, 254)}"

def _generate_ipv6() -> str:
    """Generate IPv6 address"""
    return f"2001:db8:{random.randint(1000, 9999):04x}::{random.randint(1, 65535):04x}"

def _generate_mac() -> str:
    """Generate MAC address"""
    return ":".join([f"{random.randint(0, 255):02x}" for _ in range(6)])

def _generate_transaction_id() -> str:
    """Generate DHCP transaction ID"""
    return f"{random.randint(0, 4294967295):08x}"

def _generate_duid() -> str:
    """Generate DHCP Unique Identifier"""
    return ''.join([f"{random.randint(0, 255):02x}" for _ in range(random.randint(6, 20))])

def windows_dhcp_log(overrides: dict | None = None) -> str:
    """
    Return a single Windows DHCP log event as CSV string.
    
    Pass `overrides` to force any field to a specific value:
        windows_dhcp_log({"eventId": "10"})
    """
    now = datetime.now()
    event_time = now - timedelta(seconds=random.randint(0, 300))
    
    # Select event type
    event_id = random.choice(list(DHCP_EVENTS.keys()))
    description = DHCP_EVENTS[event_id]
    
    # Determine if IPv6 event
    is_ipv6 = event_id in [30, 31, 32] or random.random() < 0.1
    
    # Generate network details
    ip_address = _generate_ipv6() if is_ipv6 else _generate_ip()
    hostname = random.choice(HOSTNAMES)
    mac_address = _generate_mac()
    username = random.choice(["", f"CORP\\user{random.randint(1, 100)}", f"guest{random.randint(1, 50)}"])
    
    # Generate DHCP-specific fields
    transaction_id = _generate_transaction_id()
    q_result = str(random.choice([0, 1, 2, 5]))  # Query result codes
    probation_time = str(random.randint(0, 3600))  # Seconds
    correlation_id = str(random.randint(100000, 999999))
    dhcid = f"dhcid_{random.randint(1000, 9999)}"
    
    # Vendor and user class information
    vendor_class_ascii, vendor_class_hex = random.choice(VENDOR_CLASSES)
    user_class_ascii = random.choice(USER_CLASSES)
    user_class_hex = user_class_ascii.encode('ascii').hex()
    
    # Relay agent information
    relay_agent_info = f"relay_{random.randint(1, 100)}" if random.random() < 0.3 else ""
    
    # DNS registration error
    dns_reg_error = str(random.choice(DNS_ERROR_CODES)) if random.random() < 0.2 else ""
    
    # Build CSV fields based on random field count (parser supports variable field counts)
    base_fields = [
        str(event_id),
        event_time.strftime("%m/%d/%y,%H:%M:%S"),
        description,
        ip_address,
        hostname,
        mac_address if not is_ipv6 else "",
        username,
        transaction_id,
        q_result,
        probation_time,
        correlation_id,
        dhcid,
        vendor_class_hex,
        vendor_class_ascii,
        user_class_hex,
        user_class_ascii,
        relay_agent_info,
        dns_reg_error
    ]
    
    # Handle IPv6 events differently
    if is_ipv6:
        # IPv6 format: eventId, timestamp, description, ipv6Address, hostname, errorCode, duidLength, duidBytesHex, userName, dhcid, subnetPrefix
        duid = _generate_duid()
        subnet_prefix = f"2001:db8:{random.randint(1000, 9999):04x}::/64"
        
        ipv6_fields = [
            str(event_id),
            event_time.strftime("%m/%d/%y,%H:%M:%S"),
            description,
            ip_address,  # IPv6 address
            hostname,
            str(random.choice(DNS_ERROR_CODES)),  # errorCode
            str(len(duid) // 2),  # duidLength
            duid,  # duidBytesHex
            username,
            dhcid,
            subnet_prefix
        ]
        fields = ipv6_fields
    else:
        # Randomly truncate fields to match parser's variable format support
        field_count = random.choices(
            [6, 8, 10, 12, 14, 16, 18],  # Number of fields to include
            weights=[0.1, 0.1, 0.15, 0.2, 0.2, 0.15, 0.1]  # Weights
        )[0]
        fields = base_fields[:field_count]
    
    # Apply overrides
    if overrides:
        for key, value in overrides.items():
            if key == "eventId" and len(fields) > 0:
                fields[0] = str(value)
            elif key == "description" and len(fields) > 2:
                fields[2] = str(value)
            elif key == "ipAddress" and len(fields) > 3:
                fields[3] = str(value)
            elif key == "hostname" and len(fields) > 4:
                fields[4] = str(value)
    
    return ",".join(fields)

if __name__ == "__main__":
    # Generate sample logs
    print("Sample Windows DHCP Server events:")
    for event_id in [10, 30, 50]:
        print(f"\nEvent ID {event_id}:")
        print(windows_dhcp_log({"eventId": event_id}))
        print()