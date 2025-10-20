#!/usr/bin/env python3
"""
Microsoft Windows Event Log generator
Generates synthetic Windows Event Log events (Security, System, Application)
"""
import json
import random
import time
from datetime import datetime, timezone, timedelta
from typing import Dict, Any

# Common Windows Event IDs by category
SECURITY_EVENTS = [
    {"id": 4624, "name": "Successful Logon", "level": "Information"},
    {"id": 4625, "name": "Failed Logon", "level": "Information"},
    {"id": 4634, "name": "Account Logoff", "level": "Information"},
    {"id": 4648, "name": "Logon with Explicit Credentials", "level": "Information"},
    {"id": 4720, "name": "User Account Created", "level": "Information"},
    {"id": 4726, "name": "User Account Deleted", "level": "Information"},
    {"id": 4728, "name": "Member Added to Security Group", "level": "Information"},
    {"id": 4729, "name": "Member Removed from Security Group", "level": "Information"},
    {"id": 4732, "name": "Member Added to Local Group", "level": "Information"},
    {"id": 4740, "name": "User Account Locked", "level": "Information"},
    {"id": 4767, "name": "User Account Unlocked", "level": "Information"},
    {"id": 4778, "name": "Session Reconnected", "level": "Information"},
    {"id": 4779, "name": "Session Disconnected", "level": "Information"},
    {"id": 5156, "name": "Windows Filtering Platform Connection", "level": "Information"},
    {"id": 1102, "name": "Audit Log Cleared", "level": "Information"}
]

SYSTEM_EVENTS = [
    {"id": 7034, "name": "Service Crashed", "level": "Error"},
    {"id": 7035, "name": "Service Control Manager", "level": "Information"},
    {"id": 7036, "name": "Service Start/Stop", "level": "Information"},
    {"id": 7040, "name": "Service Start Type Changed", "level": "Information"},
    {"id": 6005, "name": "Event Log Service Started", "level": "Information"},
    {"id": 6006, "name": "Event Log Service Stopped", "level": "Information"},
    {"id": 6008, "name": "Unexpected Shutdown", "level": "Error"},
    {"id": 6009, "name": "System Started", "level": "Information"},
    {"id": 1074, "name": "System Shutdown Initiated", "level": "Information"},
    {"id": 41, "name": "System Rebooted Without Shutdown", "level": "Critical"}
]

APPLICATION_EVENTS = [
    {"id": 1000, "name": "Application Error", "level": "Error"},
    {"id": 1001, "name": "Application Hang", "level": "Error"},
    {"id": 1002, "name": "Application Recovery", "level": "Information"},
    {"id": 2, "name": "Application Start", "level": "Information"},
    {"id": 4, "name": "Application Stop", "level": "Information"}
]

# Logon types
LOGON_TYPES = {
    2: "Interactive",
    3: "Network", 
    4: "Batch",
    5: "Service",
    7: "Unlock",
    8: "NetworkCleartext",
    9: "NewCredentials",
    10: "RemoteInteractive",
    11: "CachedInteractive"
}

# Authentication packages
AUTH_PACKAGES = ["NTLM", "Kerberos", "Negotiate", "PKU2U", "WDigest"]

# Windows services
SERVICES = [
    "Windows Update", "DHCP Client", "DNS Client", "Print Spooler",
    "Task Scheduler", "Windows Firewall", "Remote Registry", "Server",
    "Workstation", "Windows Time", "BITS", "Themes", "Audio Service"
]

# Computer names and users
COMPUTERS = [f"WKS-{random.randint(1000, 9999)}" for _ in range(20)]
USERS = [f"user{i:03d}" for i in range(1, 101)]
ADMIN_USERS = ["administrator", "admin", "sysadmin", "domainadmin"]

def generate_ip() -> str:
    """Generate a random IP address"""
    return f"10.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"

def microsoft_windows_eventlog_log() -> str:
    """Generate a single Windows Event Log entry that matches parser patterns exactly"""
    now = datetime.now(timezone.utc)
    event_time = now - timedelta(minutes=random.randint(0, 10))  # Last 10 minutes only
    
    # Choose event type - focus on Security events for the parser
    event_info = random.choice(SECURITY_EVENTS)
    computer_name = random.choice(COMPUTERS)
    
    # Generate user details - using Starfleet characters
    user = random.choice(["jean.picard", "jordy.laforge", "worf.security", "data.android"])
    domain = "STARFLEET"
    
    # Generate security identifiers and logon info
    logon_id = f"0x{random.randint(100000, 999999):x}"
    security_id = f"S-1-5-21-{random.randint(1000000000, 9999999999)}-{random.randint(1000000000, 9999999999)}-{random.randint(1000000000, 9999999999)}-{random.randint(1000, 9999)}"
    logon_type = random.choice(list(LOGON_TYPES.keys()))
    
    # Build the EXACT format that matches the parser patterns using ACTUAL CR/LF and TAB characters
    # Based on parser regex: ".*Subject.*Account Name:\\\\t\\\\t$Account_Name$\\\\r\\\\n"  
    # The parser expects real \r\n and \t characters, not escaped string literals
    
    event_text = "An account was successfully logged on.\r\n\r\n"
    event_text += "Subject:\r\n"
    event_text += f"\tSecurity ID:\t\t{security_id}\r\n"
    event_text += f"\tAccount Name:\t\t{user}\r\n"
    event_text += f"\tAccount Domain:\t\t{domain}\r\n"
    event_text += f"\tLogon ID:\t\t{logon_id}\r\n\r\n"
    event_text += "Logon Information:\r\n"
    event_text += f"\tLogon Type:\t\t{logon_type}\r\n"
    event_text += "\tRestricted Admin Mode:\t-\r\n"
    event_text += "\tVirtual Account:\t\tNo\r\n"
    event_text += "\tElevated Token:\t\tYes\r\n\r\n"
    event_text += "Impersonation Level:\t\tImpersonation\r\n\r\n"
    event_text += "New Logon:\r\n"
    event_text += f"\tSecurity ID:\t\t{security_id}\r\n"
    event_text += f"\tAccount Name:\t\t{user}\r\n"
    event_text += f"\tAccount Domain:\t\t{domain}\r\n"
    event_text += f"\tLogon ID:\t\t{logon_id}\r\n"
    event_text += f"\tLinked Logon ID:\t\t{logon_id}\r\n"
    event_text += "\tNetwork Account Name:\t-\r\n"
    event_text += "\tNetwork Account Domain:\t-\r\n"
    event_text += f"\tLogon GUID:\t\t{{{random.randint(10000000, 99999999):08x}-{random.randint(1000, 9999):04x}-{random.randint(1000, 9999):04x}-{random.randint(1000, 9999):04x}-{random.randint(100000000000, 999999999999):012x}}}\r\n\r\n"
    event_text += "Process Information:\r\n"
    event_text += f"\tProcess ID:\t\t0x{random.randint(1000, 8000):x}\r\n"
    event_text += "\tProcess Name:\t\tC:\\Windows\\System32\\winlogon.exe\r\n\r\n"
    event_text += "Network Information:\r\n"
    event_text += f"\tWorkstation Name:\t{computer_name}\r\n"
    event_text += f"\tSource Network Address:\t{generate_ip()}\r\n"
    event_text += f"\tSource Port:\t\t{random.randint(49152, 65535)}\r\n\r\n"
    event_text += "Detailed Authentication Information:\r\n"
    event_text += f"\tLogon Process:\t\t{random.choice(['Advapi', 'User32', 'Kerberos'])}\r\n"
    event_text += f"\tAuthentication Package:\t{random.choice(AUTH_PACKAGES)}\r\n"
    event_text += "\tTransited Services:\t-\r\n"
    event_text += "\tPackage Name (NTLM only):\t-\r\n"
    event_text += f"\tKey Length:\t\t{random.choice([0, 128, 256])}"
    
    # Convert \r\n to literal \\r\\n for single-line transmission to /raw endpoint
    # This prevents line splitting while preserving the format the parser expects
    event_text_escaped = event_text.replace('\r\n', '\\r\\n').replace('\t', '\\t')
    
    return event_text_escaped

if __name__ == "__main__":
    # Generate sample events
    print("Sample Microsoft Windows Event Log Events:")
    print("=" * 50)
    for i in range(3):
        print(f"\nEvent {i+1}:")
        print(microsoft_windows_eventlog_log())