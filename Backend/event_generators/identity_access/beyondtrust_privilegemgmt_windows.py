#!/usr/bin/env python3
"""
BeyondTrust Privilege Management for Windows event generator
Generates endpoint privilege management events in CSV format
"""
from __future__ import annotations
import random
import time
from datetime import datetime, timezone, timedelta
from typing import Dict

# Event types and activities
ACTIVITY_IDS = [
    "EPM_ALLOW", "EPM_BLOCK", "EPM_ELEVATE", "EPM_PROMPT", "EPM_AUDIT", 
    "EPM_REMOVE", "EPM_INSTALL", "EPM_EXECUTE", "EPM_ACCESS", "EPM_MODIFY"
]

EVENT_DETAILS = [
    "Application execution allowed by policy",
    "Application execution blocked by policy", 
    "Application elevated to administrator privileges",
    "User prompted for privilege elevation",
    "Application access audited",
    "Application removed from system",
    "Software installation detected",
    "Process execution monitored",
    "File access attempt logged",
    "Registry modification detected",
    "Service installation blocked",
    "PowerShell script execution elevated",
    "MSI installer allowed with elevation",
    "Unsigned executable blocked",
    "Administrative rights granted temporarily"
]

# Users and devices
USERS = ["jdoe", "asmith", "bjohnson", "cwilliams", "admin", "service_user", "contractor"]
DEVICES = ["DESKTOP-ABC123", "LAPTOP-XYZ789", "WORKSTATION-001", "DEV-MACHINE-02", "SERVER-WEB01"]

# Policy groups and app groups  
POLICY_GROUPS = ["Standard Users", "Power Users", "Developers", "IT Administrators", "Contractors", "Service Accounts"]
APP_GROUPS = ["Office Applications", "Development Tools", "System Utilities", "Web Browsers", "Custom Applications"]

# Reasons and tokens
REASONS = [
    "Business justification provided",
    "Administrative task required",
    "Software development need",
    "System maintenance activity",
    "Emergency access granted",
    "Troubleshooting requirement",
    "Security incident response",
    "Compliance audit activity"
]

CUSTOM_TOKENS = ["CORP\\Domain", "LOCAL\\Workgroup", "AAD\\Cloud", "TRUST\\External"]

# Applications and processes
APPLICATIONS = [
    ("cmd.exe", "Command Prompt", "System", "Microsoft Windows", "MSOFT", "10.0.19041.1", "10.0.19041.1"),
    ("powershell.exe", "PowerShell", "Script", "Microsoft PowerShell", "POWERSHELL", "7.2.1", "7.2.1.0"),
    ("notepad.exe", "Notepad", "Editor", "Microsoft Notepad", "NOTEPAD", "10.0.19041.1", "10.0.19041.1"),
    ("chrome.exe", "Google Chrome", "Browser", "Google Chrome", "CHROME", "91.0.4472.124", "91.0.4472.124"),
    ("devenv.exe", "Visual Studio", "Development", "Microsoft Visual Studio", "DEVENV", "16.11.2", "16.11.31727.386"),
    ("msiexec.exe", "Windows Installer", "Installer", "Microsoft Windows Installer", "MSI", "5.0.19041.1", "5.0.19041.1"),
    ("regsvr32.exe", "Register Server", "System", "Microsoft Register Server", "REGSVR32", "10.0.19041.1", "10.0.19041.1"),
    ("rundll32.exe", "Run DLL", "System", "Microsoft Run DLL", "RUNDLL32", "10.0.19041.1", "10.0.19041.1")
]

# Event types and UAC levels
EVENT_TYPES = ["Allow", "Block", "Elevate", "Prompt", "Audit", "Remove"]
UAC_LEVELS = ["0", "1", "2", "3", "4"]  # UAC integrity levels
SHELL_TYPES = ["explorer.exe", "cmd.exe", "powershell.exe", "winlogon.exe"]

# Services
SERVICES = [
    ("Windows Update", "wuauserv", "Automatic Updates Service"),
    ("BITS", "bits", "Background Intelligent Transfer Service"), 
    ("Defender", "windefend", "Windows Defender Antivirus Service"),
    ("EventLog", "eventlog", "Windows Event Log Service"),
    ("Spooler", "spooler", "Print Spooler Service")
]

def _generate_ip():
    """Generate IP address"""
    return f"10.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"

def _generate_hash():
    """Generate a hash fingerprint"""
    return ''.join(random.choices('0123456789abcdef', k=32))

def beyondtrust_privilegemgmt_windows_log(overrides: dict | None = None) -> str:
    """
    Return a single BeyondTrust Privilege Management Windows event as CSV string.
    
    Pass `overrides` to force any field to a specific value:
        beyondtrust_privilegemgmt_windows_log({"activity_id": "EPM_BLOCK"})
    """
    now = datetime.now(timezone.utc)
    event_time = now - timedelta(seconds=random.randint(0, 300))
    
    # Select application and event details
    app_desc, app_name, app_type, product_name, product_code, product_version, file_version = random.choice(APPLICATIONS)
    activity_id = random.choice(ACTIVITY_IDS)
    event_detail = random.choice(EVENT_DETAILS)
    
    # Generate process IDs
    pid = random.randint(1000, 9999)
    ppid = random.randint(100, 999)
    
    # Select service if relevant
    service_display_name, service_name, service_desc = random.choice(SERVICES) if random.random() < 0.3 else ("", "", "")
    
    # Build CSV fields according to parser format
    fields = [
        event_time.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],  # timestamp with milliseconds
        "[INFO]:",
        activity_id,
        "",  # empty field
        event_detail,
        random.choice(USERS),
        random.choice(DEVICES),
        random.choice(POLICY_GROUPS),
        random.choice(APP_GROUPS),
        random.choice(REASONS),
        random.choice(CUSTOM_TOKENS),
        _generate_hash(),  # hash fingerprint
        f"CN={random.choice(DEVICES)}, OU=Computers, DC=corp, DC=local",  # certificate issuer
        str(pid),
        str(ppid),
        "",  # empty field
        app_desc,
        app_type,
        product_name,
        product_code,
        product_version,
        file_version,
        _generate_ip(),
        random.choice(DEVICES),
        "NT AUTHORITY\\SYSTEM" if random.random() < 0.3 else f"CORP\\{random.choice(USERS)}",  # file owner
        random.choice(SHELL_TYPES),
        f"Token_{random.randint(1000, 9999)}",
        random.choice(EVENT_TYPES),
        random.choice(USERS) if random.random() < 0.5 else "",  # authorizing user
        random.choice(UAC_LEVELS),
        f"{{{random.randint(10000000, 99999999)}-{random.randint(1000, 9999)}-{random.randint(1000, 9999)}-{random.randint(1000, 9999)}-{random.randint(100000000000, 999999999999)}}}",  # COM CLSID
        f"{{{random.randint(10000000, 99999999)}-{random.randint(1000, 9999)}-{random.randint(1000, 9999)}-{random.randint(1000, 9999)}-{random.randint(100000000000, 999999999999)}}}",  # COM AppID  
        f"C:\\Windows\\System32\\{app_desc}" if random.random() < 0.7 else f"C:\\Program Files\\{product_name}\\{app_desc}",  # COM server path
        f"{product_name} Application",  # COM display name
        f"https://example.com/{random.choice(['download', 'update', 'install'])}" if random.random() < 0.2 else "",  # URL
        f"Microsoft.{random.choice(['Office', 'Edge', 'Teams', 'Store'])}" if random.random() < 0.2 else "",  # Windows Store app name
        "Microsoft Corporation" if random.random() < 0.2 else "",  # Windows Store app publisher
        f"{random.randint(1, 10)}.{random.randint(0, 9)}.{random.randint(0, 99)}" if random.random() < 0.2 else "",  # Windows Store app version
        random.choice(["Fixed", "Removable", "Network", "CD-ROM", "RAM"]) if random.random() < 0.3 else "",  # drive type
        service_name,
        service_display_name,
        random.choice(["Success", "Failed", "Pending", "Denied"]) if random.random() < 0.4 else "",  # challenge response status
    ]
    
    # Apply overrides
    if overrides:
        # Map common override keys to field positions
        field_map = {
            "activity_id": 2,
            "event_details": 4, 
            "user_name": 5,
            "device_name": 6,
            "event_type": 25
        }
        for key, value in overrides.items():
            if key in field_map:
                fields[field_map[key]] = str(value)
    
    return ",".join(fields)

if __name__ == "__main__":
    # Generate sample logs
    print("Sample BeyondTrust Privilege Management Windows events:")
    for activity in ["EPM_ALLOW", "EPM_BLOCK", "EPM_ELEVATE"]:
        print(f"\n{activity} event:")
        print(beyondtrust_privilegemgmt_windows_log({"activity_id": activity}))
        print()