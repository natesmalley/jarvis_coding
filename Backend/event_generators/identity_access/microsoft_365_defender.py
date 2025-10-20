#!/usr/bin/env python3
"""
Microsoft 365 Defender event generator
Generates synthetic Microsoft 365 Defender endpoint security logs
"""
import json
import random
import time
from datetime import datetime, timezone, timedelta
from typing import Dict

# Action types
ACTION_TYPES = [
    "ProcessCreated",
    "NetworkConnectionFailed", 
    "NetworkConnectionSuccess",
    "Quarantine",
    "FileCreated",
    "FileDeleted",
    "RegistryValueSet",
    "PowerShellCommand",
    "SuspiciousProcess",
    "MalwareDetected"
]

# Star Trek themed device names
DEVICE_NAMES = [
    "ENTERPRISE-BRIDGE-01", "ENTERPRISE-BRIDGE-02", "ENTERPRISE-BRIDGE-03",
    "ENTERPRISE-ENG-01", "ENTERPRISE-ENG-02", "ENTERPRISE-MED-01",
    "ENTERPRISE-SEC-01", "ENTERPRISE-SCI-01", "HOLODECK-01", "HOLODECK-02",
    "TRANSPORTER-01", "SHUTTLEBAY-01", "READYROOM-01", "TENFORWARD-01"
]

# Star Trek themed account names
ACCOUNT_NAMES = [
    "jean.picard", "william.riker", "data.android", "geordi.laforge",
    "worf.security", "deanna.troi", "beverly.crusher", "wesley.crusher",
    "guinan.bartender", "obrien.transporter", "system", "service"
]

# Star Trek themed account domains
ACCOUNT_DOMAINS = ["STARFLEET", "ENTERPRISE", "FEDERATION", "NT AUTHORITY"]

# Star Trek themed file names
FILE_NAMES = [
    "lcars.exe", "powershell.exe", "cmd.exe", "padd.exe",
    "borg-malware.exe", "romulan-virus.dll", "ferengi-trojan.scr", 
    "captains-log.pdf", "warp-script.ps1", "shields-config.xml", 
    "sensor-data.txt", "tricorder.exe", "phaser-control.exe"
]

# Star Trek themed folder paths
FOLDER_PATHS = [
    "C:\\Starfleet\\System32",
    "C:\\Program Files\\LCARS\\Application", 
    "C:\\Users\\picard\\Downloads",
    "C:\\Users\\riker\\Documents",
    "C:\\Users\\data\\Analysis",
    "C:\\Starfleet\\Temp",
    "C:\\Bridge\\Operations",
    "C:\\Engineering\\Core"
]

# Process names
PROCESS_NAMES = [
    "chrome.exe", "firefox.exe", "powershell.exe", "cmd.exe",
    "explorer.exe", "svchost.exe", "winlogon.exe", "lsass.exe"
]

# Star Trek themed remote URLs
REMOTE_URLS = [
    "https://starfleet.corp",
    "https://memory-alpha.org",
    "https://romulan-spy.net",
    "https://borg-collective.net",
    "https://ferengi-phishing.com"
]

# Star Trek themed malware detection IDs
DETECTION_IDS = [
    "Trojan:Romulan/Cloak",
    "Virus:Borg/Assimilate",
    "Adware:Ferengi/Profit", 
    "Ransomware:Orion/Cryptor",
    "Backdoor:Dominion/Changeling"
]

def generate_device_id() -> str:
    """Generate device ID"""
    return f"{random.randint(1000000000000000, 9999999999999999):016x}".upper()

def generate_hash() -> str:
    """Generate SHA1 hash"""
    return ''.join(random.choices('0123456789abcdef', k=40))

def generate_md5() -> str:
    """Generate MD5 hash"""
    return ''.join(random.choices('0123456789abcdef', k=32))

def generate_ip() -> str:
    """Generate IP address"""
    return f"{random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"

def microsoft_365_defender_log(overrides: dict = None) -> Dict:
    """Generate a single Microsoft 365 Defender event log"""
    now = datetime.now(timezone.utc)
    event_time = now - timedelta(minutes=random.randint(0, 10))
    
    action_type = random.choice(ACTION_TYPES)
    device_name = random.choice(DEVICE_NAMES)
    device_id = generate_device_id()
    account_name = random.choice(ACCOUNT_NAMES)
    account_domain = random.choice(ACCOUNT_DOMAINS)
    
    # Base event structure
    event = {
        "Timestamp": event_time.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "DeviceName": device_name,
        "DeviceId": device_id,
        "AccountName": account_name,
        "AccountDomain": account_domain,
        "ActionType": action_type
    }
    
    # Add specific fields based on action type
    if action_type == "ProcessCreated":
        event.update({
            "ProcessId": random.randint(1000, 65535),
            "ProcessName": random.choice(PROCESS_NAMES),
            "ProcessCommandLine": f"\"{random.choice(FOLDER_PATHS)}\\{random.choice(PROCESS_NAMES)}\" --args",
            "ParentProcessId": random.randint(100, 999),
            "ParentProcessName": "explorer.exe",
            "FolderPath": random.choice(FOLDER_PATHS),
            "SHA1": generate_hash(),
            "MD5": generate_md5()
        })
        
    elif "NetworkConnection" in action_type:
        event.update({
            "RemoteUrl": random.choice(REMOTE_URLS),
            "RemoteIP": generate_ip(),
            "RemotePort": random.choice([80, 443, 8080, 8443, 9999]),
            "Protocol": random.choice(["HTTP", "HTTPS", "TCP", "UDP"]),
            "ProcessName": random.choice(PROCESS_NAMES),
            "ProcessCommandLine": f"\"{random.choice(FOLDER_PATHS)}\\{random.choice(PROCESS_NAMES)}\"",
            "FailureReason": "Domain blocked by policy" if "Failed" in action_type else None
        })
        
    elif action_type == "Quarantine" or action_type == "MalwareDetected":
        event.update({
            "FileName": random.choice(FILE_NAMES),
            "FolderPath": random.choice(FOLDER_PATHS),
            "SHA1": generate_hash(),
            "MD5": generate_md5(),
            "DetectionId": random.choice(DETECTION_IDS),
            "AdditionalFields": {
                "ThreatName": random.choice(DETECTION_IDS),
                "Severity": random.choice(["Low", "Medium", "High", "Critical"])
            }
        })
        
    elif "File" in action_type:
        event.update({
            "FileName": random.choice(FILE_NAMES),
            "FolderPath": random.choice(FOLDER_PATHS),
            "SHA1": generate_hash(),
            "MD5": generate_md5()
        })
        
    elif action_type == "PowerShellCommand":
        event.update({
            "ProcessName": "powershell.exe",
            "ProcessCommandLine": "powershell.exe -NoProfile -ExecutionPolicy Bypass -Command \"Get-Process\"",
            "FolderPath": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0"
        })
    
    # Remove None values
    event = {k: v for k, v in event.items() if v is not None}
    
    # Apply overrides if provided (for scenario customization)
    if overrides:
        event.update(overrides)
    
    return event

if __name__ == "__main__":
    # Generate sample events
    print("Sample Microsoft 365 Defender Events:")
    print("=" * 50)
    for i in range(3):
        print(f"\nEvent {i+1}:")
        print(json.dumps(microsoft_365_defender_log(), indent=2))