#!/usr/bin/env python3
"""
CyberArk PAS (Privileged Access Security) event generator (JSON format)
"""
from __future__ import annotations
import json
import random
import time
import hashlib
from datetime import datetime, timezone, timedelta
from typing import Dict

# Policy names and categories
POLICIES = [
    ("Elevate to Administrator", "elevation"),
    ("Block Unauthorized Software", "application_control"),
    ("Ransomware Protection", "threat_protection"),
    ("Credential Theft Protection", "credential_protection"),
    ("Network Access Control", "network_control"),
    ("USB Device Control", "device_control"),
    ("Registry Protection", "system_protection"),
    ("Service Control", "service_management"),
]

# Event types
EVENT_TYPES = [
    "Policy Applied",
    "Policy Blocked",
    "Elevation Requested",
    "Elevation Approved",
    "Elevation Denied",
    "Application Blocked",
    "Threat Detected",
    "Suspicious Activity",
    "Configuration Changed",
    "Audit Event",
]

# Source types
SOURCE_TYPES = ["Application", "Service", "Process", "User", "System", "Network"]

# Users and computers
USERS = [
    "jean.picard", "william.riker", "data.android", "geordi.laforge", "worf.security", 
    "deanna.troi", "beverly.crusher", "wesley.crusher", "tasha.yar", "guinan.bartender",
    "james.kirk", "spock.science", "leonard.mccoy", "montgomery.scott", "nyota.uhura",
    "pavel.chekov", "hikaru.sulu", "benjamin.sisko", "kira.nerys", "julian.bashir",
    "jadzia.dax", "miles.obrien", "odo.security", "kathryn.janeway", "chakotay.commander",
    "tuvok.security", "tom.paris", "belanna.torres", "harry.kim", "seven.of.nine", "admin"
]
COMPUTERS = [
    "ENTERPRISE-NCC1701", "DEFIANT-NX74205", "VOYAGER-NCC74656", "DISCOVERY-NCC1031", 
    "BRIDGE-01", "ENGINEERING-CORE", "SICKBAY-TERMINAL", "HOLODECK-02", "TRANSPORTER-ROOM1",
    "READY-ROOM", "TEN-FORWARD", "STELLAR-CARTOGRAPHY", "ASTROMETRICS-LAB"
]
DOMAINS = ["STARFLEET", "FEDERATION", "CORP"]

# Common applications and processes
APPLICATIONS = [
    ("chrome.exe", "Google Chrome", "Google LLC", "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe"),
    ("firefox.exe", "Mozilla Firefox", "Mozilla Corporation", "C:\\Program Files\\Mozilla Firefox\\firefox.exe"),
    ("powershell.exe", "Windows PowerShell", "Microsoft Corporation", "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"),
    ("cmd.exe", "Windows Command Processor", "Microsoft Corporation", "C:\\Windows\\System32\\cmd.exe"),
    ("excel.exe", "Microsoft Excel", "Microsoft Corporation", "C:\\Program Files\\Microsoft Office\\root\\Office16\\EXCEL.EXE"),
    ("outlook.exe", "Microsoft Outlook", "Microsoft Corporation", "C:\\Program Files\\Microsoft Office\\root\\Office16\\OUTLOOK.EXE"),
    ("notepad++.exe", "Notepad++", "Don HO don.h@free.fr", "C:\\Program Files\\Notepad++\\notepad++.exe"),
    ("putty.exe", "PuTTY", "Simon Tatham", "C:\\Program Files\\PuTTY\\putty.exe"),
]

# Threat actions
THREAT_ACTIONS = ["Block", "Allow", "Quarantine", "Delete", "Monitor", "Alert"]

def _generate_hash(hash_type="SHA256"):
    """Generate a random hash"""
    random_data = str(random.random()).encode()
    if hash_type == "MD5":
        return hashlib.md5(random_data).hexdigest()
    elif hash_type == "SHA1":
        return hashlib.sha1(random_data).hexdigest()
    else:
        return hashlib.sha256(random_data).hexdigest()

def _generate_sid():
    """Generate a Windows-style SID"""
    return f"S-1-5-21-{random.randint(100000000, 999999999)}-{random.randint(100000000, 999999999)}-{random.randint(1000, 9999)}-{random.randint(1000, 9999)}"

def _iso_timestamp():
    """Generate ISO format timestamp"""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")

def cyberark_pas_log(overrides: dict | None = None) -> str:
    """
    Return a single CyberArk PAS event as JSON string.
    
    Pass `overrides` to force any field to a specific value:
        cyberark_pas_log({"userName": "specific_user"})
    """
    # Select random attributes (allow overrides)
    policy_name, policy_category = random.choice(POLICIES)
    event_type = random.choice(EVENT_TYPES)
    source_type = random.choice(SOURCE_TYPES)
    user = random.choice(USERS)
    computer = random.choice(COMPUTERS)
    domain = random.choice(DOMAINS)
    app_info = random.choice(APPLICATIONS)
    
    # Apply user override if provided
    if overrides and "user" in overrides:
        user = overrides["user"]
    elif overrides and "userName" in overrides:
        user = overrides["userName"]
    
    # Generate timestamps
    now = datetime.now(timezone.utc)
    first_event_time = now - timedelta(hours=random.randint(1, 24))
    last_event_time = now
    
    # Base event structure
    event = {
        "policyName": policy_name,
        "policyCategory": policy_category,
        "eventType": event_type,
        "sourceType": source_type,
        "sourceName": app_info[0],
        "userName": user,
        "computerName": computer,
        "agentId": _generate_hash("MD5")[:16],
        "eventCount": random.randint(1, 100),
        "agentEventCount": random.randint(1, 50),
        "skippedCount": random.randint(0, 10),
        "firstEventDate": first_event_time.strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
        "lastEventDate": last_event_time.strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
        "arrivalTime": _iso_timestamp(),
        "modificationTime": _iso_timestamp(),
        "operatingSystemType": "Windows",
        "userIsAdmin": random.choice(["true", "false"]),
    }
    
    # Add file/application details
    if source_type in ["Application", "Process"]:
        event.update({
            "fileName": app_info[0],
            "originalFileName": app_info[0],
            "filePath": app_info[3],
            "filePathWithoutFilename": "\\".join(app_info[3].split("\\")[:-1]),
            "fileDescription": app_info[1],
            "productName": app_info[1],
            "company": app_info[2],
            "publisher": app_info[2],
            "hash": _generate_hash(),
            "fileSize": str(random.randint(100000, 50000000)),
            "fileVersion": f"{random.randint(1, 20)}.{random.randint(0, 99)}.{random.randint(0, 9999)}.{random.randint(0, 99)}",
            "mimeType": "application/x-msdownload",
            "fileQualifier": _generate_hash("MD5")[:16],
        })
    
    # Add process details for certain events
    if event_type in ["Elevation Requested", "Application Blocked", "Threat Detected"]:
        event.update({
            "processCommandLine": f"{app_info[0]} {random.choice(['--no-sandbox', '/quiet', '-ExecutionPolicy Bypass', '/c whoami'])}",
            "workingDirectory": "\\".join(app_info[3].split("\\")[:-1]),
            "interpreter": "none",
        })
    
    # Add source process details for suspicious activities
    if event_type in ["Suspicious Activity", "Threat Detected"]:
        parent_app = random.choice(APPLICATIONS)
        event.update({
            "sourceProcessCommandLine": f"{parent_app[0]} /c {app_info[0]}",
            "sourceProcessUsername": user,
            "sourceProcessHash": _generate_hash(),
            "sourceProcessPublisher": parent_app[2],
            "sourceProcessSigner": parent_app[2],
            "sourceProcessCertificateIssuer": f"CN={parent_app[2]}, O={parent_app[2]}, L=Redmond, S=Washington, C=US",
            "fatherProcess": parent_app[0],
        })
    
    # Add threat protection details
    if policy_category == "threat_protection" or event_type == "Threat Detected":
        event.update({
            "threatProtectionAction": random.choice(THREAT_ACTIONS),
            "threatProtectionActionId": str(random.randint(1, 10)),
            "deceptionType": random.choice(["Honeypot", "Decoy", "Canary", "None"]),
        })
    
    # Add elevation/justification details
    if "Elevation" in event_type:
        event.update({
            "justification": f"Need to {random.choice(['install software', 'modify system settings', 'access protected resources', 'run diagnostics'])}",
            "justificationEmail": f"{user}@company.com",
            "runAsUsername": "Administrator" if event_type == "Elevation Approved" else user,
        })
    
    # Add network details
    if policy_category == "network_control" or source_type == "Network":
        event.update({
            "sourceWSName": computer,
            "sourceWSIp": f"10.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}",
        })
    
    # Add access control details
    if policy_category in ["application_control", "credential_protection"]:
        event.update({
            "accessAction": random.choice(["Read", "Write", "Execute", "Delete"]),
            "accessTargetType": random.choice(["File", "Registry", "Service", "Process"]),
            "accessTargetName": random.choice([
                "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion",
                "C:\\Windows\\System32\\config\\SAM",
                "lsass.exe",
                "services.exe"
            ]),
            "fileAccessPermission": random.choice(["Read", "Write", "Execute", "Full Control"]),
        })
    
    # Add user details
    event.update({
        "originUserUID": _generate_sid(),
        "displayName": user.replace(".", " ").title(),
        "owner": f"{domain}\\{user}",
    })
    
    # Add Windows event details for audit events
    if event_type == "Audit Event":
        event.update({
            "winEventType": random.choice(["Security", "Application", "System"]),
            "winEventRecordId": str(random.randint(100000, 999999)),
            "logonAttemptTypeId": str(random.randint(2, 11)),
            "logonStatusId": str(random.choice([0, 0xC0000064, 0xC000006A, 0xC0000234])),
        })
    
    # Add evidence for suspicious activities
    if event_type in ["Suspicious Activity", "Threat Detected"]:
        event["evidences"] = [
            {
                "type": "behavioral",
                "description": random.choice([
                    "Process injection detected",
                    "Credential dumping attempt",
                    "Suspicious registry modification",
                    "Unauthorized network connection",
                    "Ransomware-like behavior detected"
                ]),
                "severity": random.choice(["Low", "Medium", "High", "Critical"])
            }
        ]
    
    # Add exposed users for certain events
    if event_type in ["Threat Detected", "Elevation Approved"]:
        exposed_count = random.randint(1, 5)
        event["exposedUsers"] = [f"user{i}" for i in range(exposed_count)]
    
    # Apply package/bundle info for applications
    if source_type == "Application" and random.random() > 0.5:
        event.update({
            "packageName": app_info[1].replace(" ", ".").lower(),
            "bundleName": app_info[1],
            "bundleVersion": f"{random.randint(1, 20)}.{random.randint(0, 99)}",
            "bundleId": f"com.{app_info[2].split()[0].lower()}.{app_info[1].split()[0].lower()}",
            "applicationSubType": random.choice(["Desktop", "Service", "Driver", "Script"]),
        })
    
    # Apply any overrides
    if overrides:
        event.update(overrides)
    
    return json.dumps(event)

if __name__ == "__main__":
    # Generate a few sample logs
    for _ in range(3):
        print(cyberark_pas_log())
        print()