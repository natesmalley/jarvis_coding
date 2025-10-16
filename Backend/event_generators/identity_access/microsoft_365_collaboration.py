#!/usr/bin/env python3
"""
Microsoft 365 Collaboration event generator
Generates synthetic M365 SharePoint/OneDrive activity logs
"""
import json
import random
import time
from datetime import datetime, timezone, timedelta
from typing import Dict

# Operations
OPERATIONS = [
    "FileDownloaded",
    "FileUploaded", 
    "FileModified",
    "FileDeleted",
    "FileMoved",
    "FileCopied",
    "FileViewed",
    "FileShared",
    "AccessInvitationAccepted",
    "AccessRequestCreated",
    "AccessRequestApproved",
    "SharingLinkCreated",
    "SharingLinkUsed"
]

# Star Trek themed users
USERS = [
    "jean.picard@starfleet.corp",
    "william.riker@starfleet.corp", 
    "data.android@starfleet.corp",
    "geordi.laforge@starfleet.corp",
    "worf.security@starfleet.corp",
    "deanna.troi@starfleet.corp",
    "beverly.crusher@starfleet.corp",
    "wesley.crusher@starfleet.corp",
    "james.kirk@starfleet.corp",
    "spock.science@starfleet.corp",
    "leonard.mccoy@starfleet.corp",
    "montgomery.scott@starfleet.corp",
    "external.vulcan@embassy.vulcan",
    "contractor@ferengi-trading.com"
]

# Star Trek themed site URLs
SITE_URLS = [
    "https://starfleet-my.sharepoint.com/sites/Bridge",
    "https://starfleet-my.sharepoint.com/sites/Engineering", 
    "https://starfleet-my.sharepoint.com/sites/Science",
    "https://starfleet-my.sharepoint.com/sites/Security",
    "https://starfleet-my.sharepoint.com/sites/Medical",
    "https://starfleet-my.sharepoint.com/sites/Command",
    "https://starfleet-my.sharepoint.com/sites/Operations"
]

# Star Trek themed file names
FILE_NAMES = [
    "StarfleetRegulations.docx",
    "BridgeRotations.xlsx", 
    "SecurityProtocols.docx",
    "MissionBriefing.pptx",
    "FirstContact.pdf",
    "WarpCoreSpecs.txt",
    "ReplicatorDatabase.sql",
    "TransporterConfig.json",
    "CaptainsLog.docx",
    "ShieldsAnalysis.xlsx",
    "DiplomaticTreaty.pdf",
    "HolodeckPrograms.json"
]

# Star Trek themed file paths
FILE_PATHS = [
    "/Bridge Documents/",
    "/Personal Logs/",
    "/Command/",
    "/Archive/",
    "/Starfleet Templates/",
    "/Engineering Schematics/",
    "/Medical Records/"
]

def generate_object_id() -> str:
    """Generate SharePoint object ID path"""
    base_path = random.choice(FILE_PATHS)
    file_name = random.choice(FILE_NAMES)
    return base_path + file_name

def microsoft_365_collaboration_log(overrides: dict = None) -> Dict:
    """Generate a single Microsoft 365 Collaboration event log"""
    now = datetime.now(timezone.utc)
    event_time = now - timedelta(minutes=random.randint(0, 10))
    
    operation = random.choice(OPERATIONS)
    user_id = random.choice(USERS)
    site_url = random.choice(SITE_URLS)
    object_id = generate_object_id()
    file_name = object_id.split("/")[-1]
    
    # Generate appropriate details based on operation
    if "Access" in operation:
        target_user = random.choice([u for u in USERS if u != user_id])
        details = f"User {user_id} {operation.lower()} for {file_name}"
    elif "Sharing" in operation:
        details = f"Sharing link {operation.lower().replace('sharing', '').replace('link', '').strip()} for {file_name}"
    else:
        details = f"User {user_id} {operation.lower()} {file_name}"
    
    # Determine if this is suspicious activity
    is_suspicious = (
        "external" in user_id or 
        "contractor" in user_id or
        "Secrets" in file_name or
        "Database" in file_name or
        operation in ["FileDeleted", "SharingLinkCreated"]
    )
    
    event = {
        "TimeStamp": event_time.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "UserId": user_id,
        "Operation": operation,
        "SiteUrl": site_url,
        "ObjectId": object_id,
        "FileName": file_name,
        "Details": details,
        "UserAgent": random.choice([
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Microsoft Office/16.0 (Microsoft OneDrive for Business)",
            "Microsoft SharePoint Online"
        ]),
        "ClientIP": f"{random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}",
        "Workload": "SharePoint" if "sharepoint" in site_url else "OneDrive",
        "RecordType": random.choice([6, 14, 25]),  # SharePoint/OneDrive record types
        "Version": "1"
    }
    
    # Add conditional fields based on operation
    if "Access" in operation:
        event["TargetUser"] = target_user
        event["RequestedBy"] = user_id
    elif "Request" in operation:
        event["RequestedBy"] = user_id
    
    # Add threat indicators for suspicious activity
    if is_suspicious:
        event["ThreatIndicator"] = "Suspicious file or user activity detected"
    
    # Apply overrides if provided (for scenario customization)
    if overrides:
        event.update(overrides)
    
    return event

if __name__ == "__main__":
    # Generate sample events
    print("Sample Microsoft 365 Collaboration Events:")
    print("=" * 50)
    for i in range(3):
        print(f"\nEvent {i+1}:")
        print(json.dumps(microsoft_365_collaboration_log(), indent=2))