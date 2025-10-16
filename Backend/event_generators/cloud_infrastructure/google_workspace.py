#!/usr/bin/env python3
"""
Google Workspace event generator
Generates synthetic Google Workspace admin and user activity events
"""
import json
import random
import time
import uuid
from datetime import datetime, timezone, timedelta
from typing import Dict, List

# Event types by service
EVENT_TYPES = {
    "login": [
        {"name": "login_success", "type": "login"},
        {"name": "login_failure", "type": "login"},
        {"name": "login_challenge", "type": "login"},
        {"name": "logout", "type": "login"},
        {"name": "suspicious_login", "type": "login"},
        {"name": "suspicious_login_less_secure_app", "type": "login"},
        {"name": "account_disabled_password_leak", "type": "login"}
    ],
    "admin": [
        {"name": "CREATE_USER", "type": "USER_SETTINGS"},
        {"name": "DELETE_USER", "type": "USER_SETTINGS"},
        {"name": "CHANGE_PASSWORD", "type": "USER_SETTINGS"},
        {"name": "GRANT_ADMIN_ROLE", "type": "USER_SETTINGS"},
        {"name": "REVOKE_ADMIN_ROLE", "type": "USER_SETTINGS"},
        {"name": "CREATE_GROUP", "type": "GROUP_SETTINGS"},
        {"name": "ADD_GROUP_MEMBER", "type": "GROUP_SETTINGS"},
        {"name": "CHANGE_APPLICATION_SETTING", "type": "APPLICATION_SETTINGS"},
        {"name": "CREATE_ROLE", "type": "DELEGATED_ADMIN_SETTINGS"},
        {"name": "ASSIGN_ROLE", "type": "DELEGATED_ADMIN_SETTINGS"}
    ],
    "drive": [
        {"name": "create", "type": "access"},
        {"name": "upload", "type": "access"},
        {"name": "view", "type": "access"},
        {"name": "edit", "type": "access"},
        {"name": "download", "type": "access"},
        {"name": "delete", "type": "access"},
        {"name": "share", "type": "acl_change"},
        {"name": "change_user_access", "type": "acl_change"},
        {"name": "change_visibility", "type": "acl_change"}
    ],
    "gmail": [
        {"name": "email_forwarding_out_of_domain", "type": "email_settings"},
        {"name": "email_delegate_added", "type": "email_settings"},
        {"name": "change_email_setting", "type": "email_settings"},
        {"name": "suspicious_email_attachment", "type": "email_security"},
        {"name": "phishing_email_detected", "type": "email_security"}
    ],
    "meet": [
        {"name": "meeting_start", "type": "video_conferencing"},
        {"name": "meeting_end", "type": "video_conferencing"},
        {"name": "participant_join", "type": "video_conferencing"},
        {"name": "participant_leave", "type": "video_conferencing"},
        {"name": "recording_start", "type": "video_conferencing"},
        {"name": "recording_download", "type": "video_conferencing"}
    ]
}

# Star Trek themed users and emails
USERS = [
    {"email": "jean.picard@starfleet.corp", "name": "Jean-Luc Picard"},
    {"email": "william.riker@starfleet.corp", "name": "William T. Riker"},
    {"email": "data.android@starfleet.corp", "name": "Data Android"},
    {"email": "jordy.laforge@starfleet.corp", "name": "Geordi La Forge"},
    {"email": "worf.security@starfleet.corp", "name": "Worf Security"},
    {"email": "beverly.crusher@starfleet.corp", "name": "Beverly Crusher"},
    {"email": "deanna.troi@starfleet.corp", "name": "Deanna Troi"},
    {"email": "starfleet-admin@enterprise.starfleet.corp", "name": "Starfleet Admin"}
]

# IP addresses
def generate_ip() -> str:
    """Generate IP address"""
    if random.random() < 0.8:  # 80% internal
        return f"10.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"
    else:  # 20% external
        return f"{random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"

def google_workspace_log() -> Dict:
    """Generate a single Google Workspace event log"""
    now = datetime.now(timezone.utc)
    # Use recent timestamps (last 10 minutes)
    event_time = now - timedelta(minutes=random.randint(0, 10))
    
    # Select service and event
    service = random.choice(list(EVENT_TYPES.keys()))
    event_info = random.choice(EVENT_TYPES[service])
    
    # Select actor
    actor = random.choice(USERS)
    
    # Base event structure
    event = {
        "kind": "admin#reports#activity",
        "id": {
            "time": event_time.isoformat(),
            "uniqueQualifier": str(random.randint(1000000000000000000, 9999999999999999999)),
            "applicationName": service,
            "customerId": "C01NCC1701"
        },
        "etag": f'"{uuid.uuid4().hex}"',
        "actor": {
            "email": actor["email"],
            "profileId": str(random.randint(100000000000000000, 999999999999999999))
        },
        "ipAddress": generate_ip(),
        "events": [{
            "type": event_info["type"],
            "name": event_info["name"],
            "parameters": []
        }]
    }
    
    # Add event-specific parameters
    parameters = event["events"][0]["parameters"]
    
    if service == "login":
        parameters.extend([
            {"name": "login_type", "value": random.choice(["google", "saml", "exchange"])},
            {"name": "login_challenge_method", "multiValue": ["password", "2sv"]} if "challenge" in event_info["name"] else None,
            {"name": "is_suspicious", "boolValue": True} if "suspicious" in event_info["name"] else None,
            {"name": "login_failure_type", "value": random.choice(["login_failure_invalid_password", "login_failure_account_disabled", "login_failure_2sv_required"])} if "failure" in event_info["name"] else None
        ])
        parameters = [p for p in parameters if p is not None]
        
    elif service == "admin":
        target_user = random.choice(USERS)
        parameters.extend([
            {"name": "USER_EMAIL", "value": target_user["email"]},
            {"name": "USER_NAME", "value": target_user["name"]},
            {"name": "SETTING_NAME", "value": random.choice(["Gmail", "Drive", "Calendar", "Mobile"])},
            {"name": "NEW_VALUE", "value": random.choice(["true", "false", "ENABLED", "DISABLED"])},
            {"name": "OLD_VALUE", "value": random.choice(["true", "false", "ENABLED", "DISABLED"])}
        ])
        
    elif service == "drive":
        parameters.extend([
            {"name": "doc_id", "value": uuid.uuid4().hex},
            {"name": "doc_title", "value": random.choice(["Starfleet Q4 Report.xlsx", "Enterprise Mission Plan.docx", "Starfleet Budget 2378.xlsx", "Bridge Presentation.pptx", "Senior Staff Meeting Notes.doc"])},
            {"name": "doc_type", "value": random.choice(["document", "spreadsheet", "presentation", "folder"])},
            {"name": "visibility", "value": random.choice(["private", "people_with_link", "public"])},
            {"name": "owner", "value": actor["email"]},
            {"name": "primary_event", "boolValue": True}
        ])
        
        if "share" in event_info["name"] or "acl_change" in event_info["type"]:
            target = random.choice(USERS)
            parameters.extend([
                {"name": "target_user", "value": target["email"]},
                {"name": "permission", "value": random.choice(["can_view", "can_comment", "can_edit"])},
                {"name": "visibility_change", "value": random.choice(["private_to_people_with_link", "private_to_public", "people_with_link_to_public"])}
            ])
            
    elif service == "gmail":
        parameters.extend([
            {"name": "setting_name", "value": random.choice(["forwarding", "pop", "imap", "delegation"])},
            {"name": "setting_value", "value": random.choice(["enabled", "disabled"])},
            {"name": "destination_address", "value": f"external{random.randint(1, 100)}@gmail.com"} if "forwarding" in event_info["name"] else None,
            {"name": "delegate_address", "value": random.choice(USERS)["email"]} if "delegate" in event_info["name"] else None
        ])
        parameters = [p for p in parameters if p is not None]
        
    elif service == "meet":
        parameters.extend([
            {"name": "meeting_id", "value": f"{random.choice(['abc', 'xyz', 'def'])}-{random.choice(['defg', 'hijk', 'lmno'])}-{random.choice(['pqr', 'stu', 'vwx'])}"},
            {"name": "meeting_title", "value": random.choice(["Bridge Team Standup", "Diplomatic Meeting", "Engineering Review", "All Hands Starfleet", "Captain's 1:1 Meeting"])},
            {"name": "duration_seconds", "intValue": random.randint(300, 7200)},
            {"name": "participant_count", "intValue": random.randint(2, 100)},
            {"name": "is_external", "boolValue": random.choice([True, False])},
            {"name": "recording_enabled", "boolValue": random.choice([True, False])}
        ])
    
    # Add organization info
    event["ownerDomain"] = "starfleet.corp"
    
    # Add warning for suspicious events
    if any(word in event_info["name"] for word in ["suspicious", "leak", "phishing"]):
        event["warning"] = {
            "code": random.choice(["SUSPICIOUS_LOGIN", "ACCOUNT_COMPROMISE", "DATA_LEAK"]),
            "message": "This event may indicate a security concern"
        }
    
    return event

if __name__ == "__main__":
    # Generate sample events
    print("Sample Google Workspace Events:")
    print("=" * 50)
    for i in range(3):
        print(f"\nEvent {i+1}:")
        print(google_workspace_log())