#!/usr/bin/env python3
"""
PingProtect event generator
Generates synthetic PingProtect authentication and security events
"""
import random
from datetime import datetime, timezone, timedelta
import uuid

CLIENT_IDS = ["adminui", "auth-service", "mobile-app"]
USER_IDS = [str(uuid.uuid4()) for _ in range(5)]
ACTION_TYPES = ["SECRET.READ", "ROLE_ASSIGNMENT.DELETED", "MFA.CHALLENGE"]
STATUSES = ["SUCCESS", "FAILURE"]

def get_random_ip():
    return f"212.36.185.{random.randint(1, 255)}" if random.random() < 0.5 else f"203.0.113.{random.randint(1, 255)}"

def pingprotect_log() -> dict:
    """Generate a single PingProtect event log"""
    now = datetime.now(timezone.utc)
    event_time = now - timedelta(minutes=random.randint(0, 60))
    
    client_id = random.choice(CLIENT_IDS)
    user_id = random.choice(USER_IDS)
    source_ip = get_random_ip()
    action_type = random.choice(ACTION_TYPES)
    status = random.choice(STATUSES)
    
    timestamp = event_time.isoformat().replace('+00:00', 'Z')
    recorded_at = timestamp.replace('Z', '.000Z')
    
    # Use flat structure with dot notation (as parser expects)
    log_dict = {
        "timestamp": timestamp,
        "dataSource": "PingProtect",
        "recordedAt": recorded_at,
        "actors.client.id": client_id,
        "actors.user.id": user_id,
        "source.ip": source_ip,
        "action.type": action_type
    }
    
    if action_type == "SECRET.READ":
        description = "Secret Read"
        app_id = str(uuid.uuid4())
        log_dict["action.description"] = description
        log_dict["resources.application.id"] = app_id
        
        if status == "SUCCESS":
            message = f"Client secret read for application '{app_id}'"
        else:
            message = "Failed to read client secret - access denied"
    
    elif action_type == "ROLE_ASSIGNMENT.DELETED":
        description = "Role Assignment Deleted" 
        app_id = str(uuid.uuid4())
        log_dict["action.description"] = description
        log_dict["resources.application.id"] = app_id
        
        if status == "SUCCESS":
            message = f"Deleted role assignment {app_id}"
        else:
            message = "Failed to delete role assignment - insufficient permissions"
    
    else:  # MFA.CHALLENGE
        description = "MFA push challenge"
        log_dict["action.description"] = description
        
        if status == "SUCCESS":
            message = "User approved push notification"
        else:
            message = "User declined push notification"
    
    log_dict["result.status"] = status
    log_dict["result.description"] = message
    
    return log_dict

if __name__ == "__main__":
    import json
    print("Sample PingProtect Events:")
    print("=" * 50)
    for i in range(3):
        print(f"\nEvent {i+1}:")
        print(json.dumps(pingprotect_log(), indent=2))