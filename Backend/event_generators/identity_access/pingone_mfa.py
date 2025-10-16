#!/usr/bin/env python3
"""
PingOne MFA event generator
Generates synthetic PingOne MFA authentication events
"""
import random
from datetime import datetime, timezone, timedelta
import uuid

USERS = ["jane.doe@example.com", "john.doe@example.com", "admin@example.com", "service@example.com"]
ACTION_TYPES = ["MFA.AUTHENTICATE", "MFA.ENROLL"]
FACTORS = ["PUSH", "TOTP", "SMS", "EMAIL"]
STATUSES = ["SUCCESS", "FAILURE"]

def get_random_ip():
    return f"198.51.100.{random.randint(1, 255)}"

def pingone_mfa_log() -> dict:
    """Generate a single PingOne MFA event log"""
    now = datetime.now(timezone.utc)
    event_time = now - timedelta(minutes=random.randint(0, 60))
    
    user = random.choice(USERS)
    source_ip = get_random_ip()
    action_type = random.choice(ACTION_TYPES)
    factor = random.choice(FACTORS)
    status = random.choice(STATUSES)
    session_id = str(uuid.uuid4())
    
    timestamp = event_time.isoformat().replace('+00:00', 'Z')
    recorded_at = timestamp
    
    if action_type == "MFA.AUTHENTICATE":
        if status == "SUCCESS":
            if factor == "PUSH":
                description = "User approved push notification"
            elif factor == "TOTP":
                description = "Time-based OTP validated successfully"
            else:
                description = f"{factor} authentication successful"
        else:
            if factor == "TOTP":
                description = "Invalid time-based OTP"
            elif factor == "PUSH":
                description = "Push notification declined"
            else:
                description = f"{factor} authentication failed"
    else:  # MFA.ENROLL
        description = f"User enrolled new {factor} factor"
        status = "SUCCESS"  # Enrollment is usually successful
    
    log_dict = {
        "timestamp": timestamp,
        "dataSource": "PingOneMFA",
        "recordedAt": recorded_at,
        "user": user,
        "source.ip": source_ip,
        "action.type": action_type,
        "factor": factor,
        "result.status": status,
        "description": description,
        "sessionId": session_id
    }
    
    return log_dict

if __name__ == "__main__":
    import json
    print("Sample PingOne MFA Events:")
    print("=" * 50)
    for i in range(3):
        print(f"\nEvent {i+1}:")
        print(json.dumps(pingone_mfa_log(), indent=2))