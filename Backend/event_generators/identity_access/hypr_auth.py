#!/usr/bin/env python3
"""
HYPR authentication event generator
Generates synthetic HYPR FIDO2 and passwordless authentication events in syslog format
"""
import random
from datetime import datetime, timezone, timedelta

# Event types
EVENT_TYPES = ["REGISTRATION", "AUTHENTICATION", "VERIFICATION", "ENROLLMENT", "REVOCATION"]

# Users
USERS = [
    "alice@example.com", "bob@company.org", "charlie@business.net", 
    "admin@system.com", "user@domain.com", "service@app.com"
]

# Devices
DEVICES = ["iPhone13", "Samsung-Galaxy", "Google-Pixel", "iPad", "Windows-Hello", "MacBook-Touch"]

# Success indicators
SUCCESS_VALUES = [True, False]

# Authenticators
AUTHENTICATORS = ["FIDO2", "Biometric", "Push", "SMS", "Email", "Hardware-Token"]

# Messages
MESSAGES = [
    "User registered new FIDO2 credential", "Biometric authentication successful",
    "Push notification approved", "User enrollment completed", "Device verification failed",
    "Authentication request processed", "Token revoked successfully"
]

def hypr_auth_log() -> dict:
    """Generate a single HYPR authentication event log in syslog format"""
    now = datetime.now(timezone.utc)
    event_time = now - timedelta(minutes=random.randint(0, 1440))
    
    timestamp = event_time.strftime("%Y-%m-%dT%H:%M:%SZ")
    event_type = random.choice(EVENT_TYPES)
    user = random.choice(USERS)
    device = random.choice(DEVICES)
    is_successful = random.choice(SUCCESS_VALUES)
    authenticator = random.choice(AUTHENTICATORS)
    message = random.choice(MESSAGES)
    
    # Generate syslog format matching the original test event
    log = (f'{timestamp} HYPR eventType="{event_type}" user="{user}" '
           f'device="{device}" isSuccessful={str(is_successful).lower()} '
           f'authenticator="{authenticator}" message="{message}"')
    
    # Return dict with raw log and ATTR_FIELDS for HEC compatibility
    return {
        "raw": log
    }

# ATTR_FIELDS for AI-SIEM compatibility
if __name__ == "__main__":
    print("Sample HYPR Authentication Events:")
    print("=" * 50)
    for i in range(3):
        print(f"\nEvent {i+1}:")
        print(hypr_auth_log())