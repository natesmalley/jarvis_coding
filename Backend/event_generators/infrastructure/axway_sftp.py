#!/usr/bin/env python3
"""
Axway SFTP event generator
Generates synthetic Axway SFTP file transfer events in syslog format
"""
import random
from datetime import datetime, timezone, timedelta

# SFTP event types
EVENTS = ["LOGIN", "UPLOAD", "DOWNLOAD", "DELETE", "RENAME", "LOGOUT"]

# User names
USERS = ["sftp_user", "batch_user", "backup_user", "sync_user", "transfer_user", "service_account"]

# Results
RESULTS = ["SUCCESS", "FAILURE"]

# Messages
MESSAGES = [
    "User authenticated via public key",
    "User authenticated via password",
    "File transfer completed successfully",
    "File upload failed - permission denied",
    "Connection established",
    "Session terminated",
    "Directory listing requested"
]

def generate_ip() -> str:
    """Generate IP address"""
    return f"{random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"

def axway_sftp_log() -> str:
    """Generate a single Axway SFTP event log in syslog format"""
    now = datetime.now(timezone.utc)
    event_time = now - timedelta(minutes=random.randint(0, 1440))
    
    timestamp = event_time.strftime("%Y-%m-%dT%H:%M:%SZ")
    session_id = f"sftp-{random.randint(1000, 9999)}"
    user = random.choice(USERS)
    event = random.choice(EVENTS)
    remote_ip = generate_ip()
    result = random.choice(RESULTS)
    message = random.choice(MESSAGES)
    
    # Generate syslog format matching the original test event
    # 2025-08-06T21:00:00Z AxwaySFTP session_id="sftp-1001" user="sftp_user" event="LOGIN" remote_ip="198.51.100.90" result="SUCCESS" message="User authenticated via public key"
    log = (f'{timestamp} AxwaySFTP session_id="{session_id}" user="{user}" '
           f'event="{event}" remote_ip="{remote_ip}" result="{result}" '
           f'message="{message}"')
    
    return log

# ATTR_FIELDS for AI-SIEM compatibility
if __name__ == "__main__":
    # Generate sample events
    print("Sample Axway SFTP Events:")
    print("=" * 50)
    for i in range(3):
        print(f"\nEvent {i+1}:")
        print(axway_sftp_log())