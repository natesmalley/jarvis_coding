#!/usr/bin/env python3
"""
Linux Authentication event generator
Generates synthetic Linux authentication logs from /var/log/auth.log
"""
import json
import random
import time
from datetime import datetime, timezone, timedelta
from typing import Dict

# Process names
PROCESS_NAMES = ["sshd", "sudo", "su", "login", "gdm-session-worker", "polkit"]

# Authentication methods
AUTH_METHODS = ["password", "publickey", "keyboard-interactive", "pam"]

# Usernames
USERNAMES = ["root", "alice", "bob", "service", "admin", "ubuntu", "centos"]

# Hostnames
HOSTNAMES = ["server", "web01", "db01", "app01", "firewall"]

# Auth events
AUTH_EVENTS = [
    "Failed password",
    "Accepted password", 
    "Accepted publickey",
    "Failed publickey",
    "session opened",
    "session closed",
    "sudo command",
    "authentication failure"
]

def generate_ip() -> str:
    """Generate IP address"""
    return f"{random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"

def generate_process_id() -> int:
    """Generate process ID"""
    return random.randint(1000, 65535)

def generate_session_id() -> str:
    """Generate session ID"""
    return f"session-{random.randint(10000, 99999)}"

def linux_auth_log() -> Dict:
    """Generate a single Linux authentication event log"""
    now = datetime.now(timezone.utc)
    event_time = now - timedelta(minutes=random.randint(0, 1440))
    
    process_name = random.choice(PROCESS_NAMES)
    process_id = generate_process_id()
    username = random.choice(USERNAMES)
    hostname = random.choice(HOSTNAMES)
    auth_event = random.choice(AUTH_EVENTS)
    auth_method = random.choice(AUTH_METHODS)
    src_ip = generate_ip()
    src_port = random.randint(32768, 65535)
    
    # Determine status based on event type
    if "Failed" in auth_event or "failure" in auth_event:
        status = "failure"
        status_detail = "Authentication failed"
    elif "Accepted" in auth_event or "opened" in auth_event:
        status = "success"
        status_detail = "Authentication successful"
    else:
        status = "unknown"
        status_detail = "Session event"
    
    # Generate message based on event type
    if auth_event in ["Failed password", "Accepted password"]:
        message = f"{auth_event} for {username} from {src_ip} port {src_port} ssh2"
    elif auth_event in ["Failed publickey", "Accepted publickey"]:
        message = f"{auth_event} for {username} from {src_ip} port {src_port} ssh2"
    elif "session" in auth_event:
        message = f"pam_unix({process_name}:session): {auth_event} for user {username}"
        if "opened" in auth_event:
            message += f" by (uid={random.randint(0, 1000)})"
    elif "sudo" in auth_event:
        message = f"sudo: {username} : TTY=pts/{random.randint(0, 10)} ; PWD=/home/{username} ; USER=root ; COMMAND=/bin/ls"
    else:
        message = f"{process_name}: {auth_event} for {username}"
    
    event = {
        "timestamp": event_time.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "hostname": hostname,
        "facility": "auth",
        "severity": "warning" if status == "failure" else "info",
        "process_name": process_name,
        "process_id": process_id,
        "username": username,
        "src_ip": src_ip,
        "src_port": src_port,
        "auth_method": auth_method,
        "status": status,
        "status_detail": status_detail,
        "message": message,
        "session_id": generate_session_id() if "session" in auth_event else None
    }
    
    # Remove None values
    event = {k: v for k, v in event.items() if v is not None}
    
    return event

if __name__ == "__main__":
    # Generate sample events
    print("Sample Linux Authentication Events:")
    print("=" * 50)
    for i in range(3):
        print(f"\nEvent {i+1}:")
        print(linux_auth_log())