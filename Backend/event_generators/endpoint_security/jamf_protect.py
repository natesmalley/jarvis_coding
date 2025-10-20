#!/usr/bin/env python3
"""
Jamf Protect event generator
Generates synthetic Jamf Protect endpoint security events in syslog format
"""
import random
from datetime import datetime, timezone, timedelta

# SentinelOne AI-SIEM specific field attributes
# Event types (matching parser expectations)
EVENT_TYPES = [
    "ProcessExecution", 
    "MalwareDetection", 
    "USBDevice", 
    "NetworkConnection", 
    "FileCreated",
    "LoginWindow",
    "SystemExtension",
    "KextLoaded",
    "SuspiciousActivity",
    "GatekeeperAlert"
]

# Computer IDs - Star Trek themed
COMPUTER_IDS = [
    "ENTERPRISE-BRIDGE-01",
    "ENGINEERING-MAC-02", 
    "SECURITY-STATION-03",
    "SICKBAY-TERMINAL-04",
    "READY-ROOM-MAC-05",
    "HOLODECK-CONTROL-06",
    "TRANSPORTER-ROOM-07",
    "TEN-FORWARD-POS-08"
]

# Users - Star Trek characters
USERS = [
    "jean.picard",
    "jordy.laforge",
    "worf.security",
    "data.android",
    "beverly.crusher",
    "wesley.crusher",
    "deanna.troi",
    "william.riker"
]

# Processes - Mix of legitimate and suspicious
PROCESSES = [
    "/Applications/Firefox.app/Contents/MacOS/firefox",
    "/Applications/Chrome.app/Contents/MacOS/Google Chrome", 
    "/Applications/Safari.app/Contents/MacOS/Safari",
    "/Applications/Slack.app/Contents/MacOS/Slack",
    "/Applications/Terminal.app/Contents/MacOS/Terminal",
    "/usr/bin/ssh",
    "/usr/bin/curl",
    "/bin/bash",
    "/usr/bin/python3",
    "/usr/bin/osascript",
    "/System/Library/CoreServices/Finder.app/Contents/MacOS/Finder",
    "/usr/libexec/xpcproxy",
    "/usr/sbin/screencapture",
    "/usr/bin/dscl",
    "/usr/bin/security"
]

# Verdicts
VERDICTS = ["allowed", "blocked", "quarantined", "flagged", "monitored"]

# Messages - More detailed and realistic
MESSAGES = [
    "Process launched with elevated privileges",
    "Suspicious network connection detected",
    "USB device mounted",
    "Malware signature detected",
    "File created in sensitive location",
    "Login attempt detected",
    "System extension loaded",
    "Kernel extension activity detected",
    "Gatekeeper bypass attempt",
    "Screen recording permission requested",
    "Keychain access detected",
    "LaunchAgent installed",
    "Persistence mechanism detected",
    "Code injection attempt blocked"
]

def jamf_protect_log() -> str:
    """Generate a single Jamf Protect event log in syslog format"""
    now = datetime.now(timezone.utc)
    # Generate events from last 10 minutes for recent timestamps
    event_time = now - timedelta(seconds=random.randint(0, 600))
    
    timestamp = event_time.strftime("%Y-%m-%dT%H:%M:%SZ")  # No milliseconds to match parser pattern
    event_type = random.choice(EVENT_TYPES)
    computer_id = random.choice(COMPUTER_IDS)
    user = random.choice(USERS)
    process_name = random.choice(PROCESSES)
    
    # Generate SHA256 hash (realistic looking)
    sha256 = ''.join(random.choices('abcdef0123456789', k=64))
    verdict = random.choice(VERDICTS)
    
    # Select message based on event type for more realism
    if event_type == "MalwareDetection":
        message = random.choice([
            "Malware signature detected",
            "Suspicious binary execution blocked",
            "Known malicious hash identified"
        ])
    elif event_type == "ProcessExecution":
        message = random.choice([
            "Process launched with elevated privileges",
            "Unsigned application executed",
            "Process executed from temporary directory"
        ])
    elif event_type == "USBDevice":
        message = random.choice([
            "USB device mounted",
            "External storage device connected",
            "Removable media detected"
        ])
    elif event_type == "NetworkConnection":
        message = random.choice([
            "Suspicious network connection detected",
            "Outbound connection to known C2 server",
            "Unusual port activity detected"
        ])
    elif event_type == "FileCreated":
        message = random.choice([
            "File created in sensitive location",
            "LaunchAgent installed",
            "Persistence mechanism detected"
        ])
    elif event_type == "GatekeeperAlert":
        message = random.choice([
            "Gatekeeper bypass attempt",
            "Unsigned application blocked",
            "Developer ID verification failed"
        ])
    else:
        message = random.choice(MESSAGES)
    
    # Add additional fields that might be useful
    pid = random.randint(100, 99999)
    parent_pid = random.randint(1, pid - 1)
    
    # Generate syslog format with all expected fields
    # Try without timestamp prefix to see if parser works better
    log = (f'eventType="{event_type}" '
           f'computerId="{computer_id}" user="{user}" '
           f'processName="{process_name}" sha256="{sha256}" '
           f'verdict="{verdict}" message="{message}" '
           f'pid="{pid}" parentPid="{parent_pid}" '
           f'domain="starfleet.corp" timestamp="{timestamp}"')
    
    return log

if __name__ == "__main__":
    # Generate sample events
    print("Sample Jamf Protect Events:")
    print("=" * 50)
    for i in range(3):
        print(f"\nEvent {i+1}:")
        print(jamf_protect_log())