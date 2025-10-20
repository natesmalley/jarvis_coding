#!/usr/bin/env python3
"""
CyberArk Conjur Secrets Management event generator
Generates synthetic CyberArk Conjur audit logs
"""
import json
import random
import time
from datetime import datetime, timezone, timedelta
from typing import Dict

# Operations
OPERATIONS = ["authenticate", "check", "fetch", "create", "update", "delete", "list"]

# Results
RESULTS = ["success", "denied", "failure", "error"]

# Authenticators
AUTHENTICATORS = ["authn", "authn-ldap", "authn-oidc", "authn-k8s", "authn-jwt"]

# Users
USERS = [
    "prod:user:alice", "prod:user:bob", "prod:user:charlie",
    "test:user:developer1", "test:user:developer2",
    "admin:user:sysadmin", "service:user:app1", "service:user:app2"
]

# Secrets
SECRETS = [
    "prod:secrets:db/password",
    "prod:secrets:api/key",
    "prod:secrets:ssl/certificate",
    "test:secrets:db/password",
    "service:secrets:token",
    "admin:secrets:root/password"
]

# Resources
RESOURCES = [
    "prod:policy:database",
    "prod:policy:application",
    "test:policy:development",
    "admin:policy:system"
]

# Privileges
PRIVILEGES = ["read", "write", "execute", "create", "update", "delete"]

# Hostnames
HOSTNAMES = ["conjur-master", "conjur-standby", "conjur-follower"]

def generate_priority() -> int:
    """Generate syslog priority (facility * 8 + severity)"""
    # Local0 facility (16) + Info severity (6) = 134
    return random.choice([134, 132, 131, 130])  # info, warning, error, crit

def generate_process_id() -> int:
    """Generate process ID"""
    return random.randint(1000, 9999)

def cyberark_conjur_log() -> Dict:
    """Generate a single CyberArk Conjur audit event log"""
    now = datetime.now(timezone.utc)
    event_time = now - timedelta(minutes=random.randint(0, 1440))
    
    operation = random.choice(OPERATIONS)
    result = random.choice(RESULTS)
    user = random.choice(USERS)
    authenticator = random.choice(AUTHENTICATORS)
    hostname = random.choice(HOSTNAMES)
    process_id = generate_process_id()
    priority = generate_priority()
    
    # Select appropriate resource based on operation
    if operation in ["fetch", "check"]:
        resource = random.choice(SECRETS)
        privilege = random.choice(PRIVILEGES)
    else:
        resource = random.choice(RESOURCES)
        privilege = None
    
    # Create structured log entry based on RFC 5424 format
    event = {
        "timestamp": event_time.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "hostname": hostname,
        "facility": "local0",
        "severity": "info" if result == "success" else "warn",
        "priority": priority,
        "process_id": process_id,
        "operation": operation,
        "result": result,
        "role": user,
        "authenticator": authenticator,
        "user": user,
        "resource_id": resource if operation in ["fetch", "check"] else None,
        "secret_id": resource if operation == "fetch" else None,
        "privileges": privilege if operation == "check" else None,
        "message": f"{user} {result} {operation} on {resource}" + 
                  (f" with {authenticator}" if operation == "authenticate" else "")
    }
    
    # Remove None values
    event = {k: v for k, v in event.items() if v is not None}
    
    return event

if __name__ == "__main__":
    # Generate sample events
    print("Sample CyberArk Conjur Audit Events:")
    print("=" * 50)
    for i in range(3):
        print(f"\nEvent {i+1}:")
        print(cyberark_conjur_log())