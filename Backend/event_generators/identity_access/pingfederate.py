#!/usr/bin/env python3
"""
PingFederate SSO Authentication event generator
Generates synthetic PingFederate authentication and provisioning logs
"""
import json
import random
import time
from datetime import datetime, timezone, timedelta
from typing import Dict

# Log levels
LOG_LEVELS = ["INFO", "WARN", "ERROR", "DEBUG"]

# Logger names
LOGGER_NAMES = [
    "com.pingidentity.pf.authn",
    "com.pingidentity.pf.sso",
    "com.pingidentity.provisioner",
    "com.pingidentity.pf.adapter",
    "com.pingidentity.pf.oauth"
]

# Operations
OPERATIONS = ["authenticate", "sso", "provisioning", "token_exchange", "logout"]

# Adapter IDs
ADAPTER_IDS = ["LDAPAdapter", "KerberosAdapter", "SAMLAdapter", "OAuthAdapter", "RadiusAdapter"]

# Token types
TOKEN_TYPES = ["ID_TOKEN", "ACCESS_TOKEN", "REFRESH_TOKEN", "SAML_ASSERTION"]

# Status values
STATUSES = ["success", "failure", "pending", "error"]

# Failure reasons
FAILURE_REASONS = [
    "invalid password",
    "account locked",
    "user not found",
    "expired credentials",
    "invalid token",
    "session timeout"
]

# Usernames
USERNAMES = ["alice", "bob", "charlie", "admin", "service", "external_user"]

# Connectors (for provisioning)
CONNECTORS = ["Salesforce", "Azure AD", "Google Workspace", "ServiceNow", "Workday"]

# Provisioning operations
PROV_OPERATIONS = ["createUser", "updateUser", "deleteUser", "createGroup", "updateGroup"]

def generate_ip() -> str:
    """Generate IP address"""
    return f"{random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"

def generate_session_id() -> str:
    """Generate session ID"""
    return ''.join(random.choices('abcdef0123456789', k=32))

def generate_transaction_id() -> str:
    """Generate transaction ID"""
    return f"txn-{random.randint(1000, 9999)}"

def pingfederate_log() -> Dict:
    """Generate a single PingFederate authentication event log"""
    now = datetime.now(timezone.utc)
    event_time = now - timedelta(minutes=random.randint(0, 1440))
    
    operation = random.choice(OPERATIONS)
    log_level = random.choice(LOG_LEVELS)
    logger_name = random.choice(LOGGER_NAMES)
    username = random.choice(USERNAMES)
    client_ip = generate_ip()
    adapter_id = random.choice(ADAPTER_IDS)
    status = random.choice(STATUSES)
    
    # Base event structure
    event = {
        "timestamp": event_time.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "log_level": log_level,
        "logger_name": logger_name,
        "operation": operation,
        "username": username,
        "client_ip": client_ip,
        "status": status
    }
    
    # Add specific fields based on operation
    if operation == "authenticate":
        event.update({
            "adapter_id": adapter_id,
            "session_id": generate_session_id(),
            "token_type": random.choice(TOKEN_TYPES),
            "reason": random.choice(FAILURE_REASONS) if status == "failure" else None,
            "message": f"Authentication {status} for user {username}" +
                      (f"; reason={event.get('reason')}" if status == "failure" else "") +
                      f"; ClientIP={client_ip}; AdapterId={adapter_id}"
        })
        
    elif operation == "sso":
        event.update({
            "session_id": generate_session_id(),
            "token_type": random.choice(TOKEN_TYPES),
            "target_application": random.choice(["App1", "App2", "Portal", "Dashboard"]),
            "message": f"SSO {status} for user {username} to application"
        })
        
    elif operation == "provisioning":
        connector = random.choice(CONNECTORS)
        prov_op = random.choice(PROV_OPERATIONS)
        transaction_id = generate_transaction_id()
        
        event.update({
            "transaction_id": transaction_id,
            "connector": connector,
            "prov_operation": prov_op,
            "attributes": {
                "username": f"{username}@example.com",
                "role": random.choice(["StandardUser", "AdminUser", "PowerUser"])
            },
            "message": f"Provisioning transactionId={transaction_id}; Connector={connector}; Operation={prov_op}; Status={status.upper()}"
        })
        
    elif operation == "token_exchange":
        event.update({
            "token_type": random.choice(TOKEN_TYPES),
            "client_id": f"client-{random.randint(1000, 9999)}",
            "scope": random.choice(["read", "write", "admin"]),
            "message": f"Token exchange {status} for client"
        })
        
    elif operation == "logout":
        event.update({
            "session_id": generate_session_id(),
            "message": f"User {username} logged out successfully"
        })
    
    # Remove None values
    event = {k: v for k, v in event.items() if v is not None}
    
    return event

if __name__ == "__main__":
    # Generate sample events
    print("Sample PingFederate SSO Events:")
    print("=" * 50)
    for i in range(3):
        print(f"\nEvent {i+1}:")
        print(pingfederate_log())