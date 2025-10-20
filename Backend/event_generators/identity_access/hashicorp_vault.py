#!/usr/bin/env python3
"""
HashiCorp Vault event generator (JSON format)
"""
from __future__ import annotations
import json
import random
import time
import uuid
from datetime import datetime, timezone, timedelta
from typing import Dict, List

# Vault operations
OPERATIONS = [
    "read", "create", "update", "delete", "list", "login", "logout",
    "auth", "token_create", "token_revoke", "token_renew", "lease_revoke",
    "policy_create", "policy_delete", "policy_update", "mount", "unmount",
    "seal", "unseal", "rotate", "backup", "restore", "snapshot"
]

# Auth methods
AUTH_METHODS = [
    "userpass", "ldap", "okta", "aws", "azure", "gcp", "kubernetes", 
    "jwt", "oidc", "github", "cert", "approle", "token"
]

# Secret engines
SECRET_ENGINES = [
    "kv", "database", "pki", "aws", "azure", "gcp", "ssh", "transit",
    "totp", "consul", "nomad", "rabbitmq", "cassandra", "mongodb"
]

# Vault paths
VAULT_PATHS = [
    "secret/data/app/database", "secret/data/app/api-keys", "secret/data/prod/db-creds",
    "secret/data/dev/tokens", "auth/userpass/login/{user}", "auth/aws/login",
    "pki/issue/web-server", "database/creds/readonly", "aws/creds/s3-readonly",
    "sys/auth", "sys/policy", "sys/mounts", "sys/seal-status", "sys/health"
]

# Entity types
ENTITY_TYPES = [
    "token", "policy", "auth_method", "secret_engine", "lease", "role",
    "entity", "group", "alias", "namespace", "audit_device"
]

# Request types
REQUEST_TYPES = ["read", "write", "delete", "list", "sudo"]

# Response statuses
HTTP_STATUSES = [200, 201, 204, 400, 401, 403, 404, 405, 429, 500, 502, 503]

# Error types
ERROR_TYPES = [
    "permission denied", "invalid request", "sealed vault", "token expired",
    "path not found", "method not allowed", "rate limit exceeded", 
    "internal server error", "bad gateway", "service unavailable"
]

# Users and entities  
USERS = [
    ("john.doe", "human", "developer"),
    ("jane.smith", "human", "devops"),
    ("bob.johnson", "human", "admin"),
    ("app-server-01", "service", "application"),
    ("ci-pipeline", "service", "automation"),
    ("monitoring", "service", "observability"),
    ("backup-service", "service", "backup")
]

# Policies
POLICIES = [
    "admin", "developer", "readonly", "app-server", "ci-cd", "monitoring",
    "database-admin", "pki-operator", "secret-reader", "secret-writer"
]

def _generate_ip():
    """Generate an IP address"""
    return f"10.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"

def _generate_token():
    """Generate a Vault token"""
    return f"hvs.{uuid.uuid4().hex}"

def _generate_lease_id():
    """Generate a lease ID"""
    return f"{random.choice(SECRET_ENGINES)}/creds/{uuid.uuid4().hex[:8]}/{uuid.uuid4().hex}"

def hashicorp_vault_log(overrides: dict | None = None) -> str:
    """
    Return a single HashiCorp Vault audit log event as JSON string.
    
    Pass `overrides` to force any field to a specific value:
        hashicorp_vault_log({"type": "request"})
    """
    # Generate timestamps
    now = datetime.now(timezone.utc)
    timestamp = now - timedelta(seconds=random.randint(0, 300))
    
    # Select operation and user
    operation = random.choice(OPERATIONS)
    user_name, entity_type, user_role = random.choice(USERS)
    
    # Determine if this is a request or response
    log_type = random.choice(["request", "response"])
    
    # Generate path based on operation
    if operation in ["login", "logout"]:
        path = f"auth/{random.choice(AUTH_METHODS)}/login/{user_name}"
    elif operation in ["token_create", "token_revoke", "token_renew"]:
        path = "auth/token/" + operation.split("_")[1]
    elif operation.startswith("policy"):
        path = f"sys/policy/{random.choice(POLICIES)}"
    elif operation in ["mount", "unmount"]:
        path = f"sys/mounts/{random.choice(SECRET_ENGINES)}"
    elif operation in ["seal", "unseal"]:
        path = f"sys/{operation}"
    else:
        path = random.choice(VAULT_PATHS).replace("{user}", user_name)
    
    # Generate request/response details
    if log_type == "request":
        http_status = None
        request_id = str(uuid.uuid4())
    else:
        http_status = random.choice(HTTP_STATUSES)
        request_id = str(uuid.uuid4())
    
    # Base audit log structure
    event = {
        "time": timestamp.strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
        "type": log_type,
        "auth": {
            "client_token": _generate_token(),
            "accessor": f"acc_{uuid.uuid4().hex[:16]}",
            "display_name": user_name,
            "policies": random.sample(POLICIES, random.randint(1, 3)),
            "token_policies": random.sample(POLICIES, random.randint(1, 2)),
            "metadata": {
                "username": user_name if entity_type == "human" else None,
                "service": user_name if entity_type == "service" else None,
            },
            "entity_id": str(uuid.uuid4()),
            "token_type": random.choice(["service", "batch", "recovery"]),
            "token_ttl": random.randint(3600, 86400),  # 1 hour to 1 day
            "token_issue_time": timestamp.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        },
        "request": {
            "id": request_id,
            "operation": operation,
            "mount_type": random.choice(SECRET_ENGINES) if operation not in ["seal", "unseal"] else "",
            "client_token": _generate_token(),
            "client_token_accessor": f"acc_{uuid.uuid4().hex[:16]}",
            "namespace": {
                "id": "root",
                "path": ""
            },
            "path": path,
            "data": _generate_request_data(operation, path),
            "policy_override": False,
            "remote_address": _generate_ip(),
            "wrap_ttl": 0,
            "headers": {
                "user-agent": [random.choice([
                    "vault/1.12.0", "terraform/1.3.0", "consul-template/0.29.0",
                    "vault-k8s/1.1.0", "nomad/1.4.0", "python-hvac/1.0.2"
                ])],
                "content-type": ["application/json"],
                "x-forwarded-for": [_generate_ip()]
            }
        },
        "response": {
            "mount_type": random.choice(SECRET_ENGINES) if operation not in ["seal", "unseal"] else "",
            "data": _generate_response_data(operation, path, http_status) if log_type == "response" else None
        } if log_type == "response" else None,
        "error": _generate_error(http_status) if log_type == "response" and http_status >= 400 else ""
    }
    
    # Add response-specific fields
    if log_type == "response":
        event["response"].update({
            "status_code": http_status,
            "duration": random.randint(1, 1000),  # milliseconds
            "headers": {
                "cache-control": ["no-store"],
                "content-type": ["application/json"],
                "x-vault-request-id": [request_id]
            }
        })
        
        # Add lease information for secret reads
        if operation == "read" and "secret" in path and http_status == 200:
            event["response"]["lease_id"] = _generate_lease_id()
            event["response"]["renewable"] = random.choice([True, False])
            event["response"]["lease_duration"] = random.randint(3600, 86400)
        
        # Add auth information for login operations
        if operation == "login" and http_status == 200:
            event["response"]["auth"] = {
                "client_token": _generate_token(),
                "accessor": f"acc_{uuid.uuid4().hex[:16]}",
                "policies": random.sample(POLICIES, random.randint(1, 3)),
                "token_policies": random.sample(POLICIES, random.randint(1, 2)),
                "lease_duration": random.randint(3600, 86400),
                "renewable": True,
                "entity_id": str(uuid.uuid4()),
                "token_type": "service",
                "orphan": False
            }
    
    # Add Vault cluster information
    event.update({
        "cluster_id": str(uuid.uuid4()),
        "version": "1.12.0",
        "build_date": "2023-10-20T09:15:00Z",
        "hostname": f"vault-{random.randint(1, 3)}.company.com",
        "node_id": f"node_{uuid.uuid4().hex[:8]}"
    })
    
    # Apply any overrides
    if overrides:
        event.update(overrides)
    
    return json.dumps(event)

def _generate_request_data(operation: str, path: str) -> Dict:
    """Generate request data based on operation"""
    if operation == "create" and "secret" in path:
        return {
            "data": {
                "username": f"user_{random.randint(1000, 9999)}",
                "password": f"pass_{uuid.uuid4().hex[:16]}"
            },
            "options": {},
            "version": random.randint(1, 10)
        }
    elif operation == "login":
        return {
            "username": random.choice(USERS)[0],
            "password": "***HMAC-SHA256***"  # Vault hashes sensitive data in audit logs
        }
    elif operation in ["token_create", "token_renew"]:
        return {
            "ttl": f"{random.randint(1, 24)}h",
            "policies": random.sample(POLICIES, random.randint(1, 2)),
            "renewable": True
        }
    elif operation == "policy_create":
        return {
            "policy": "path \"secret/*\" { capabilities = [\"read\", \"list\"] }"
        }
    else:
        return {}

def _generate_response_data(operation: str, path: str, status_code: int) -> Dict:
    """Generate response data based on operation and status"""
    if status_code >= 400:
        return None
        
    if operation == "read" and "secret" in path:
        return {
            "data": {
                "username": f"user_{random.randint(1000, 9999)}",
                "password": f"pass_{uuid.uuid4().hex[:16]}",
                "created_time": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
                "version": random.randint(1, 10)
            },
            "metadata": {
                "created_time": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
                "custom_metadata": None,
                "deletion_time": "",
                "destroyed": False,
                "version": random.randint(1, 10)
            }
        }
    elif operation == "list":
        return {
            "keys": [f"item-{i}" for i in range(random.randint(1, 10))]
        }
    elif operation in ["seal", "unseal"]:
        return {
            "sealed": operation == "seal",
            "t": 3,  # threshold
            "n": 5,  # total shares
            "progress": random.randint(0, 3) if operation == "unseal" else 0,
            "version": "1.12.0",
            "cluster_name": "vault-cluster-1",
            "cluster_id": str(uuid.uuid4())
        }
    else:
        return {}

def _generate_error(status_code: int) -> str:
    """Generate error message based on status code"""
    error_map = {
        400: "invalid request",
        401: "permission denied", 
        403: "permission denied",
        404: "path not found",
        405: "method not allowed",
        429: "rate limit exceeded",
        500: "internal server error",
        502: "bad gateway",
        503: "service unavailable"
    }
    return error_map.get(status_code, "unknown error")

if __name__ == "__main__":
    # Generate sample logs
    print("Sample HashiCorp Vault events:")
    for op_type in ["login", "read", "create", "token_create"]:
        print(f"\n{op_type.upper()} operation:")
        print(hashicorp_vault_log({"request": {"operation": op_type}}))
        print()