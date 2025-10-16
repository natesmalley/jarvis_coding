#!/usr/bin/env python3
"""
Teleport access proxy event generator
Generates synthetic Teleport audit and session events
"""
import json
import random
import time
import uuid
from datetime import datetime, timezone, timedelta
from typing import Dict

# Teleport event types
EVENT_TYPES = [
    "session.start",
    "session.end",
    "session.join",
    "session.leave",
    "user.login",
    "user.logout",
    "auth.failed",
    "exec",
    "scp",
    "ssh.port_forward",
    "db.session.start",
    "db.session.end",
    "db.session.query",
    "kube.request",
    "app.session.start",
    "app.session.end",
    "cert.create",
    "role.created",
    "role.deleted",
    "trusted_cluster.create",
    "trusted_cluster.delete"
]

# User names
USERS = ["alice", "bob", "charlie", "diana", "admin", "service-account", "developer1"]

# Server/node names
NODES = ["web-server-01", "db-server-01", "app-server-01", "k8s-node-01", "bastion-01"]

# Database names
DATABASES = ["postgres-prod", "mysql-staging", "mongodb-dev", "redis-cache"]

# Kubernetes resources
K8S_RESOURCES = ["pods", "services", "deployments", "configmaps", "secrets"]
K8S_NAMESPACES = ["default", "production", "staging", "development", "kube-system"]

def teleport_log() -> Dict:
    """Generate a single Teleport event log"""
    now = datetime.now(timezone.utc)
    event_time = now - timedelta(minutes=random.randint(0, 1440))
    
    event_type = random.choice(EVENT_TYPES)
    
    # Base event structure
    event = {
        "event": event_type,
        "uid": str(uuid.uuid4()),
        "time": event_time.isoformat() + "Z",
        "user": random.choice(USERS),
        "cluster_name": "teleport.company.com"
    }
    
    # Add event-specific fields
    if "session" in event_type:
        session_id = str(uuid.uuid4())
        event.update({
            "sid": session_id,
            "namespace": "default",
            "server_id": str(uuid.uuid4()),
            "server_hostname": random.choice(NODES),
            "server_addr": f"10.0.{random.randint(1, 10)}.{random.randint(1, 254)}:22",
            "session_recording": "node",
            "interactive": True
        })
        
        if event_type == "session.start":
            event.update({
                "terminal_size": "80x24",
                "login": event["user"],
                "server_labels": {
                    "env": random.choice(["prod", "staging", "dev"]),
                    "type": "server"
                }
            })
        elif event_type == "session.end":
            event.update({
                "session_start": (event_time - timedelta(minutes=random.randint(1, 120))).isoformat() + "Z",
                "session_stop": event_time.isoformat() + "Z",
                "bytes_transmitted": random.randint(1000, 1000000),
                "bytes_received": random.randint(1000, 1000000)
            })
    
    elif event_type in ["user.login", "user.logout", "auth.failed"]:
        event.update({
            "method": random.choice(["local", "oidc", "saml", "github"]),
            "success": event_type != "auth.failed",
            "client_ip": f"{random.randint(10, 192)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"
        })
        if event_type == "auth.failed":
            event["error"] = random.choice([
                "invalid credentials",
                "user not found",
                "account locked",
                "mfa challenge failed"
            ])
    
    elif event_type == "exec":
        event.update({
            "sid": str(uuid.uuid4()),
            "server_hostname": random.choice(NODES),
            "command": random.choice([
                "ls -la",
                "cat /etc/passwd",
                "systemctl status nginx",
                "docker ps",
                "kubectl get pods",
                "tail -f /var/log/app.log"
            ]),
            "exitCode": random.choice([0, 0, 0, 1, 127]),
            "cgroup_id": random.randint(1000, 9999),
            "program": random.choice(["bash", "sh", "zsh"])
        })
    
    elif "db.session" in event_type:
        db_name = random.choice(DATABASES)
        event.update({
            "db_service": db_name,
            "db_protocol": db_name.split('-')[0],
            "db_uri": f"{db_name}.internal:5432",
            "db_user": event["user"],
            "db_name": f"{db_name}_db"
        })
        
        if event_type == "db.session.query":
            event["db_query"] = random.choice([
                "SELECT * FROM users LIMIT 10",
                "UPDATE products SET price = price * 1.1",
                "INSERT INTO logs (message) VALUES ('test')",
                "DELETE FROM sessions WHERE created_at < NOW() - INTERVAL '7 days'"
            ])
    
    elif event_type == "kube.request":
        event.update({
            "kubernetes_cluster": "k8s-prod",
            "kubernetes_users": [event["user"]],
            "kubernetes_groups": ["system:authenticated"],
            "resource": random.choice(K8S_RESOURCES),
            "namespace": random.choice(K8S_NAMESPACES),
            "verb": random.choice(["get", "list", "create", "update", "delete", "watch"]),
            "request_path": f"/api/v1/namespaces/{random.choice(K8S_NAMESPACES)}/{random.choice(K8S_RESOURCES)}",
            "response_code": random.choice([200, 201, 403, 404]),
            "response_reason": random.choice(["OK", "Created", "Forbidden", "NotFound"])
        })
    
    elif "app.session" in event_type:
        event.update({
            "app_name": random.choice(["grafana", "jenkins", "gitlab", "jira"]),
            "app_uri": f"https://{random.choice(['grafana', 'jenkins', 'gitlab', 'jira'])}.company.com",
            "app_public_addr": f"{random.choice(['grafana', 'jenkins', 'gitlab', 'jira'])}.company.com",
            "app_labels": {
                "env": random.choice(["prod", "staging"]),
                "team": random.choice(["platform", "devops", "security"])
            }
        })
    
    elif event_type == "cert.create":
        event.update({
            "cert_type": random.choice(["user", "host", "db", "app"]),
            "identity": {
                "user": event["user"],
                "roles": random.sample(["admin", "developer", "auditor", "db-admin"], random.randint(1, 3)),
                "traits": {
                    "logins": [event["user"]],
                    "kubernetes_groups": ["system:masters"] if "admin" in event.get("identity", {}).get("roles", []) else []
                }
            },
            "ttl": random.choice([3600, 7200, 28800, 86400])  # 1h, 2h, 8h, 24h
        })
    
    # Add metadata
    event["metadata"] = {
        "origin": random.choice(["web", "cli", "api"]),
        "session_id": str(uuid.uuid4()) if "session" not in event_type else event.get("sid")
    }
    
    return event

if __name__ == "__main__":
    # Generate sample events
    print("Sample Teleport Events:")
    print("=" * 50)
    for i in range(3):
        print(f"\nEvent {i+1}:")
        print(teleport_log())