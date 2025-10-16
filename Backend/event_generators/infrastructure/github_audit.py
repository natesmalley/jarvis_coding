#!/usr/bin/env python3
"""
GitHub audit log event generator
Generates synthetic GitHub audit logs in syslog format
"""
import random
from datetime import datetime, timezone, timedelta

# SentinelOne AI-SIEM specific field attributes
# Actions
ACTIONS = [
    "repo.create", "repo.destroy", "repo.archive", "repo.unarchive",
    "repo.public", "repo.private", "repo.transfer",
    "team.create", "team.destroy", "team.add_member", "team.remove_member",
    "org.add_member", "org.remove_member", "org.update_member",
    "repo.add_collaborator", "repo.remove_collaborator",
    "repo.change_collaborator_permission",
    "oauth_access.create", "oauth_access.destroy",
    "public_key.create", "public_key.delete",
    "repo_secret.create", "repo_secret.update", "repo_secret.remove",
    "protected_branch.create", "protected_branch.destroy",
    "pull_request.merge", "pull_request.close"
]

# Outcomes
OUTCOMES = ["success", "failure", "unknown"]

# Organizations
ORGS = ["acme-corp", "tech-startup", "enterprise-co", "dev-team", "ops-group"]

# Repositories  
REPOS = [
    "web-app", "mobile-app", "api-gateway", "microservice-auth",
    "infrastructure", "documentation", "config-repo", "test-suite",
    "data-pipeline", "ml-models", "frontend", "backend", "new-repo"
]

# Users
USERS = [
    "alice", "bob", "charlie", "devuser", "admin", "cicd-bot",
    "release-manager", "security-scanner", "dependabot"
]

def generate_ip() -> str:
    """Generate IP address"""
    return f"{random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"

def github_audit_log():
    """Generate a single GitHub audit event in JSON format for parse=gron"""
    now = datetime.now(timezone.utc)
    event_time = now - timedelta(minutes=random.randint(0, 1440))
    
    timestamp = event_time.strftime("%Y-%m-%dT%H:%M:%SZ")
    actor = random.choice(USERS)
    org = random.choice(ORGS)
    repo = random.choice(REPOS)
    action = random.choice(ACTIONS)
    outcome = random.choice(OUTCOMES)
    ip = generate_ip()
    
    # Build description based on action
    if "repo" in action:
        description = f"Repository {org}/{repo} {action.split('.')[1]}"
        repository = f"{org}/{repo}"
    elif "team" in action:
        team_name = random.choice(["developers", "admins", "reviewers"])
        description = f"Team {team_name} {action.split('.')[1]}"
        repository = f"{org}/team-management"
    elif "org" in action:
        description = f"Organization {org} {action.split('.')[1]}"
        repository = f"{org}/org-settings"
    else:
        description = f"Action {action} performed"
        repository = f"{org}/{repo}"
    
    # Return JSON object for parse=gron compatibility
    return {
        "timestamp": timestamp,
        "actor": actor,
        "org": org,
        "repository": repository,
        "action": action,
        "outcome": outcome,
        "description": description,
        "source_ip": ip
    }

if __name__ == "__main__":
    # Generate sample events
    print("Sample GitHub Audit Events:")
    print("=" * 50)
    for i in range(3):
        print(f"\nEvent {i+1}:")
        print(github_audit_log())