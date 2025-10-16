#!/usr/bin/env python3
"""
Buildkite CI/CD event generator
Generates synthetic Buildkite audit and pipeline events
"""
import json
import random
import time
import uuid
from datetime import datetime, timezone, timedelta
from typing import Dict

# Event types in Buildkite
EVENT_TYPES = [
    "pipeline.created",
    "pipeline.updated",
    "pipeline.deleted",
    "build.started",
    "build.finished",
    "build.failed",
    "build.canceled",
    "agent.connected",
    "agent.disconnected",
    "user.login",
    "user.logout",
    "team.member.added",
    "team.member.removed",
    "api_key.created",
    "api_key.deleted",
    "webhook.created",
    "webhook.updated"
]

# Build states
BUILD_STATES = ["passed", "failed", "canceled", "skipped", "blocked", "running"]

# Pipeline names
PIPELINES = [
    "frontend-app",
    "backend-api",
    "mobile-ios",
    "mobile-android",
    "infrastructure",
    "data-pipeline",
    "ml-training",
    "security-scan"
]

# User names
USERS = ["alice.dev", "bob.builder", "charlie.admin", "diana.devops", "evan.engineer"]

def buildkite_log() -> Dict:
    """Generate a single Buildkite event log"""
    now = datetime.now(timezone.utc)
    event_time = now - timedelta(minutes=random.randint(0, 1440))
    
    event_type = random.choice(EVENT_TYPES)
    
    # Base event structure
    event = {
        "id": str(uuid.uuid4()),
        "type": event_type,
        "occurredAt": event_time.isoformat(),
        "organizationUuid": f"org_{uuid.uuid4().hex[:8]}",
        "organizationSlug": "acme-corp",
        "actorUuid": f"user_{uuid.uuid4().hex[:8]}",
        "actorName": random.choice(USERS),
        "actorType": "User"
    }
    
    # Add event-specific fields
    if "pipeline" in event_type:
        event.update({
            "pipelineUuid": f"pipeline_{uuid.uuid4().hex[:8]}",
            "pipelineSlug": random.choice(PIPELINES),
            "subject": {
                "type": "Pipeline",
                "uuid": f"pipeline_{uuid.uuid4().hex[:8]}",
                "name": random.choice(PIPELINES)
            }
        })
    
    elif "build" in event_type:
        pipeline = random.choice(PIPELINES)
        event.update({
            "buildUuid": f"build_{uuid.uuid4().hex[:8]}",
            "buildNumber": random.randint(1, 1000),
            "buildState": random.choice(BUILD_STATES),
            "pipelineSlug": pipeline,
            "branch": random.choice(["main", "develop", "feature/new-feature", "hotfix/bug-fix"]),
            "commit": uuid.uuid4().hex[:7],
            "message": f"Update {pipeline} configuration",
            "subject": {
                "type": "Build",
                "uuid": f"build_{uuid.uuid4().hex[:8]}",
                "number": random.randint(1, 1000),
                "url": f"https://buildkite.com/acme-corp/{pipeline}/builds/{random.randint(1, 1000)}"
            }
        })
        
    elif "agent" in event_type:
        event.update({
            "agentUuid": f"agent_{uuid.uuid4().hex[:8]}",
            "agentName": f"build-agent-{random.randint(1, 10)}",
            "agentHostname": f"agent-{random.randint(1, 10)}.buildkite.local",
            "subject": {
                "type": "Agent",
                "uuid": f"agent_{uuid.uuid4().hex[:8]}",
                "name": f"build-agent-{random.randint(1, 10)}"
            }
        })
        
    elif "user" in event_type:
        event.update({
            "ipAddress": f"{random.randint(10, 192)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}",
            "userAgent": random.choice([
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
                "Mozilla/5.0 (X11; Linux x86_64)"
            ]),
            "sessionUuid": f"session_{uuid.uuid4().hex[:8]}"
        })
    
    elif "api_key" in event_type:
        event.update({
            "apiKeyUuid": f"key_{uuid.uuid4().hex[:8]}",
            "apiKeyDescription": random.choice([
                "CI/CD Integration",
                "Monitoring Dashboard",
                "Deployment Script",
                "Testing Framework"
            ]),
            "subject": {
                "type": "APIKey",
                "uuid": f"key_{uuid.uuid4().hex[:8]}"
            }
        })
    
    # Add context data
    event["context"] = {
        "requestId": str(uuid.uuid4()),
        "userAgent": "buildkite-webhook/1.0"
    }
    
    return event

if __name__ == "__main__":
    # Generate sample events
    print("Sample Buildkite Events:")
    print("=" * 50)
    for i in range(3):
        print(f"\nEvent {i+1}:")
        print(buildkite_log())