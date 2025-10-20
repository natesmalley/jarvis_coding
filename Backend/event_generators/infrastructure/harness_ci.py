#!/usr/bin/env python3
"""
Harness CI/CD event generator
Generates synthetic Harness CI/CD pipeline events in syslog format
"""
import random
from datetime import datetime, timezone, timedelta

# Pipelines
PIPELINES = ["pipeline-123", "pipeline-456", "pipeline-789", "frontend-build", "backend-deploy"]

# Execution IDs
EXECUTION_IDS = ["exec-789", "exec-101", "exec-202", "exec-303", "exec-404"]

# Statuses
STATUSES = ["STARTED", "SUCCEEDED", "FAILED", "RUNNING", "PAUSED", "CANCELLED"]

# Triggers
TRIGGERS = ["manual", "webhook", "schedule", "pull_request", "git_push"]

# Initiators
INITIATORS = ["devuser", "admin", "ci-bot", "scheduler", "webhook-service"]

# Messages
MESSAGES = [
    "Pipeline execution started", "Build stage completed", "Deployment successful",
    "Tests passed", "Quality gate failed", "Security scan completed", "Rollback initiated"
]

def harness_ci_log():
    """Generate a single Harness CI/CD event log in syslog format"""
    now = datetime.now(timezone.utc)
    event_time = now - timedelta(minutes=random.randint(0, 1440))
    
    timestamp = event_time.strftime("%Y-%m-%dT%H:%M:%SZ")
    pipeline_id = random.choice(PIPELINES)
    execution_id = random.choice(EXECUTION_IDS)
    status = random.choice(STATUSES)
    trigger = random.choice(TRIGGERS)
    initiator = random.choice(INITIATORS)
    message = random.choice(MESSAGES)
    
    # Generate syslog format matching the parser's expected format
    log = (f'{timestamp} Harness pipelineId="{pipeline_id}" executionId="{execution_id}" '
           f'status="{status}" trigger="{trigger}" initiator="{initiator}" '
           f'message="{message}"')
    
    # Return just the raw log string for proper parser compatibility
    return log

def harness_ci_log_dict():
    """Generate Harness CI/CD event as dict (for backward compatibility)"""
    return {
        "raw": harness_ci_log()
    }

# ATTR_FIELDS for AI-SIEM compatibility
if __name__ == "__main__":
    print("Sample Harness CI/CD Events:")
    print("=" * 50)
    for i in range(3):
        print(f"\nEvent {i+1}:")
        print(harness_ci_log())