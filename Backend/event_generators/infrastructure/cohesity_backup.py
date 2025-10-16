#!/usr/bin/env python3
"""
Cohesity backup event generator
Generates synthetic Cohesity backup system events in syslog format
"""
import random
from datetime import datetime, timezone, timedelta

# SentinelOne AI-SIEM specific field attributes
# Job names
JOB_NAMES = [
    "Daily_VM_Backup", "Weekly_SQL_Backup", "Monthly_Archive", "Adhoc_DB_Backup",
    "Exchange_Backup", "File_Server_Backup", "NAS_Backup", "Cloud_Sync", 
    "Disaster_Recovery", "Compliance_Archive", "Daily_Exchange_Backup"
]

# Object names
OBJECT_NAMES = [
    "vm-Prod01", "vm-Dev02", "vm-Test03", "sql-server-01", "web-server-02", 
    "file-server-01", "exchange-01", "nas-storage", "cloud-archive"
]

# Statuses
STATUSES = ["STARTED", "COMPLETED", "FAILED", "PAUSED", "RUNNING", "CANCELLED", "WARNING"]

# Initiators
INITIATORS = ["schedule", "manual", "policy", "system", "user", "trigger"]

# Messages
MESSAGES = [
    "Protection run started", "Backup completed successfully", "Backup failed due to network error",
    "Scheduled backup initiated", "Manual backup requested", "Policy-driven backup started",
    "Incremental backup in progress", "Full backup completed"
]

def cohesity_backup_log() -> str:
    """Generate a single Cohesity backup event log in syslog format"""
    now = datetime.now(timezone.utc)
    event_time = now - timedelta(minutes=random.randint(0, 1440))
    
    timestamp = event_time.strftime("%Y-%m-%dT%H:%M:%SZ")
    run_id = f"r-{random.randint(1000, 9999)}"
    job_name = random.choice(JOB_NAMES)
    object_name = random.choice(OBJECT_NAMES)
    status = random.choice(STATUSES)
    initiated_by = random.choice(INITIATORS)
    message = random.choice(MESSAGES)
    
    # Generate syslog format matching the original test event
    log = (f'{timestamp} Cohesity runId="{run_id}" jobName="{job_name}" '
           f'objectName="{object_name}" status="{status}" initiatedBy="{initiated_by}" '
           f'message="{message}"')
    
    return log

if __name__ == "__main__":
    print("Sample Cohesity Backup Events:")
    print("=" * 50)
    for i in range(3):
        print(f"\nEvent {i+1}:")
        print(cohesity_backup_log())