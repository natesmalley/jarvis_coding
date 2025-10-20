#!/usr/bin/env python3
"""
Veeam Backup event generator
Generates synthetic Veeam backup system events
"""
import random
from datetime import datetime, timezone, timedelta
import uuid

JOB_NAMES = [
    "Daily_Exchange_Backup", "Weekly_SQL_Backup", "VMware_Prod_Backup",
    "File_Server_Backup", "Monthly_Archive", "DR_Replication"
]

SEVERITIES = ["Info", "Warning", "Error"]
RESULTS = [0, 1, 2]  # 0=Success, 1=Warning, 2=Error

ERROR_MESSAGES = [
    "Failed to process VM 'Prod-Web01': Cannot connect to host",
    "Network timeout during backup operation",
    "Insufficient disk space on backup repository",
    "VM snapshot creation failed"
]

def generate_session_id():
    return str(uuid.uuid4())

def generate_duration():
    hours = random.randint(0, 8)
    minutes = random.randint(0, 59)
    seconds = random.randint(0, 59)
    return f"{hours:02d}:{minutes:02d}:{seconds:02d}"

def generate_size():
    value = random.randint(1, 2000)
    unit = random.choice(["GB", "TB"])
    return f"{value}{unit}"

def veeam_backup_log() -> dict:
    """Generate a single Veeam backup event log"""
    now = datetime.now(timezone.utc)
    event_time = now - timedelta(minutes=random.randint(0, 480))
    
    job_id = random.randint(1, 10)
    job_name = random.choice(JOB_NAMES)
    session_id = generate_session_id()
    result = random.choice(RESULTS)
    duration = generate_duration()
    objects_processed = random.randint(1, 50)
    total_size = generate_size()
    
    # Determine severity and message based on result
    if result == 0:  # Success
        severity = "Info"
        description = f"Backup job '{job_name}' finished successfully"
    elif result == 1:  # Warning
        severity = "Warning"
        description = f"Backup job '{job_name}' finished with warnings"
        warning_count = random.randint(1, 5)
        affected_objects = "SQLServer01, SQLServer02"
    else:  # Error
        severity = "Error" 
        description = f"Backup job '{job_name}' failed"
        error_message = random.choice(ERROR_MESSAGES)
        objects_processed = random.randint(0, 10)  # Fewer objects for failed jobs
    
    timestamp = event_time.isoformat().replace('+00:00', 'Z')
    
    log_dict = {
        "timestamp": timestamp,
        "dataSource": "veeam-backup",
        "severity": severity,
        "JobID": job_id,
        "JobName": job_name,
        "JobSessionID": session_id,
        "JobResult": result,
        "Description": description,
        "Duration": duration,
        "ObjectsProcessed": objects_processed,
        "TotalSize": total_size
    }
    
    # Add result-specific fields
    if result == 1:  # Warning
        log_dict["WarningCount"] = warning_count
        log_dict["AffectedObjects"] = affected_objects
    elif result == 2:  # Error
        log_dict["ErrorMessage"] = error_message
    
    return log_dict

if __name__ == "__main__":
    import json
    print("Sample Veeam Backup Events:")
    print("=" * 50)
    for i in range(3):
        print(f"\nEvent {i+1}:")
        print(json.dumps(veeam_backup_log(), indent=2))