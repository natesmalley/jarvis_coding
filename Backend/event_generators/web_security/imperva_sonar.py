#!/usr/bin/env python3
"""
Imperva Sonar event generator
Generates synthetic Imperva Sonar database security events
"""
import random
from datetime import datetime, timezone, timedelta

EVENT_TYPES = ["DB_LOGIN", "SQL_QUERY", "POLICY_VIOLATION"]
DB_USERS = ["report_user", "admin_user", "contractor_user", "app_user", "backup_user"]
DATABASES = ["finance", "hr", "inventory", "customer", "audit"]
OUTCOMES = ["SUCCESS", "ALLOWED", "BLOCKED"]
POLICIES = ["SensitiveDataAccess", "DropObject", "AdminAccess", "DataExfiltration"]

SQL_STATEMENTS = [
    "SELECT * FROM payroll WHERE ssn='***'",
    "INSERT INTO users VALUES ('***')",
    "UPDATE accounts SET balance = ***",
    "DROP TABLE employees",
    "DELETE FROM audit_log WHERE date < '2024-01-01'",
    "SELECT TOP 1000 * FROM customer_data"
]

def get_random_ip():
    """Generate a random IP address."""
    return f"192.0.2.{random.randint(1, 255)}" if random.random() < 0.7 else f"203.0.113.{random.randint(1, 255)}"

def imperva_sonar_log() -> dict:
    """Generate a single Imperva Sonar event log"""
    now = datetime.now(timezone.utc)
    event_time = now - timedelta(minutes=random.randint(0, 60))
    
    event_type = random.choice(EVENT_TYPES)
    db_user = random.choice(DB_USERS)
    source_ip = get_random_ip()
    database = random.choice(DATABASES)
    
    timestamp = event_time.isoformat().replace('+00:00', 'Z')
    log_dict = {
        "timestamp": timestamp,
        "dataSource": "ImpervaSonar",
        "eventType": event_type,
        "databaseUser": db_user,
        "sourceIP": source_ip,
        "database": database
    }
    
    if event_type == "DB_LOGIN":
        outcome = random.choice(["SUCCESS", "FAILURE"])
        log_dict["outcome"] = outcome
        
        if outcome == "SUCCESS":
            message = f"User {db_user} connected to {database} database"
        else:
            message = f"User {db_user} failed to connect to {database} database"
    
    elif event_type == "SQL_QUERY":
        statement = random.choice(SQL_STATEMENTS)
        outcome = "ALLOWED"
        policy = random.choice(POLICIES)
        
        log_dict["statement"] = statement
        log_dict["outcome"] = outcome
        log_dict["policy"] = policy
        
        table_name = "payroll" if "payroll" in statement else "audit_log" if "audit_log" in statement else "table"
        message = f"Query executed against {table_name} table"
    
    else:  # POLICY_VIOLATION
        statement = random.choice([s for s in SQL_STATEMENTS if "DROP" in s or "DELETE" in s])
        outcome = "BLOCKED"
        policy = random.choice(POLICIES)
        
        log_dict["statement"] = statement
        log_dict["outcome"] = outcome
        log_dict["policy"] = policy
        
        if "DROP" in statement:
            message = "Drop table command blocked by security policy"
        else:
            message = "Bulk delete operation blocked by security policy"
    
    log_dict["message"] = message
    return log_dict

if __name__ == "__main__":
    import json
    print("Sample Imperva Sonar Events:")
    print("=" * 50)
    for i in range(3):
        print(f"\nEvent {i+1}:")
        print(json.dumps(imperva_sonar_log(), indent=2))