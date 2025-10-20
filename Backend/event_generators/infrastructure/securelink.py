#!/usr/bin/env python3
"""
SecureLink remote access event generator
Generates synthetic SecureLink privileged remote access events
"""
import json
import random
import time
from datetime import datetime, timezone, timedelta
from typing import Dict

# Event types
EVENT_TYPES = [
    {"type": "SESSION_START", "severity": "INFO", "category": "Access"},
    {"type": "SESSION_END", "severity": "INFO", "category": "Access"},
    {"type": "CONNECTION_ESTABLISHED", "severity": "INFO", "category": "Connection"},
    {"type": "CONNECTION_TERMINATED", "severity": "INFO", "category": "Connection"},
    {"type": "FILE_TRANSFER", "severity": "WARNING", "category": "Data Transfer"},
    {"type": "COMMAND_EXECUTED", "severity": "WARNING", "category": "Command"},
    {"type": "SCREEN_RECORDING", "severity": "INFO", "category": "Monitoring"},
    {"type": "KEYSTROKE_LOGGING", "severity": "INFO", "category": "Monitoring"},
    {"type": "UNAUTHORIZED_ACCESS", "severity": "CRITICAL", "category": "Security"},
    {"type": "POLICY_VIOLATION", "severity": "HIGH", "category": "Compliance"},
    {"type": "APPROVAL_REQUEST", "severity": "INFO", "category": "Workflow"},
    {"type": "APPROVAL_GRANTED", "severity": "INFO", "category": "Workflow"},
    {"type": "APPROVAL_DENIED", "severity": "WARNING", "category": "Workflow"},
    {"type": "EMERGENCY_ACCESS", "severity": "CRITICAL", "category": "Emergency"}
]

# Access methods
ACCESS_METHODS = [
    "RDP", "SSH", "Telnet", "VNC", "HTTP", "HTTPS", 
    "FTP", "SFTP", "SCP", "Database", "Application"
]

# Vendor types
VENDOR_TYPES = [
    "IT Support", "Software Vendor", "Hardware Vendor", "Managed Service Provider",
    "Consultant", "Auditor", "Contractor", "System Integrator", "Cloud Provider"
]

# Target systems
TARGET_SYSTEMS = [
    "Production Server", "Database Server", "Web Server", "Application Server",
    "Network Device", "Security Appliance", "Storage System", "Backup System",
    "Monitoring System", "Development Server", "Test Server", "Critical Infrastructure"
]

# Risk levels
RISK_LEVELS = ["Low", "Medium", "High", "Critical"]

def generate_ip() -> str:
    """Generate a random IP address"""
    return f"{random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"

def securelink_log() -> Dict:
    """Generate a single SecureLink event log"""
    now = datetime.now(timezone.utc)
    event_time = now - timedelta(minutes=random.randint(0, 1440))
    
    event_info = random.choice(EVENT_TYPES)
    
    event = {
        "timestamp": event_time.isoformat(),
        "event_id": f"SL-{random.randint(1000000, 9999999)}",
        "session_id": f"session_{random.randint(100000000, 999999999)}",
        "event_type": event_info["type"],
        "severity": event_info["severity"],
        "category": event_info["category"],
        "vendor_name": f"Vendor_{random.randint(1, 100)}",
        "vendor_type": random.choice(VENDOR_TYPES),
        "vendor_email": f"vendor{random.randint(1, 100)}@{random.choice(['partner', 'contractor', 'supplier'])}.com",
        "vendor_organization": f"{random.choice(['TechCorp', 'ServicePro', 'Solutions Inc', 'Systems LLC'])}",
        "technician_name": f"Tech_{random.randint(1, 50)}",
        "technician_id": f"TECH{random.randint(10000, 99999)}",
        "source_ip": generate_ip(),
        "source_country": random.choice(["US", "CA", "GB", "DE", "FR", "IN", "AU", "JP"]),
        "target_system": random.choice(TARGET_SYSTEMS),
        "target_ip": f"10.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}",
        "target_hostname": f"srv-{random.randint(100, 999)}.company.local",
        "access_method": random.choice(ACCESS_METHODS),
        "protocol": random.choice(["TCP", "UDP", "HTTPS", "SSH"]),
        "port": random.choice([22, 23, 80, 443, 3389, 5900, 1433, 3306, 5432]),
        "business_justification": random.choice([
            "Emergency system maintenance",
            "Scheduled maintenance window",
            "Critical bug fix deployment",
            "Security patch installation", 
            "System troubleshooting",
            "Performance optimization",
            "Database maintenance",
            "Network configuration"
        ]),
        "risk_level": random.choice(RISK_LEVELS),
        "approval_status": random.choice(["Approved", "Pending", "Denied", "Emergency Override"]),
        "approver": f"manager{random.randint(1, 20)}@company.com",
        "duration_minutes": random.randint(5, 480) if "END" in event_info["type"] else None
    }
    
    # Add event-specific fields
    if "SESSION" in event_info["type"]:
        event.update({
            "session_type": random.choice(["Interactive", "File Transfer", "Command Line", "Application"]),
            "concurrent_sessions": random.randint(1, 5),
            "session_recording": random.choice([True, False]),
            "keystroke_logging": random.choice([True, False]),
            "screen_recording": random.choice([True, False]),
            "idle_timeout": random.randint(15, 60),  # minutes
            "max_session_time": random.randint(60, 480),  # minutes
            "client_software": random.choice([
                "SecureLink Client v3.2.1",
                "RDP Client", 
                "SSH Client",
                "Web Browser",
                "Mobile App"
            ])
        })
        
        if "END" in event_info["type"]:
            event.update({
                "session_start_time": (event_time - timedelta(minutes=event["duration_minutes"])).isoformat(),
                "data_transferred_mb": random.randint(0, 1000),
                "commands_executed": random.randint(0, 50),
                "files_accessed": random.randint(0, 20),
                "termination_reason": random.choice([
                    "User initiated", "Timeout", "Admin terminated", 
                    "System shutdown", "Network error", "Policy violation"
                ])
            })
    
    elif event_info["type"] == "FILE_TRANSFER":
        event.update({
            "transfer_direction": random.choice(["Upload", "Download", "Bidirectional"]),
            "file_name": random.choice([
                "system_backup.zip", "config_export.xml", "log_files.tar.gz",
                "patch_file.exe", "database_dump.sql", "diagnostic_report.pdf"
            ]),
            "file_size_mb": random.randint(1, 1000),
            "file_hash": ''.join(random.choices('abcdef0123456789', k=64)),
            "transfer_speed_mbps": random.randint(1, 100),
            "encryption_used": random.choice([True, False]),
            "virus_scan_result": random.choice(["Clean", "Suspicious", "Infected", "Not Scanned"]),
            "dlp_scan_result": random.choice(["Allowed", "Blocked", "Quarantined", "Alert"])
        })
    
    elif event_info["type"] == "COMMAND_EXECUTED":
        event.update({
            "command": random.choice([
                "systemctl restart nginx",
                "sudo apt update && apt upgrade",
                "mysql -u root -p < backup.sql",
                "ps aux | grep apache",
                "netstat -tulpn", 
                "tail -f /var/log/messages",
                "chmod 755 /usr/local/bin/script.sh",
                "crontab -e",
                "iptables -L",
                "docker ps -a"
            ]),
            "command_category": random.choice([
                "System Administration", "Database Management", "Network Configuration",
                "File Operations", "Process Management", "Security", "Monitoring"
            ]),
            "execution_result": random.choice(["Success", "Failed", "Warning"]),
            "return_code": random.choice([0, 1, 2, 127]),
            "output_size_bytes": random.randint(0, 10000),
            "privileged_execution": random.choice([True, False]),
            "risk_score": random.randint(1, 100)
        })
    
    elif event_info["type"] in ["SCREEN_RECORDING", "KEYSTROKE_LOGGING"]:
        event.update({
            "recording_id": f"REC_{random.randint(1000000, 9999999)}",
            "recording_duration": random.randint(60, 28800),  # seconds
            "file_size_mb": random.randint(10, 500),
            "compression_ratio": round(random.uniform(0.3, 0.8), 2),
            "quality_setting": random.choice(["Low", "Medium", "High", "Ultra"]),
            "retention_period_days": random.randint(30, 2555),
            "automated_analysis": random.choice([True, False]),
            "suspicious_activity_detected": random.choice([True, False])
        })
    
    elif event_info["type"] == "UNAUTHORIZED_ACCESS":
        event.update({
            "blocked_reason": random.choice([
                "No valid approval",
                "Outside business hours",
                "Suspicious location",
                "Multiple failed attempts",
                "Blacklisted IP",
                "Expired credentials",
                "Policy violation"
            ]),
            "failed_attempts": random.randint(1, 10),
            "lockout_applied": random.choice([True, False]),
            "security_alert_sent": True,
            "incident_created": f"INC-{random.randint(100000, 999999)}",
            "threat_score": random.randint(70, 100)
        })
    
    elif event_info["type"] == "POLICY_VIOLATION":
        event.update({
            "policy_name": random.choice([
                "Remote Access Policy",
                "Data Transfer Policy", 
                "Command Execution Policy",
                "Session Recording Policy",
                "Vendor Access Policy"
            ]),
            "violation_type": random.choice([
                "Unauthorized file transfer",
                "Excessive session duration",
                "Prohibited command execution",
                "Access outside approved hours",
                "Unapproved target system"
            ]),
            "policy_severity": random.choice(["Low", "Medium", "High", "Critical"]),
            "automatic_remediation": random.choice([True, False]),
            "compliance_impact": random.choice(["None", "Minor", "Moderate", "Significant"])
        })
    
    elif "APPROVAL" in event_info["type"]:
        event.update({
            "request_id": f"REQ-{random.randint(100000, 999999)}",
            "requested_access_duration": random.randint(60, 480),  # minutes
            "approval_workflow": f"WF_{random.randint(1, 10)}",
            "approval_chain": [
                f"manager{random.randint(1, 5)}@company.com",
                f"security{random.randint(1, 3)}@company.com"
            ],
            "business_hours_only": random.choice([True, False]),
            "monitoring_required": random.choice([True, False]),
            "special_conditions": random.choice([
                "", "Supervisor must be present", "Recording mandatory", 
                "No file transfer allowed", "Read-only access only"
            ])
        })
        
        if event_info["type"] == "APPROVAL_DENIED":
            event.update({
                "denial_reason": random.choice([
                    "Insufficient business justification",
                    "High risk system access",
                    "Outside maintenance window",
                    "Incomplete approval chain",
                    "Policy violation history"
                ])
            })
    
    elif event_info["type"] == "EMERGENCY_ACCESS":
        event.update({
            "emergency_type": random.choice([
                "System Outage", "Security Incident", "Critical Bug",
                "Data Loss", "Network Failure", "Service Degradation"
            ]),
            "incident_ticket": f"INC-{random.randint(100000, 999999)}",
            "emergency_contact": f"oncall{random.randint(1, 10)}@company.com",
            "post_access_review_required": True,
            "emergency_duration_minutes": random.randint(30, 240),
            "business_impact": random.choice(["Low", "Medium", "High", "Critical"]),
            "service_affected": random.choice([
                "Customer Portal", "Payment Processing", "Email System",
                "Database Service", "Network Infrastructure", "Security Systems"
            ])
        })
    
    # Add compliance and audit fields
    event.update({
        "compliance_frameworks": random.sample([
            "SOX", "PCI-DSS", "HIPAA", "GDPR", "SOC2", "ISO27001", "NIST"
        ], random.randint(1, 3)),
        "audit_trail_id": f"AUDIT_{random.randint(1000000, 9999999)}",
        "data_classification": random.choice(["Public", "Internal", "Confidential", "Restricted"]),
        "retention_period": random.randint(90, 2555),  # days
        "privacy_impact": random.choice(["None", "Low", "Medium", "High"])
    })
    
    # Add geographical and network information
    event.update({
        "geolocation": {
            "latitude": round(random.uniform(-90, 90), 6),
            "longitude": round(random.uniform(-180, 180), 6),
            "city": random.choice(["New York", "London", "Tokyo", "Sydney", "Toronto"]),
            "region": random.choice(["North America", "Europe", "Asia Pacific"])
        },
        "network_segment": random.choice(["DMZ", "Internal", "Management", "Production"]),
        "bandwidth_used_mbps": random.randint(1, 100),
        "latency_ms": random.randint(10, 500)
    })
    
    # Remove None values
    event = {k: v for k, v in event.items() if v is not None}
    
    return event

if __name__ == "__main__":
    # Generate sample events
    print("Sample SecureLink Events:")
    print("=" * 50)
    for i in range(3):
        print(f"\nEvent {i+1}:")
        print(securelink_log())