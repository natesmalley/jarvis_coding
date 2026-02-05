#!/usr/bin/env python3
"""
AsyncRAT Phishing Campaign - Operation Silent Schedule
=======================================================

Scenario: Sophisticated phishing attack delivering AsyncRAT malware through weaponized PDF
with multi-stage payload delivery, process injection, and attempted lateral movement.

Timeline:
- Days 1-5: Normal HR user baseline
- Day 6: Phishing delivery, PDF exploit, AsyncRAT infection, persistence, C2, lateral movement

Attack Chain:
1. Phishing email with malicious PDF attachment
2. PDF exploit (CVE-2023-21608) executes JavaScript
3. JavaScript drops PowerShell script with AMSI bypass
4. PowerShell downloads AsyncRAT (update.exe)
5. Process injection into explorer.exe
6. Dual persistence (Scheduled Task + Registry Run Key)
7. Reconnaissance and credential harvesting
8. C2 communication with fallback methods
9. Lateral movement attempts (port scanning, SMB)
10. Data exfiltration preparation
11. Detection and comprehensive containment

MITRE ATT&CK Techniques:
- T1566.001, T1204.002, T1203, T1059.001, T1562.001, T1027, T1055
- T1053.005, T1547.001, T1071.001, T1071.004, T1018, T1087.002
- T1046, T1003.001, T1056.001, T1113, T1005
"""

import json
import os
import sys
import errno
import random
from datetime import datetime, timezone, timedelta
from typing import Dict, List
import json
import sys
import os
import errno
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'event_generators'))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'event_generators', 'shared'))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'event_generators', 'email_security'))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'event_generators', 'identity_access'))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'event_generators', 'endpoint_security'))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'event_generators', 'network_security'))

from proofpoint import proofpoint_log
from microsoft_365_collaboration import microsoft_365_collaboration_log
from sentinelone_endpoint import sentinelone_endpoint_log
from paloalto_firewall import paloalto_firewall_log

# Import HEC sender - will be used if S1_HEC_TOKEN is set at runtime
try:
    from hec_sender import send_one
    HEC_AVAILABLE = True
except ImportError:
    print("⚠️  Warning: hec_sender not available, events will only be saved to JSON")
    HEC_AVAILABLE = False
    send_one = None

VICTIM_PROFILE = {
    "name": "Sara Mitchell",
    "email": "sara.mitchell@securatech.com",
    "department": "Human Resources",
    "role": "HR Manager",
    "location": "Austin, Texas",
    "normal_ip": "10.50.25.112",
    "hostname": "HR-SARA-PC",
    "work_hours_start": 8,
    "work_hours_end": 17,
}

ATTACKER_PROFILE = {
    "sender_email": "hr-benefits@securatech-update.com",
    "sender_name": "HR Benefits Team",
    "phishing_domain": "temp-files.cloud",
    "c2_primary_ip": "185.234.72.156",
    "c2_primary_port": 443,
    "c2_backup_domain": "malware-updates.tk",
    "c2_backup_port": 8080,
    "payload_url": "hxxp://temp-files.cloud/update.exe",
    "malicious_pdf": "Benefits_Update_2024.pdf",
    "malware_family": "AsyncRAT",
}

def get_scenario_time(base_time: datetime, day: int, hour: int, minute: int = 0, second: int = 0) -> str:
    event_time = base_time + timedelta(days=day, hours=hour, minutes=minute, seconds=second)
    return event_time.isoformat()

def create_event(timestamp: str, source: str, phase: str, event_data: dict) -> Dict:
    return {"timestamp": timestamp, "source": source, "phase": phase, "event": event_data}

def generate_normal_day_events(base_time: datetime, day: int) -> List[Dict]:
    events = []
    
    login_time = get_scenario_time(base_time, day, 9, 0)
    m365_login_str = microsoft_365_collaboration_log()
    m365_login = json.loads(m365_login_str) if isinstance(m365_login_str, str) else m365_login_str
    m365_login['TimeStamp'] = login_time
    m365_login['UserId'] = VICTIM_PROFILE['email']
    m365_login['ClientIP'] = VICTIM_PROFILE['normal_ip']
    m365_login['Operation'] = 'UserLoggedIn'
    m365_login['Workload'] = 'Exchange'
    m365_login['EventType'] = 'Audit.Exchange'
    events.append(create_event(login_time, "microsoft_365_collaboration", "normal_behavior", m365_login))
    
    file_times = [10, 11, 14, 15]
    hr_files = ["Employee_Handbook_2024.pdf", "Benefits_Enrollment_Guide.xlsx", 
                "PTO_Policy_Updates.docx", "New_Hire_Checklist.xlsx"]
    
    for i, hour in enumerate(file_times):
        file_time = get_scenario_time(base_time, day, hour, 15)
        m365_file_str = microsoft_365_collaboration_log()
        m365_file = json.loads(m365_file_str) if isinstance(m365_file_str, str) else m365_file_str
        filename = hr_files[i % len(hr_files)]
        m365_file['TimeStamp'] = file_time
        m365_file['UserId'] = VICTIM_PROFILE['email']
        m365_file['ClientIP'] = VICTIM_PROFILE['normal_ip']
        m365_file['Operation'] = 'FileAccessed'
        m365_file['ObjectId'] = f"/HR/Documents/{filename}"
        m365_file['FileName'] = filename
        m365_file['Workload'] = 'SharePoint'
        m365_file['EventType'] = 'Audit.SharePoint'
        events.append(create_event(file_time, "microsoft_365_collaboration", "normal_behavior", m365_file))
    
    proc_time = get_scenario_time(base_time, day, 12, 30)
    s1_proc = sentinelone_endpoint_log({
        "event.type": "Process Creation",
        "event.time": int((base_time + timedelta(days=day, hours=12, minutes=30)).timestamp() * 1000),
        "endpoint.name": VICTIM_PROFILE["hostname"],
        "src.process.user": VICTIM_PROFILE["email"].split("@")[0],
        "src.process.name": "outlook.exe",
        "src.process.cmdline": "C:\\Program Files\\Microsoft Office\\Office16\\OUTLOOK.EXE",
    })
    events.append(create_event(proc_time, "sentinelone_endpoint", "normal_behavior", s1_proc))
    
    return events

def generate_phishing_delivery(base_time: datetime) -> List[Dict]:
    events = []
    day = 5
    
    delivery_time = get_scenario_time(base_time, day, 9, 15)
    pf = proofpoint_log({
        "recipient": [VICTIM_PROFILE["email"]],
        "sender": ATTACKER_PROFILE["sender_email"],
        "subject": "Updated Benefits Package - Action Required",
        "threatType": "attachment",
        "phishScore": 95,
        "policyRoutes": ["deliver"],
        "messageParts": [{
            "disposition": "attached",
            "filename": ATTACKER_PROFILE["malicious_pdf"],
            "contentType": "application/pdf",
            "sandboxStatus": "threat",
            "threatStatus": "malicious",
        }],
        "spf": "fail",
        "dkimv": "none",
        "dmarc": "fail",
    })
    events.append(create_event(delivery_time, "proofpoint", "phishing_delivery", pf))

    return events

def generate_email_interaction(base_time: datetime) -> List[Dict]:
    events = []
    day = 5
    
    open_time = get_scenario_time(base_time, day, 9, 18)
    m365_open_str = microsoft_365_collaboration_log()
    m365_open = json.loads(m365_open_str) if isinstance(m365_open_str, str) else m365_open_str
    m365_open['TimeStamp'] = open_time
    m365_open['UserId'] = VICTIM_PROFILE['email']
    m365_open['ClientIP'] = VICTIM_PROFILE['normal_ip']
    m365_open['Operation'] = 'MailItemsAccessed'
    m365_open['ObjectId'] = f"/Inbox/{ATTACKER_PROFILE['malicious_pdf']}"
    m365_open['FileName'] = ATTACKER_PROFILE['malicious_pdf']
    m365_open['Workload'] = 'Exchange'
    m365_open['EventType'] = 'Audit.Exchange'
    events.append(create_event(open_time, "microsoft_365_collaboration", "email_interaction", m365_open))
    
    return events

def generate_pdf_exploitation(base_time: datetime) -> List[Dict]:
    events = []
    day = 5
    
    pdf_open_time = get_scenario_time(base_time, day, 9, 18, 15)
    s1_pdf = sentinelone_endpoint_log({
        "event.type": "Process Creation",
        "event.time": int((base_time + timedelta(days=day, hours=9, minutes=18, seconds=15)).timestamp() * 1000),
        "endpoint.name": VICTIM_PROFILE["hostname"],
        "src.process.user": VICTIM_PROFILE["email"].split("@")[0],
        "src.process.name": "AcroRd32.exe",
        "src.process.cmdline": f"\"C:\\Program Files\\Adobe\\Acrobat Reader DC\\Reader\\AcroRd32.exe\" \"C:\\Users\\{VICTIM_PROFILE['email'].split('@')[0]}\\Downloads\\{ATTACKER_PROFILE['malicious_pdf']}\"",
        "src.process.parent.name": "explorer.exe",
    })
    events.append(create_event(pdf_open_time, "sentinelone_endpoint", "pdf_exploit", s1_pdf))
    
    js_exec_time = get_scenario_time(base_time, day, 9, 18, 18)
    s1_js = sentinelone_endpoint_log({
        "event.type": "Suspicious Activity",
        "meta.event.name": "SUSPICIOUS",
        "event.time": int((base_time + timedelta(days=day, hours=9, minutes=18, seconds=18)).timestamp() * 1000),
        "endpoint.name": VICTIM_PROFILE["hostname"],
        "src.process.user": VICTIM_PROFILE["email"].split("@")[0],
        "src.process.name": "AcroRd32.exe",
        "src.process.cmdline": f"AcroRd32.exe - JavaScript execution detected",
        "indicators.description": "CVE-2023-21608 exploitation detected",
        "src.process.indicatorEvasionCount": 1,
    })
    events.append(create_event(js_exec_time, "sentinelone_endpoint", "pdf_exploit", s1_js))
    
    return events

def generate_powershell_execution(base_time: datetime) -> List[Dict]:
    events = []
    day = 5
    
    ps_drop_time = get_scenario_time(base_time, day, 9, 18, 20)
    s1_ps_drop = sentinelone_endpoint_log({
        "event.type": "File Creation",
        "event.time": int((base_time + timedelta(days=day, hours=9, minutes=18, seconds=20)).timestamp() * 1000),
        "endpoint.name": VICTIM_PROFILE["hostname"],
        "src.process.user": VICTIM_PROFILE["email"].split("@")[0],
        "src.process.name": "AcroRd32.exe",
        "target.process.name": "update_script.ps1",
        "target.file.path": f"C:\\Users\\{VICTIM_PROFILE['email'].split('@')[0]}\\AppData\\Local\\Temp\\update_script.ps1",
    })
    events.append(create_event(ps_drop_time, "sentinelone_endpoint", "powershell_stage", s1_ps_drop))
    
    defender_disable_time = get_scenario_time(base_time, day, 9, 18, 25)
    s1_defender = sentinelone_endpoint_log({
        "event.type": "PowerShell Execution",
        "meta.event.name": "SCRIPTS",
        "event.time": int((base_time + timedelta(days=day, hours=9, minutes=18, seconds=25)).timestamp() * 1000),
        "endpoint.name": VICTIM_PROFILE["hostname"],
        "src.process.user": VICTIM_PROFILE["email"].split("@")[0],
        "src.process.name": "powershell.exe",
        "src.process.cmdline": "powershell.exe -Command Set-MpPreference -DisableRealtimeMonitoring $true",
        "src.process.parent.name": "AcroRd32.exe",
        "src.process.indicatorEvasionCount": 2,
        "indicators.description": "Attempt to disable Windows Defender",
    })
    events.append(create_event(defender_disable_time, "sentinelone_endpoint", "powershell_stage", s1_defender))
    
    amsi_bypass_time = get_scenario_time(base_time, day, 9, 18, 30)
    s1_amsi = sentinelone_endpoint_log({
        "event.type": "PowerShell Execution",
        "meta.event.name": "SCRIPTS",
        "event.time": int((base_time + timedelta(days=day, hours=9, minutes=18, seconds=30)).timestamp() * 1000),
        "endpoint.name": VICTIM_PROFILE["hostname"],
        "src.process.user": VICTIM_PROFILE["email"].split("@")[0],
        "src.process.name": "powershell.exe",
        "src.process.cmdline": "powershell.exe -Command [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')",
        "src.process.indicatorEvasionCount": 3,
        "indicators.description": "AMSI bypass attempt detected",
    })
    events.append(create_event(amsi_bypass_time, "sentinelone_endpoint", "powershell_stage", s1_amsi))
    
    encoded_ps_time = get_scenario_time(base_time, day, 9, 18, 45)
    s1_encoded = sentinelone_endpoint_log({
        "event.type": "PowerShell Execution",
        "meta.event.name": "SCRIPTS",
        "event.time": int((base_time + timedelta(days=day, hours=9, minutes=18, seconds=45)).timestamp() * 1000),
        "endpoint.name": VICTIM_PROFILE["hostname"],
        "src.process.user": VICTIM_PROFILE["email"].split("@")[0],
        "src.process.name": "powershell.exe",
        "src.process.cmdline": "powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -EncodedCommand SQBuAHYAbwBrAGUALQBXAGUAYgBSAGUAcQB1AGUAcwB0AA==",
        "src.process.indicatorEvasionCount": 4,
        "indicators.description": "Base64 encoded PowerShell command",
    })
    events.append(create_event(encoded_ps_time, "sentinelone_endpoint", "powershell_stage", s1_encoded))
    
    return events

def generate_payload_download(base_time: datetime) -> List[Dict]:
    events = []
    day = 5
    
    dns_resolve_time = get_scenario_time(base_time, day, 9, 18, 48)
    s1_dns_payload = {
        "event.type": "DNS Resolved",
        "event.time": int((base_time + timedelta(days=day, hours=9, minutes=18, seconds=48)).timestamp() * 1000),
        "event.dns.request": f"type: 1 {ATTACKER_PROFILE['phishing_domain']}",
        "event.dns.response": f"type: 1 {ATTACKER_PROFILE['c2_primary_ip']};",
        "event.dns.responseCode": 0,
        "endpoint.name": VICTIM_PROFILE["hostname"],
        "src.process.name": "powershell.exe",
        "src.process.displayName": "Windows PowerShell",
        "src.process.cmdline": "powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -EncodedCommand SQBuAHYAbwBrAGUALQBXAGUAYgBSAGUAcQB1AGUAcwB0AA==",
        "src.process.image.path": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "src.process.user": VICTIM_PROFILE["email"].split("@")[0],
        "src.process.pid": 8472,
        "src.process.signedStatus": "signed",
        "src.process.parent.name": "AcroRd32.exe",
        "src.process.parent.image.path": "C:\\Program Files\\Adobe\\Acrobat Reader DC\\Reader\\AcroRd32.exe",
    }
    events.append(create_event(dns_resolve_time, "sentinelone_endpoint", "payload_download", s1_dns_payload))
    
    download_time = get_scenario_time(base_time, day, 9, 18, 50)
    s1_download = sentinelone_endpoint_log({
        "event.type": "Network Connection",
        "meta.event.name": "HTTP",
        "event.time": int((base_time + timedelta(days=day, hours=9, minutes=18, seconds=50)).timestamp() * 1000),
        "endpoint.name": VICTIM_PROFILE["hostname"],
        "src.process.user": VICTIM_PROFILE["email"].split("@")[0],
        "src.process.name": "powershell.exe",
        "event.network.direction": "Outbound",
        "dst.ip.address": "185.234.72.156",
        "dst.port.number": 80,
        "event.network.url": "hxxp://temp-files.cloud/update.exe",
    })
    events.append(create_event(download_time, "sentinelone_endpoint", "payload_download", s1_download))
    
    pa_download = paloalto_firewall_log()
    events.append(create_event(download_time, "paloalto_firewall", "payload_download", {"raw": pa_download}))
    
    file_written_time = get_scenario_time(base_time, day, 9, 18, 55)
    s1_file = sentinelone_endpoint_log({
        "event.type": "File Creation",
        "event.time": int((base_time + timedelta(days=day, hours=9, minutes=18, seconds=55)).timestamp() * 1000),
        "endpoint.name": VICTIM_PROFILE["hostname"],
        "src.process.user": VICTIM_PROFILE["email"].split("@")[0],
        "src.process.name": "powershell.exe",
        "target.file.path": f"C:\\Users\\{VICTIM_PROFILE['email'].split('@')[0]}\\AppData\\Local\\Temp\\update.exe",
        "target.file.sha256": "a1b2c3d4e5f6789012345678901234567890abcdef1234567890abcdef123456",
        "indicators.description": "Suspicious executable downloaded from internet",
    })
    events.append(create_event(file_written_time, "sentinelone_endpoint", "payload_download", s1_file))
    
    return events

def generate_asyncrat_execution(base_time: datetime) -> List[Dict]:
    events = []
    day = 5
    
    exec_time = get_scenario_time(base_time, day, 9, 19)
    s1_exec = sentinelone_endpoint_log({
        "event.type": "Process Creation",
        "event.time": int((base_time + timedelta(days=day, hours=9, minutes=19)).timestamp() * 1000),
        "endpoint.name": VICTIM_PROFILE["hostname"],
        "src.process.user": VICTIM_PROFILE["email"].split("@")[0],
        "src.process.name": "update.exe",
        "src.process.cmdline": f"C:\\Users\\{VICTIM_PROFILE['email'].split('@')[0]}\\AppData\\Local\\Temp\\update.exe",
        "src.process.parent.name": "powershell.exe",
        "indicators.description": "AsyncRAT malware execution detected",
        "src.process.indicatorMalwareCount": 5,
    })
    events.append(create_event(exec_time, "sentinelone_endpoint", "asyncrat_execution", s1_exec))
    
    injection_time = get_scenario_time(base_time, day, 9, 19, 10)
    s1_inject = sentinelone_endpoint_log({
        "event.type": "Process Injection",
        "meta.event.name": "INJECTION",
        "event.time": int((base_time + timedelta(days=day, hours=9, minutes=19, seconds=10)).timestamp() * 1000),
        "endpoint.name": VICTIM_PROFILE["hostname"],
        "src.process.user": VICTIM_PROFILE["email"].split("@")[0],
        "src.process.name": "update.exe",
        "target.process.name": "explorer.exe",
        "src.process.indicatorInjectionCount": 1,
        "src.process.indicatorEvasionCount": 5,
        "indicators.description": "Process injection into explorer.exe detected",
    })
    events.append(create_event(injection_time, "sentinelone_endpoint", "asyncrat_execution", s1_inject))
    
    detection_time = get_scenario_time(base_time, day, 9, 19, 30)
    s1_alert = sentinelone_endpoint_log({
        "event.type": "Alert",
        "meta.event.name": "THREATDETECTION",
        "event.time": int((base_time + timedelta(days=day, hours=9, minutes=19, seconds=30)).timestamp() * 1000),
        "endpoint.name": VICTIM_PROFILE["hostname"],
        "src.process.user": VICTIM_PROFILE["email"].split("@")[0],
        "src.process.name": "explorer.exe",
        "indicators.description": "HIGH PRIORITY: Process injection and malicious behavior detected",
        "threat.classification": "Malware",
        "threat.name": "AsyncRAT",
    })
    events.append(create_event(detection_time, "sentinelone_endpoint", "detection", s1_alert))
    
    return events

def generate_persistence(base_time: datetime) -> List[Dict]:
    events = []
    day = 5
    
    schtask_time = get_scenario_time(base_time, day, 9, 22)
    s1_schtask = sentinelone_endpoint_log({
        "event.type": "Scheduled Task Update",
        "meta.event.name": "SCHEDTASKUPDATE",
        "event.time": int((base_time + timedelta(days=day, hours=9, minutes=22)).timestamp() * 1000),
        "endpoint.name": VICTIM_PROFILE["hostname"],
        "src.process.user": VICTIM_PROFILE["email"].split("@")[0],
        "src.process.name": "schtasks.exe",
        "src.process.cmdline": "schtasks.exe /create /tn SystemUpdateCheck /tr \"C:\\Users\\sara.mitchell\\AppData\\Roaming\\Microsoft\\Windows\\Templates\\svchost.exe\" /sc hourly /mo 4 /ru SYSTEM",
        "task.name": "SystemUpdateCheck",
        "src.process.indicatorPersistenceCount": 3,
        "indicators.description": "Suspicious scheduled task created with SYSTEM privileges",
    })
    events.append(create_event(schtask_time, "sentinelone_endpoint", "persistence", s1_schtask))
    
    ootb_detection_time = get_scenario_time(base_time, day, 9, 23)
    ootb_alert = {
        "alert_id": "OOTB-2026-001",
        "alert_name": "OOTB: Suspicious Scheduled Task Creation",
        "severity": "HIGH",
        "user": VICTIM_PROFILE["email"],
        "hostname": VICTIM_PROFILE["hostname"],
        "description": "Scheduled task 'SystemUpdateCheck' created with non-standard execution parameters",
        "detection_method": "Out-of-the-Box Detection Rule",
        "task_name": "SystemUpdateCheck",
        "task_path": "C:\\Users\\sara.mitchell\\AppData\\Roaming\\Microsoft\\Windows\\Templates\\svchost.exe",
        "run_as": "SYSTEM",
        "mitre_technique": "T1053.005",
    }
    events.append(create_event(ootb_detection_time, "soar_alert", "detection", ootb_alert))
    
    registry_time = get_scenario_time(base_time, day, 9, 22, 30)
    s1_registry = sentinelone_endpoint_log({
        "event.type": "Registry Modification",
        "meta.event.name": "REGMODIFICATION",
        "event.time": int((base_time + timedelta(days=day, hours=9, minutes=22, seconds=30)).timestamp() * 1000),
        "endpoint.name": VICTIM_PROFILE["hostname"],
        "src.process.user": VICTIM_PROFILE["email"].split("@")[0],
        "src.process.name": "explorer.exe",
        "target.registry.path": "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\WindowsUpdate",
        "target.registry.value": "C:\\Users\\sara.mitchell\\AppData\\Roaming\\Microsoft\\Windows\\Templates\\svchost.exe",
        "src.process.indicatorPersistenceCount": 4,
        "indicators.description": "Registry run key persistence mechanism",
    })
    events.append(create_event(registry_time, "sentinelone_endpoint", "persistence", s1_registry))
    
    return events

def generate_reconnaissance(base_time: datetime) -> List[Dict]:
    events = []
    day = 5
    
    commands = [
        ("tasklist.exe", "tasklist.exe /v", "Process enumeration activity", 24, 0),
        ("net.exe", "net.exe user /domain", "Active Directory user enumeration", 24, 15),
    ]
    
    for cmd_name, cmd_line, desc, minute, second in commands:
        cmd_time = get_scenario_time(base_time, day, 9, minute, second)
        s1_cmd = sentinelone_endpoint_log({
            "event.type": "Process Creation",
            "event.time": int((base_time + timedelta(days=day, hours=9, minutes=minute, seconds=second)).timestamp() * 1000),
            "endpoint.name": VICTIM_PROFILE["hostname"],
            "src.process.user": VICTIM_PROFILE["email"].split("@")[0],
            "src.process.name": cmd_name,
            "src.process.cmdline": cmd_line,
            "src.process.parent.name": "explorer.exe",
            "indicators.description": desc,
        })
        events.append(create_event(cmd_time, "sentinelone_endpoint", "reconnaissance", s1_cmd))
    
    cred_harvest_time = get_scenario_time(base_time, day, 9, 24, 30)
    s1_cred = sentinelone_endpoint_log({
        "event.type": "Credential Access",
        "meta.event.name": "CREDENTIALACCESS",
        "event.time": int((base_time + timedelta(days=day, hours=9, minutes=24, seconds=30)).timestamp() * 1000),
        "endpoint.name": VICTIM_PROFILE["hostname"],
        "src.process.user": VICTIM_PROFILE["email"].split("@")[0],
        "src.process.name": "explorer.exe",
        "target.file.path": "C:\\Users\\sara.mitchell\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Login Data",
        "indicators.description": "Attempt to access browser credential store",
    })
    events.append(create_event(cred_harvest_time, "sentinelone_endpoint", "reconnaissance", s1_cred))
    
    screenshot_time = get_scenario_time(base_time, day, 9, 24, 45)
    s1_screen = sentinelone_endpoint_log({
        "event.type": "Screen Capture",
        "event.time": int((base_time + timedelta(days=day, hours=9, minutes=24, seconds=45)).timestamp() * 1000),
        "endpoint.name": VICTIM_PROFILE["hostname"],
        "src.process.user": VICTIM_PROFILE["email"].split("@")[0],
        "src.process.name": "explorer.exe",
        "indicators.description": "Screen capture activity detected (every 30 seconds)",
    })
    events.append(create_event(screenshot_time, "sentinelone_endpoint", "reconnaissance", s1_screen))
    
    return events

def generate_c2_communication(base_time: datetime) -> List[Dict]:
    events = []
    day = 5
    
    for i in range(3):
        beacon_time = get_scenario_time(base_time, day, 9, 25 + i)
        s1_c2 = sentinelone_endpoint_log({
            "event.type": "Network Connection",
            "meta.event.name": "HTTPS",
            "event.time": int((base_time + timedelta(days=day, hours=9, minutes=25 + i)).timestamp() * 1000),
            "endpoint.name": VICTIM_PROFILE["hostname"],
            "src.process.user": VICTIM_PROFILE["email"].split("@")[0],
            "src.process.name": "explorer.exe",
            "event.network.direction": "Outbound",
            "event.network.connectionStatus": "Established",
            "dst.ip.address": ATTACKER_PROFILE["c2_primary_ip"],
            "dst.port.number": ATTACKER_PROFILE["c2_primary_port"],
            "indicators.description": "Suspicious TLS handshake pattern - 60 second beaconing",
            "src.process.netConnOutCount": 5 + i,
        })
        events.append(create_event(beacon_time, "sentinelone_endpoint", "c2_communication", s1_c2))
        pa_c2 = paloalto_firewall_log()
        events.append(create_event(beacon_time, "paloalto_firewall", "c2_communication", {"raw": pa_c2}))
    
    c2_detection_time = get_scenario_time(base_time, day, 9, 25, 30)
    c2_alert = {
        "alert_id": "NET-2026-001",
        "alert_name": "Suspicious C2 Communication Detected",
        "severity": "CRITICAL",
        "user": VICTIM_PROFILE["email"],
        "hostname": VICTIM_PROFILE["hostname"],
        "description": "Outbound HTTPS to known C2 IP with suspicious TLS patterns",
        "c2_ip": ATTACKER_PROFILE["c2_primary_ip"],
        "detection_method": "Network Monitoring - TLS Analysis",
        "beacon_interval": "60 seconds",
        "mitre_technique": "T1071.001",
    }
    events.append(create_event(c2_detection_time, "soar_alert", "detection", c2_alert))
    
    firewall_block_time = get_scenario_time(base_time, day, 9, 26)
    fw_block = {
        "action_id": "FW-BLOCK-001",
        "action_type": "Firewall Block IP",
        "blocked_ip": ATTACKER_PROFILE["c2_primary_ip"],
        "status": "SUCCESS",
        "description": "Outbound traffic to C2 IP blocked via threat intelligence",
        "automated": True,
    }
    events.append(create_event(firewall_block_time, "soar_response", "containment", fw_block))
    
    backup_c2_dns_time = get_scenario_time(base_time, day, 9, 26, 30)
    s1_backup_dns = {
        "event.type": "DNS Resolved",
        "event.time": int((base_time + timedelta(days=day, hours=9, minutes=26, seconds=30)).timestamp() * 1000),
        "event.dns.request": f"type: 1 {ATTACKER_PROFILE['c2_backup_domain']}",
        "event.dns.response": "type: 1 198.51.100.42;",
        "event.dns.responseCode": 0,
        "endpoint.name": VICTIM_PROFILE["hostname"],
        "src.process.name": "explorer.exe",
        "src.process.displayName": "Windows Explorer",
        "src.process.cmdline": "C:\\Windows\\explorer.exe",
        "src.process.image.path": "C:\\Windows\\explorer.exe",
        "src.process.user": VICTIM_PROFILE["email"].split("@")[0],
        "src.process.pid": 4892,
        "src.process.signedStatus": "signed",
        "src.process.parent.name": "userinit.exe",
    }
    events.append(create_event(backup_c2_dns_time, "sentinelone_endpoint", "c2_communication", s1_backup_dns))
    
    tunnel_subdomains = [
        "a1b2c3d4e5f6g7h8",
        "x9y8z7w6v5u4t3s2",
        "cmd-whoami-base64",
    ]
    for i, subdomain in enumerate(tunnel_subdomains):
        dns_tunnel_time = get_scenario_time(base_time, day, 9, 27, i * 5)
        s1_tunnel = {
            "event.type": "DNS Resolved",
            "event.time": int((base_time + timedelta(days=day, hours=9, minutes=27, seconds=i*5)).timestamp() * 1000),
            "event.dns.request": f"type: 16 {subdomain}.{ATTACKER_PROFILE['c2_backup_domain']}",
            "event.dns.response": "type: 16 TXT;",
            "event.dns.responseCode": 0,
            "endpoint.name": VICTIM_PROFILE["hostname"],
            "src.process.name": "explorer.exe",
            "src.process.displayName": "Windows Explorer",
            "src.process.image.path": "C:\\Windows\\explorer.exe",
            "src.process.user": VICTIM_PROFILE["email"].split("@")[0],
            "src.process.pid": 4892,
            "indicators.description": f"Suspicious DNS TXT query - possible DNS tunneling",
        }
        events.append(create_event(dns_tunnel_time, "sentinelone_endpoint", "c2_communication", s1_tunnel))
    
    pa_dns = paloalto_firewall_log()
    events.append(create_event(get_scenario_time(base_time, day, 9, 27, 15), "paloalto_firewall", "c2_communication", {"raw": pa_dns}))
    
    return events

def generate_lateral_movement(base_time: datetime) -> List[Dict]:
    events = []
    day = 5
    
    internal_hosts = [
        ("dc01.securatech.local", "10.50.1.10"),
        ("fileserver.securatech.local", "10.50.1.20"),
        ("sqlserver.securatech.local", "10.50.1.30"),
        ("exchange.securatech.local", "10.50.1.40"),
    ]
    for i, (hostname, ip) in enumerate(internal_hosts):
        dns_recon_time = get_scenario_time(base_time, day, 9, 30, i * 3)
        s1_internal_dns = {
            "event.type": "DNS Resolved",
            "event.time": int((base_time + timedelta(days=day, hours=9, minutes=30, seconds=i*3)).timestamp() * 1000),
            "event.dns.request": f"type: 1 {hostname}",
            "event.dns.response": f"type: 1 {ip};",
            "event.dns.responseCode": 0,
            "endpoint.name": VICTIM_PROFILE["hostname"],
            "src.process.name": "explorer.exe",
            "src.process.displayName": "Windows Explorer",
            "src.process.image.path": "C:\\Windows\\explorer.exe",
            "src.process.user": VICTIM_PROFILE["email"].split("@")[0],
            "src.process.pid": 4892,
            "indicators.description": "Internal network reconnaissance - hostname enumeration",
        }
        events.append(create_event(dns_recon_time, "sentinelone_endpoint", "lateral_movement", s1_internal_dns))
    
    port_scan_time = get_scenario_time(base_time, day, 9, 32)
    s1_scan = sentinelone_endpoint_log({
        "event.type": "Network Connection",
        "meta.event.name": "PORTSCAN",
        "event.time": int((base_time + timedelta(days=day, hours=9, minutes=32)).timestamp() * 1000),
        "endpoint.name": VICTIM_PROFILE["hostname"],
        "src.process.user": VICTIM_PROFILE["email"].split("@")[0],
        "src.process.name": "explorer.exe",
        "event.network.direction": "Outbound",
        "indicators.description": "Port scanning detected on internal network ranges",
    })
    events.append(create_event(port_scan_time, "sentinelone_endpoint", "lateral_movement", s1_scan))
    
    scan_details = [
        {"port": 445, "protocol": "SMB", "attempts": 247},
        {"port": 3389, "protocol": "RDP", "attempts": 89},
        {"port": 22, "protocol": "SSH", "attempts": 156},
    ]
    
    for i, scan in enumerate(scan_details):
        scan_time = get_scenario_time(base_time, day, 9, 33 + i)
        pa_scan = paloalto_firewall_log()
        fw_alert = {
            "alert_id": f"FW-SCAN-{i+1:03d}",
            "alert_name": f"Port Scanning Detected - {scan['protocol']}",
            "severity": "HIGH",
            "source_host": VICTIM_PROFILE["hostname"],
            "target_port": scan["port"],
            "connection_attempts": scan["attempts"],
            "description": f"Extensive {scan['protocol']} port scanning activity detected",
        }
        events.append(create_event(scan_time, "paloalto_firewall", "lateral_movement", {"raw": pa_scan, "alert": fw_alert}))
    
    smb_exploit_time = get_scenario_time(base_time, day, 9, 35)
    s1_smb = sentinelone_endpoint_log({
        "event.type": "Network Connection",
        "event.time": int((base_time + timedelta(days=day, hours=9, minutes=35)).timestamp() * 1000),
        "endpoint.name": VICTIM_PROFILE["hostname"],
        "src.process.user": VICTIM_PROFILE["email"].split("@")[0],
        "src.process.name": "explorer.exe",
        "dst.port.number": 445,
        "indicators.description": "SMB exploitation attempt (EternalBlue variants)",
    })
    events.append(create_event(smb_exploit_time, "sentinelone_endpoint", "lateral_movement", s1_smb))
    
    priv_esc_time = get_scenario_time(base_time, day, 9, 37)
    s1_priv = sentinelone_endpoint_log({
        "event.type": "Privilege Escalation",
        "meta.event.name": "PRIVESC",
        "event.time": int((base_time + timedelta(days=day, hours=9, minutes=37)).timestamp() * 1000),
        "endpoint.name": VICTIM_PROFILE["hostname"],
        "src.process.user": VICTIM_PROFILE["email"].split("@")[0],
        "src.process.name": "explorer.exe",
        "indicators.description": "Token impersonation and privilege escalation attempts",
    })
    events.append(create_event(priv_esc_time, "sentinelone_endpoint", "lateral_movement", s1_priv))
    
    lsass_time = get_scenario_time(base_time, day, 9, 37, 30)
    s1_lsass = sentinelone_endpoint_log({
        "event.type": "Credential Access",
        "meta.event.name": "LSASSDUMP",
        "event.time": int((base_time + timedelta(days=day, hours=9, minutes=37, seconds=30)).timestamp() * 1000),
        "endpoint.name": VICTIM_PROFILE["hostname"],
        "src.process.user": VICTIM_PROFILE["email"].split("@")[0],
        "src.process.name": "explorer.exe",
        "target.process.name": "lsass.exe",
        "indicators.description": "CRITICAL: LSASS memory dump attempt for credential extraction",
        "src.process.indicatorPersistenceCount": 5,
    })
    events.append(create_event(lsass_time, "sentinelone_endpoint", "lateral_movement", s1_lsass))
    
    return events

def generate_data_exfiltration_prep(base_time: datetime) -> List[Dict]:
    events = []
    day = 5
    
    activities = [
        ("File Access", "cmd.exe /c dir C:\\Users\\*.docx *.xlsx *.pdf /s", 
         "File system enumeration for sensitive document types", 40, 0),
    ]
    
    for event_type, cmd_line, desc, minute, second in activities:
        activity_time = get_scenario_time(base_time, day, 9, minute, second)
        s1_activity = sentinelone_endpoint_log({
            "event.type": event_type,
            "event.time": int((base_time + timedelta(days=day, hours=9, minutes=minute, seconds=second)).timestamp() * 1000),
            "endpoint.name": VICTIM_PROFILE["hostname"],
            "src.process.user": VICTIM_PROFILE["email"].split("@")[0],
            "src.process.name": "explorer.exe",
            "src.process.cmdline": cmd_line,
            "indicators.description": desc,
        })
        events.append(create_event(activity_time, "sentinelone_endpoint", "data_exfiltration_prep", s1_activity))
    
    sql_conn_time = get_scenario_time(base_time, day, 9, 40, 15)
    s1_sql = sentinelone_endpoint_log({
        "event.type": "Network Connection",
        "event.time": int((base_time + timedelta(days=day, hours=9, minutes=40, seconds=15)).timestamp() * 1000),
        "endpoint.name": VICTIM_PROFILE["hostname"],
        "src.process.user": VICTIM_PROFILE["email"].split("@")[0],
        "src.process.name": "explorer.exe",
        "dst.ip.address": "10.50.10.50",
        "dst.port.number": 1433,
        "indicators.description": "Connection attempt to internal SQL server",
    })
    events.append(create_event(sql_conn_time, "sentinelone_endpoint", "data_exfiltration_prep", s1_sql))
    
    keylog_time = get_scenario_time(base_time, day, 9, 40, 30)
    s1_keylog = sentinelone_endpoint_log({
        "event.type": "Keylogger Detection",
        "meta.event.name": "KEYLOGGER",
        "event.time": int((base_time + timedelta(days=day, hours=9, minutes=40, seconds=30)).timestamp() * 1000),
        "endpoint.name": VICTIM_PROFILE["hostname"],
        "src.process.user": VICTIM_PROFILE["email"].split("@")[0],
        "src.process.name": "explorer.exe",
        "indicators.description": "Keylogger functionality activated",
    })
    events.append(create_event(keylog_time, "sentinelone_endpoint", "data_exfiltration_prep", s1_keylog))
    
    staging_time = get_scenario_time(base_time, day, 9, 40, 45)
    s1_staging = sentinelone_endpoint_log({
        "event.type": "File Creation",
        "event.time": int((base_time + timedelta(days=day, hours=9, minutes=40, seconds=45)).timestamp() * 1000),
        "endpoint.name": VICTIM_PROFILE["hostname"],
        "src.process.user": VICTIM_PROFILE["email"].split("@")[0],
        "src.process.name": "explorer.exe",
        "target.file.path": "C:\\Users\\sara.mitchell\\AppData\\Local\\Temp\\Microsoft\\EdgeUpdate\\staged_data.zip",
        "indicators.description": "Data staging directory created for exfiltration",
    })
    events.append(create_event(staging_time, "sentinelone_endpoint", "data_exfiltration_prep", s1_staging))
    
    return events

def generate_comprehensive_response(base_time: datetime) -> List[Dict]:
    events = []
    day = 5
    
    correlation_time = get_scenario_time(base_time, day, 9, 30)
    correlation_alert = {
        "alert_id": "SOAR-2026-ASYNC-001",
        "alert_name": "Email-to-Execution Attack Chain Correlated",
        "severity": "CRITICAL",
        "user": VICTIM_PROFILE["email"],
        "hostname": VICTIM_PROFILE["hostname"],
        "description": "Complete attack chain detected: Phishing email → PDF exploit → PowerShell → AsyncRAT → Persistence → C2",
        "detection_method": "Storyline Attack Chain Analysis",
        "mitre_techniques": ["T1566.001", "T1203", "T1059.001", "T1055", "T1053.005", "T1071.001"],
        "attack_chain": "email → PDF → JavaScript → PowerShell → process injection → persistence mechanisms",
    }
    events.append(create_event(correlation_time, "soar_alert", "detection", correlation_alert))
    
    response_actions = [
        ("Network Isolation", VICTIM_PROFILE["hostname"], "Workstation immediately isolated from network via SentinelOne", 41, 0),
        ("Remove Scheduled Task", "SystemUpdateCheck", "Malicious scheduled task removed from endpoint", 41, 15),
        ("Registry Cleanup", "HKCU\\...\\Run\\WindowsUpdate", "Registry persistence mechanism removed", 41, 30),
        ("Forensic Imaging", VICTIM_PROFILE["hostname"], "Full memory and disk forensic imaging initiated", 41, 45),
        ("Company-Wide Alert", "All Users", "Security awareness alert sent regarding AsyncRAT phishing campaign", 42, 0),
        ("Emergency Patch Deployment", "CVE-2023-21608", "Emergency patch for PDF vulnerability deployed company-wide", 42, 30),
        ("DNS Sinkholing", "malware-updates.tk", "DNS sinkholing implemented for malicious domains", 43, 0),
        ("Enhanced Logging", "PowerShell", "PowerShell logging and constrained language mode enabled company-wide", 43, 30),
        ("YARA Rule Deployment", "AsyncRAT", "Custom YARA rules deployed to detect AsyncRAT variants", 44, 0),
        ("Threat Hunting", "All Endpoints", "Proactive threat hunting initiated across all endpoints for similar IoCs", 45, 0),
    ]
    
    for i, (action_type, target, desc, minute, second) in enumerate(response_actions):
        action_time = get_scenario_time(base_time, day, 9, minute, second)
        action = {
            "action_id": f"SOAR-ACT-{i+1:03d}",
            "action_type": action_type,
            "target": target,
            "status": "SUCCESS" if i < 7 else "IN_PROGRESS",
            "timestamp": action_time,
            "description": desc,
            "automated": i < 7,
        }
        events.append(create_event(action_time, "soar_response", "incident_response", action))
    
    return events

def generate_asyncrat_phishing_scenario():
    print("=" * 80)
    print("🎯 ASYNCRAT PHISHING CAMPAIGN - OPERATION SILENT SCHEDULE")
    print("=" * 80)
    print(f"Victim: {VICTIM_PROFILE['name']} ({VICTIM_PROFILE['email']})")
    print(f"Department: {VICTIM_PROFILE['department']}")
    print(f"Location: {VICTIM_PROFILE['location']}")
    print(f"Malware: {ATTACKER_PROFILE['malware_family']}")
    print("=" * 80)
    
    base_time = datetime.now(timezone.utc) - timedelta(days=6)
    all_events = []
    
    print("\n📊 PHASE 1: Normal Behavior Baseline (Days 1-5)")
    print("-" * 80)
    for day in range(5):
        print(f"Day {day + 1}: {(base_time + timedelta(days=day)).strftime('%Y-%m-%d')}")
        day_events = generate_normal_day_events(base_time, day)
        all_events.extend(day_events)
        print(f"   ✓ Generated {len(day_events)} normal activity events")
    
    phases = [
        ("✉️  PHASE 2: Phishing Delivery (Day 6 - 09:15 AM)", generate_phishing_delivery, "Phishing email with malicious PDF delivered"),
        ("📧 PHASE 3: Email Interaction (Day 6 - 09:18 AM)", generate_email_interaction, "User opened email and clicked PDF attachment"),
        ("📄 PHASE 4: PDF Exploitation CVE-2023-21608 (Day 6 - 09:18 AM)", generate_pdf_exploitation, "PDF exploit executed JavaScript payload"),
        ("💻 PHASE 5: Multi-Stage PowerShell Execution (Day 6 - 09:18 AM)", generate_powershell_execution, "PowerShell with AMSI bypass and base64 encoding"),
        ("⬇️  PHASE 6: AsyncRAT Payload Download (Day 6 - 09:18 AM)", generate_payload_download, f"update.exe downloaded from {ATTACKER_PROFILE['payload_url']}"),
        ("🦠 PHASE 7: AsyncRAT Execution & Process Injection (Day 6 - 09:19 AM)", generate_asyncrat_execution, "AsyncRAT injected into explorer.exe - HIGH PRIORITY ALERT"),
        ("🔒 PHASE 8: Persistence Mechanisms (Day 6 - 09:22 AM)", generate_persistence, "Scheduled task + Registry run key + OOTB Detection"),
        ("🔍 PHASE 9: Reconnaissance & Credential Harvesting (Day 6 - 09:24 AM)", generate_reconnaissance, "Process enumeration, AD queries, credential harvesting"),
        ("🌐 PHASE 10: C2 Communication (Day 6 - 09:25 AM)", generate_c2_communication, f"C2 beaconing to {ATTACKER_PROFILE['c2_primary_ip']}, firewall blocked, DNS tunneling"),
        ("🔀 PHASE 11: Lateral Movement Attempts (Day 6 - 09:32 AM)", generate_lateral_movement, "Port scanning: SMB (247), RDP (89), SSH (156), LSASS dump"),
        ("📁 PHASE 12: Data Exfiltration Preparation (Day 6 - 09:40 AM)", generate_data_exfiltration_prep, "File enumeration, keylogger, staging directory"),
        ("🚨 PHASE 13: Detection & Comprehensive Response (Day 6 - 09:30 AM)", generate_comprehensive_response, "Full attack chain correlated, 10 response actions"),
    ]
    
    for header, gen_func, summary in phases:
        print("\n" + "=" * 80)
        print(header)
        print("-" * 80)
        phase_events = gen_func(base_time)
        all_events.extend(phase_events)
        print(f"   ✓ {summary}")
    
    all_events.sort(key=lambda x: x["timestamp"])
    
    scenario_summary = {
        "scenario_name": "AsyncRAT Phishing Campaign - Operation Silent Schedule",
        "user_profile": VICTIM_PROFILE,
        "attacker_profile": ATTACKER_PROFILE,
        "timeline_start": base_time.isoformat(),
        "timeline_end": (base_time + timedelta(days=6)).isoformat(),
        "total_events": len(all_events),
        "phases": [
            {"name": phase_name, "events": len([e for e in all_events if e["phase"] == phase_key])}
            for phase_name, phase_key in [
                ("Normal Behavior Baseline", "normal_behavior"),
                ("Phishing Delivery", "phishing_delivery"),
                ("Email Interaction", "email_interaction"),
                ("PDF Exploitation", "pdf_exploit"),
                ("PowerShell Execution", "powershell_stage"),
                ("Payload Download", "payload_download"),
                ("AsyncRAT Execution", "asyncrat_execution"),
                ("Persistence", "persistence"),
                ("Reconnaissance", "reconnaissance"),
                ("C2 Communication", "c2_communication"),
                ("Lateral Movement", "lateral_movement"),
                ("Data Exfiltration Prep", "data_exfiltration_prep"),
                ("Detection & Response", "detection"),
            ]
        ],
        "detections": [
            "High Priority Alert - Process Injection (SentinelOne)",
            "OOTB - Suspicious Scheduled Task Creation",
            "Network Monitoring - Suspicious C2 Communication",
            "Storyline - Complete Attack Chain Correlation",
            "Port Scanning Detection (Firewall)",
            "LSASS Memory Dump Attempt",
            "DNS Tunneling Detection",
        ],
        "mitre_techniques": [
            "T1566.001", "T1204.002", "T1203", "T1059.001", "T1562.001", "T1027",
            "T1055", "T1053.005", "T1547.001", "T1071.001", "T1071.004", "T1018",
            "T1087.002", "T1046", "T1003.001", "T1056.001", "T1113", "T1005",
        ],
        "events": all_events,
    }
    
    print("\n" + "=" * 80)
    print("✅ SCENARIO GENERATION COMPLETE")
    print("=" * 80)
    print(f"Total Events: {len(all_events)}")
    print(f"Data Sources: Proofpoint, Microsoft 365, SentinelOne, Palo Alto, SOAR")
    print(f"Timeline: {(base_time).strftime('%Y-%m-%d')} to {(base_time + timedelta(days=6)).strftime('%Y-%m-%d')}")
    print(f"Attack Duration: ~26 minutes (09:15 - 09:41)")
    print("=" * 80)
    
    return scenario_summary

def send_to_hec(event_data, event_type, trace_id=None, phase=None):
    """Send event to SentinelOne HEC"""
    # Map event types to product names
    type_to_product = {
        "proofpoint": "proofpoint",
        "microsoft_365": "microsoft_365_collaboration",
        "sentinelone": "sentinelone_endpoint",
        "palo_alto": "paloalto_firewall",
        "soar_alert": "custom",
        "soar_response": "custom",
    }
    
    product = type_to_product.get(event_type, event_type)
    
    attr_fields = {
        "dataSource.vendor": event_type.split('_')[0].title() if '_' in event_type else event_type.title(),
        "dataSource.name": event_type.replace('_', ' ').title(),
        "dataSource.category": "security"
    }
    
    if trace_id:
        attr_fields["scenario.trace_id"] = trace_id
    if phase:
        attr_fields["scenario.phase"] = phase
    
    try:
        send_one(event_data, product, attr_fields)
        return True
    except Exception as e:
        print(f" Error: {str(e)}", end="")
        return False

if __name__ == "__main__":
    scenario = generate_asyncrat_phishing_scenario()
    
    # Send events to HEC if token is set and hec_sender is available
    hec_token = os.getenv('S1_HEC_TOKEN')
    if HEC_AVAILABLE and hec_token:
        worker_count = int(os.getenv('S1_HEC_WORKERS', '10'))
        trace_id = os.getenv('S1_TRACE_ID', f"asyncrat-{datetime.now().strftime('%Y%m%d-%H%M%S')}")
        tag_phase = os.getenv('S1_TAG_PHASE', '1') == '1'
        
        print("\n" + "=" * 80)
        print(f"📤 SENDING {len(scenario['events'])} EVENTS TO HEC")
        print("=" * 80)
        print(f"Workers: {worker_count}")
        print(f"Trace ID: {trace_id}")
        print(f"Phase Tagging: {'Enabled' if tag_phase else 'Disabled'}")
        print("=" * 80 + "\n")
        
        counts = {"success": 0, "error": 0}
        lock = threading.Lock()
        
        def send_event(event):
            try:
                phase = event.get('phase') if tag_phase else None
                result = send_to_hec(
                    event['event'],
                    event['source'],
                    trace_id=trace_id,
                    phase=phase
                )
                with lock:
                    if result:
                        counts["success"] += 1
                        print(".", end="", flush=True)
                    else:
                        counts["error"] += 1
                        print("E", end="", flush=True)
            except Exception as e:
                import traceback
                with lock:
                    counts["error"] += 1
                    print(f"\nX: {type(e).__name__}: {str(e)[:50]}", flush=True)
                    if counts["error"] == 1:
                        traceback.print_exc()
        
        with ThreadPoolExecutor(max_workers=worker_count) as executor:
            futures = [executor.submit(send_event, event) for event in scenario['events']]
            for future in as_completed(futures):
                future.result()
        
        print("\n\n" + "=" * 80)
        print("✅ HEC SENDING COMPLETE")
        print("=" * 80)
        print(f"Success: {counts['success']}/{len(scenario['events'])}")
        print(f"Errors: {counts['error']}")
        print("=" * 80 + "\n")
    
    preferred_dir = os.environ.get("SCENARIO_OUTPUT_DIR") or os.path.join(os.path.dirname(__file__), "configs")
    output_file = os.path.join(preferred_dir, "asyncrat_phishing_scenario.json")
    
    def _attempt_save(path: str) -> bool:
        try:
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, 'w') as f:
                json.dump(scenario, f, indent=2)
            print(f"\n💾 Scenario saved to: {path}")
            if not hec_token:
                print("\nTo send events to HEC, set S1_HEC_TOKEN and re-run this script")
            return True
        except OSError as e:
            if e.errno == errno.EROFS:
                print(f"⚠️  Read-only filesystem when saving to {path}. Will try fallback.")
            else:
                print(f"⚠️  Failed to save scenario to {path}: {e}")
            return False
    
    if not _attempt_save(output_file):
        pass
