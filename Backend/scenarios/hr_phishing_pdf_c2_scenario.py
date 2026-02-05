#!/usr/bin/env python3
"""
HR Phishing PDF -> PowerShell -> Scheduled Task -> C2 Scenario
=============================================================

Scenario: Spear phishing email leads to malicious PDF execution, persistence via
scheduled task, and command-and-control beacons detected across multiple tools.

Sources:
- Proofpoint (email security)
- Microsoft 365 (Exchange/O365 activity)
- SentinelOne (EDR)
- Palo Alto Networks (Firewall)

Timeline:
- Days 1-5: Normal HR user baseline
- Day 6: Phishing delivery, user interaction, PDF execution, persistence, C2

MITRE:
- T1566.002 Spearphishing Link
- T1204.002 User Execution: Malicious File
- T1059.001 PowerShell
- T1053.005 Scheduled Task/Job
- T1071.001 Web Protocols (C2)
"""

import json
import os
import sys
import errno
from datetime import datetime, timezone, timedelta
from typing import Dict, List

# Add event_generators to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'event_generators'))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'event_generators', 'email_security'))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'event_generators', 'identity_access'))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'event_generators', 'endpoint_security'))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'event_generators', 'network_security'))

# Import generators
from proofpoint import proofpoint_log
from microsoft_365_collaboration import microsoft_365_collaboration_log
from sentinelone_endpoint import sentinelone_endpoint_log
from paloalto_firewall import paloalto_firewall_log

# Victim and attacker profiles
VICTIM_PROFILE = {
    "name": "Sarah Mitchell",
    "email": "sarah.mitchell@securatech.com",
    "department": "Human Resources",
    "role": "HR Manager",
    "location": "Austin, Texas",
    "normal_ip": "10.50.25.112",
    "hostname": "HR-SARAH-PC",
    "work_hours_start": 8,
    "work_hours_end": 17,
}

ATTACKER_PROFILE = {
    "sender_email": "careers-update@securatech-hr.com",  # typosquatted domain
    "sender_name": "HR Benefits Team",
    "phishing_domain": "securatech-benefits.com",
    "c2_ip": "185.220.101.45",
    "c2_domain": "update-service.securatech-cdn.com",
    "c2_port": 443,
    "malicious_pdf": "2024_Benefits_Update.pdf",
}

# Helpers

def get_scenario_time(base_time: datetime, day: int, hour: int, minute: int = 0, second: int = 0) -> str:
    event_time = base_time + timedelta(days=day, hours=hour, minutes=minute, seconds=second)
    return event_time.isoformat()


def create_event(timestamp: str, source: str, phase: str, event_data: dict) -> Dict:
    return {"timestamp": timestamp, "source": source, "phase": phase, "event": event_data}


# Phase: Baseline

def generate_normal_day_events(base_time: datetime, day: int) -> List[Dict]:
    events: List[Dict] = []

    # 9:00 AM legitimate email received (Proofpoint)
    email_time = get_scenario_time(base_time, day, 9, 0)
    pf = proofpoint_log({
        "recipient": [VICTIM_PROFILE["email"]],
        "policyRoutes": ["deliver"],
        "threatType": "none",
        "subject": "Team meeting and onboarding updates",
    })
    events.append(create_event(email_time, "proofpoint", "normal_behavior", pf))

    # 10:15 AM OneDrive file access (M365)
    m365_time = get_scenario_time(base_time, day, 10, 15)
    m365 = microsoft_365_collaboration_log({
        "TimeStamp": m365_time,
        "UserId": VICTIM_PROFILE["email"],
        "ClientIP": VICTIM_PROFILE["normal_ip"],
        "Operation": "FileViewed",
        "ObjectId": "/HR/Benefits/2024_Open_Enrollment_Guide.pdf",
        "FileName": "2024_Open_Enrollment_Guide.pdf",
        "TargetUser": VICTIM_PROFILE["email"],
        "EventType": "Audit.SharePoint",
    })
    events.append(create_event(m365_time, "microsoft_365_collaboration", "normal_behavior", m365))

    # Noon sentinelone benign process
    s1_time = get_scenario_time(base_time, day, 12, 0)
    s1 = sentinelone_endpoint_log({
        "event.time": int((base_time + timedelta(days=day, hours=12)).timestamp() * 1000),
        "endpoint.name": VICTIM_PROFILE["hostname"],
        "src.process.user": VICTIM_PROFILE["email"].split("@")[0],
        "src.process.name": "chrome.exe",
        "src.process.cmdline": "chrome.exe --new-window https://intranet.securatech.com",
        "event.type": "Process Creation",
    })
    events.append(create_event(s1_time, "sentinelone_endpoint", "normal_behavior", s1))

    return events


# Phase: Phishing delivery

def generate_phishing_delivery(base_time: datetime) -> List[Dict]:
    events: List[Dict] = []
    day = 5  # Day 6 (0-indexed)

    delivery_time = get_scenario_time(base_time, day, 9, 15)
    pf = proofpoint_log({
        "recipient": [VICTIM_PROFILE["email"]],
        "sender": ATTACKER_PROFILE["sender_email"],
        "subject": "Action Required: 2024 Benefits Enrollment Update",
        "threatType": "phish",
        "phishScore": 90,
        "policyRoutes": ["deliver"],
        "messageParts": [{
            "disposition": "inline",
            "contentType": "text/html",
            "oContentType": "text/html",
            "isUnsupported": False,
            "urls": [{
                "url": f"https://{ATTACKER_PROFILE['phishing_domain']}/enroll?id=sm2024",
                "isRewritten": True,
                "threatStatus": "malicious",
            }],
        }],
        "spf": "fail",
        "dkimv": "none",
        "dmarc": "fail",
    })
    events.append(create_event(delivery_time, "proofpoint", "phishing_delivery", pf))

    return events


# Phase: Email interaction

def generate_email_interaction(base_time: datetime) -> List[Dict]:
    events: List[Dict] = []
    day = 5

    open_time = get_scenario_time(base_time, day, 9, 18)
    m365_open = microsoft_365_collaboration_log({
        "TimeStamp": open_time,
        "UserId": VICTIM_PROFILE["email"],
        "ClientIP": VICTIM_PROFILE["normal_ip"],
        "Operation": "MailItemsAccessed",
        "ObjectId": "/Inbox/Action Required: 2024 Benefits Enrollment Update",
        "FileName": "Action Required: 2024 Benefits Enrollment Update",
    })
    events.append(create_event(open_time, "microsoft_365_collaboration", "delivery_interaction", m365_open))

    click_time = get_scenario_time(base_time, day, 9, 19)
    m365_click = microsoft_365_collaboration_log({
        "TimeStamp": click_time,
        "UserId": VICTIM_PROFILE["email"],
        "ClientIP": VICTIM_PROFILE["normal_ip"],
        "Operation": "SharingLinkUsed",
        "ObjectId": f"https://{ATTACKER_PROFILE['phishing_domain']}/enroll?id=sm2024",
        "FileName": "Enrollment Link",
    })
    events.append(create_event(click_time, "microsoft_365_collaboration", "delivery_interaction", m365_click))

    return events


# Phase: PDF download

def generate_pdf_download(base_time: datetime) -> List[Dict]:
    events: List[Dict] = []
    day = 5

    dl_time = get_scenario_time(base_time, day, 9, 19, 30)
    m365_dl = microsoft_365_collaboration_log({
        "TimeStamp": dl_time,
        "UserId": VICTIM_PROFILE["email"],
        "ClientIP": VICTIM_PROFILE["normal_ip"],
        "Operation": "FileDownloaded",
        "ObjectId": f"/Downloads/{ATTACKER_PROFILE['malicious_pdf']}",
        "FileName": ATTACKER_PROFILE["malicious_pdf"],
        "Workload": "OneDrive",
        "RecordType": 14,
    })
    events.append(create_event(dl_time, "microsoft_365_collaboration", "delivery_interaction", m365_dl))

    # Firewall traffic entry (CSV string); include as raw line in event
    pa_line = paloalto_firewall_log()
    events.append(create_event(dl_time, "paloalto_firewall", "delivery_interaction", {"raw": pa_line}))

    return events


# Phase: Malicious execution and persistence

def generate_malicious_execution(base_time: datetime) -> List[Dict]:
    events: List[Dict] = []
    day = 5

    # PowerShell spawned by Adobe Reader
    ps_time = get_scenario_time(base_time, day, 9, 20)
    s1_ps = sentinelone_endpoint_log({
        "event.type": "PowerShell Execution",
        "meta.event.name": "SCRIPTS",
        "event.time": int((base_time + timedelta(days=day, hours=9, minutes=20)).timestamp() * 1000),
        "endpoint.name": VICTIM_PROFILE["hostname"],
        "src.process.user": VICTIM_PROFILE["email"].split("@")[0],
        "src.process.name": "powershell.exe",
        "src.process.cmdline": "powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -enc JABjAD0ATgBlAHcALQBPAGIAagBlAGMAdAA...",
        "src.process.parent.name": "AcroRd32.exe",
        "src.process.parent.cmdline": f"\"C\\\\Program Files\\\\Adobe\\\\Acrobat Reader DC\\\\Reader\\\\AcroRd32.exe\" \"C:\\Users\\{VICTIM_PROFILE['email'].split('@')[0]}\\Downloads\\{ATTACKER_PROFILE['malicious_pdf']}\"",
        "src.process.indicatorPersistenceCount": 1,
        "src.process.indicatorEvasionCount": 2,
    })
    events.append(create_event(ps_time, "sentinelone_endpoint", "execution", s1_ps))

    # Scheduled task creation
    task_time = get_scenario_time(base_time, day, 9, 21)
    s1_task = sentinelone_endpoint_log({
        "event.type": "Scheduled Task Update",
        "meta.event.name": "SCHEDTASKUPDATE",
        "event.time": int((base_time + timedelta(days=day, hours=9, minutes=21)).timestamp() * 1000),
        "endpoint.name": VICTIM_PROFILE["hostname"],
        "src.process.user": VICTIM_PROFILE["email"].split("@")[0],
        "src.process.name": "schtasks.exe",
        "src.process.cmdline": "schtasks /create /tn \"Adobe Update Service\" /tr \"powershell.exe -WindowStyle Hidden -enc ...\" /sc minute /mo 5",
        "task.name": "Adobe Update Service",
        "task.path": "C:\\Windows\\System32\\Tasks\\Adobe Update Service",
        "src.process.indicatorPersistenceCount": 3,
    })
    events.append(create_event(task_time, "sentinelone_endpoint", "persistence", s1_task))

    return events


# Phase: C2 beacons

def generate_c2_beacons(base_time: datetime) -> List[Dict]:
    events: List[Dict] = []
    day = 5

    # First beacon at 9:25 AM, then every 5 minutes for three beacons
    for i in range(3):
        b_time = get_scenario_time(base_time, day, 9, 25 + i * 5)
        # SentinelOne network connection event
        s1_net = sentinelone_endpoint_log({
            "event.type": "Network Connection",
            "meta.event.name": "HTTP",
            "event.time": int((base_time + timedelta(days=day, hours=9, minutes=25 + i * 5)).timestamp() * 1000),
            "endpoint.name": VICTIM_PROFILE["hostname"],
            "src.process.user": VICTIM_PROFILE["email"].split("@")[0],
            "src.process.name": "powershell.exe",
            "event.network.direction": "Outbound",
            "event.network.connectionStatus": "Established",
            "dst.ip.address": ATTACKER_PROFILE["c2_ip"],
            "dst.port.number": ATTACKER_PROFILE["c2_port"],
            "src.process.netConnOutCount": 5 + i,
        })
        events.append(create_event(b_time, "sentinelone_endpoint", "command_and_control", s1_net))

        # Palo Alto raw log (traffic/threat)
        pa_line = paloalto_firewall_log()
        events.append(create_event(b_time, "paloalto_firewall", "command_and_control", {"raw": pa_line}))

    return events


# Phase: SOAR detections and response

def generate_soar_detections(base_time: datetime) -> List[Dict]:
    events: List[Dict] = []
    day = 5

    det_time = get_scenario_time(base_time, day, 9, 30)
    alerts = [
        {
            "alert_id": "SOAR-2026-0001",
            "alert_name": "Proofpoint Phishing Email Detected",
            "severity": "HIGH",
            "user": VICTIM_PROFILE["email"],
            "description": "Spearphish with malicious URL delivered to user",
            "detection_method": "Email Security",
            "mitre_technique": "T1566.002",
        },
        {
            "alert_id": "SOAR-2026-0002",
            "alert_name": "EDR - PowerShell from PDF Reader",
            "severity": "CRITICAL",
            "user": VICTIM_PROFILE["email"],
            "description": "PowerShell spawned by AcroRd32.exe with encoded command",
            "detection_method": "SentinelOne Behavioral AI",
            "mitre_technique": "T1059.001",
        },
        {
            "alert_id": "SOAR-2026-0003",
            "alert_name": "EDR - Scheduled Task Persistence",
            "severity": "HIGH",
            "user": VICTIM_PROFILE["email"],
            "description": "Suspicious scheduled task created (Adobe Update Service)",
            "detection_method": "SentinelOne Deep Visibility",
            "mitre_technique": "T1053.005",
        },
        {
            "alert_id": "SOAR-2026-0004",
            "alert_name": "Firewall - C2 Communication",
            "severity": "CRITICAL",
            "user": VICTIM_PROFILE["email"],
            "description": "Outbound SSL to known C2 IP 185.220.101.45",
            "detection_method": "Palo Alto Threat",
            "mitre_technique": "T1071.001",
        },
    ]

    for i, alert in enumerate(alerts):
        t = get_scenario_time(base_time, day, 9, 30, i)
        events.append(create_event(t, "soar_alert", "detection", alert))

    # Automated response
    actions = [
        {
            "action_id": "SOAR-ACT-001",
            "action_type": "EDR Isolate Endpoint",
            "endpoint": VICTIM_PROFILE["hostname"],
            "status": "SUCCESS",
            "timestamp": get_scenario_time(base_time, day, 9, 31),
            "description": "Host isolated via SentinelOne API",
            "automated": True,
        },
        {
            "action_id": "SOAR-ACT-002",
            "action_type": "Firewall Block IP",
            "status": "SUCCESS",
            "timestamp": get_scenario_time(base_time, day, 9, 31, 30),
            "description": f"C2 IP {ATTACKER_PROFILE['c2_ip']} blocked at perimeter",
            "automated": True,
        },
        {
            "action_id": "SOAR-ACT-003",
            "action_type": "Email Quarantine",
            "status": "SUCCESS",
            "timestamp": get_scenario_time(base_time, day, 9, 32),
            "description": "Original phishing email quarantined in Proofpoint",
            "automated": True,
        },
        {
            "action_id": "SOAR-ACT-004",
            "action_type": "Disable Scheduled Task",
            "status": "SUCCESS",
            "timestamp": get_scenario_time(base_time, day, 9, 32, 30),
            "description": "Suspicious scheduled task removed from endpoint",
            "automated": True,
        },
    ]

    for action in actions:
        events.append(create_event(action["timestamp"], "soar_response", "incident_response", action))

    return events


def generate_hr_phishing_pdf_c2_scenario():
    print("=" * 80)
    print("🎯 HR PHISHING PDF -> POWERSHELL -> SCHEDULED TASK -> C2 SCENARIO")
    print("=" * 80)
    print(f"User: {VICTIM_PROFILE['name']} ({VICTIM_PROFILE['email']})")
    print(f"Department: {VICTIM_PROFILE['department']}")
    print(f"Location: {VICTIM_PROFILE['location']}")
    print("=" * 80)

    # Start scenario 6 days ago
    base_time = datetime.now(timezone.utc) - timedelta(days=6)

    all_events: List[Dict] = []

    # Phase 1: Baseline (Days 1-5)
    print("\n📊 PHASE 1: Normal Behavior Baseline (Days 1-5)")
    print("-" * 80)
    for day in range(5):
        print(f"Day {day + 1}: {(base_time + timedelta(days=day)).strftime('%Y-%m-%d')}")
        day_events = generate_normal_day_events(base_time, day)
        all_events.extend(day_events)
        print(f"   ✓ Generated {len(day_events)} normal activity events")

    # Phase 2: Phishing Delivery (Day 6)
    print("\n" + "=" * 80)
    print("✉️  PHASE 2: Phishing Delivery (Day 6)")
    print("-" * 80)
    phish_events = generate_phishing_delivery(base_time)
    all_events.extend(phish_events)
    print(f"   ✓ Generated {len(phish_events)} phishing delivery events")

    # Phase 3: Email Interaction (Day 6)
    print("\n" + "=" * 80)
    print("📬 PHASE 3: Email Interaction (Day 6)")
    print("-" * 80)
    interact_events = generate_email_interaction(base_time)
    all_events.extend(interact_events)
    print(f"   ✓ Generated {len(interact_events)} email interaction events")

    # Phase 4: PDF Download (Day 6)
    print("\n" + "=" * 80)
    print("📄 PHASE 4: PDF Download (Day 6)")
    print("-" * 80)
    dl_events = generate_pdf_download(base_time)
    all_events.extend(dl_events)
    print(f"   ✓ Generated {len(dl_events)} download events")

    # Phase 5: Execution & Persistence (Day 6)
    print("\n" + "=" * 80)
    print("⚙️  PHASE 5: Execution & Persistence (Day 6)")
    print("-" * 80)
    exec_events = generate_malicious_execution(base_time)
    all_events.extend(exec_events)
    print(f"   ✓ Generated {len(exec_events)} execution/persistence events")

    # Phase 6: Command & Control (Day 6)
    print("\n" + "=" * 80)
    print("🌐 PHASE 6: Command & Control (Day 6)")
    print("-" * 80)
    c2_events = generate_c2_beacons(base_time)
    all_events.extend(c2_events)
    print(f"   ✓ Generated {len(c2_events)} C2 events")

    # Phase 7: Detection & Response (Day 6)
    print("\n" + "=" * 80)
    print("🔔 PHASE 7: Detection & Response (Day 6)")
    print("-" * 80)
    det_events = generate_soar_detections(base_time)
    all_events.extend(det_events)
    print(f"   ✓ Generated {len(det_events)} detection/response events")

    # Sort by timestamp
    all_events.sort(key=lambda x: x["timestamp"])

    # Summary
    scenario_summary = {
        "scenario_name": "HR Phishing PDF -> PowerShell -> Scheduled Task -> C2",
        "user_profile": VICTIM_PROFILE,
        "attacker_profile": ATTACKER_PROFILE,
        "timeline_start": base_time.isoformat(),
        "timeline_end": (base_time + timedelta(days=6)).isoformat(),
        "total_events": len(all_events),
        "phases": [
            {"name": "Normal Behavior Baseline", "days": "1-5", "events": len([e for e in all_events if e["phase"] == "normal_behavior"])},
            {"name": "Phishing Delivery", "day": "6", "events": len([e for e in all_events if e["phase"] == "phishing_delivery"])},
            {"name": "Delivery Interaction", "day": "6", "events": len([e for e in all_events if e["phase"] == "delivery_interaction"])},
            {"name": "Execution", "day": "6", "events": len([e for e in all_events if e["phase"] == "execution"])},
            {"name": "Persistence", "day": "6", "events": len([e for e in all_events if e["phase"] == "persistence"])},
            {"name": "Command & Control", "day": "6", "events": len([e for e in all_events if e["phase"] == "command_and_control"])},
            {"name": "Detection & Response", "day": "6", "events": len([e for e in all_events if e["phase"] in ["detection", "incident_response"])},
        ],
        "detections": [
            "Phishing Email (Proofpoint)",
            "PowerShell from PDF (SentinelOne)",
            "Scheduled Task Persistence (SentinelOne)",
            "C2 Communication (Palo Alto)",
        ],
        "mitre_techniques": [
            "T1566.002 - Spearphishing Link",
            "T1204.002 - User Execution",
            "T1059.001 - PowerShell",
            "T1053.005 - Scheduled Task",
            "T1071.001 - Web Protocols",
        ],
        "events": all_events,
    }

    print("\n" + "=" * 80)
    print("✅ SCENARIO GENERATION COMPLETE")
    print("=" * 80)
    print(f"Total Events: {len(all_events)}")
    print("Data Sources: Proofpoint, Microsoft 365, SentinelOne, Palo Alto, SOAR")
    print(f"Timeline: {(base_time).strftime('%Y-%m-%d')} to {(base_time + timedelta(days=6)).strftime('%Y-%m-%d')}")
    print("=" * 80)

    return scenario_summary


if __name__ == "__main__":
    scenario = generate_hr_phishing_pdf_c2_scenario()

    preferred_dir = os.environ.get("SCENARIO_OUTPUT_DIR") or os.path.join(os.path.dirname(__file__), "configs")
    output_file = os.path.join(preferred_dir, "hr_phishing_pdf_c2_scenario.json")

    def _attempt_save(path: str) -> bool:
        try:
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, 'w') as f:
                json.dump(scenario, f, indent=2)
            print(f"\n💾 Scenario saved to: {path}")
            print("\nTo replay this scenario, use the scenario_hec_sender.py script")
            return True
        except OSError as e:
            if e.errno == errno.EROFS:
                print(f"⚠️  Read-only filesystem when saving to {path}. Will try fallback.")
            else:
                print(f"⚠️  Failed to save scenario to {path}: {e}")
            return False

    if not _attempt_save(output_file):
        pass
