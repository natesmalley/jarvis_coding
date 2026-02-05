#!/usr/bin/env python3
"""
Apollo Ransomware Attack Scenario - Proofpoint & M365 Events
============================================================

This scenario generates ONLY Proofpoint and Microsoft 365 events to correlate
with existing EDR/WEL data for the Apollo ransomware attack chain.

Attack Chain (EDR/WEL already exists):
1. Phishing email with malicious XLSX → Machine "Bridge" (jeanluc)
2. XLSX spawns PowerShell
3. Scheduled task creation
4. Download apollo.exe from C2 server
5. Mimikatz credential dumping
6. Brute force 20 login attempts
7. Lateral movement to machine "Enterprise"
8. Scheduled task creation on Enterprise

Key Correlation Points:
- Machine 1: bridge (Windows Server 2019 Datacenter)
- Machine 2: Enterprise (Windows Server 2025 Datacenter)
- Domain: STARFLEET
- User: jeanluc (STARFLEET\\jeanluc)
- C2: http://13.233.252.37:5000
- Malware: apollo.exe
- File hashes: SHA256=3a3db5b782c70973bc533ef5a5474b3577435da2b51399512c09e6d0e4f62d5d
"""

import json
import os
import sys
import uuid
import threading
from datetime import datetime, timedelta, timezone
from typing import Dict, List

script_dir = os.path.dirname(os.path.abspath(__file__))
backend_dir = os.path.dirname(script_dir)
sys.path.insert(0, backend_dir)
sys.path.insert(0, os.path.join(backend_dir, 'event_generators'))
sys.path.insert(0, os.path.join(backend_dir, 'event_generators', 'shared'))

from email_security.proofpoint import proofpoint_log
from identity_access.microsoft_365_collaboration import microsoft_365_collaboration_log

HEC_AVAILABLE = False
try:
    from hec_sender import send_one
    HEC_AVAILABLE = True
except ImportError:
    pass

# Attack Profile - correlates with existing OCSF alert data
ATTACKER_PROFILE = {
    "sender_email": "hr-updates@starfleet-benefits.com",
    "sender_name": "Starfleet HR Benefits",
    "sender_ip": "45.33.32.156",
    "malicious_xlsx": "TestBook.xlsm",
    "xlsx_sha1": "cc1ff78c45cc7beff6a181a9f09941ed820d11fe",
    "xlsx_path": "C:\\Users\\jeanluc\\AppData\\Local\\Microsoft\\Windows\\INetCache\\Content.Outlook\\8SIIXRNA\\TestBook.xlsm",
    "c2_server": "13.233.252.37",
    "c2_port": 5000,
    "c2_url": "http://13.233.252.37:5000/direct/download/54aa8a44-d93a-4683-9b98-afab6611783b",
    "malware_name": "apollo.exe",
    "malware_sha256": "3a3db5b782c70973bc533ef5a5474b3577435da2b51399512c09e6d0e4f62d5d",
    "malware_sha1": "847cf78e3006e2d5915f6e2a3f15cc7a5b26fef1",
    "malware_md5": "bda1c2974bb06957acbc40593c69b925",
}

VICTIM_PROFILE = {
    "name": "Jean-Luc Picard",
    "email": "jeanluc@starfleet.com",
    "domain": "STARFLEET",
    "username": "jeanluc",
    "department": "Command",
    "role": "Captain",
    "machine_bridge": "bridge",
    "machine_enterprise": "Enterprise",
    "client_ip": "10.50.1.100",
}


def get_scenario_time(base_time: datetime, minutes_offset: int, seconds_offset: int = 0) -> str:
    event_time = base_time + timedelta(minutes=minutes_offset, seconds=seconds_offset)
    return event_time.isoformat()


def create_event(timestamp: str, source: str, phase: str, event_data: dict) -> Dict:
    return {"timestamp": timestamp, "source": source, "phase": phase, "event": event_data}


def generate_proofpoint_phishing_delivery(base_time: datetime) -> List[Dict]:
    """Generate Proofpoint email delivery event for malicious XLSX"""
    events = []
    
    delivery_time = get_scenario_time(base_time, 0)
    
    pf_event = {
        "GUID": str(uuid.uuid4()),
        "QID": f"r{uuid.uuid4().hex[:12]}",
        "ccAddresses": [],
        "clusterId": "starfleet_hosted",
        "completelyRewritten": True,
        "fromAddress": [ATTACKER_PROFILE["sender_email"]],
        "headerFrom": f"\"{ATTACKER_PROFILE['sender_name']}\" <{ATTACKER_PROFILE['sender_email']}>",
        "headerReplyTo": ATTACKER_PROFILE["sender_email"],
        "impostorScore": 0,
        "malwareScore": 100,
        "messageID": f"<{uuid.uuid4()}@starfleet-benefits.com>",
        "messageSize": 245678,
        "messageTime": delivery_time,
        "modulesRun": ["av", "spam", "spf", "dkim", "dmarc", "urldefense", "attachment_defense", "impostor"],
        "phishScore": 95,
        "policyRoutes": ["default_inbound", "quarantine"],
        "quarantineFolder": "Malware",
        "quarantineRule": "attachment_malware",
        "recipient": [VICTIM_PROFILE["email"]],
        "replyToAddress": [ATTACKER_PROFILE["sender_email"]],
        "sender": ATTACKER_PROFILE["sender_email"],
        "senderIP": ATTACKER_PROFILE["sender_ip"],
        "spamScore": 85,
        "subject": "RE: Test Workbook - Please Review",
        "threatsInfoMap": [
            {
                "campaignId": str(uuid.uuid4()),
                "classification": "malware",
                "threat": ATTACKER_PROFILE["malicious_xlsx"],
                "threatId": str(uuid.uuid4()),
                "threatStatus": "active",
                "threatTime": delivery_time,
                "threatType": "attachment",
                "threatUrl": ""
            }
        ],
        "toAddresses": [VICTIM_PROFILE["email"]],
        "xmailer": "Microsoft Outlook 16.0",
        "messageParts": [
            {
                "disposition": "attached",
                "filename": ATTACKER_PROFILE["malicious_xlsx"],
                "sha1": ATTACKER_PROFILE["xlsx_sha1"],
                "contentType": "application/vnd.ms-excel.sheet.macroEnabled.12",
                "sandboxStatus": "threat",
                "threatStatus": "malicious",
                "oContentType": "application/vnd.ms-excel.sheet.macroEnabled.12"
            },
            {
                "disposition": "inline",
                "contentType": "text/html",
                "sandboxStatus": "clean"
            }
        ],
        "spf": "softfail",
        "dkim": "none",
        "dmarc": "fail",
    }
    events.append(create_event(delivery_time, "proofpoint", "phishing_delivery", pf_event))
    
    return events


def generate_m365_email_interaction(base_time: datetime) -> List[Dict]:
    """Generate M365 events for email access and attachment download"""
    events = []
    
    # Email accessed - 5 minutes after delivery (user checks email)
    email_access_time = get_scenario_time(base_time, 5)
    m365_email_access = microsoft_365_collaboration_log()
    m365_email_access['TimeStamp'] = email_access_time
    m365_email_access['UserId'] = VICTIM_PROFILE['email']
    m365_email_access['ClientIP'] = VICTIM_PROFILE['client_ip']
    m365_email_access['Operation'] = 'MailItemsAccessed'
    m365_email_access['ObjectId'] = f"/Inbox/{ATTACKER_PROFILE['malicious_xlsx']}"
    m365_email_access['FileName'] = ATTACKER_PROFILE['malicious_xlsx']
    m365_email_access['Workload'] = 'Exchange'
    m365_email_access['EventType'] = 'Audit.Exchange'
    m365_email_access['Details'] = f"User {VICTIM_PROFILE['email']} accessed email with malicious attachment {ATTACKER_PROFILE['malicious_xlsx']}"
    m365_email_access['SiteUrl'] = f"https://outlook.office365.com/mail/inbox"
    # Parser-mapped fields for OCSF synthetic columns
    m365_email_access['RequestedBy'] = VICTIM_PROFILE['name']  # -> actor.user.name
    events.append(create_event(email_access_time, "microsoft_365_collaboration", "email_interaction", m365_email_access))
    
    # Attachment preview/download - 6 minutes after delivery
    attachment_time = get_scenario_time(base_time, 6)
    m365_attachment = microsoft_365_collaboration_log()
    m365_attachment['TimeStamp'] = attachment_time
    m365_attachment['UserId'] = VICTIM_PROFILE['email']
    m365_attachment['ClientIP'] = VICTIM_PROFILE['client_ip']
    m365_attachment['Operation'] = 'FileDownloaded'
    m365_attachment['ObjectId'] = f"/Attachments/{ATTACKER_PROFILE['malicious_xlsx']}"
    m365_attachment['FileName'] = ATTACKER_PROFILE['malicious_xlsx']
    m365_attachment['Workload'] = 'Exchange'
    m365_attachment['Details'] = f"User {VICTIM_PROFILE['email']} downloaded attachment {ATTACKER_PROFILE['malicious_xlsx']} from phishing email"
    m365_attachment['SiteUrl'] = f"https://outlook.office365.com/mail/inbox"
    # Parser-mapped fields for OCSF synthetic columns
    m365_attachment['RequestedBy'] = VICTIM_PROFILE['name']  # -> actor.user.name
    events.append(create_event(attachment_time, "microsoft_365_collaboration", "email_interaction", m365_attachment))
    
    # File opened in Excel Online / locally - 7 minutes after delivery
    file_open_time = get_scenario_time(base_time, 7)
    m365_file_open = microsoft_365_collaboration_log()
    m365_file_open['TimeStamp'] = file_open_time
    m365_file_open['UserId'] = VICTIM_PROFILE['email']
    m365_file_open['ClientIP'] = VICTIM_PROFILE['client_ip']
    m365_file_open['Operation'] = 'FileAccessed'
    m365_file_open['ObjectId'] = f"/Documents/{ATTACKER_PROFILE['malicious_xlsx']}"
    m365_file_open['FileName'] = ATTACKER_PROFILE['malicious_xlsx']
    m365_file_open['Workload'] = 'OneDrive'
    m365_file_open['Details'] = f"User {VICTIM_PROFILE['email']} opened malicious macro-enabled file {ATTACKER_PROFILE['malicious_xlsx']}"
    m365_file_open['SiteUrl'] = f"https://starfleet-my.sharepoint.com/personal/{VICTIM_PROFILE['username']}"
    # Parser-mapped fields for OCSF synthetic columns
    m365_file_open['RequestedBy'] = VICTIM_PROFILE['name']  # -> actor.user.name
    events.append(create_event(file_open_time, "microsoft_365_collaboration", "file_access", m365_file_open))
    
    return events


def generate_m365_suspicious_activity(base_time: datetime) -> List[Dict]:
    """Generate M365 events showing suspicious activity after compromise"""
    events = []
    
    # Multiple failed logins (brute force) - starts ~15 min after initial compromise
    for i in range(20):
        login_time = get_scenario_time(base_time, 15 + (i // 5), (i % 5) * 10)
        target_users = [
            "worf.security@starfleet.com",
            "data.android@starfleet.com", 
            "william.riker@starfleet.com",
            "beverly.crusher@starfleet.com",
        ]
        target_user = target_users[i % len(target_users)]
        m365_failed_login = microsoft_365_collaboration_log()
        m365_failed_login['TimeStamp'] = login_time
        m365_failed_login['UserId'] = target_user
        m365_failed_login['ClientIP'] = VICTIM_PROFILE['client_ip']
        m365_failed_login['Operation'] = 'UserLoginFailed'
        m365_failed_login['Workload'] = 'AzureActiveDirectory'
        m365_failed_login['Details'] = f"Failed login attempt from compromised host {VICTIM_PROFILE['machine_bridge']} ({VICTIM_PROFILE['client_ip']}) targeting {target_user}"
        m365_failed_login['ObjectId'] = f"/AzureAD/Users/{target_user}"
        m365_failed_login['FileName'] = ''
        m365_failed_login['SiteUrl'] = 'https://login.microsoftonline.com'
        # Parser-mapped fields for OCSF synthetic columns
        m365_failed_login['RequestedBy'] = VICTIM_PROFILE['name']  # -> actor.user.name (attacker/source)
        m365_failed_login['TargetUser'] = target_user  # -> user.email_addr (target)
        events.append(create_event(login_time, "microsoft_365_collaboration", "brute_force", m365_failed_login))
    
    return events


def generate_apollo_ransomware_scenario() -> Dict:
    """Generate the complete Apollo ransomware scenario (Proofpoint + M365 only)"""
    
    # Use current time as base, adjusted to correlate with existing alerts
    # The OCSF alert timestamp 1770236573000 ms = some point in time
    # We'll generate events leading up to that
    base_time = datetime.now(timezone.utc).replace(hour=9, minute=0, second=0, microsecond=0)
    
    print("\n" + "=" * 80)
    print("🚀 APOLLO RANSOMWARE SCENARIO - PROOFPOINT & M365 EVENTS")
    print("=" * 80)
    print(f"Target: {VICTIM_PROFILE['name']} ({VICTIM_PROFILE['email']})")
    print(f"Machine: {VICTIM_PROFILE['machine_bridge']} → {VICTIM_PROFILE['machine_enterprise']}")
    print(f"Domain: {VICTIM_PROFILE['domain']}")
    print(f"Malware: {ATTACKER_PROFILE['malware_name']}")
    print("=" * 80 + "\n")
    
    all_events = []
    
    phases = [
        ("📧 PHASE 1: Phishing Email Delivery", generate_proofpoint_phishing_delivery, "Malicious XLSX delivered via Proofpoint"),
        ("📬 PHASE 2: Email Interaction", generate_m365_email_interaction, "User opens email and downloads attachment"),
        ("🔓 PHASE 3: Brute Force Attempts", generate_m365_suspicious_activity, "Failed login attempts to other accounts"),
    ]
    
    for phase_name, generator_func, description in phases:
        print(f"\n{phase_name}")
        print(f"   {description}")
        phase_events = generator_func(base_time)
        all_events.extend(phase_events)
        print(f"   ✓ Generated {len(phase_events)} events")
    
    all_events.sort(key=lambda x: x["timestamp"])
    
    scenario = {
        "scenario_id": f"apollo-ransomware-{datetime.now().strftime('%Y%m%d-%H%M%S')}",
        "scenario_name": "Apollo Ransomware - Proofpoint & M365 Events",
        "description": "Correlated email security and collaboration events for Apollo ransomware attack",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "timeline_start": base_time.isoformat(),
        "total_events": len(all_events),
        "correlation_details": {
            "victim_email": VICTIM_PROFILE["email"],
            "victim_username": VICTIM_PROFILE["username"],
            "victim_domain": VICTIM_PROFILE["domain"],
            "machine_initial": VICTIM_PROFILE["machine_bridge"],
            "machine_lateral": VICTIM_PROFILE["machine_enterprise"],
            "malware": ATTACKER_PROFILE["malware_name"],
            "malware_sha256": ATTACKER_PROFILE["malware_sha256"],
            "c2_server": ATTACKER_PROFILE["c2_server"],
            "attachment": ATTACKER_PROFILE["malicious_xlsx"],
        },
        "phases": [
            {"name": "Phishing Delivery", "source": "proofpoint", "events": len([e for e in all_events if e["phase"] == "phishing_delivery"])},
            {"name": "Email Interaction", "source": "microsoft_365", "events": len([e for e in all_events if e["phase"] in ["email_interaction", "file_access"]])},
            {"name": "Brute Force", "source": "microsoft_365", "events": len([e for e in all_events if e["phase"] == "brute_force"])},
        ],
        "events": all_events,
    }
    
    print("\n" + "=" * 80)
    print("📊 SCENARIO SUMMARY")
    print("=" * 80)
    print(f"Total Events: {len(all_events)}")
    print(f"  - Proofpoint: {len([e for e in all_events if e['source'] == 'proofpoint'])}")
    print(f"  - M365: {len([e for e in all_events if 'microsoft' in e['source']])}")
    print("=" * 80)
    
    return scenario


def send_to_hec(event_data: dict, event_type: str, trace_id: str = None, phase: str = None) -> bool:
    """Send a single event to HEC"""
    type_to_product = {
        "proofpoint": "proofpoint",
        "microsoft_365_collaboration": "microsoft_365_collaboration",
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
    scenario = generate_apollo_ransomware_scenario()
    
    hec_token = os.getenv('S1_HEC_TOKEN')
    if HEC_AVAILABLE and hec_token:
        worker_count = int(os.getenv('S1_HEC_WORKERS', '10'))
        trace_id = os.getenv('S1_TRACE_ID', f"apollo-{datetime.now().strftime('%Y%m%d-%H%M%S')}")
        tag_phase = os.getenv('S1_TAG_PHASE', '1') == '1'
        
        print("\n" + "=" * 80)
        print(f"📤 SENDING {len(scenario['events'])} EVENTS TO HEC")
        print(f"Workers: {worker_count}")
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
                with lock:
                    counts["error"] += 1
                    print(f"\nError sending event: {e}")
        
        from concurrent.futures import ThreadPoolExecutor
        with ThreadPoolExecutor(max_workers=worker_count) as executor:
            executor.map(send_event, scenario['events'])
        
        print(f"\n\n{'=' * 80}")
        print(f"✅ HEC SENDING COMPLETE")
        print(f"   Success: {counts['success']}")
        print(f"   Errors: {counts['error']}")
        print(f"{'=' * 80}\n")
    
    output_dir = os.getenv('SCENARIO_OUTPUT_DIR', os.path.join(script_dir, 'configs'))
    os.makedirs(output_dir, exist_ok=True)
    
    output_file = os.path.join(output_dir, f"apollo_ransomware_scenario.json")
    with open(output_file, 'w') as f:
        json.dump(scenario, f, indent=2, default=str)
    
    print(f"\n💾 Scenario saved to: {output_file}")
    
    if not (HEC_AVAILABLE and hec_token):
        print("\n📝 To send events to HEC, set S1_HEC_TOKEN environment variable")
