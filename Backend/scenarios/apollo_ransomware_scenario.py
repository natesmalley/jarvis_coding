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
import copy
import gzip
import threading
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional

import requests

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
except (ImportError, RuntimeError):
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

CORRELATION_CONFIG = {
    "scenario_id": "apollo_ransomware_scenario",
    "name": "Apollo Ransomware - STARFLEET Attack",
    "description": "Correlates Proofpoint and M365 events with existing EDR/WEL data for the Apollo ransomware attack chain targeting STARFLEET.",
    
    "default_query": """dataSource.name in ('SentinelOne','Windows Event Logs') endpoint.name contains ("Enterprise", "bridge")
| group newest_timestamp = newest(timestamp), oldest_timestamp = oldest(timestamp) by event.type, src.process.user, endpoint.name, src.endpoint.ip.address, dst.ip.address
| sort newest_timestamp
| columns event.type, src.process.user, endpoint.name, oldest_timestamp, newest_timestamp, src.endpoint.ip.address, dst.ip.address""",
    
    "time_anchors": [
        {
            "id": "bridge_first_activity",
            "name": "Bridge First Activity",
            "description": "First EDR/WEL activity on the bridge machine (initial compromise)",
            "query_match": {"endpoint.name": "bridge"},
            "use_field": "oldest_timestamp",
            "required": True
        },
        {
            "id": "bridge_last_activity",
            "name": "Bridge Last Activity",
            "description": "Last EDR/WEL activity on bridge before lateral movement",
            "query_match": {"endpoint.name": "bridge"},
            "use_field": "newest_timestamp",
            "required": False
        },
        {
            "id": "enterprise_first_activity",
            "name": "Enterprise First Activity",
            "description": "First activity on Enterprise (lateral movement target)",
            "query_match": {"endpoint.name": "Enterprise"},
            "use_field": "oldest_timestamp",
            "required": False
        }
    ],
    
    "phase_mapping": {
        "phishing_delivery": {
            "anchor": "bridge_first_activity",
            "offset_minutes": -5,
            "description": "Phishing email arrives ~5 min before first EDR activity"
        },
        "email_interaction": {
            "anchor": "bridge_first_activity",
            "offset_minutes": -2,
            "description": "User opens email and downloads attachment ~2 min before EDR sees XLSX open"
        },
        "sharepoint_bruteforce": {
            "anchor": "bridge_first_activity",
            "offset_minutes": 15,
            "description": "SharePoint recon begins after initial compromise established"
        },
        "sharepoint_exfil": {
            "anchor": "bridge_first_activity",
            "offset_minutes": 20,
            "description": "Data exfiltration from SharePoint after recon"
        }
    },
    
    "fallback_behavior": "offset_from_now"
}

# Alert configuration for scenario phases
ALERT_PHASE_MAPPING = {
    "📬 PHASE 2: Email Interaction": {
        "template": "proofpoint_email_alert",
        "offset_minutes": 2,  # 2 min after delivery (user clicks link)
        "overrides": {
            "finding_info.title": "Malicious Email Link Clicked",
            "finding_info.desc": f"User {VICTIM_PROFILE['email']} clicked malicious link in phishing email from {ATTACKER_PROFILE['sender_email']}"
        }
    },
    "📤 PHASE 4: Data Exfiltration": {
        "template": "sharepoint_data_exfil_alert",
        "offset_minutes": 20,  # 20 min after initial compromise
        "overrides": {
            "finding_info.title": "Data Exfiltration from SharePoint",
            "finding_info.desc": f"User {VICTIM_PROFILE['email']} downloaded sensitive documents including Personnel Records and Command Codes"
        }
    },
    "rdp_download": {
        "template": "o365_rdp_sharepoint_access",
        "offset_minutes": 25,  # 25 min after initial compromise
        "overrides": {
            "finding_info.title": "Apollo Ransomware - RDP Files Downloaded",
            "finding_info.desc": f"User {VICTIM_PROFILE['email']} downloaded RDP files from SharePoint - potential lateral movement preparation"
        }
    }
}


def resolve_time_anchors(siem_context: Dict, anchors_config: List[Dict]) -> Dict[str, datetime]:
    """Resolve time anchors from SIEM query results or pre-resolved anchors"""
    resolved = {}
    
    # Check if anchors are already pre-resolved (from frontend/API)
    pre_resolved = siem_context.get("anchors", {})
    if pre_resolved:
        for anchor_id, anchor_data in pre_resolved.items():
            timestamp_str = anchor_data.get("timestamp") if isinstance(anchor_data, dict) else anchor_data
            if timestamp_str:
                try:
                    if isinstance(timestamp_str, str):
                        parsed = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
                    else:
                        parsed = timestamp_str
                    resolved[anchor_id] = parsed
                except (ValueError, TypeError):
                    continue
        if resolved:
            return resolved
    
    # Fall back to resolving from raw results
    for anchor in anchors_config:
        anchor_id = anchor["id"]
        query_match = anchor["query_match"]
        use_field = anchor["use_field"]
        
        for row in siem_context.get("results", []):
            match = True
            for key, value in query_match.items():
                row_value = row.get(key, "")
                if isinstance(value, str) and value.lower() not in str(row_value).lower():
                    match = False
                    break
            
            if match:
                timestamp_str = row.get(use_field)
                if timestamp_str:
                    try:
                        if isinstance(timestamp_str, str):
                            parsed = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
                        else:
                            parsed = timestamp_str
                        resolved[anchor_id] = parsed
                        break
                    except (ValueError, TypeError):
                        continue
    
    return resolved


def calculate_phase_times(anchors: Dict[str, datetime], phase_mapping: Dict) -> Dict[str, datetime]:
    """Calculate phase start times based on resolved anchors"""
    phase_times = {}
    
    for phase_name, mapping in phase_mapping.items():
        anchor_id = mapping["anchor"]
        offset_minutes = mapping["offset_minutes"]
        
        if anchor_id in anchors:
            phase_times[phase_name] = anchors[anchor_id] + timedelta(minutes=offset_minutes)
        else:
            phase_times[phase_name] = None
    
    return phase_times


def get_scenario_time(base_time: datetime, minutes_offset: int, seconds_offset: int = 0) -> str:
    event_time = base_time + timedelta(minutes=minutes_offset, seconds=seconds_offset)
    return event_time.isoformat()


def create_event(timestamp: str, source: str, phase: str, event_data: dict) -> Dict:
    return {"timestamp": timestamp, "source": source, "phase": phase, "event": event_data}


def load_alert_template(template_id: str) -> Optional[Dict]:
    """Load an alert template JSON from the templates directory"""
    templates_dir = os.path.join(backend_dir, 'api', 'app', 'alerts', 'templates')
    template_path = os.path.join(templates_dir, f"{template_id}.json")
    if not os.path.exists(template_path):
        print(f"   ⚠️  Template not found: {template_path}")
        return None
    with open(template_path, 'r') as f:
        return json.load(f)


def send_phase_alert(
    phase_name: str,
    base_time: datetime,
    uam_config: dict
) -> bool:
    """Send alert for a specific phase with correct timing.
    
    Standalone implementation — loads template from disk and sends
    directly via requests + gzip. No AlertService dependency.
    """
    if phase_name not in ALERT_PHASE_MAPPING:
        return False
    
    mapping = ALERT_PHASE_MAPPING[phase_name]
    
    # Load template
    template = load_alert_template(mapping["template"])
    if not template:
        return False
    
    alert = copy.deepcopy(template)
    
    # Calculate alert timestamp
    alert_time = base_time + timedelta(minutes=mapping["offset_minutes"])
    time_ms = int(alert_time.timestamp() * 1000)
    
    # Inject fresh UID
    if "finding_info" not in alert:
        alert["finding_info"] = {}
    alert["finding_info"]["uid"] = str(uuid.uuid4())
    
    # Set timestamps
    alert["time"] = time_ms
    if "metadata" not in alert:
        alert["metadata"] = {}
    alert["metadata"]["logged_time"] = time_ms
    alert["metadata"]["modified_time"] = time_ms
    
    # Set user as the resource
    alert["resources"] = [{
        "uid": VICTIM_PROFILE["email"],
        "name": VICTIM_PROFILE["email"]
    }]
    
    # Apply overrides
    overrides = mapping.get("overrides", {})
    for key, value in overrides.items():
        if "." in key:
            keys = key.split(".")
            current = alert
            for k in keys[:-1]:
                if k not in current:
                    current[k] = {}
                current = current[k]
            current[keys[-1]] = value
        else:
            alert[key] = value
    
    # Send alert via UAM ingest API
    try:
        ingest_url = uam_config['uam_ingest_url'].rstrip('/') + '/v1/alerts'
        scope = uam_config['uam_account_id']
        if uam_config.get('uam_site_id'):
            scope = f"{scope}:{uam_config['uam_site_id']}"
        
        headers = {
            "Authorization": f"Bearer {uam_config['uam_service_token']}",
            "S1-Scope": scope,
            "Content-Encoding": "gzip",
            "Content-Type": "application/json",
        }
        
        payload = json.dumps(alert).encode("utf-8")
        gzipped = gzip.compress(payload)
        
        print(f"\n      📤 Alert Details:")
        print(f"         Template: {mapping['template']}")
        print(f"         Title: {alert.get('finding_info', {}).get('title', 'N/A')}")
        print(f"         User: {VICTIM_PROFILE['email']}")
        print(f"         Time: {alert_time.isoformat()} ({time_ms}ms)")
        print(f"         URL: {ingest_url}")
        print(f"         Scope: {scope}")
        print(f"         Payload: {len(payload)} bytes -> {len(gzipped)} bytes (gzip)")
        print(f"         Full JSON: {json.dumps(alert, indent=2)}")
        
        resp = requests.post(ingest_url, headers=headers, data=gzipped, timeout=30)
        
        print(f"         Response: {resp.status_code} {resp.reason}")
        if resp.content:
            print(f"         Body: {resp.text[:200]}")
        
        return resp.status_code == 202
        
    except Exception as e:
        print(f"   ✗ Alert send failed: {e}")
        import traceback
        traceback.print_exc()
        return False


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


def generate_m365_sharepoint_bruteforce(base_time: datetime) -> List[Dict]:
    """Generate M365 events for SharePoint brute force (failed access attempts to sensitive sites)"""
    events = []
    
    # Attacker probes restricted SharePoint sites - starts ~10 min after macro execution
    restricted_sites = [
        ("/sites/Executive/Shared Documents/Board-Meetings/", "Executive Board site"),
        ("/sites/Finance/Shared Documents/Payroll/", "Finance Payroll site"),
        ("/sites/IT-Admin/Shared Documents/Credentials/", "IT Admin Credentials site"),
        ("/sites/Legal/Shared Documents/Contracts/", "Legal Contracts site"),
        ("/sites/Security/Shared Documents/Incident-Response/", "Security IR site"),
    ]
    
    for i, (site_path, site_desc) in enumerate(restricted_sites):
        # Multiple failed access attempts per site
        for attempt in range(3):
            fail_time = get_scenario_time(base_time, 10 + i, attempt * 15)
            m365_denied = microsoft_365_collaboration_log()
            m365_denied['TimeStamp'] = fail_time
            m365_denied['UserId'] = VICTIM_PROFILE['email']
            m365_denied['ClientIP'] = VICTIM_PROFILE['client_ip']
            m365_denied['Operation'] = 'AccessDenied'
            m365_denied['Workload'] = 'SharePoint'
            m365_denied['ObjectId'] = site_path
            m365_denied['FileName'] = ''
            m365_denied['SiteUrl'] = f"https://starfleet.sharepoint.com{site_path.rsplit('/', 2)[0]}"
            m365_denied['Details'] = f"Access denied: User {VICTIM_PROFILE['email']} attempted to access restricted {site_desc}"
            m365_denied['RequestedBy'] = VICTIM_PROFILE['name']
            m365_denied['ResultStatus'] = 'Failed'
            events.append(create_event(fail_time, "microsoft_365_collaboration", "sharepoint_bruteforce", m365_denied))
    
    return events


def generate_m365_sharepoint_exfil(base_time: datetime) -> List[Dict]:
    """Generate M365 events for SharePoint data exfiltration (successful access after finding open site)"""
    events = []
    
    # Attacker finds accessible SharePoint site and downloads sensitive docs - ~20 min after compromise
    sensitive_docs = [
        ("Starfleet-Personnel-Records.xlsx", "/sites/HR/Shared Documents/Personnel/"),
        ("Command-Codes-Q1-2026.docx", "/sites/Operations/Shared Documents/Classified/"),
        ("Enterprise-Schematics-NCC1701D.pdf", "/sites/Engineering/Shared Documents/Blueprints/"),
        ("Security-Protocols-Alpha.docx", "/sites/Security/Shared Documents/Protocols/"),
        ("Medical-Research-Classified.xlsx", "/sites/Medical/Shared Documents/Research/"),
    ]
    
    for i, (doc_name, doc_path) in enumerate(sensitive_docs):
        # Access event
        access_time = get_scenario_time(base_time, 20 + i, 0)
        m365_access = microsoft_365_collaboration_log()
        m365_access['TimeStamp'] = access_time
        m365_access['UserId'] = VICTIM_PROFILE['email']
        m365_access['ClientIP'] = VICTIM_PROFILE['client_ip']
        m365_access['Operation'] = 'FileAccessed'
        m365_access['Workload'] = 'SharePoint'
        m365_access['ObjectId'] = f"{doc_path}{doc_name}"
        m365_access['FileName'] = doc_name
        m365_access['SiteUrl'] = f"https://starfleet.sharepoint.com{doc_path.rsplit('/', 2)[0]}"
        m365_access['Details'] = f"User {VICTIM_PROFILE['email']} accessed sensitive document {doc_name}"
        m365_access['RequestedBy'] = VICTIM_PROFILE['name']
        events.append(create_event(access_time, "microsoft_365_collaboration", "sharepoint_access", m365_access))
        
        # Download event - 30 seconds after access
        download_time = get_scenario_time(base_time, 20 + i, 30)
        m365_download = microsoft_365_collaboration_log()
        m365_download['TimeStamp'] = download_time
        m365_download['UserId'] = VICTIM_PROFILE['email']
        m365_download['ClientIP'] = VICTIM_PROFILE['client_ip']
        m365_download['Operation'] = 'FileDownloaded'
        m365_download['Workload'] = 'SharePoint'
        m365_download['ObjectId'] = f"{doc_path}{doc_name}"
        m365_download['FileName'] = doc_name
        m365_download['SiteUrl'] = f"https://starfleet.sharepoint.com{doc_path.rsplit('/', 2)[0]}"
        m365_download['Details'] = f"User {VICTIM_PROFILE['email']} downloaded sensitive document {doc_name} - potential data exfiltration"
        m365_download['RequestedBy'] = VICTIM_PROFILE['name']
        events.append(create_event(download_time, "microsoft_365_collaboration", "sharepoint_exfil", m365_download))
    
    # Add RDP file download event - 5 minutes after exfil starts
    rdp_time = get_scenario_time(base_time, 25, 0)
    m365_rdp = microsoft_365_collaboration_log()
    m365_rdp['TimeStamp'] = rdp_time
    m365_rdp['UserId'] = VICTIM_PROFILE['email']
    m365_rdp['ClientIP'] = VICTIM_PROFILE['client_ip']
    m365_rdp['Operation'] = 'FileDownloaded'
    m365_rdp['Workload'] = 'SharePoint'
    m365_rdp['ObjectId'] = "/sites/IT-Admin/Shared Documents/Remote/enterprise-access.rdp"
    m365_rdp['FileName'] = "enterprise-access.rdp"
    m365_rdp['SiteUrl'] = "https://starfleet.sharepoint.com/sites/IT-Admin"
    m365_rdp['Details'] = f"User {VICTIM_PROFILE['email']} downloaded RDP file - potential lateral movement tool"
    m365_rdp['RequestedBy'] = VICTIM_PROFILE['name']
    events.append(create_event(rdp_time, "microsoft_365_collaboration", "rdp_download", m365_rdp))
    
    return events


def generate_apollo_ransomware_scenario(siem_context: Optional[Dict] = None) -> Dict:
    """Generate the complete Apollo ransomware scenario (Proofpoint + M365 only)
    
    Args:
        siem_context: Optional dict with SIEM query results for timestamp correlation.
                      Expected format: {"results": [...], "anchors": {...}}
                      If provided, timestamps are calculated relative to existing EDR/WEL data.
                      If None, falls back to offset from current time.
    """
    
    # Determine base time based on SIEM context or fallback
    use_correlation = False
    resolved_anchors = {}
    phase_times = {}
    
    if siem_context and siem_context.get("results"):
        resolved_anchors = resolve_time_anchors(siem_context, CORRELATION_CONFIG["time_anchors"])
        if resolved_anchors:
            phase_times = calculate_phase_times(resolved_anchors, CORRELATION_CONFIG["phase_mapping"])
            use_correlation = True
            # Use phishing_delivery phase time as base, or first resolved anchor
            base_time = phase_times.get("phishing_delivery") or list(resolved_anchors.values())[0]
            print("\n" + "=" * 80)
            print("🔗 CORRELATION MODE - Using SIEM context for timestamps")
            print("=" * 80)
            print("Resolved Anchors:")
            for anchor_id, anchor_time in resolved_anchors.items():
                print(f"  • {anchor_id}: {anchor_time.isoformat()}")
            print("\nPhase Times:")
            for phase_name, phase_time in phase_times.items():
                if phase_time:
                    print(f"  • {phase_name}: {phase_time.isoformat()}")
            print("=" * 80)
        else:
            print("\n⚠️  No anchors resolved from SIEM context, falling back to offset mode")
            base_time = datetime.now(timezone.utc).replace(hour=9, minute=0, second=0, microsecond=0)
    else:
        base_time = datetime.now(timezone.utc).replace(hour=9, minute=0, second=0, microsecond=0)
    
    print("\n" + "=" * 80)
    print("🚀 APOLLO RANSOMWARE SCENARIO - PROOFPOINT & M365 EVENTS")
    print("=" * 80)
    print(f"Target: {VICTIM_PROFILE['name']} ({VICTIM_PROFILE['email']})")
    print(f"Machine: {VICTIM_PROFILE['machine_bridge']} → {VICTIM_PROFILE['machine_enterprise']}")
    print(f"Domain: {VICTIM_PROFILE['domain']}")
    print(f"Malware: {ATTACKER_PROFILE['malware_name']}")
    print(f"Mode: {'Correlation' if use_correlation else 'Offset from now'}")
    print(f"Base Time: {base_time.isoformat()}")
    print("=" * 80 + "\n")
    
    # Initialize alert detonation from env vars
    alerts_enabled = os.getenv('SCENARIO_ALERTS_ENABLED', 'false').lower() == 'true'
    uam_config = None
    
    if alerts_enabled:
        uam_ingest_url = os.getenv('UAM_INGEST_URL', '')
        uam_account_id = os.getenv('UAM_ACCOUNT_ID', '')
        uam_service_token = os.getenv('UAM_SERVICE_TOKEN', '')
        uam_site_id = os.getenv('UAM_SITE_ID', '')
        
        if uam_ingest_url and uam_account_id and uam_service_token:
            uam_config = {
                'uam_ingest_url': uam_ingest_url,
                'uam_account_id': uam_account_id,
                'uam_service_token': uam_service_token,
                'uam_site_id': uam_site_id,
            }
            print("\n🚨 ALERT DETONATION ENABLED")
            print(f"   UAM Ingest: {uam_ingest_url}")
            print(f"   Account ID: {uam_account_id}")
            print("=" * 80)
        else:
            print("⚠️  SCENARIO_ALERTS_ENABLED=true but UAM credentials missing")
            alerts_enabled = False
    
    all_events = []
    
    # Build phases with appropriate base times
    if use_correlation and phase_times:
        phases = [
            ("📧 PHASE 1: Phishing Email Delivery", generate_proofpoint_phishing_delivery, 
             "Malicious XLSX delivered via Proofpoint", phase_times.get("phishing_delivery", base_time)),
            ("📬 PHASE 2: Email Interaction", generate_m365_email_interaction, 
             "User opens email and downloads TestBook.xlsm", phase_times.get("email_interaction", base_time)),
            ("🔍 PHASE 3: SharePoint Recon", generate_m365_sharepoint_bruteforce, 
             "Failed access attempts to restricted SharePoint sites", phase_times.get("sharepoint_bruteforce", base_time)),
            ("📤 PHASE 4: Data Exfiltration", generate_m365_sharepoint_exfil, 
             "Downloading sensitive documents from SharePoint", phase_times.get("sharepoint_exfil", base_time)),
        ]
    else:
        phases = [
            ("📧 PHASE 1: Phishing Email Delivery", generate_proofpoint_phishing_delivery, 
             "Malicious XLSX delivered via Proofpoint", base_time),
            ("📬 PHASE 2: Email Interaction", generate_m365_email_interaction, 
             "User opens email and downloads TestBook.xlsm", base_time),
            ("🔍 PHASE 3: SharePoint Recon", generate_m365_sharepoint_bruteforce, 
             "Failed access attempts to restricted SharePoint sites", base_time),
            ("📤 PHASE 4: Data Exfiltration", generate_m365_sharepoint_exfil, 
             "Downloading sensitive documents from SharePoint", base_time),
        ]
    
    for phase_name, generator_func, description, phase_base_time in phases:
        print(f"\n{phase_name}")
        print(f"   {description}")
        print(f"   Base: {phase_base_time.isoformat()}")
        phase_events = generator_func(phase_base_time)
        all_events.extend(phase_events)
        print(f"   ✓ Generated {len(phase_events)} events")
        
        # Send corresponding alert if enabled and phase has alert mapping
        if alerts_enabled and phase_name in ALERT_PHASE_MAPPING:
            print(f"   📤 Sending alert for {phase_name}...", end=" ")
            success = send_phase_alert(phase_name, phase_base_time, uam_config)
            print(f"{'✓' if success else '✗'}")
        
        # Send RDP alert after data exfiltration phase
        if alerts_enabled and phase_name == "📤 PHASE 4: Data Exfiltration":
            print(f"   📤 Sending RDP download alert...", end=" ")
            success = send_phase_alert("rdp_download", phase_base_time, uam_config)
            print(f"{'✓' if success else '✗'}")
    
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
        "full_attack_chain": [
            {"phase": 1, "step": "Phishing Email Delivered", "log_source": "Proofpoint", "event_type": "EmailDelivered", "description": f"Phishing email with {ATTACKER_PROFILE['malicious_xlsx']} from {ATTACKER_PROFILE['sender_email']} sent to {VICTIM_PROFILE['email']}", "generated": True},
            {"phase": 2, "step": "Email Opened", "log_source": "M365", "event_type": "MailItemsAccessed", "description": f"User {VICTIM_PROFILE['email']} opened phishing email containing {ATTACKER_PROFILE['malicious_xlsx']}", "generated": True},
            {"phase": 3, "step": "Attachment Downloaded", "log_source": "M365", "event_type": "FileDownloaded", "description": f"User {VICTIM_PROFILE['email']} downloaded {ATTACKER_PROFILE['malicious_xlsx']} (SHA1: {ATTACKER_PROFILE['xlsx_sha1']})", "generated": True},
            {"phase": 4, "step": "Malicious File Opened", "log_source": "M365", "event_type": "FileAccessed", "description": f"User opened macro-enabled {ATTACKER_PROFILE['malicious_xlsx']} at {ATTACKER_PROFILE['xlsx_path']}", "generated": True},
            {"phase": 5, "step": "PowerShell Spawned", "log_source": "EDR/WEL", "event_type": "ProcessCreate_4688", "description": f"EXCEL.EXE spawned powershell.exe with encoded command on {VICTIM_PROFILE['machine_bridge']}", "generated": False},
            {"phase": 6, "step": "Scheduled Task Created (Initial)", "log_source": "EDR/WEL", "event_type": "ScheduledTaskCreated_4698", "description": f"Persistence task 'WindowsUpdate' created on {VICTIM_PROFILE['machine_bridge']} to run {ATTACKER_PROFILE['malware_name']}", "generated": False},
            {"phase": 7, "step": "Initial C2 Beacon", "log_source": "EDR/Firewall", "event_type": "NetworkConnection", "description": f"{ATTACKER_PROFILE['malware_name']} on {VICTIM_PROFILE['machine_bridge']} connected to C2 {ATTACKER_PROFILE['c2_server']}:{ATTACKER_PROFILE['c2_port']}", "generated": False},
            {"phase": 8, "step": "Credential Dump (Mimikatz)", "log_source": "EDR/WEL", "event_type": "ProcessCreate_4688/LSASS_4663", "description": f"Mimikatz executed on {VICTIM_PROFILE['machine_bridge']} - LSASS memory accessed for credential extraction", "generated": False},
            {"phase": 9, "step": "Brute Force (Domain Auth)", "log_source": "WEL", "event_type": "FailedLogon_4625", "description": f"Multiple failed logon attempts from {VICTIM_PROFILE['machine_bridge']} ({VICTIM_PROFILE['client_ip']}) against domain accounts", "generated": False},
            {"phase": 10, "step": "Lateral Movement", "log_source": "WEL", "event_type": "SuccessfulLogon_4624", "description": f"Type 3 network logon from {VICTIM_PROFILE['machine_bridge']} to {VICTIM_PROFILE['machine_enterprise']} DC using stolen credentials", "generated": False},
            {"phase": 11, "step": "Scheduled Task Created (Lateral)", "log_source": "EDR/WEL", "event_type": "ScheduledTaskCreated_4698", "description": f"Persistence task created on {VICTIM_PROFILE['machine_enterprise']} Domain Controller to run {ATTACKER_PROFILE['malware_name']}", "generated": False},
            {"phase": 12, "step": "Lateral C2 Beacon", "log_source": "EDR/Firewall", "event_type": "NetworkConnection", "description": f"{ATTACKER_PROFILE['malware_name']} on {VICTIM_PROFILE['machine_enterprise']} connected to C2 {ATTACKER_PROFILE['c2_server']}:{ATTACKER_PROFILE['c2_port']}", "generated": False},
            {"phase": 13, "step": "SharePoint Recon", "log_source": "M365", "event_type": "AccessDenied", "description": f"User {VICTIM_PROFILE['email']} attempted access to restricted SharePoint sites (Executive, Finance, IT-Admin, Legal, Security)", "generated": True},
            {"phase": 14, "step": "SharePoint Data Access", "log_source": "M365", "event_type": "FileAccessed", "description": f"User {VICTIM_PROFILE['email']} accessed sensitive SharePoint documents (Personnel Records, Command Codes, Schematics)", "generated": True},
            {"phase": 15, "step": "SharePoint Data Exfil", "log_source": "M365", "event_type": "FileDownloaded", "description": f"User {VICTIM_PROFILE['email']} downloaded sensitive documents from SharePoint - data exfiltration", "generated": True},
        ],
        "generated_phases": [
            {"name": "Phishing Delivery", "source": "proofpoint", "events": len([e for e in all_events if e["phase"] == "phishing_delivery"])},
            {"name": "Email Interaction", "source": "microsoft_365", "events": len([e for e in all_events if e["phase"] in ["email_interaction", "file_access"]])},
            {"name": "SharePoint Recon", "source": "microsoft_365", "events": len([e for e in all_events if e["phase"] == "sharepoint_bruteforce"])},
            {"name": "Data Exfiltration", "source": "microsoft_365", "events": len([e for e in all_events if e["phase"] in ["sharepoint_access", "sharepoint_exfil"]])},
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
    # Check for SIEM context from environment (passed by correlation scenario runner)
    siem_context = None
    siem_context_json = os.getenv('SIEM_CONTEXT')
    if siem_context_json:
        try:
            siem_context = json.loads(siem_context_json)
            print("📥 Loaded SIEM context from environment")
        except json.JSONDecodeError as e:
            print(f"⚠️  Failed to parse SIEM_CONTEXT: {e}")
    
    scenario = generate_apollo_ransomware_scenario(siem_context=siem_context)
    
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
