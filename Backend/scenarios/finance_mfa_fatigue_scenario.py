#!/usr/bin/env python3
"""
Finance Employee MFA Fatigue Attack Scenario
============================================

Scenario: User Access and Incident Response for Finance Employee (Jake)

Timeline:
- Days 1-7: Normal user behavior baseline
- Day 8: MFA fatigue attack from Russia, data exfiltration
- Day 8 (Post-incident): SOAR detection and automated response

Attack Chain:
1. Attacker floods MFA requests (MFA Fatigue)
2. Frustrated user approves one request
3. Attacker accesses M365/OneDrive
4. Downloads 27 sensitive finance documents
5. SOAR detects impossible travel, locks account

Detections Generated:
- Okta MFA Fatigue Alert
- Okta Impossible Traveler Alert
- UEBA Irregular Login Alert
- UEBA Irregular Data Downloads Alert
"""

import json
import sys
import os
import errno
import random
import copy
import gzip
import uuid
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional

import requests

backend_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Add event_generators to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'event_generators'))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'event_generators', 'identity_access'))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'event_generators', 'cloud_infrastructure'))

# Import generators
from okta_system_log import okta_system_log
from microsoft_azuread import azuread_log
from microsoft_365_collaboration import microsoft_365_collaboration_log

# User Profile
JAKE_PROFILE = {
    "name": "Jake Thompson",
    "email": "jake.thompson@securatech.com",
    "department": "Finance",
    "role": "Finance Analyst",
    "location": "Denver, Colorado",
    "normal_ip": "73.229.104.12",  # Denver office IP
    "work_hours_start": 8,  # 8 AM
    "work_hours_end": 17  # 5 PM
}

ATTACKER_PROFILE = {
    "ip": "185.194.106.94",  # Russian IP (Moscow)
    "location": "Moscow, Russia",
    "timezone_offset": 10  # Moscow is UTC+3, Denver is UTC-7 = 10 hour difference
}

# Alert configuration for scenario phases
# Maps scenario detection phases to existing UAM alert templates with overrides
ALERT_PHASE_MAPPING = {
    "mfa_fatigue": {
        "template": "o365_brute_force_success",
        "offset_minutes": 0,
        "overrides": {
            "finding_info.title": "HELIOS - Okta MFA Fatigue Attack Detected",
            "finding_info.desc": f"15 consecutive MFA push requests detected for {JAKE_PROFILE['email']} within 15 minutes from {ATTACKER_PROFILE['ip']} ({ATTACKER_PROFILE['location']}), followed by user acceptance. MITRE ATT&CK: T1621 - Multi-Factor Authentication Request Generation.",
            "severity_id": 5,
            "severity": "critical",
        }
    },
    "impossible_traveler": {
        "template": "o365_noncompliant_login",
        "offset_minutes": 1,
        "overrides": {
            "finding_info.title": "HELIOS - Impossible Traveler Detected",
            "finding_info.desc": f"Login from {ATTACKER_PROFILE['location']} ({ATTACKER_PROFILE['ip']}) detected for {JAKE_PROFILE['email']} 30 minutes after Denver login. Geographic distance: 8,000+ miles. MITRE ATT&CK: T1078 - Valid Accounts.",
            "severity_id": 5,
            "severity": "critical",
        }
    },
    "ueba_irregular_login": {
        "template": "o365_sneaky_2fa",
        "offset_minutes": 2,
        "overrides": {
            "finding_info.title": "HELIOS - UEBA Irregular Login Pattern",
            "finding_info.desc": f"Login detected for {JAKE_PROFILE['email']} at 7:30 PM from {ATTACKER_PROFILE['ip']} - outside normal working hours (8 AM - 5 PM). Baseline deviation: 11.5 hours. Risk score: 85. MITRE ATT&CK: T1078 - Valid Accounts.",
            "severity_id": 4,
            "severity": "high",
        }
    },
    "data_exfiltration": {
        "template": "sharepoint_data_exfil_alert",
        "offset_minutes": 3,
        "overrides": {
            "finding_info.title": "HELIOS - Irregular Data Download Activity",
            "finding_info.desc": f"27 sensitive financial documents downloaded by {JAKE_PROFILE['email']} from {ATTACKER_PROFILE['ip']} ({ATTACKER_PROFILE['location']}) in 30 minutes - 15x normal daily average. Data volume: 4.2 GB. Sensitive data types: PII, Financial Records, Client Data. MITRE ATT&CK: T1530 - Data from Cloud Storage Object.",
            "severity_id": 5,
            "severity": "critical",
        }
    },
}


def load_alert_template(template_id: str) -> Optional[Dict]:
    """Load an alert template JSON from the templates directory"""
    candidate_dirs = [
        os.path.join(backend_dir, 'api', 'app', 'alerts', 'templates'),  # local dev
        os.path.join(backend_dir, 'app', 'alerts', 'templates'),          # Docker
    ]
    for templates_dir in candidate_dirs:
        template_path = os.path.join(templates_dir, f"{template_id}.json")
        if os.path.exists(template_path):
            with open(template_path, 'r') as f:
                return json.load(f)
    print(f"   ⚠️  Template not found: {template_id}.json (searched {candidate_dirs})")
    return None


def send_phase_alert(
    phase_name: str,
    alert_time: datetime,
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
    offset_time = alert_time + timedelta(minutes=mapping["offset_minutes"])
    time_ms = int(offset_time.timestamp() * 1000)

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

    # Set resource to Jake's email with a consistent GUID
    email_asset_uid = uam_config.get('email_asset_uid')
    if not email_asset_uid:
        email_asset_uid = str(uuid.uuid5(uuid.NAMESPACE_DNS, JAKE_PROFILE["email"]))
        uam_config['email_asset_uid'] = email_asset_uid
    alert["resources"] = [{
        "uid": email_asset_uid,
        "name": JAKE_PROFILE["email"]
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
            "S1-Trace-Id": "helios-ingest-uam:alwayslog",
        }

        payload = json.dumps(alert).encode("utf-8")
        gzipped = gzip.compress(payload)

        print(f"\n      📤 Alert Details:")
        print(f"         Template: {mapping['template']}")
        print(f"         Title: {alert.get('finding_info', {}).get('title', 'N/A')}")
        print(f"         User: {JAKE_PROFILE['email']}")
        print(f"         Time: {offset_time.isoformat()} ({time_ms}ms)")
        print(f"         URL: {ingest_url}")
        print(f"         Scope: {scope}")
        print(f"         Payload: {len(payload)} bytes -> {len(gzipped)} bytes (gzip)")

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


def get_scenario_time(base_time: datetime, day: int, hour: int, minute: int = 0, second: int = 0) -> str:
    """Calculate timestamp for scenario event"""
    event_time = base_time + timedelta(days=day, hours=hour, minutes=minute, seconds=second)
    return event_time.isoformat()

def create_event(timestamp: str, source: str, phase: str, event_data: dict) -> Dict:
    """Wrap event data with scenario metadata"""
    return {
        "timestamp": timestamp,
        "source": source,
        "phase": phase,
        "event": event_data
    }

def generate_normal_day_events(base_time: datetime, day: int) -> List[Dict]:
    """Generate Jake's normal daily activity for Days 1-7"""
    events = []
    
    # Morning login (8:30 AM)
    login_time = get_scenario_time(base_time, day, 8, 30)
    okta_login_str = okta_system_log()
    okta_login = json.loads(okta_login_str) if isinstance(okta_login_str, str) else okta_login_str
    # Customize for normal login and set published to scenario timestamp
    okta_login['published'] = login_time
    okta_login['eventType'] = 'user.session.start'
    okta_login['actor']['alternateId'] = JAKE_PROFILE['email']
    okta_login['actor']['displayName'] = JAKE_PROFILE['name']
    okta_login['client']['ipAddress'] = JAKE_PROFILE['normal_ip']
    okta_login['client']['geographicalContext']['city'] = 'Denver'
    okta_login['client']['geographicalContext']['state'] = 'Colorado'
    okta_login['client']['geographicalContext']['country'] = 'United States'
    okta_login['outcome']['result'] = 'SUCCESS'
    okta_login['outcome']['reason'] = 'User logged in successfully'
    okta_login['displayMessage'] = 'User successfully authenticated'
    okta_login['severity'] = 'INFO'
    
    events.append(create_event(login_time, "okta_ocsf_logs", "normal_behavior", okta_login))
    
    # Azure AD sign-in
    azuread_signin_str = azuread_log()
    azuread_signin = json.loads(azuread_signin_str) if isinstance(azuread_signin_str, str) else azuread_signin_str
    azuread_signin['initiatedByUserUserPrincipalName'] = JAKE_PROFILE['email']
    azuread_signin['initiatedByUserIpAddress'] = JAKE_PROFILE['normal_ip']
    azuread_signin['result'] = 'success'
    azuread_signin['activityDisplayName'] = 'User signed in'
    
    events.append(create_event(login_time, "microsoft_azuread", "normal_behavior", azuread_signin))
    
    # Regular M365 file access throughout the day (9 AM - 5 PM)
    file_access_times = [9, 10, 11, 14, 15, 16]  # Various times during workday
    file_names = [
        "Q4_Financial_Report.xlsx",
        "Client_Portfolio_Analysis.xlsx",
        "Monthly_Budget_Summary.xlsx",
        "Revenue_Forecast.xlsx",
        "Expense_Report.xlsx"
    ]
    
    for i, hour in enumerate(file_access_times):
        file_time = get_scenario_time(base_time, day, hour, 15)
        m365_event_str = microsoft_365_collaboration_log()
        m365_event = json.loads(m365_event_str) if isinstance(m365_event_str, str) else m365_event_str
        
        filename = file_names[i % len(file_names)]
        file_path = f"/Finance Department/Reports/{filename}"
        file_size = random.randint(50000, 500000)  # 50KB - 500KB
        
        m365_event['TimeStamp'] = file_time
        m365_event['UserId'] = JAKE_PROFILE['email']
        m365_event['ClientIP'] = JAKE_PROFILE['normal_ip']
        m365_event['Operation'] = 'FileAccessed'
        m365_event['ObjectId'] = file_path
        m365_event['FileName'] = filename
        m365_event['FileSize'] = file_size
        m365_event['Workload'] = 'SharePoint'
        m365_event['RecordType'] = 6  # SharePoint file operations
        m365_event['SiteUrl'] = 'https://securatech.sharepoint.com/sites/Finance'
        m365_event['TargetUser'] = JAKE_PROFILE['email']  # Maps to user.email_addr for queries
        m365_event['EventType'] = 'Audit.SharePoint'  # Maps to event.type
        # Remove unrealistic fields
        m365_event.pop('Details', None)
        m365_event.pop('RequestedBy', None)
        m365_event.pop('ThreatIndicator', None)
        
        events.append(create_event(file_time, "microsoft_365_collaboration", "normal_behavior", m365_event))
    
    return events

def generate_mfa_fatigue_attack(base_time: datetime) -> List[Dict]:
    """Generate Day 8 MFA fatigue attack events"""
    events = []
    day = 7  # Day 8 (0-indexed)
    
    print(f"🚨 Day 8 - MFA Fatigue Attack from Russia")
    print(f"   Attacker IP: {ATTACKER_PROFILE['ip']}")
    print(f"   Location: {ATTACKER_PROFILE['location']}")
    
    # IMPOSSIBLE TRAVELER: Normal Denver login at 7:00 PM
    denver_login_time = get_scenario_time(base_time, day, 19, 0)  # 7:00 PM
    okta_denver_str = okta_system_log()
    okta_denver = json.loads(okta_denver_str) if isinstance(okta_denver_str, str) else okta_denver_str
    okta_denver['published'] = denver_login_time
    okta_denver['eventType'] = 'user.session.start'
    okta_denver['actor']['alternateId'] = JAKE_PROFILE['email']
    okta_denver['actor']['displayName'] = JAKE_PROFILE['name']
    okta_denver['client']['ipAddress'] = JAKE_PROFILE['normal_ip']
    okta_denver['client']['geographicalContext']['city'] = 'Denver'
    okta_denver['client']['geographicalContext']['state'] = 'Colorado'
    okta_denver['client']['geographicalContext']['country'] = 'United States'
    okta_denver['outcome']['result'] = 'SUCCESS'
    okta_denver['outcome']['reason'] = 'User logged in successfully'
    okta_denver['displayMessage'] = 'Evening login from Denver office'
    okta_denver['severity'] = 'INFO'
    
    events.append(create_event(denver_login_time, "okta_ocsf_logs", "normal_behavior", okta_denver))
    
    # Azure AD sign-in from Denver at 7:00 PM
    azuread_denver_str = azuread_log()
    azuread_denver = json.loads(azuread_denver_str) if isinstance(azuread_denver_str, str) else azuread_denver_str
    azuread_denver['initiatedByUserUserPrincipalName'] = JAKE_PROFILE['email']
    azuread_denver['initiatedByUserIpAddress'] = JAKE_PROFILE['normal_ip']
    azuread_denver['result'] = 'success'
    azuread_denver['activityDisplayName'] = 'User signed in'
    
    events.append(create_event(denver_login_time, "microsoft_azuread", "normal_behavior", azuread_denver))
    print(f"   ✓ Normal Denver login at 7:00 PM (Okta + Azure AD)")
    
    # Attack starts at 7:30 PM (30 minutes later from Moscow - IMPOSSIBLE!)
    attack_start_hour = 19  # 7 PM
    attack_start_minute = 30
    print(f"   ⚠️  IMPOSSIBLE TRAVELER: Moscow login 30 minutes after Denver (~5,000 miles)")
    
    # Generate 15 failed MFA attempts (MFA Fatigue)
    for i in range(15):
        attempt_time = get_scenario_time(base_time, day, attack_start_hour, attack_start_minute + i)
        
        # Failed Okta MFA attempt
        okta_mfa_str = okta_system_log()
        okta_mfa = json.loads(okta_mfa_str) if isinstance(okta_mfa_str, str) else okta_mfa_str
        okta_mfa['published'] = attempt_time
        okta_mfa['eventType'] = 'user.mfa.challenge'
        okta_mfa['actor']['alternateId'] = JAKE_PROFILE['email']
        okta_mfa['actor']['displayName'] = JAKE_PROFILE['name']
        okta_mfa['client']['ipAddress'] = ATTACKER_PROFILE['ip']
        okta_mfa['client']['geographicalContext']['city'] = 'Moscow'
        okta_mfa['client']['geographicalContext']['state'] = 'Moscow'
        okta_mfa['client']['geographicalContext']['country'] = 'Russia'
        okta_mfa['outcome']['result'] = 'FAILURE'
        okta_mfa['outcome']['reason'] = 'User rejected MFA push notification'
        okta_mfa['displayMessage'] = f'MFA push request #{i+1} - Waiting for user approval'
        okta_mfa['severity'] = 'WARN'
        
        events.append(create_event(attempt_time, "okta_ocsf_logs", "mfa_fatigue", okta_mfa))
    
    # User accepts MFA (attempt #14)
    accept_time = get_scenario_time(base_time, day, attack_start_hour, attack_start_minute + 14)
    okta_success_str = okta_system_log()
    okta_success = json.loads(okta_success_str) if isinstance(okta_success_str, str) else okta_success_str
    okta_success['published'] = accept_time
    okta_success['eventType'] = 'user.mfa.challenge'
    okta_success['actor']['alternateId'] = JAKE_PROFILE['email']
    okta_success['actor']['displayName'] = JAKE_PROFILE['name']
    okta_success['client']['ipAddress'] = ATTACKER_PROFILE['ip']
    okta_success['client']['geographicalContext']['city'] = 'Moscow'
    okta_success['client']['geographicalContext']['state'] = 'Moscow'
    okta_success['client']['geographicalContext']['country'] = 'Russia'
    okta_success['outcome']['result'] = 'SUCCESS'
    okta_success['outcome']['reason'] = 'MFA challenge passed'
    okta_success['displayMessage'] = 'User approved MFA push - Access granted'
    okta_success['severity'] = 'INFO'
    
    events.append(create_event(accept_time, "okta_ocsf_logs", "initial_access", okta_success))
    
    # Session start immediately after successful MFA (30 seconds later)
    session_time = get_scenario_time(base_time, day, attack_start_hour, attack_start_minute + 14, 30)
    okta_session_str = okta_system_log()
    okta_session = json.loads(okta_session_str) if isinstance(okta_session_str, str) else okta_session_str
    okta_session['published'] = session_time
    okta_session['eventType'] = 'user.session.start'
    okta_session['actor']['alternateId'] = JAKE_PROFILE['email']
    okta_session['actor']['displayName'] = JAKE_PROFILE['name']
    okta_session['client']['ipAddress'] = ATTACKER_PROFILE['ip']
    okta_session['client']['geographicalContext']['city'] = 'Moscow'
    okta_session['client']['geographicalContext']['state'] = 'Moscow'
    okta_session['client']['geographicalContext']['country'] = 'Russia'
    okta_session['outcome']['result'] = 'SUCCESS'
    okta_session['outcome']['reason'] = 'Session started'
    okta_session['displayMessage'] = 'Session established after MFA'
    okta_session['severity'] = 'INFO'
    
    events.append(create_event(session_time, "okta_ocsf_logs", "initial_access", okta_session))
    print(f"   ✓ MFA accepted after 15 attempts")
    
    # Attacker tries to access Okta Admin Console - BLOCKED (1 minute later)
    admin_attempt_time = get_scenario_time(base_time, day, attack_start_hour, attack_start_minute + 15, 30)
    okta_admin_str = okta_system_log()
    okta_admin = json.loads(okta_admin_str) if isinstance(okta_admin_str, str) else okta_admin_str
    okta_admin['published'] = admin_attempt_time
    okta_admin['eventType'] = 'user.session.access_admin_app'
    okta_admin['legacyEventType'] = 'user.session.access_admin_app'
    okta_admin['actor']['alternateId'] = JAKE_PROFILE['email']
    okta_admin['actor']['displayName'] = JAKE_PROFILE['name']
    okta_admin['client']['ipAddress'] = ATTACKER_PROFILE['ip']
    okta_admin['client']['geographicalContext']['city'] = 'Moscow'
    okta_admin['client']['geographicalContext']['state'] = 'Moscow'
    okta_admin['client']['geographicalContext']['country'] = 'Russia'
    okta_admin['outcome']['result'] = 'FAILURE'
    okta_admin['outcome']['reason'] = 'Insufficient permissions to access admin console'
    okta_admin['displayMessage'] = 'User attempted to access Okta admin console but was denied'
    okta_admin['severity'] = 'WARN'
    
    events.append(create_event(admin_attempt_time, "okta_ocsf_logs", "initial_access", okta_admin))
    print(f"   ✓ Failed attempt to access Okta admin console from Moscow")
    
    # Azure AD sign-in from Russia
    azuread_russia_str = azuread_log()
    azuread_russia = json.loads(azuread_russia_str) if isinstance(azuread_russia_str, str) else azuread_russia_str
    azuread_russia['initiatedByUserUserPrincipalName'] = JAKE_PROFILE['email']
    azuread_russia['initiatedByUserIpAddress'] = ATTACKER_PROFILE['ip']
    azuread_russia['result'] = 'success'
    azuread_russia['activityDisplayName'] = 'User signed in'
    azuread_russia['unmapped.location'] = 'Moscow, Russia'
    azuread_russia['unmapped.riskDetail'] = 'unfamiliarLocation'
    
    events.append(create_event(accept_time, "microsoft_azuread", "initial_access", azuread_russia))
    print(f"   ✓ Azure AD sign-in from Russia successful")
    
    return events

def generate_data_exfiltration(base_time: datetime) -> List[Dict]:
    """Generate OneDrive file access and data exfiltration events"""
    events = []
    day = 7  # Day 8
    
    # Exfiltration starts immediately after successful login (7:45 PM)
    exfil_start_hour = 19
    exfil_start_minute = 45
    
    print(f"📂 Data Exfiltration - 27 Files Downloaded")
    
    # Sensitive finance files accessed and downloaded
    sensitive_files = [
        "Client_Financial_Statements_Q4.pdf",
        "Investment_Portfolio_Analysis.xlsx",
        "Client_Master_List.xlsx",
        "Personal_Financial_Records.xlsx",
        "Q4_Revenue_Projection.xlsx",
        "Internal_Budget_2024.xlsx",
        "Client_Investment_Strategy.docx",
        "Acquisition_Financial_Model.xlsx",
        "Executive_Compensation_Report.xlsx",
        "Merger_Analysis_Confidential.xlsx",
        "Client_SSN_Tax_Records.xlsx",
        "Banking_Account_Details.xlsx",
        "Wire_Transfer_Instructions.xlsx",
        "Offshore_Accounts_Summary.xlsx",
        "Insider_Trading_Compliance.xlsx",
        "Board_Meeting_Financials.pdf",
        "Shareholder_Distribution.xlsx",
        "Crypto_Holdings_Report.xlsx",
        "Trust_Fund_Allocations.xlsx",
        "Estate_Planning_Documents.pdf",
        "High_Net_Worth_Clients.xlsx",
        "Private_Equity_Deals.xlsx",
        "Hedge_Fund_Positions.xlsx",
        "Risk_Assessment_Internal.xlsx",
        "Regulatory_Filing_Draft.xlsx",
        "Audit_Findings_Confidential.pdf",
        "Forensic_Accounting_Report.xlsx"
    ]
    
    for i, filename in enumerate(sensitive_files):
        # File accessed
        access_time = get_scenario_time(base_time, day, exfil_start_hour, exfil_start_minute + i)
        m365_access_str = microsoft_365_collaboration_log()
        m365_access = json.loads(m365_access_str) if isinstance(m365_access_str, str) else m365_access_str
        file_path = f"/Finance Department/Confidential/{filename}"
        file_size = random.randint(100000, 5000000)  # 100KB - 5MB for sensitive files
        
        m365_access['TimeStamp'] = access_time
        m365_access['UserId'] = JAKE_PROFILE['email']
        m365_access['ClientIP'] = ATTACKER_PROFILE['ip']
        m365_access['Operation'] = 'FileAccessed'
        m365_access['ObjectId'] = file_path
        m365_access['FileName'] = filename
        m365_access['FileSize'] = file_size
        m365_access['Workload'] = 'SharePoint'
        m365_access['RecordType'] = 6  # SharePoint file operations
        m365_access['SiteUrl'] = 'https://securatech.sharepoint.com/sites/Finance'
        m365_access['TargetUser'] = JAKE_PROFILE['email']  # Maps to user.email_addr for queries
        m365_access['EventType'] = 'Audit.SharePoint'  # Maps to event.type
        m365_access['UserAgent'] = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Automated Download'
        # Remove unrealistic fields
        m365_access.pop('Details', None)
        m365_access.pop('RequestedBy', None)
        m365_access.pop('ThreatIndicator', None)
        
        events.append(create_event(access_time, "microsoft_365_collaboration", "data_exfiltration", m365_access))
        
        # File downloaded (30 seconds later)
        download_time = get_scenario_time(base_time, day, exfil_start_hour, exfil_start_minute + i, 30)
        m365_download_str = microsoft_365_collaboration_log()
        m365_download = json.loads(m365_download_str) if isinstance(m365_download_str, str) else m365_download_str
        
        m365_download['TimeStamp'] = download_time
        m365_download['UserId'] = JAKE_PROFILE['email']
        m365_download['ClientIP'] = ATTACKER_PROFILE['ip']
        m365_download['Operation'] = 'FileDownloaded'
        m365_download['ObjectId'] = file_path
        m365_download['FileName'] = filename
        m365_download['FileSize'] = file_size
        m365_download['Workload'] = 'SharePoint'
        m365_download['RecordType'] = 6  # SharePoint file operations
        m365_download['SiteUrl'] = 'https://securatech.sharepoint.com/sites/Finance'
        m365_download['TargetUser'] = JAKE_PROFILE['email']  # Maps to user.email_addr for queries
        m365_download['EventType'] = 'Audit.SharePoint'  # Maps to event.type
        # Remove unrealistic fields
        m365_download.pop('Details', None)
        m365_download.pop('RequestedBy', None)
        m365_download.pop('ThreatIndicator', None)
        
        events.append(create_event(download_time, "microsoft_365_collaboration", "data_exfiltration", m365_download))
    
    print(f"   ✓ {len(sensitive_files)} sensitive files accessed and downloaded")
    
    # Attacker downloads RDP files for persistent access (8:15 PM - 8:17 PM)
    rdp_files = [
        "FinanceServer01.rdp",
        "TreasurySystem.rdp", 
        "ERPDatabase.rdp"
    ]
    
    print(f"🔑 Attacker downloading RDP files for persistent access")
    for i, rdp_file in enumerate(rdp_files):
        # File accessed
        rdp_access_time = get_scenario_time(base_time, day, 20, 15 + i)
        m365_rdp_access_str = microsoft_365_collaboration_log()
        m365_rdp_access = json.loads(m365_rdp_access_str) if isinstance(m365_rdp_access_str, str) else m365_rdp_access_str
        
        rdp_path = f"/Finance Department/Remote Access/{rdp_file}"
        rdp_size = random.randint(2000, 5000)
        
        m365_rdp_access['TimeStamp'] = rdp_access_time
        m365_rdp_access['UserId'] = JAKE_PROFILE['email']
        m365_rdp_access['ClientIP'] = ATTACKER_PROFILE['ip']  # Moscow IP
        m365_rdp_access['Operation'] = 'FileAccessed'
        m365_rdp_access['ObjectId'] = rdp_path
        m365_rdp_access['FileName'] = rdp_file
        m365_rdp_access['FileSize'] = rdp_size
        m365_rdp_access['SourceFileExtension'] = 'rdp'  # Critical for detection
        m365_rdp_access['Workload'] = 'SharePoint'
        m365_rdp_access['RecordType'] = 6
        m365_rdp_access['SiteUrl'] = 'https://securatech.sharepoint.com/sites/Finance'
        m365_rdp_access['TargetUser'] = JAKE_PROFILE['email']
        m365_rdp_access['EventType'] = 'Audit.SharePoint'
        m365_rdp_access['UserAgent'] = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Automated Download'
        m365_rdp_access.pop('Details', None)
        m365_rdp_access.pop('RequestedBy', None)
        m365_rdp_access.pop('ThreatIndicator', None)
        
        events.append(create_event(rdp_access_time, "microsoft_365_collaboration", "data_exfiltration", m365_rdp_access))
        
        # File downloaded
        rdp_download_time = get_scenario_time(base_time, day, 20, 15 + i, 30)
        m365_rdp_download_str = microsoft_365_collaboration_log()
        m365_rdp_download = json.loads(m365_rdp_download_str) if isinstance(m365_rdp_download_str, str) else m365_rdp_download_str
        
        m365_rdp_download['TimeStamp'] = rdp_download_time
        m365_rdp_download['UserId'] = JAKE_PROFILE['email']
        m365_rdp_download['ClientIP'] = ATTACKER_PROFILE['ip']  # Moscow IP
        m365_rdp_download['Operation'] = 'FileDownloaded'
        m365_rdp_download['ObjectId'] = rdp_path
        m365_rdp_download['FileName'] = rdp_file
        m365_rdp_download['FileSize'] = rdp_size
        m365_rdp_download['SourceFileExtension'] = 'rdp'  # Critical for detection
        m365_rdp_download['Workload'] = 'SharePoint'
        m365_rdp_download['RecordType'] = 6
        m365_rdp_download['SiteUrl'] = 'https://securatech.sharepoint.com/sites/Finance'
        m365_rdp_download['TargetUser'] = JAKE_PROFILE['email']
        m365_rdp_download['EventType'] = 'Audit.SharePoint'
        m365_rdp_download.pop('Details', None)
        m365_rdp_download.pop('RequestedBy', None)
        m365_rdp_download.pop('ThreatIndicator', None)
        
        events.append(create_event(rdp_download_time, "microsoft_365_collaboration", "data_exfiltration", m365_rdp_download))
    
    print(f"   ✓ {len(rdp_files)} RDP files downloaded from Moscow IP")
    
    return events

def generate_soar_detections(base_time: datetime) -> List[Dict]:
    """Generate SOAR detection and response alerts"""
    events = []
    day = 7  # Day 8
    
    # SOAR detections trigger 2 minutes after exfiltration starts
    detection_hour = 20  # 8:00 PM
    detection_minute = 15
    
    print(f"🔔 SOAR Automated Detection and Response")
    
    # Alert 1: Okta MFA Fatigue Detection
    mfa_fatigue_alert = {
        "alert_id": "SOAR-2024-0122-001",
        "alert_name": "Okta MFA Fatigue Attack Detected",
        "severity": "HIGH",
        "user": JAKE_PROFILE['email'],
        "description": "15 consecutive MFA push requests detected within 15 minutes, followed by acceptance",
        "source_ip": ATTACKER_PROFILE['ip'],
        "detection_method": "Behavioral Analytics",
        "recommended_action": "Lock account and initiate credential reset",
        "mitre_technique": "T1621 - Multi-Factor Authentication Request Generation"
    }
    
    alert_time = get_scenario_time(base_time, day, detection_hour, detection_minute)
    events.append(create_event(alert_time, "soar_alert", "detection", mfa_fatigue_alert))
    print(f"   ✓ MFA Fatigue Alert generated")
    
    # Alert 2: Impossible Traveler Detection
    impossible_traveler_alert = {
        "alert_id": "SOAR-2024-0122-002",
        "alert_name": "Okta Impossible Traveler Detected",
        "severity": "CRITICAL",
        "user": JAKE_PROFILE['email'],
        "description": f"Login from Moscow, Russia while user has no recent travel. Last login was from Denver 12 hours ago.",
        "source_ip": ATTACKER_PROFILE['ip'],
        "ip_reputation": "Malicious - Flagged by VirusTotal (5/68 vendors)",
        "geographic_anomaly": "8,000+ miles from last known location",
        "detection_method": "Geolocation Analysis",
        "recommended_action": "Immediate account lockout",
        "mitre_technique": "T1078 - Valid Accounts"
    }
    
    alert_time2 = get_scenario_time(base_time, day, detection_hour, detection_minute + 1)
    events.append(create_event(alert_time2, "soar_alert", "detection", impossible_traveler_alert))
    print(f"   ✓ Impossible Traveler Alert generated")
    
    # Alert 3: UEBA Irregular Login
    ueba_login_alert = {
        "alert_id": "SOAR-2024-0122-003",
        "alert_name": "UEBA Irregular Login Pattern",
        "severity": "HIGH",
        "user": JAKE_PROFILE['email'],
        "description": "Login detected at 7:30 PM - outside normal working hours (8 AM - 5 PM)",
        "source_ip": ATTACKER_PROFILE['ip'],
        "baseline_deviation": "11.5 hours outside normal login window",
        "risk_score": 85,
        "detection_method": "User and Entity Behavior Analytics (UEBA)",
        "recommended_action": "Require additional verification",
        "mitre_technique": "T1078 - Valid Accounts"
    }
    
    alert_time3 = get_scenario_time(base_time, day, detection_hour, detection_minute + 2)
    events.append(create_event(alert_time3, "soar_alert", "detection", ueba_login_alert))
    print(f"   ✓ UEBA Irregular Login Alert generated")
    
    # Alert 4: UEBA Irregular Data Downloads
    ueba_download_alert = {
        "alert_id": "SOAR-2024-0122-004",
        "alert_name": "UEBA Irregular Data Download Activity",
        "severity": "CRITICAL",
        "user": JAKE_PROFILE['email'],
        "description": "27 sensitive financial documents downloaded in 30 minutes - 15x normal daily average",
        "source_ip": ATTACKER_PROFILE['ip'],
        "files_accessed": 27,
        "data_volume": "4.2 GB",
        "baseline_deviation": "1,500% increase from normal daily activity",
        "risk_score": 95,
        "sensitive_data_types": ["PII", "Financial Records", "Client Data", "Confidential Reports"],
        "detection_method": "Data Loss Prevention + UEBA",
        "recommended_action": "Immediate account lockout and forensic investigation",
        "mitre_technique": "T1530 - Data from Cloud Storage Object"
    }
    
    alert_time4 = get_scenario_time(base_time, day, detection_hour, detection_minute + 3)
    events.append(create_event(alert_time4, "soar_alert", "detection", ueba_download_alert))
    print(f"   ✓ UEBA Irregular Data Download Alert generated")
    
    # SOAR Automated Response Actions
    response_actions = [
        {
            "action_id": "SOAR-ACTION-001",
            "action_type": "Account Lockout",
            "user": JAKE_PROFILE['email'],
            "status": "SUCCESS",
            "timestamp": get_scenario_time(base_time, day, detection_hour, detection_minute + 5),
            "description": "User account locked via Okta API",
            "automated": True
        },
        {
            "action_id": "SOAR-ACTION-002",
            "action_type": "Password Reset Initiated",
            "user": JAKE_PROFILE['email'],
            "status": "PENDING",
            "timestamp": get_scenario_time(base_time, day, detection_hour, detection_minute + 5, 30),
            "description": "Password reset email sent to verified secondary contact",
            "automated": True
        },
        {
            "action_id": "SOAR-ACTION-003",
            "action_type": "Security Team Notification",
            "recipients": ["soc@securatech.com", "ciso@securatech.com"],
            "status": "SUCCESS",
            "timestamp": get_scenario_time(base_time, day, detection_hour, detection_minute + 6),
            "description": "High-priority incident ticket created - IR-2024-0122",
            "automated": True
        },
        {
            "action_id": "SOAR-ACTION-004",
            "action_type": "User Notification",
            "user": JAKE_PROFILE['email'],
            "status": "SUCCESS",
            "timestamp": get_scenario_time(base_time, day, detection_hour, detection_minute + 6, 30),
            "description": "SMS and email sent to user about suspicious activity",
            "automated": True
        }
    ]
    
    for action in response_actions:
        events.append(create_event(action['timestamp'], "soar_response", "incident_response", action))
    
    print(f"   ✓ {len(response_actions)} automated response actions executed")
    
    return events

def generate_finance_mfa_fatigue_scenario():
    """
    Main function to generate the complete Finance MFA Fatigue scenario
    """
    print("=" * 80)
    print("🎯 FINANCE EMPLOYEE MFA FATIGUE ATTACK SCENARIO")
    print("=" * 80)
    print(f"User: {JAKE_PROFILE['name']} ({JAKE_PROFILE['email']})")
    print(f"Department: {JAKE_PROFILE['department']}")
    print(f"Location: {JAKE_PROFILE['location']}")
    print("=" * 80)
    
    # Start scenario 8 days ago
    base_time = datetime.now(timezone.utc) - timedelta(days=8)
    
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
            if uam_site_id:
                print(f"   Site ID: {uam_site_id}")
            print("=" * 80)
        else:
            print("⚠️  SCENARIO_ALERTS_ENABLED=true but UAM credentials missing")
            alerts_enabled = False
    
    all_events = []
    
    # Phase 1: Normal Behavior Baseline (Days 1-7)
    print("\n📊 PHASE 1: Normal Behavior Baseline (Days 1-7)")
    print("-" * 80)
    for day in range(7):
        print(f"Day {day + 1}: {(base_time + timedelta(days=day)).strftime('%Y-%m-%d')}")
        day_events = generate_normal_day_events(base_time, day)
        all_events.extend(day_events)
        print(f"   ✓ Generated {len(day_events)} normal activity events")
    
    print(f"\nTotal normal behavior events: {len(all_events)}")
    
    # Phase 2: MFA Fatigue Attack (Day 8)
    print("\n" + "=" * 80)
    print("🚨 PHASE 2: MFA Fatigue Attack (Day 8)")
    print("-" * 80)
    attack_events = generate_mfa_fatigue_attack(base_time)
    all_events.extend(attack_events)
    print(f"\nTotal attack events: {len(attack_events)}")
    
    # Phase 3: Data Exfiltration (Day 8)
    print("\n" + "=" * 80)
    print("📂 PHASE 3: Data Exfiltration (Day 8)")
    print("-" * 80)
    exfil_events = generate_data_exfiltration(base_time)
    all_events.extend(exfil_events)
    print(f"\nTotal exfiltration events: {len(exfil_events)}")
    
    # Phase 4: SOAR Detection and Response (Day 8)
    print("\n" + "=" * 80)
    print("🔔 PHASE 4: SOAR Detection and Response (Day 8)")
    print("-" * 80)
    detection_events = generate_soar_detections(base_time)
    all_events.extend(detection_events)
    print(f"\nTotal detection/response events: {len(detection_events)}")
    
    # Send UAM alerts for each detection phase
    if alerts_enabled and uam_config:
        # Detection time = Day 8, 8:15 PM (same as SOAR detections)
        detection_time = base_time + timedelta(days=7, hours=20, minutes=15)
        print(f"\n🔔 SENDING UAM ALERTS")
        alert_phases = [
            ("mfa_fatigue", "MFA Fatigue Attack"),
            ("impossible_traveler", "Impossible Traveler"),
            ("ueba_irregular_login", "UEBA Irregular Login"),
            ("data_exfiltration", "Data Exfiltration"),
        ]
        for alert_key, alert_desc in alert_phases:
            print(f"   📤 {alert_desc}...", end=" ")
            success = send_phase_alert(alert_key, detection_time, uam_config)
            print(f"{'✓' if success else '✗'}")
    
    # Sort all events by timestamp
    all_events.sort(key=lambda x: x['timestamp'])
    
    # Create scenario summary
    scenario_summary = {
        "scenario_name": "Finance Employee MFA Fatigue Attack",
        "user_profile": JAKE_PROFILE,
        "attacker_profile": ATTACKER_PROFILE,
        "timeline_start": base_time.isoformat(),
        "timeline_end": (base_time + timedelta(days=8)).isoformat(),
        "total_events": len(all_events),
        "phases": [
            {"name": "Normal Behavior Baseline", "days": "1-7", "events": len([e for e in all_events if e['phase'] == 'normal_behavior'])},
            {"name": "MFA Fatigue Attack", "day": "8", "events": len([e for e in all_events if e['phase'] == 'mfa_fatigue'])},
            {"name": "Initial Access", "day": "8", "events": len([e for e in all_events if e['phase'] == 'initial_access'])},
            {"name": "Data Exfiltration", "day": "8", "events": len([e for e in all_events if e['phase'] == 'data_exfiltration'])},
            {"name": "Detection & Response", "day": "8", "events": len([e for e in all_events if e['phase'] in ['detection', 'incident_response']])}
        ],
        "detections": [
            "Okta MFA Fatigue Attack",
            "Okta Impossible Traveler",
            "UEBA Irregular Login Pattern",
            "UEBA Irregular Data Downloads"
        ],
        "mitre_techniques": [
            "T1621 - Multi-Factor Authentication Request Generation",
            "T1078 - Valid Accounts",
            "T1530 - Data from Cloud Storage Object"
        ],
        "events": all_events
    }
    
    print("\n" + "=" * 80)
    print("✅ SCENARIO GENERATION COMPLETE")
    print("=" * 80)
    print(f"Total Events: {len(all_events)}")
    print(f"Data Sources: Okta, Azure AD, Microsoft 365, SOAR")
    print(f"Timeline: {(base_time).strftime('%Y-%m-%d')} to {(base_time + timedelta(days=8)).strftime('%Y-%m-%d')}")
    print("=" * 80)
    
    return scenario_summary

if __name__ == "__main__":
    # Generate the scenario
    scenario = generate_finance_mfa_fatigue_scenario()

    # Save to JSON file with container-safe fallbacks
    preferred_dir = os.environ.get("SCENARIO_OUTPUT_DIR") or os.path.join(os.path.dirname(__file__), "configs")
    output_file = os.path.join(preferred_dir, "finance_mfa_fatigue_scenario.json")

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
        # Fallback to Docker's writable data mount if available
        fallback_dir = os.environ.get("SCENARIO_OUTPUT_DIR", "/app/data/scenarios/configs")
        fallback_path = os.path.join(fallback_dir, "finance_mfa_fatigue_scenario.json")
        if not _attempt_save(fallback_path):
            # As a last resort, skip saving but exit successfully (the scenario already printed to stdout)
            print("ℹ️  Skipping file save due to filesystem restrictions. Scenario generation completed successfully.")
