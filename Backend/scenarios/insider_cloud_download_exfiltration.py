#!/usr/bin/env python3
"""
Insider Data Exfiltration via Cloud Download Scenario
======================================================

Scenario: Insider Threat - Large-Scale Cloud Data Exfiltration

Timeline:
- Days 1-7: Normal user behavior baseline
- Day 8: Unusual large-volume downloads from Microsoft 365/SharePoint
- Day 8 (Post-download): Files copied to removable USB storage
- Day 8 (Post-incident): Automated detection alerts

Attack Chain:
1. Insider accesses M365/SharePoint during off-hours
2. Downloads 180+ sensitive files (excluding benign system files)
3. Files include financial data, client records, PII
4. DLP classifies files as Confidential/Restricted
5. EDR detects subsequent file writes to USB removable media
6. SIEM generates insider threat alerts

Detections Generated:
- Unusual Data Download Volume Alert
- Sensitive File Download Alert (DLP)
- Off-Hours Access Pattern Alert
- Removable Media Write Alert (EDR)
- Insider Threat Risk Score Elevation
"""

import json
import sys
import os
import errno
import random
from datetime import datetime, timezone, timedelta
from typing import Dict, List

# Add event_generators to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'event_generators'))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'event_generators', 'identity_access'))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'event_generators', 'endpoint_security'))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'event_generators', 'email_security'))

# Import generators
from okta_authentication import okta_authentication_log
from microsoft_365_collaboration import microsoft_365_collaboration_log
from sentinelone_endpoint import sentinelone_endpoint_log
from proofpoint import proofpoint_log

# Insider User Profile
INSIDER_PROFILE = {
    "name": "Sarah Martinez",
    "email": "sarah.martinez@securatech.com",
    "department": "Finance",
    "role": "Senior Financial Analyst",
    "location": "Boston, Massachusetts",
    "normal_ip": "198.51.100.85",
    "home_ip": "73.162.45.128",
    "work_hours_start": 8,
    "work_hours_end": 17,
    "endpoint_name": "WS-305",
    "endpoint_os": "Windows 11"
}

# Sensitive file categories with realistic names
SENSITIVE_FILES = {
    "financial": [
        "Q4_Financial_Statements_2024.xlsx",
        "Annual_Revenue_Report.xlsx",
        "Client_Billing_Records.xlsx",
        "Investment_Portfolio_Summary.xlsx",
        "Merger_Acquisition_Financials.pdf",
        "Executive_Compensation_Details.xlsx",
        "Banking_Account_Information.xlsx",
        "Wire_Transfer_Records.xlsx",
        "Tax_Filing_Documents.pdf",
        "Audit_Results_Confidential.xlsx",
        "Budget_Allocation_2025.xlsx",
        "Profit_Loss_Statements.xlsx",
        "Cash_Flow_Analysis.xlsx",
        "Revenue_Projections_Q1.xlsx",
        "Expense_Reports_Executive.xlsx",
        "Financial_Forecast_Model.xlsx",
        "Capital_Expenditure_Plans.xlsx",
        "Debt_Schedule_Analysis.xlsx",
        "Asset_Valuation_Report.xlsx",
        "Treasury_Management_Data.xlsx"
    ],
    "client_data": [
        "Client_Master_List.xlsx",
        "Client_Contact_Database.xlsx",
        "High_Net_Worth_Clients.xlsx",
        "Client_SSN_Records.xlsx",
        "Client_Account_Numbers.xlsx",
        "Personal_Financial_Data.xlsx",
        "Client_Investment_Strategies.docx",
        "Client_Risk_Profiles.xlsx",
        "Client_Meeting_Notes.docx",
        "Client_Relationship_History.xlsx",
        "Prospect_Pipeline_Data.xlsx",
        "Client_Service_Agreements.pdf",
        "Client_Confidential_Correspondence.pdf",
        "Trust_Account_Details.xlsx",
        "Estate_Planning_Documents.pdf",
        "Client_Tax_Returns.pdf",
        "Insurance_Policy_Data.xlsx",
        "Beneficiary_Information.xlsx",
        "Power_of_Attorney_Records.pdf",
        "Client_Healthcare_Directives.pdf"
    ],
    "corporate": [
        "Board_Meeting_Minutes.pdf",
        "Executive_Strategy_Documents.docx",
        "Company_Acquisition_Targets.xlsx",
        "Competitive_Intelligence.docx",
        "Product_Roadmap_Confidential.pptx",
        "Merger_Due_Diligence.pdf",
        "Partnership_Agreements.pdf",
        "Intellectual_Property_Assets.xlsx",
        "Legal_Settlement_Details.pdf",
        "Regulatory_Filing_Drafts.pdf",
        "Internal_Investigation_Reports.pdf",
        "Employee_Compensation_Data.xlsx",
        "Severance_Package_Details.xlsx",
        "Organizational_Restructure_Plan.docx",
        "Confidential_HR_Records.xlsx",
        "Performance_Review_Data.xlsx",
        "Executive_Succession_Plan.docx",
        "Crisis_Management_Procedures.pdf",
        "Security_Incident_Reports.pdf",
        "Vendor_Contract_Terms.pdf"
    ],
    "research": [
        "Market_Research_Analysis.xlsx",
        "Customer_Survey_Results.xlsx",
        "Proprietary_Algorithm_Documentation.pdf",
        "Trade_Secret_Formulas.xlsx",
        "Research_Development_Data.xlsx",
        "Patent_Application_Drafts.pdf",
        "Competitive_Pricing_Analysis.xlsx",
        "Product_Testing_Results.xlsx",
        "Innovation_Pipeline.xlsx",
        "Strategic_Initiative_Plans.docx"
    ],
    "compliance": [
        "Regulatory_Compliance_Audit.pdf",
        "Internal_Controls_Assessment.xlsx",
        "Risk_Management_Framework.pdf",
        "Compliance_Violation_Reports.pdf",
        "Whistleblower_Complaints.pdf",
        "Investigation_Case_Files.pdf",
        "Sanctions_Screening_Results.xlsx",
        "AML_Transaction_Reports.xlsx",
        "SOX_Compliance_Documentation.pdf",
        "GDPR_Data_Mapping.xlsx"
    ]
}

# Benign system files to exclude from detection (normal operations)
BENIGN_SYSTEM_FILES = [
    ".tmp", ".cache", ".log", ".config", ".dat", ".ini",
    "~$", ".metadata", ".git", ".svn"
]

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

def is_benign_file(filename: str) -> bool:
    """Check if file matches benign system file patterns"""
    return any(pattern in filename.lower() for pattern in BENIGN_SYSTEM_FILES)

def generate_normal_day_events(base_time: datetime, day: int) -> List[Dict]:
    """Generate normal daily activity for Days 1-7"""
    events = []
    
    # Morning login (8:30 AM)
    login_time = get_scenario_time(base_time, day, 8, 30)
    okta_login_str = okta_authentication_log()
    okta_login = json.loads(okta_login_str) if isinstance(okta_login_str, str) else okta_login_str
    
    okta_login['published'] = login_time
    okta_login['eventType'] = 'user.session.start'
    okta_login['actor']['alternateId'] = INSIDER_PROFILE['email']
    okta_login['actor']['displayName'] = INSIDER_PROFILE['name']
    okta_login['client']['ipAddress'] = INSIDER_PROFILE['normal_ip']
    okta_login['client']['geographicalContext']['city'] = 'Boston'
    okta_login['client']['geographicalContext']['state'] = 'Massachusetts'
    okta_login['client']['geographicalContext']['country'] = 'United States'
    okta_login['outcome']['result'] = 'SUCCESS'
    okta_login['displayMessage'] = 'User successfully authenticated'
    okta_login['severity'] = 'INFO'
    
    events.append(create_event(login_time, "okta_authentication", "normal_behavior", okta_login))
    
    # Regular M365 file access throughout the day (normal operations)
    access_times = [9, 10, 11, 14, 15, 16]
    normal_files = [
        "Monthly_Status_Report.xlsx",
        "Team_Meeting_Agenda.docx",
        "Project_Timeline.xlsx",
        "Budget_Review.xlsx",
        "Quarterly_Presentation.pptx"
    ]
    
    for i, hour in enumerate(access_times):
        file_time = get_scenario_time(base_time, day, hour, random.randint(0, 45))
        m365_event = microsoft_365_collaboration_log()
        
        filename = normal_files[i % len(normal_files)]
        file_path = f"/Finance Department/Shared/{filename}"
        file_size = random.randint(50000, 500000)
        
        m365_event['TimeStamp'] = file_time
        m365_event['UserId'] = INSIDER_PROFILE['email']
        m365_event['ClientIP'] = INSIDER_PROFILE['normal_ip']
        m365_event['Operation'] = random.choice(['FileAccessed', 'FileViewed', 'FileModified'])
        m365_event['ObjectId'] = file_path
        m365_event['FileName'] = filename
        m365_event['FileSize'] = file_size
        m365_event['Workload'] = 'SharePoint'
        m365_event['RecordType'] = 6
        m365_event['SiteUrl'] = 'https://securatech.sharepoint.com/sites/Finance'
        m365_event['TargetUser'] = INSIDER_PROFILE['email']
        m365_event['EventType'] = 'Audit.SharePoint'
        m365_event.pop('Details', None)
        m365_event.pop('RequestedBy', None)
        m365_event.pop('ThreatIndicator', None)
        
        events.append(create_event(file_time, "microsoft_365_collaboration", "normal_behavior", m365_event))
    
    return events

def generate_exfiltration_downloads(base_time: datetime) -> List[Dict]:
    """Generate Day 8 large-volume download spike"""
    events = []
    day = 7
    
    print(f"📥 Day 8 - Large-Scale Data Exfiltration via Cloud Download")
    print(f"   User: {INSIDER_PROFILE['name']} ({INSIDER_PROFILE['email']})")
    print(f"   Source IP: {INSIDER_PROFILE['home_ip']} (Home/VPN)")
    
    # Off-hours login at 10:30 PM
    login_time = get_scenario_time(base_time, day, 22, 30)
    okta_offhours_str = okta_authentication_log()
    okta_offhours = json.loads(okta_offhours_str) if isinstance(okta_offhours_str, str) else okta_offhours_str
    
    okta_offhours['published'] = login_time
    okta_offhours['eventType'] = 'user.session.start'
    okta_offhours['actor']['alternateId'] = INSIDER_PROFILE['email']
    okta_offhours['actor']['displayName'] = INSIDER_PROFILE['name']
    okta_offhours['client']['ipAddress'] = INSIDER_PROFILE['home_ip']
    okta_offhours['client']['geographicalContext']['city'] = 'Boston'
    okta_offhours['client']['geographicalContext']['state'] = 'Massachusetts'
    okta_offhours['client']['geographicalContext']['country'] = 'United States'
    okta_offhours['outcome']['result'] = 'SUCCESS'
    okta_offhours['displayMessage'] = 'Off-hours login from home network'
    okta_offhours['severity'] = 'INFO'
    
    events.append(create_event(login_time, "okta_authentication", "off_hours_access", okta_offhours))
    print(f"   ✓ Off-hours login at 10:30 PM")
    
    # Massive download activity starts at 10:45 PM
    download_start_hour = 22
    download_start_minute = 45
    
    print(f"   📂 Starting bulk download of sensitive files...")
    
    # Aggregate all sensitive files
    all_sensitive_files = []
    for category, files in SENSITIVE_FILES.items():
        for filename in files:
            all_sensitive_files.append({
                "name": filename,
                "category": category,
                "sensitivity": random.choice(["Confidential", "Restricted", "Highly Confidential"]),
                "labels": random.sample(["PII", "Financial", "Client Data", "Trade Secret", "Compliance"], k=random.randint(1, 3))
            })
    
    # Generate 180 download events (heavy volume)
    download_count = 180
    downloaded_files = random.sample(all_sensitive_files, min(download_count, len(all_sensitive_files)))
    
    # If we need more, duplicate with variations
    while len(downloaded_files) < download_count:
        base_file = random.choice(all_sensitive_files)
        suffix = random.randint(2, 10)
        name_parts = base_file['name'].rsplit('.', 1)
        new_name = f"{name_parts[0]}_v{suffix}.{name_parts[1]}" if len(name_parts) > 1 else f"{base_file['name']}_v{suffix}"
        downloaded_files.append({
            "name": new_name,
            "category": base_file['category'],
            "sensitivity": base_file['sensitivity'],
            "labels": base_file['labels']
        })
    
    for i, file_info in enumerate(downloaded_files):
        # Spread downloads over 90 minutes (one every ~30 seconds)
        minute_offset = i // 2
        second_offset = (i % 2) * 30
        
        download_time = get_scenario_time(base_time, day, download_start_hour, download_start_minute + minute_offset, second_offset)
        
        m365_download = microsoft_365_collaboration_log()
        file_path = f"/Finance Department/Confidential/{file_info['category'].title()}/{file_info['name']}"
        file_size = random.randint(500000, 15000000)  # 500KB to 15MB
        
        m365_download['TimeStamp'] = download_time
        m365_download['UserId'] = INSIDER_PROFILE['email']
        m365_download['ClientIP'] = INSIDER_PROFILE['home_ip']
        m365_download['Operation'] = random.choice(['FileDownloaded', 'FileSyncDownloadedFull'])
        m365_download['ObjectId'] = file_path
        m365_download['FileName'] = file_info['name']
        m365_download['FileSize'] = file_size
        m365_download['SourceFileExtension'] = file_info['name'].split('.')[-1]
        m365_download['Workload'] = 'SharePoint'
        m365_download['RecordType'] = 6
        m365_download['SiteUrl'] = 'https://securatech.sharepoint.com/sites/Finance'
        m365_download['TargetUser'] = INSIDER_PROFILE['email']
        m365_download['EventType'] = 'Audit.SharePoint'
        m365_download['UserAgent'] = 'Microsoft Office/16.0 (OneDrive Sync)'
        
        # Add DLP classification fields
        m365_download['SensitivityLabel'] = file_info['sensitivity']
        m365_download['Labels'] = file_info['labels']
        m365_download['DLPPolicyMatches'] = ['Sensitive Data Policy', 'Financial Data Protection']
        
        m365_download.pop('Details', None)
        m365_download.pop('RequestedBy', None)
        m365_download.pop('ThreatIndicator', None)
        
        events.append(create_event(download_time, "microsoft_365_collaboration", "data_exfiltration", m365_download))
    
    print(f"   ✓ {len(downloaded_files)} sensitive files downloaded")
    
    # Calculate total data volume
    total_size_mb = sum(random.randint(500000, 15000000) for _ in downloaded_files) / 1024 / 1024
    print(f"   📊 Total data volume: {total_size_mb:.1f} MB")
    
    return events

def generate_usb_copy_activity(base_time: datetime) -> List[Dict]:
    """Generate EDR events showing files copied to removable USB storage"""
    events = []
    day = 7
    
    print(f"💾 USB Removable Media Activity Detected")
    
    # USB mount event at 12:15 AM (following downloads)
    usb_mount_time = get_scenario_time(base_time, day + 1, 0, 15)
    
    usb_mount_event = sentinelone_endpoint_log({
        "event.type": "Device Connected",
        "event.category": "Device",
        "endpoint.name": INSIDER_PROFILE['endpoint_name'],
        "endpoint.os": INSIDER_PROFILE['endpoint_os'],
        "src.process.user": INSIDER_PROFILE['name'].lower().replace(' ', '.'),
        "device.type": "USB Storage",
        "device.vendor": "SanDisk",
        "device.model": "Cruzer Blade 128GB",
        "device.serialNumber": f"USB-{random.randint(100000, 999999)}",
        "event.time": int(datetime.fromisoformat(usb_mount_time).timestamp() * 1000)
    })
    
    events.append(create_event(usb_mount_time, "sentinelone_endpoint", "usb_exfiltration", usb_mount_event))
    print(f"   ✓ USB device connected: SanDisk Cruzer Blade 128GB")
    
    # File copy events to USB drive (E:\ drive letter)
    # Copy 50 files to USB (subset of downloaded files)
    usb_file_count = 50
    copy_start_minute = 17
    
    sensitive_filenames = []
    for category_files in SENSITIVE_FILES.values():
        sensitive_filenames.extend(category_files)
    
    files_to_copy = random.sample(sensitive_filenames, min(usb_file_count, len(sensitive_filenames)))
    
    for i, filename in enumerate(files_to_copy):
        copy_time = get_scenario_time(base_time, day + 1, 0, copy_start_minute + (i // 3), (i % 3) * 20)
        
        file_copy_event = sentinelone_endpoint_log({
            "event.type": "File Creation",
            "event.category": "File",
            "meta.event.name": "FILECREATION",
            "endpoint.name": INSIDER_PROFILE['endpoint_name'],
            "endpoint.os": INSIDER_PROFILE['endpoint_os'],
            "src.process.user": INSIDER_PROFILE['name'].lower().replace(' ', '.'),
            "src.process.name": "explorer.exe",
            "src.process.cmdline": "C:\\Windows\\explorer.exe",
            "tgt.file.path": f"E:\\ExfilData\\{filename}",
            "tgt.file.size": random.randint(500000, 15000000),
            "device.type": "USB Storage",
            "device.path": "E:\\",
            "event.time": int(datetime.fromisoformat(copy_time).timestamp() * 1000)
        })
        
        events.append(create_event(copy_time, "sentinelone_endpoint", "usb_exfiltration", file_copy_event))
    
    print(f"   ✓ {len(files_to_copy)} files copied to USB storage (E:\\ExfilData\\)")
    
    # USB unmount event at 12:45 AM
    usb_unmount_time = get_scenario_time(base_time, day + 1, 0, 45)
    
    usb_unmount_event = sentinelone_endpoint_log({
        "event.type": "Device Disconnected",
        "event.category": "Device",
        "endpoint.name": INSIDER_PROFILE['endpoint_name'],
        "endpoint.os": INSIDER_PROFILE['endpoint_os'],
        "src.process.user": INSIDER_PROFILE['name'].lower().replace(' ', '.'),
        "device.type": "USB Storage",
        "device.vendor": "SanDisk",
        "device.model": "Cruzer Blade 128GB",
        "event.time": int(datetime.fromisoformat(usb_unmount_time).timestamp() * 1000)
    })
    
    events.append(create_event(usb_unmount_time, "sentinelone_endpoint", "usb_exfiltration", usb_unmount_event))
    print(f"   ✓ USB device safely removed")
    
    return events

def generate_dlp_alerts(base_time: datetime) -> List[Dict]:
    """Generate DLP classification alerts (optional Proofpoint-style DLP context)"""
    events = []
    day = 7
    
    print(f"🔔 DLP and Detection Alerts Generated")
    
    # DLP Alert for sensitive data download
    dlp_alert_time = get_scenario_time(base_time, day, 23, 15)
    
    dlp_alert = {
        "alert_id": "DLP-2024-1215-001",
        "alert_name": "High Volume Sensitive Data Download Detected",
        "severity": "HIGH",
        "user": INSIDER_PROFILE['email'],
        "description": "User downloaded 180+ files classified as Confidential/Restricted from SharePoint",
        "source_ip": INSIDER_PROFILE['home_ip'],
        "data_classification": ["Confidential", "Restricted", "PII", "Financial"],
        "file_count": 180,
        "total_size_mb": 1847.3,
        "policy_violated": "Sensitive Data Protection Policy",
        "detection_method": "Data Loss Prevention (DLP)",
        "recommended_action": "Investigate user activity and review access permissions",
        "mitre_technique": "T1530 - Data from Cloud Storage Object"
    }
    
    events.append(create_event(dlp_alert_time, "dlp_alert", "detection", dlp_alert))
    print(f"   ✓ DLP Alert: High Volume Sensitive Data Download")
    
    # UEBA Alert for off-hours access
    ueba_alert_time = get_scenario_time(base_time, day, 23, 20)
    
    ueba_alert = {
        "alert_id": "UEBA-2024-1215-002",
        "alert_name": "Off-Hours Access with Unusual Download Volume",
        "severity": "HIGH",
        "user": INSIDER_PROFILE['email'],
        "description": "User accessed SharePoint at 10:30 PM (outside normal 8 AM - 5 PM hours) and downloaded 50x normal daily volume",
        "source_ip": INSIDER_PROFILE['home_ip'],
        "access_time": "22:30",
        "normal_hours": "08:00 - 17:00",
        "baseline_deviation": "5000% increase from normal daily download activity",
        "risk_score": 92,
        "detection_method": "User and Entity Behavior Analytics (UEBA)",
        "recommended_action": "Immediate investigation and potential account suspension",
        "mitre_technique": "T1078 - Valid Accounts"
    }
    
    events.append(create_event(ueba_alert_time, "soar_alert", "detection", ueba_alert))
    print(f"   ✓ UEBA Alert: Off-Hours Access Pattern")
    
    # EDR Alert for USB write activity
    edr_alert_time = get_scenario_time(base_time, day + 1, 0, 50)
    
    edr_alert = {
        "alert_id": "EDR-2024-1215-003",
        "alert_name": "Sensitive Data Written to Removable Media",
        "severity": "CRITICAL",
        "user": INSIDER_PROFILE['name'],
        "endpoint": INSIDER_PROFILE['endpoint_name'],
        "description": "50 files copied to USB removable storage device following large SharePoint download",
        "device_type": "USB Storage",
        "device_model": "SanDisk Cruzer Blade 128GB",
        "files_written": 50,
        "detection_method": "Endpoint Detection and Response (EDR)",
        "recommended_action": "Immediate endpoint isolation and forensic investigation",
        "mitre_technique": "T1052.001 - Exfiltration Over Physical Medium: USB"
    }
    
    events.append(create_event(edr_alert_time, "soar_alert", "detection", edr_alert))
    print(f"   ✓ EDR Alert: Removable Media Write Detected")
    
    # Insider Threat Risk Score Elevation
    insider_threat_time = get_scenario_time(base_time, day + 1, 1, 0)
    
    insider_threat_alert = {
        "alert_id": "INSIDER-2024-1215-004",
        "alert_name": "Insider Threat Risk Score Elevated - Data Exfiltration Indicators",
        "severity": "CRITICAL",
        "user": INSIDER_PROFILE['email'],
        "department": INSIDER_PROFILE['department'],
        "risk_score": 95,
        "previous_risk_score": 15,
        "indicators": [
            "Off-hours cloud access",
            "Unusual data download volume (180 files, 1.8 GB)",
            "DLP policy violations (Confidential/PII data)",
            "USB removable media usage",
            "Files copied to external storage"
        ],
        "timeline": "10:30 PM - 12:45 AM",
        "detection_method": "Insider Threat Analytics",
        "recommended_action": "Immediate containment: Suspend account, isolate endpoint, initiate investigation",
        "mitre_tactics": ["Collection", "Exfiltration"],
        "mitre_techniques": ["T1530", "T1052.001"]
    }
    
    events.append(create_event(insider_threat_time, "soar_alert", "detection", insider_threat_alert))
    print(f"   ✓ Insider Threat Alert: Risk Score Elevated to 95")
    
    return events

def generate_insider_exfiltration_scenario():
    """
    Main function to generate the complete Insider Data Exfiltration scenario
    """
    print("=" * 80)
    print("🎯 INSIDER DATA EXFILTRATION VIA CLOUD DOWNLOAD SCENARIO")
    print("=" * 80)
    print(f"User: {INSIDER_PROFILE['name']} ({INSIDER_PROFILE['email']})")
    print(f"Department: {INSIDER_PROFILE['department']}")
    print(f"Location: {INSIDER_PROFILE['location']}")
    print(f"Endpoint: {INSIDER_PROFILE['endpoint_name']} ({INSIDER_PROFILE['endpoint_os']})")
    print("=" * 80)
    
    # Start scenario 8 days ago
    base_time = datetime.now(timezone.utc) - timedelta(days=8)
    
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
    
    # Phase 2: Large-Scale Cloud Download (Day 8)
    print("\n" + "=" * 80)
    print("📥 PHASE 2: Large-Scale Cloud Download Exfiltration (Day 8)")
    print("-" * 80)
    download_events = generate_exfiltration_downloads(base_time)
    all_events.extend(download_events)
    print(f"\nTotal download events: {len(download_events)}")
    
    # Phase 3: USB Copy Activity (Day 8)
    print("\n" + "=" * 80)
    print("💾 PHASE 3: USB Removable Media Exfiltration (Day 8)")
    print("-" * 80)
    usb_events = generate_usb_copy_activity(base_time)
    all_events.extend(usb_events)
    print(f"\nTotal USB activity events: {len(usb_events)}")
    
    # Phase 4: DLP and Detection Alerts (Day 8)
    print("\n" + "=" * 80)
    print("🔔 PHASE 4: Detection and Alerts (Day 8)")
    print("-" * 80)
    alert_events = generate_dlp_alerts(base_time)
    all_events.extend(alert_events)
    print(f"\nTotal detection/alert events: {len(alert_events)}")
    
    # Sort all events by timestamp
    all_events.sort(key=lambda x: x['timestamp'])
    
    # Create scenario summary
    scenario_summary = {
        "scenario_name": "Insider Data Exfiltration via Cloud Download",
        "user_profile": INSIDER_PROFILE,
        "timeline_start": base_time.isoformat(),
        "timeline_end": (base_time + timedelta(days=8)).isoformat(),
        "total_events": len(all_events),
        "phases": [
            {"name": "Normal Behavior Baseline", "days": "1-7", "events": len([e for e in all_events if e['phase'] == 'normal_behavior'])},
            {"name": "Off-Hours Access", "day": "8", "events": len([e for e in all_events if e['phase'] == 'off_hours_access'])},
            {"name": "Data Exfiltration (Cloud)", "day": "8", "events": len([e for e in all_events if e['phase'] == 'data_exfiltration'])},
            {"name": "USB Exfiltration", "day": "8", "events": len([e for e in all_events if e['phase'] == 'usb_exfiltration'])},
            {"name": "Detection & Alerts", "day": "8", "events": len([e for e in all_events if e['phase'] == 'detection'])}
        ],
        "detections": [
            "High Volume Sensitive Data Download",
            "Off-Hours Access Pattern",
            "DLP Policy Violations",
            "Removable Media Write Activity",
            "Insider Threat Risk Score Elevation"
        ],
        "mitre_techniques": [
            "T1530 - Data from Cloud Storage Object",
            "T1078 - Valid Accounts",
            "T1052.001 - Exfiltration Over Physical Medium: USB"
        ],
        "data_sources": [
            "Microsoft 365 Audit Logs (UAL)",
            "Okta Authentication",
            "SentinelOne EDR",
            "DLP Classification",
            "UEBA Analytics"
        ],
        "statistics": {
            "files_downloaded": 180,
            "files_copied_to_usb": 50,
            "total_data_volume_mb": 1847.3,
            "duration_hours": 2.5,
            "off_hours_start": "22:30",
            "baseline_deviation": "5000%"
        },
        "events": all_events
    }
    
    print("\n" + "=" * 80)
    print("✅ SCENARIO GENERATION COMPLETE")
    print("=" * 80)
    print(f"Total Events: {len(all_events)}")
    print(f"Data Sources: Okta, Microsoft 365, SentinelOne EDR, DLP")
    print(f"Timeline: {(base_time).strftime('%Y-%m-%d')} to {(base_time + timedelta(days=8)).strftime('%Y-%m-%d')}")
    print(f"Download Volume: 180 files (~1.8 GB)")
    print(f"USB Exfiltration: 50 files")
    print("=" * 80)
    
    return scenario_summary

if __name__ == "__main__":
    # Generate the scenario
    scenario = generate_insider_exfiltration_scenario()

    # Save to JSON file with container-safe fallbacks
    preferred_dir = os.environ.get("SCENARIO_OUTPUT_DIR") or os.path.join(os.path.dirname(__file__), "configs")
    output_file = os.path.join(preferred_dir, "insider_cloud_download_exfiltration.json")

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
        fallback_path = os.path.join(fallback_dir, "insider_cloud_download_exfiltration.json")
        if not _attempt_save(fallback_path):
            # As a last resort, skip saving but exit successfully
            print("ℹ️  Skipping file save due to filesystem restrictions. Scenario generation completed successfully.")
