#!/usr/bin/env python3
"""
Enterprise Attack Scenario - 10 Minute Compressed Version
==========================================================
Real-time attack simulation compressed to last 10 minutes for immediate visibility
"""

import json
import sys
import os
import random
from datetime import datetime, timezone, timedelta

# Add the event_python_writer directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__)))

# Import all generators
from fortinet_fortigate import forward_log
from microsoft_windows_eventlog import microsoft_windows_eventlog_log
from imperva_waf import imperva_waf_log  
from aws_cloudtrail import cloudtrail_log
from okta_authentication import okta_authentication_log
from microsoft_azuread import azuread_log
from cisco_duo import cisco_duo_log
from zscaler import zscaler_log
from proofpoint import proofpoint_log
from crowdstrike_falcon import crowdstrike_log
from hashicorp_vault import hashicorp_vault_log
from harness_ci import harness_ci_log
from pingone_mfa import pingone_mfa_log
from pingprotect import pingprotect_log
from cisco_umbrella import cisco_umbrella_log
from cisco_ise import cisco_ise_log
from f5_networks import f5_networks_log as f5_log
from netskope import netskope_log
from github_audit import github_audit_log

# Attack timeline - last 10 minutes for real-time visibility
BASE_TIME = datetime.now(timezone.utc) - timedelta(minutes=10)

def get_attack_time(phase_offset_minutes):
    """Get timestamp for attack phase"""
    return (BASE_TIME + timedelta(minutes=phase_offset_minutes)).isoformat()

def set_event_timestamp(event_data, timestamp):
    """Override event timestamp to match attack timeline"""
    if isinstance(event_data, dict):
        # For JSON events, override common timestamp fields
        event_data['timestamp'] = timestamp
        if 'time' in event_data:
            event_data['time'] = timestamp
        if 'TimeCreated' in event_data:
            event_data['TimeCreated'] = timestamp
        if '@timestamp' in event_data:
            event_data['@timestamp'] = timestamp
        # Zscaler specific timestamp field
        if 'datetime' in event_data:
            event_data['datetime'] = timestamp
    return event_data

def generate_10min_attack_scenario():
    """Generate compressed 10-minute attack scenario with all phases"""
    
    print("🚨 ENTERPRISE ATTACK SCENARIO - 10 MINUTE VERSION")
    print("=" * 80)
    print("🎯 Compressed APT Campaign for Real-Time Analysis")
    
    events = []
    attack_phases = []
    data_sources = set()
    
    # Attacker IPs and domains
    attacker_ips = ["185.220.101.45", "185.220.101.46", "185.220.101.47"]
    
    print("\n📊 ATTACK PHASES (Last 10 Minutes):")
    print("-" * 60)
    
    # ========================================
    # PHASE 1: RECONNAISSANCE (0-1 minute)
    # ========================================
    print("🔍 Phase 1: RECONNAISSANCE (0-1 minute)")
    attack_phases.append("reconnaissance")
    
    # Fortigate firewall events
    for i in range(10):
        timestamp = get_attack_time(i * 0.06)  # Spread across first minute
        event_data = forward_log()
        event_data = set_event_timestamp(event_data, timestamp)
        events.append({
            "timestamp": timestamp,
            "source": "fortinet_fortigate",
            "phase": "reconnaissance",
            "event": event_data
        })
        data_sources.add("fortinet_fortigate")
    
    # Cisco Umbrella DNS
    for i in range(5):
        timestamp = get_attack_time(0.3 + i * 0.1)
        event_data = cisco_umbrella_log()
        event_data = set_event_timestamp(event_data, timestamp)
        events.append({
            "timestamp": timestamp,
            "source": "cisco_umbrella",
            "phase": "reconnaissance",
            "event": event_data
        })
        data_sources.add("cisco_umbrella")
    
    # Imperva WAF scanning
    for i in range(5):
        timestamp = get_attack_time(0.6 + i * 0.08)
        event_data = imperva_waf_log()
        event_data = set_event_timestamp(event_data, timestamp)
        events.append({
            "timestamp": timestamp,
            "source": "imperva_waf",
            "phase": "reconnaissance",
            "event": event_data
        })
        data_sources.add("imperva_waf")
    
    print(f"   ✅ Generated {len([e for e in events if e['phase'] == 'reconnaissance'])} reconnaissance events")
    
    # ========================================
    # PHASE 2: INITIAL COMPROMISE (1-2 minutes)
    # ========================================
    print("📧 Phase 2: INITIAL COMPROMISE (1-2 minutes)")
    attack_phases.append("initial_compromise")
    
    # Phishing emails - Proofpoint
    for i in range(5):
        timestamp = get_attack_time(1 + i * 0.1)
        event_data = proofpoint_log()
        event_data = set_event_timestamp(event_data, timestamp)
        events.append({
            "timestamp": timestamp,
            "source": "proofpoint",
            "phase": "initial_compromise",
            "event": event_data
        })
        data_sources.add("proofpoint")
    
    # Malicious link clicks - Zscaler (FIXING VISIBILITY)
    for i in range(8):
        timestamp = get_attack_time(1.3 + i * 0.08)
        event_data = zscaler_log()
        # Ensure Zscaler events have proper timestamp
        event_data = set_event_timestamp(event_data, timestamp)
        events.append({
            "timestamp": timestamp,
            "source": "zscaler",
            "phase": "initial_compromise",
            "event": event_data
        })
        data_sources.add("zscaler")
    
    # Netskope downloads
    for i in range(5):
        timestamp = get_attack_time(1.7 + i * 0.06)
        event_data = netskope_log()
        event_data = set_event_timestamp(event_data, timestamp)
        events.append({
            "timestamp": timestamp,
            "source": "netskope",
            "phase": "initial_compromise",
            "event": event_data
        })
        data_sources.add("netskope")
    
    # CrowdStrike detection
    for i in range(5):
        timestamp = get_attack_time(1.85 + i * 0.03)
        event_data = crowdstrike_log()
        event_data = set_event_timestamp(event_data, timestamp)
        events.append({
            "timestamp": timestamp,
            "source": "crowdstrike_falcon",
            "phase": "initial_compromise",
            "event": event_data
        })
        data_sources.add("crowdstrike_falcon")
    
    print(f"   ✅ Generated {len([e for e in events if e['phase'] == 'initial_compromise'])} initial compromise events")
    
    # ========================================
    # PHASE 3: CREDENTIAL ACCESS (2-3.5 minutes)
    # ========================================
    print("🔐 Phase 3: CREDENTIAL ACCESS (2-3.5 minutes)")
    attack_phases.append("credential_access")
    
    # Okta failures
    for i in range(6):
        timestamp = get_attack_time(2 + i * 0.1)
        event_data = okta_authentication_log()
        event_data = set_event_timestamp(event_data, timestamp)
        events.append({
            "timestamp": timestamp,
            "source": "okta_authentication",
            "phase": "credential_access",
            "event": event_data
        })
        data_sources.add("okta_authentication")
    
    # Azure AD suspicious logins
    for i in range(6):
        timestamp = get_attack_time(2.4 + i * 0.1)
        event_data = azuread_log()
        event_data = set_event_timestamp(event_data, timestamp)
        events.append({
            "timestamp": timestamp,
            "source": "microsoft_azuread",
            "phase": "credential_access",
            "event": event_data
        })
        data_sources.add("microsoft_azuread")
    
    # Cisco Duo MFA
    for i in range(5):
        timestamp = get_attack_time(2.8 + i * 0.08)
        event_data = cisco_duo_log()
        event_data = set_event_timestamp(event_data, timestamp)
        events.append({
            "timestamp": timestamp,
            "source": "cisco_duo",
            "phase": "credential_access",
            "event": event_data
        })
        data_sources.add("cisco_duo")
    
    # PingOne MFA
    for i in range(4):
        timestamp = get_attack_time(3.1 + i * 0.08)
        event_data = pingone_mfa_log()
        event_data = set_event_timestamp(event_data, timestamp)
        events.append({
            "timestamp": timestamp,
            "source": "pingone_mfa",
            "phase": "credential_access",
            "event": event_data
        })
        data_sources.add("pingone_mfa")
    
    # Windows credential events
    for i in range(8):
        timestamp = get_attack_time(3.3 + i * 0.025)
        event_data = microsoft_windows_eventlog_log()
        event_data = set_event_timestamp(event_data, timestamp)
        events.append({
            "timestamp": timestamp,
            "source": "microsoft_windows_eventlog",
            "phase": "credential_access",
            "event": event_data
        })
        data_sources.add("microsoft_windows_eventlog")
    
    print(f"   ✅ Generated {len([e for e in events if e['phase'] == 'credential_access'])} credential access events")
    
    # ========================================
    # PHASE 4: LATERAL MOVEMENT (3.5-5.5 minutes)
    # ========================================
    print("➡️  Phase 4: LATERAL MOVEMENT (3.5-5.5 minutes)")
    attack_phases.append("lateral_movement")
    
    # Windows RDP/SMB
    for i in range(10):
        timestamp = get_attack_time(3.5 + i * 0.08)
        event_data = microsoft_windows_eventlog_log()
        event_data = set_event_timestamp(event_data, timestamp)
        events.append({
            "timestamp": timestamp,
            "source": "microsoft_windows_eventlog",
            "phase": "lateral_movement",
            "event": event_data
        })
    
    # Cisco ISE network movement
    for i in range(8):
        timestamp = get_attack_time(4.1 + i * 0.1)
        event_data = cisco_ise_log()
        event_data = set_event_timestamp(event_data, timestamp)
        events.append({
            "timestamp": timestamp,
            "source": "cisco_ise",
            "phase": "lateral_movement",
            "event": event_data
        })
        data_sources.add("cisco_ise")
    
    # F5 load balancer
    for i in range(8):
        timestamp = get_attack_time(4.7 + i * 0.08)
        event_data = f5_log()
        event_data = set_event_timestamp(event_data, timestamp)
        events.append({
            "timestamp": timestamp,
            "source": "f5_networks",
            "phase": "lateral_movement",
            "event": event_data
        })
        data_sources.add("f5_networks")
    
    # CrowdStrike lateral detection
    for i in range(6):
        timestamp = get_attack_time(5.2 + i * 0.05)
        event_data = crowdstrike_log()
        event_data = set_event_timestamp(event_data, timestamp)
        events.append({
            "timestamp": timestamp,
            "source": "crowdstrike_falcon",
            "phase": "lateral_movement",
            "event": event_data
        })
    
    print(f"   ✅ Generated {len([e for e in events if e['phase'] == 'lateral_movement'])} lateral movement events")
    
    # ========================================
    # PHASE 5: PRIVILEGE ESCALATION (5.5-6.5 minutes)
    # ========================================
    print("⬆️  Phase 5: PRIVILEGE ESCALATION (5.5-6.5 minutes)")
    attack_phases.append("privilege_escalation")
    
    # AWS privilege escalation
    for i in range(8):
        timestamp = get_attack_time(5.5 + i * 0.08)
        event_data = cloudtrail_log()
        event_data = set_event_timestamp(event_data, timestamp)
        events.append({
            "timestamp": timestamp,
            "source": "aws_cloudtrail",
            "phase": "privilege_escalation",
            "event": event_data
        })
        data_sources.add("aws_cloudtrail")
    
    # HashiCorp Vault access
    for i in range(6):
        timestamp = get_attack_time(6 + i * 0.08)
        event_data = hashicorp_vault_log()
        event_data = set_event_timestamp(event_data, timestamp)
        events.append({
            "timestamp": timestamp,
            "source": "hashicorp_vault",
            "phase": "privilege_escalation",
            "event": event_data
        })
        data_sources.add("hashicorp_vault")
    
    print(f"   ✅ Generated {len([e for e in events if e['phase'] == 'privilege_escalation'])} privilege escalation events")
    
    # ========================================
    # PHASE 6: DATA DISCOVERY (6.5-7.5 minutes)
    # ========================================
    print("🔎 Phase 6: DATA DISCOVERY (6.5-7.5 minutes)")
    attack_phases.append("data_discovery")
    
    # Database queries
    for i in range(8):
        timestamp = get_attack_time(6.5 + i * 0.08)
        event_data = imperva_waf_log()
        event_data = set_event_timestamp(event_data, timestamp)
        events.append({
            "timestamp": timestamp,
            "source": "imperva_waf",
            "phase": "data_discovery",
            "event": event_data
        })
    
    # AWS S3 enumeration
    for i in range(6):
        timestamp = get_attack_time(7 + i * 0.08)
        event_data = cloudtrail_log()
        event_data = set_event_timestamp(event_data, timestamp)
        events.append({
            "timestamp": timestamp,
            "source": "aws_cloudtrail",
            "phase": "data_discovery",
            "event": event_data
        })
    
    # GitHub repository access
    for i in range(5):
        timestamp = get_attack_time(7.3 + i * 0.04)
        event_data = github_audit_log()
        event_data = set_event_timestamp(event_data, timestamp)
        events.append({
            "timestamp": timestamp,
            "source": "github_audit",
            "phase": "data_discovery",
            "event": event_data
        })
        data_sources.add("github_audit")
    
    print(f"   ✅ Generated {len([e for e in events if e['phase'] == 'data_discovery'])} data discovery events")
    
    # ========================================
    # PHASE 7: DATA EXFILTRATION (7.5-8.5 minutes)
    # ========================================
    print("📤 Phase 7: DATA EXFILTRATION (7.5-8.5 minutes)")
    attack_phases.append("data_exfiltration")
    
    # Large data transfers via Zscaler (ENHANCED FOR VISIBILITY)
    for i in range(10):
        timestamp = get_attack_time(7.5 + i * 0.06)
        event_data = zscaler_log()
        # Ensure timestamp is set
        event_data = set_event_timestamp(event_data, timestamp)
        # Add exfiltration indicators
        if isinstance(event_data, dict):
            event_data['bytes_out'] = random.randint(10000000, 50000000)  # Large upload
            event_data['action'] = 'allowed'  # Show successful exfil
            event_data['urlcategory'] = 'Cloud Storage'
        events.append({
            "timestamp": timestamp,
            "source": "zscaler",
            "phase": "data_exfiltration",
            "event": event_data
        })
    
    # DNS tunneling via Cisco Umbrella
    for i in range(8):
        timestamp = get_attack_time(8 + i * 0.06)
        event_data = cisco_umbrella_log()
        event_data = set_event_timestamp(event_data, timestamp)
        events.append({
            "timestamp": timestamp,
            "source": "cisco_umbrella",
            "phase": "data_exfiltration",
            "event": event_data
        })
    
    # Netskope cloud uploads
    for i in range(6):
        timestamp = get_attack_time(8.3 + i * 0.03)
        event_data = netskope_log()
        event_data = set_event_timestamp(event_data, timestamp)
        events.append({
            "timestamp": timestamp,
            "source": "netskope",
            "phase": "data_exfiltration",
            "event": event_data
        })
    
    print(f"   ✅ Generated {len([e for e in events if e['phase'] == 'data_exfiltration'])} data exfiltration events")
    
    # ========================================
    # PHASE 8: PERSISTENCE (8.5-9.5 minutes)
    # ========================================
    print("🔧 Phase 8: PERSISTENCE (8.5-9.5 minutes)")
    attack_phases.append("persistence")
    
    # CI/CD backdoor
    for i in range(4):
        timestamp = get_attack_time(8.5 + i * 0.1)
        event_data = harness_ci_log()
        event_data = set_event_timestamp(event_data, timestamp)
        events.append({
            "timestamp": timestamp,
            "source": "harness_ci",
            "phase": "persistence",
            "event": event_data
        })
        data_sources.add("harness_ci")
    
    # AWS persistence
    for i in range(4):
        timestamp = get_attack_time(8.9 + i * 0.08)
        event_data = cloudtrail_log()
        event_data = set_event_timestamp(event_data, timestamp)
        events.append({
            "timestamp": timestamp,
            "source": "aws_cloudtrail",
            "phase": "persistence",
            "event": event_data
        })
    
    # Windows scheduled tasks
    for i in range(4):
        timestamp = get_attack_time(9.2 + i * 0.07)
        event_data = microsoft_windows_eventlog_log()
        event_data = set_event_timestamp(event_data, timestamp)
        events.append({
            "timestamp": timestamp,
            "source": "microsoft_windows_eventlog",
            "phase": "persistence",
            "event": event_data
        })
    
    print(f"   ✅ Generated {len([e for e in events if e['phase'] == 'persistence'])} persistence events")
    
    # ========================================
    # PHASE 9: DETECTION (9.5-10 minutes)
    # ========================================
    print("🚨 Phase 9: DETECTION & RESPONSE (9.5-10 minutes)")
    attack_phases.append("detection")
    
    # PingProtect fraud detection
    for i in range(3):
        timestamp = get_attack_time(9.5 + i * 0.1)
        event_data = pingprotect_log()
        event_data = set_event_timestamp(event_data, timestamp)
        events.append({
            "timestamp": timestamp,
            "source": "pingprotect",
            "phase": "detection",
            "event": event_data
        })
        data_sources.add("pingprotect")
    
    # CrowdStrike alerts
    for i in range(3):
        timestamp = get_attack_time(9.8 + i * 0.06)
        event_data = crowdstrike_log()
        event_data = set_event_timestamp(event_data, timestamp)
        events.append({
            "timestamp": timestamp,
            "source": "crowdstrike_falcon",
            "phase": "detection",
            "event": event_data
        })
    
    print(f"   ✅ Generated {len([e for e in events if e['phase'] == 'detection'])} detection events")
    
    # Summary
    print("\n" + "=" * 80)
    print("🎯 SCENARIO SUMMARY:")
    print(f"   📊 Total Events: {len(events)}")
    print(f"   🏢 Data Sources: {len(data_sources)}")
    print(f"   🔥 Attack Phases: {len(attack_phases)}")
    print(f"   ⏰ Timeline: {BASE_TIME.isoformat()} to {get_attack_time(10)}")
    print(f"   ⏱️  Duration: 10 minutes (real-time window)")
    
    return {
        "events": events,
        "attack_phases": attack_phases,
        "data_sources": list(data_sources),
        "metadata": {
            "total_events": len(events),
            "duration_minutes": 10,
            "timeline_start": BASE_TIME.isoformat(),
            "timeline_end": get_attack_time(10),
            "attack_type": "Compressed APT Simulation",
            "description": "10-minute compressed attack scenario for real-time visibility"
        }
    }

def save_scenario(scenario, filename="enterprise_attack_scenario_10min.json"):
    """Save scenario to file"""
    # Use /app/data directory which is writable in the container
    data_dir = "/app/data"
    if not os.path.exists(data_dir):
        # Fallback to current directory if /app/data doesn't exist (local dev)
        data_dir = "."
    
    filepath = os.path.join(data_dir, filename)
    
    # Ensure the directory exists
    os.makedirs(os.path.dirname(filepath) if os.path.dirname(filepath) else data_dir, exist_ok=True)
    
    with open(filepath, 'w') as f:
        json.dump(scenario, f, indent=2, default=str)
    print(f"\n📁 Scenario saved to: {filepath}")
    return filepath

if __name__ == "__main__":
    scenario = generate_10min_attack_scenario()
    save_scenario(scenario)
    print("\n✅ 10-minute enterprise attack scenario ready!")
    print("🎯 Use enterprise_scenario_sender_10min.py to send events to SentinelOne AI-SIEM")