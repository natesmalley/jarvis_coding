#!/usr/bin/env python3
"""
Enterprise Attack Scenario - SentinelOne AI-SIEM Showcase
==========================================================

Demonstrates sophisticated multi-platform attack correlation across:
- Fortinet Fortigate (DMZ Firewalls) 
- Windows Corp Servers
- Imperva SecureSphere Audit
- AWS CloudTrail
- Okta & Azure AD Authentication
- Cisco Duo MFA
- Zscaler Web Security
- Proofpoint Email Security
- CrowdStrike Endpoint Detection
- HashiCorp Vault
- Harness CI/CD
- PingOne MFA & PingProtect
"""

import json
import sys
import os
import time
from datetime import datetime, timezone, timedelta

# Add the event_python_writer directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__)))

# Import generators (using actual function signatures)
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

def generate_showcase_attack_scenario():
    """Generate a comprehensive enterprise attack scenario"""
    
    print("🚨 ENTERPRISE ATTACK SCENARIO - SentinelOne AI-SIEM Showcase")
    print("=" * 80)
    print("🎯 Multi-Platform Attack Campaign Demonstrating Advanced Correlation")
    print()
    
    events = []
    campaign_start = datetime.now(timezone.utc)
    
    print("📊 GENERATING ATTACK EVENTS ACROSS 14 DATA SOURCES:")
    print("-" * 60)
    
    # Phase 1: External Reconnaissance (Fortigate DMZ)
    print("🔥 Phase 1: DMZ RECONNAISSANCE")
    for i in range(3):
        event = forward_log()  # Fortigate firewall logs
        events.append({
            "source": "fortinet_fortigate", 
            "phase": "reconnaissance",
            "timestamp": (campaign_start + timedelta(minutes=i*2)).isoformat(),
            "event": event
        })
    print(f"   ✅ Generated {3} Fortinet Fortigate DMZ firewall events")
    
    # Phase 2: Authentication Attacks (Okta, Azure AD, Duo)
    print("🔥 Phase 2: IDENTITY & AUTHENTICATION")
    
    # Okta authentication events
    for i in range(4):
        event = okta_authentication_log()
        events.append({
            "source": "okta_authentication",
            "phase": "initial_access", 
            "timestamp": (campaign_start + timedelta(minutes=10 + i*1)).isoformat(),
            "event": event
        })
    
    # Azure AD events
    for i in range(3):
        event = azuread_log()
        events.append({
            "source": "microsoft_azuread",
            "phase": "initial_access",
            "timestamp": (campaign_start + timedelta(minutes=15 + i*2)).isoformat(),
            "event": event
        })
    
    # Cisco Duo MFA events
    for i in range(2):
        event = cisco_duo_log()
        events.append({
            "source": "cisco_duo",
            "phase": "initial_access",
            "timestamp": (campaign_start + timedelta(minutes=20 + i*3)).isoformat(),
            "event": event
        })
    
    # PingOne MFA events
    for i in range(2):
        event = pingone_mfa_log()
        events.append({
            "source": "pingone_mfa", 
            "phase": "initial_access",
            "timestamp": (campaign_start + timedelta(minutes=25 + i*2)).isoformat(),
            "event": event
        })
    
    print(f"   ✅ Generated {11} identity & authentication events (Okta, Azure AD, Duo, PingOne)")
    
    # Phase 3: Email Attack Vector (Proofpoint)
    print("🔥 Phase 3: EMAIL SECURITY")
    for i in range(3):
        event = proofpoint_log()
        events.append({
            "source": "proofpoint",
            "phase": "initial_access",
            "timestamp": (campaign_start + timedelta(minutes=30 + i*1)).isoformat(),
            "event": event
        })
    print(f"   ✅ Generated {3} Proofpoint email security events")
    
    # Phase 4: Web Security & Traffic (Zscaler)
    print("🔥 Phase 4: WEB SECURITY")
    for i in range(4):
        event = zscaler_log()
        events.append({
            "source": "zscaler",
            "phase": "execution",
            "timestamp": (campaign_start + timedelta(minutes=35 + i*1)).isoformat(), 
            "event": event
        })
    print(f"   ✅ Generated {4} Zscaler web security events")
    
    # Phase 5: Endpoint Detection (CrowdStrike)  
    print("🔥 Phase 5: ENDPOINT SECURITY")
    for i in range(5):
        event = crowdstrike_log()
        events.append({
            "source": "crowdstrike_falcon",
            "phase": "execution",
            "timestamp": (campaign_start + timedelta(minutes=40 + i*2)).isoformat(),
            "event": event
        })
    print(f"   ✅ Generated {5} CrowdStrike endpoint detection events")
    
    # Phase 6: Windows Server Infrastructure
    print("🔥 Phase 6: WINDOWS INFRASTRUCTURE") 
    for i in range(6):
        event = microsoft_windows_eventlog_log()
        events.append({
            "source": "microsoft_windows_eventlog",
            "phase": "lateral_movement",
            "timestamp": (campaign_start + timedelta(minutes=50 + i*2)).isoformat(),
            "event": event
        })
    print(f"   ✅ Generated {6} Windows Server events")
    
    # Phase 7: Database Security (Imperva)
    print("🔥 Phase 7: DATABASE SECURITY")
    for i in range(4):
        event = imperva_waf_log()
        events.append({
            "source": "imperva_waf", 
            "phase": "lateral_movement",
            "timestamp": (campaign_start + timedelta(minutes=60 + i*3)).isoformat(),
            "event": event
        })
    print(f"   ✅ Generated {4} Imperva database security events")
    
    # Phase 8: Cloud Infrastructure (AWS CloudTrail)
    print("🔥 Phase 8: AWS CLOUD INFRASTRUCTURE")
    for i in range(5):
        event = cloudtrail_log()
        events.append({
            "source": "aws_cloudtrail",
            "phase": "persistence",
            "timestamp": (campaign_start + timedelta(minutes=70 + i*2)).isoformat(),
            "event": event
        })
    print(f"   ✅ Generated {5} AWS CloudTrail events")
    
    # Phase 9: Secrets Management (HashiCorp Vault)
    print("🔥 Phase 9: SECRETS MANAGEMENT")
    for i in range(3):
        event = hashicorp_vault_log()
        events.append({
            "source": "hashicorp_vault",
            "phase": "credential_access", 
            "timestamp": (campaign_start + timedelta(minutes=80 + i*3)).isoformat(),
            "event": event
        })
    print(f"   ✅ Generated {3} HashiCorp Vault events")
    
    # Phase 10: CI/CD Pipeline (Harness)
    print("🔥 Phase 10: CI/CD SECURITY")
    for i in range(3):
        event = harness_ci_log()
        events.append({
            "source": "harness_ci",
            "phase": "persistence",
            "timestamp": (campaign_start + timedelta(minutes=90 + i*4)).isoformat(),
            "event": event
        })
    print(f"   ✅ Generated {3} Harness CI/CD events")
    
    # Phase 11: Fraud Detection (PingProtect)
    print("🔥 Phase 11: FRAUD DETECTION")
    for i in range(2):
        event = pingprotect_log()
        events.append({
            "source": "pingprotect",
            "phase": "detection",
            "timestamp": (campaign_start + timedelta(minutes=100 + i*5)).isoformat(),
            "event": event
        })
    print(f"   ✅ Generated {2} PingProtect fraud detection events")
    
    # Create final scenario structure
    scenario = {
        "scenario_name": "Enterprise Multi-Platform Attack Campaign",
        "description": "Sophisticated attack demonstrating SentinelOne AI-SIEM cross-platform correlation",
        "data_sources": [
            "Fortinet Fortigate (DMZ Firewalls)",
            "Microsoft Windows EventLog (Corp Servers)",
            "Imperva SecureSphere (Database Audit)", 
            "AWS CloudTrail (Cloud Infrastructure)",
            "Okta Authentication",
            "Microsoft Azure AD",
            "Cisco Duo MFA",
            "Zscaler Web Security", 
            "Proofpoint Email Security",
            "CrowdStrike Falcon EDR",
            "HashiCorp Vault (Secrets)",
            "Harness CI/CD",
            "PingOne MFA",
            "PingProtect Fraud Detection"
        ],
        "attack_phases": [
            "1. DMZ Reconnaissance (Fortigate)",
            "2. Identity Attacks (Okta, Azure AD, Duo, PingOne)", 
            "3. Email Vector (Proofpoint)",
            "4. Web Exploitation (Zscaler)",
            "5. Endpoint Compromise (CrowdStrike)", 
            "6. Lateral Movement (Windows)",
            "7. Database Access (Imperva)",
            "8. Cloud Persistence (AWS)",
            "9. Secrets Theft (Vault)",
            "10. CI/CD Compromise (Harness)",
            "11. Fraud Detection (PingProtect)"
        ],
        "campaign_start": campaign_start.isoformat(),
        "total_events": len(events),
        "events": events,
        "correlation_opportunities": [
            "🔗 Cross-platform user behavior analysis",
            "🔗 Attack progression timeline correlation",
            "🔗 Infrastructure traversal mapping",
            "🔗 Credential reuse detection",
            "🔗 Multi-stage attack reconstruction",
            "🔗 Threat hunting across data sources"
        ]
    }
    
    print(f"\n🎯 SCENARIO SUMMARY:")
    print(f"   📊 Total Events: {len(events)}")
    print(f"   🏢 Data Sources: {len(scenario['data_sources'])}")
    print(f"   🔥 Attack Phases: {len(scenario['attack_phases'])}")
    print(f"   ⏰ Timeline: {campaign_start.strftime('%Y-%m-%d %H:%M:%S')} UTC")
    
    return scenario

def save_scenario(scenario, filename="showcase_attack_scenario.json"):
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
    print("🏢 ENTERPRISE SHOWCASE ATTACK SCENARIO GENERATOR")
    print("=" * 80)
    
    scenario = generate_showcase_attack_scenario()
    filename = save_scenario(scenario)
    
    print(f"\n✅ Enterprise attack scenario ready for SentinelOne AI-SIEM!")
    print(f"📈 This scenario showcases advanced multi-platform correlation capabilities")