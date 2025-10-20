#!/usr/bin/env python3
"""
Attack Scenario Orchestrator - "Operation Digital Heist"
========================================================

Simulates a sophisticated 14-day APT campaign against a financial services company.
This orchestrator coordinates events across all security platforms to create a 
realistic, correlated attack scenario.

Attack Phases:
1. Initial Reconnaissance & Phishing (Days 1-2)
2. Initial Access & Credential Harvesting (Days 3-4) 
3. Persistence & Lateral Movement (Days 5-8)
4. Privilege Escalation & Discovery (Days 9-11)
5. Data Exfiltration & Cover-up (Days 12-14)
"""

import json
import random
import time
import uuid
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Tuple
import importlib
import sys
import os

# Add the current directory to Python path to import our generators
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# Import all our generators
from proofpoint import proofpoint_log
from mimecast import mimecast_log
from microsoft_defender_email import microsoft_defender_email_log
from microsoft_azure_ad_signin import microsoft_azure_ad_signin_log
from crowdstrike_falcon import crowdstrike_log
from darktrace import darktrace_log
from netskope import netskope_log
from cyberark_pas import cyberark_pas_log
from beyondtrust_passwordsafe import beyondtrust_passwordsafe_log
from hashicorp_vault import hashicorp_vault_log
from microsoft_365_mgmt_api import microsoft_365_mgmt_api_log
from sentinelone_endpoint import sentinelone_endpoint_log
from sentinelone_identity import sentinelone_identity_log

class AttackScenarioOrchestrator:
    def __init__(self, retroactive_days: int = 0):
        self.campaign_id = f"op_digital_heist_{uuid.uuid4().hex[:8]}"
        # If retroactive_days > 0, start the campaign in the past
        if retroactive_days > 0:
            self.start_time = datetime.now(timezone.utc) - timedelta(days=retroactive_days)
        else:
            self.start_time = datetime.now(timezone.utc)
        self.retroactive = retroactive_days > 0
        self.target_users = [
            "john.doe@financorp.com",
            "jane.smith@financorp.com", 
            "bob.johnson@financorp.com",
            "alice.williams@financorp.com",
            "admin@financorp.com"
        ]
        self.compromised_users = []
        self.compromised_systems = []
        self.stolen_credentials = []
        self.attack_infrastructure = [
            "185.220.101.42",  # Suspicious external IP
            "94.102.61.13",    # C2 server
            "phishing-bank-security.com",  # Phishing domain
            "secure-financorp-update.net"  # Typosquatted domain
        ]
        
    def generate_scenario(self, days: int = 14, events_per_day: int = 50) -> List[Dict]:
        """Generate the complete attack scenario"""
        print(f"🎯 Generating Operation Digital Heist - {days} day campaign")
        print(f"📊 Campaign ID: {self.campaign_id}")
        print(f"🎪 Target: FinanceCorp Financial Services")
        if self.retroactive:
            print(f"⏰ Retroactive Mode: Events from {self.start_time.strftime('%Y-%m-%d')} to {datetime.now(timezone.utc).strftime('%Y-%m-%d')}")
        else:
            print(f"⏰ Start Time: {self.start_time.strftime('%Y-%m-%d %H:%M:%S UTC')}")
        print("=" * 60)
        
        all_events = []
        
        for day in range(days):
            day_start = self.start_time + timedelta(days=day)
            print(f"\n📅 Day {day + 1}: {day_start.strftime('%Y-%m-%d')}")
            
            # Determine attack phase
            if day < 2:
                phase = "reconnaissance"
                print("🔍 Phase: Initial Reconnaissance & Phishing")
            elif day < 4:
                phase = "initial_access"
                print("🚪 Phase: Initial Access & Credential Harvesting")
            elif day < 8:
                phase = "persistence"
                print("🔒 Phase: Persistence & Lateral Movement")
            elif day < 11:
                phase = "escalation"
                print("⬆️  Phase: Privilege Escalation & Discovery")
            else:
                phase = "exfiltration"
                print("📤 Phase: Data Exfiltration & Cover-up")
            
            # Generate events for this day
            day_events = self._generate_day_events(day, phase, events_per_day)
            all_events.extend(day_events)
            
            print(f"   Generated {len(day_events)} events")
        
        print(f"\n✅ Campaign Complete: {len(all_events)} total events generated")
        print(f"🔴 Compromised Users: {len(self.compromised_users)}")
        print(f"💻 Compromised Systems: {len(self.compromised_systems)}")
        print(f"🔑 Stolen Credentials: {len(self.stolen_credentials)}")
        
        return all_events
    
    def _generate_day_events(self, day: int, phase: str, target_events: int) -> List[Dict]:
        """Generate events for a specific day and phase"""
        events = []
        day_start = self.start_time + timedelta(days=day)
        
        # Define event distribution by phase
        event_distribution = {
            "reconnaissance": {
                "email_security": 0.3,    # Heavy phishing attempts
                "identity": 0.15,         # Failed login attempts
                "network": 0.15,          # External reconnaissance 
                "endpoint": 0.15,         # Limited endpoint activity
                "sentinelone_endpoint": 0.1,  # SentinelOne endpoint monitoring
                "sentinelone_identity": 0.05, # SentinelOne identity monitoring
                "cloud": 0.1              # Cloud enumeration
            },
            "initial_access": {
                "email_security": 0.25,   # Successful phishing
                "identity": 0.2,          # Successful compromises
                "endpoint": 0.15,         # Malware deployment
                "sentinelone_endpoint": 0.15, # SentinelOne threat detection
                "sentinelone_identity": 0.1,  # SentinelOne authentication events
                "network": 0.1,           # C2 communication
                "cloud": 0.05             # Initial cloud access
            },
            "persistence": {
                "endpoint": 0.2,          # Persistence mechanisms
                "sentinelone_endpoint": 0.2,  # SentinelOne behavioral detection
                "identity": 0.15,         # Credential theft
                "sentinelone_identity": 0.1,  # SentinelOne identity anomalies
                "network": 0.15,          # Lateral movement
                "privileged_access": 0.15, # Privilege escalation attempts
                "cloud": 0.05             # Cloud persistence
            },
            "escalation": {
                "privileged_access": 0.3, # Heavy privilege escalation
                "sentinelone_endpoint": 0.2,  # SentinelOne advanced threats
                "endpoint": 0.15,         # Advanced malware
                "sentinelone_identity": 0.1,  # SentinelOne privilege escalation
                "network": 0.15,          # Internal reconnaissance
                "secrets": 0.05,          # Secrets access
                "cloud": 0.05             # Cloud privilege escalation
            },
            "exfiltration": {
                "network": 0.25,          # Data exfiltration
                "cloud": 0.25,            # Cloud data access
                "sentinelone_endpoint": 0.2,  # SentinelOne data access detection
                "privileged_access": 0.15, # High-privilege activities
                "sentinelone_identity": 0.1,  # SentinelOne suspicious access
                "endpoint": 0.05,         # Evidence cleanup
                "secrets": 0.05           # Secrets theft
            }
        }
        
        distribution = event_distribution[phase]
        
        for i in range(target_events):
            # Determine event time within the day
            event_time = day_start + timedelta(
                hours=random.randint(0, 23),
                minutes=random.randint(0, 59),
                seconds=random.randint(0, 59)
            )
            
            # Select event category based on distribution
            category = random.choices(
                list(distribution.keys()),
                weights=list(distribution.values())
            )[0]
            
            # Generate event based on category and phase
            event = self._generate_phase_event(category, phase, event_time, day)
            if event:
                events.append(event)
        
        return sorted(events, key=lambda x: x.get('timestamp', ''))
    
    def _generate_phase_event(self, category: str, phase: str, event_time: datetime, day: int) -> Dict:
        """Generate a specific event based on category and phase"""
        
        # Create base context for correlation
        base_context = {
            'campaign_id': self.campaign_id,
            'phase': phase,
            'day': day + 1,
            'timestamp': event_time.strftime('%Y-%m-%dT%H:%M:%S.%fZ')
        }
        
        try:
            if category == "email_security":
                return self._generate_email_event(phase, event_time, base_context)
            elif category == "identity":
                return self._generate_identity_event(phase, event_time, base_context)
            elif category == "endpoint":
                return self._generate_endpoint_event(phase, event_time, base_context)
            elif category == "network":
                return self._generate_network_event(phase, event_time, base_context)
            elif category == "cloud":
                return self._generate_cloud_event(phase, event_time, base_context)
            elif category == "privileged_access":
                return self._generate_privileged_access_event(phase, event_time, base_context)
            elif category == "secrets":
                return self._generate_secrets_event(phase, event_time, base_context)
            elif category == "sentinelone_endpoint":
                return self._generate_sentinelone_endpoint_event(phase, event_time, base_context)
            elif category == "sentinelone_identity":
                return self._generate_sentinelone_identity_event(phase, event_time, base_context)
                
        except Exception as e:
            print(f"Error generating {category} event: {e}")
            return None
    
    def _generate_email_event(self, phase: str, event_time: datetime, context: Dict) -> Dict:
        """Generate email security events"""
        if phase == "reconnaissance":
            # Heavy phishing campaign
            if random.random() < 0.7:  # 70% malicious
                event_data = proofpoint_log({
                    "threatType": "phish",
                    "subject": "Urgent: FinanceCorp Security Update Required",
                    "sender": f"security@{random.choice(['financorp-security.com', 'phishing-bank-security.com'])}",
                    "recipient": random.choice(self.target_users)
                })
            else:
                event_data = mimecast_log()
        
        elif phase == "initial_access":
            # Successful phishing with malware
            target_user = random.choice(self.target_users)
            if target_user not in self.compromised_users:
                self.compromised_users.append(target_user)
            
            event_data = microsoft_defender_email_log({
                "ThreatTypes": "Malware",
                "RecipientEmailAddress": target_user,
                "Subject": "Invoice Payment - Action Required",
                "DeliveryAction": "Delivered"  # Successful delivery
            })
        
        else:
            # Ongoing email activities
            event_data = random.choice([proofpoint_log, mimecast_log, microsoft_defender_email_log])()
        
        return {
            **context,
            'platform': 'email_security',
            'raw_event': event_data
        }
    
    def _generate_identity_event(self, phase: str, event_time: datetime, context: Dict) -> Dict:
        """Generate identity and authentication events"""
        if phase == "reconnaissance":
            # Failed login attempts
            event_data = microsoft_azure_ad_signin_log({
                "resultType": "50126",  # Invalid username/password
                "userPrincipalName": random.choice(self.target_users),
                "ipAddress": random.choice(self.attack_infrastructure[:2])
            })
        
        elif phase == "initial_access":
            # Successful compromise
            compromised_user = random.choice(self.target_users)
            if compromised_user not in self.compromised_users:
                self.compromised_users.append(compromised_user)
            
            event_data = microsoft_azure_ad_signin_log({
                "resultType": "0",  # Success
                "userPrincipalName": compromised_user,
                "ipAddress": random.choice(self.attack_infrastructure),
                "riskLevelAggregated": "high"
            })
        
        else:
            # Ongoing authentication activities
            event_data = microsoft_azure_ad_signin_log()
        
        return {
            **context,
            'platform': 'identity',
            'raw_event': event_data
        }
    
    def _generate_endpoint_event(self, phase: str, event_time: datetime, context: Dict) -> Dict:
        """Generate endpoint security events"""
        if phase == "initial_access":
            # Malware deployment
            event_data = crowdstrike_log({
                "event_simpleName": "ProcessRollup2",
                "name": "Malware Detected",
                "UserName": random.choice(self.compromised_users) if self.compromised_users else random.choice(self.target_users),
                "ThreatFamily": "Emotet",
                "Severity": 10
            })
        
        elif phase == "persistence":
            # Persistence mechanisms
            event_data = crowdstrike_log({
                "event_simpleName": "RegistryOperationDetectInfo", 
                "name": "Registry Modification",
                "category": "persistence"
            })
        
        elif phase == "escalation":
            # Privilege escalation
            event_data = crowdstrike_log({
                "event_simpleName": "CredentialDumpTool",
                "name": "Credential Theft Attempt",
                "Severity": 10
            })
        
        else:
            event_data = crowdstrike_log()
        
        return {
            **context,
            'platform': 'crowdstrike_falcon',
            'raw_event': event_data
        }
    
    def _generate_network_event(self, phase: str, event_time: datetime, context: Dict) -> Dict:
        """Generate network security events"""
        if phase == "reconnaissance":
            # External reconnaissance
            event_data = darktrace_log({
                "model": {
                    "name": "Device / Suspicious Domain",
                    "description": "Device connected to a domain with suspicious characteristics"
                },
                "score": 0.75,
                "externalDomain": random.choice(["phishing-bank-security.com", "secure-financorp-update.net"])
            })
        
        elif phase == "persistence":
            # Lateral movement
            event_data = darktrace_log({
                "model": {
                    "name": "Anomalous Server Activity / Rare External from Server",
                    "description": "Server initiated unusual outbound connection to external IP"
                },
                "score": 0.85,
                "externalIP": random.choice(self.attack_infrastructure[:2])
            })
        
        elif phase == "exfiltration":
            # Data exfiltration
            event_data = darktrace_log({
                "title": "Potential Data Exfiltration",
                "category": "exfiltration",
                "group_severity": 90,
                "dataTransfer": {
                    "bytesTransferred": random.randint(100000000, 1000000000),  # 100MB-1GB
                    "destinations": [random.choice(self.attack_infrastructure)]
                }
            })
        
        else:
            event_data = darktrace_log()
        
        return {
            **context,
            'platform': 'network',
            'raw_event': event_data
        }
    
    def _generate_cloud_event(self, phase: str, event_time: datetime, context: Dict) -> Dict:
        """Generate cloud security events"""
        if phase == "initial_access":
            event_data = netskope_log({
                "event_type": "page",
                "action": "allow",
                "user": random.choice(self.compromised_users) if self.compromised_users else random.choice(self.target_users),
                "url": "https://financorp.sharepoint.com/sites/sensitive-data"
            })
        
        elif phase == "exfiltration":
            event_data = netskope_log({
                "event_type": "download",
                "action": "allow", 
                "file_name": "customer_financial_records.xlsx",
                "file_size": random.randint(50000000, 500000000),  # 50-500MB
                "breach_score": 95
            })
        
        else:
            event_data = netskope_log()
        
        return {
            **context,
            'platform': 'cloud',
            'raw_event': event_data
        }
    
    def _generate_privileged_access_event(self, phase: str, event_time: datetime, context: Dict) -> Dict:
        """Generate privileged access management events"""
        if phase == "escalation":
            # High-privilege account access
            event_data = random.choice([cyberark_pas_log, beyondtrust_passwordsafe_log])({
                "EventType": "AccountCheckout",
                "AccountName": "administrator",
                "UserName": random.choice(self.compromised_users) if self.compromised_users else random.choice(self.target_users),
                "SystemName": "DC01",
                "Severity": "Critical"
            })
            
            # Track compromised privileged accounts
            if "administrator" not in self.stolen_credentials:
                self.stolen_credentials.append("administrator")
        
        else:
            event_data = random.choice([cyberark_pas_log, beyondtrust_passwordsafe_log])()
        
        return {
            **context,
            'platform': 'privileged_access',
            'raw_event': event_data
        }
    
    def _generate_secrets_event(self, phase: str, event_time: datetime, context: Dict) -> Dict:
        """Generate secrets management events"""
        if phase == "escalation" or phase == "exfiltration":
            # Secrets access
            event_data = hashicorp_vault_log({
                "request": {
                    "operation": "read",
                    "path": "secret/data/prod/database-credentials"
                },
                "auth": {
                    "display_name": random.choice(self.compromised_users) if self.compromised_users else random.choice(self.target_users)
                }
            })
        
        else:
            event_data = hashicorp_vault_log()
        
        return {
            **context,
            'platform': 'secrets',
            'raw_event': event_data
        }
    
    def _generate_m365_event(self, phase: str, event_time: datetime, context: Dict) -> Dict:
        """Generate Microsoft 365 management events"""
        if phase == "exfiltration":
            event_data = microsoft_365_mgmt_api_log({
                "category": "DataExfiltration",
                "activityGroupName": "Mass download by a single user",
                "severity": "critical"
            })
        else:
            event_data = microsoft_365_mgmt_api_log()
        
        return {
            **context,
            'platform': 'm365',
            'raw_event': event_data
        }
    
    def _generate_sentinelone_endpoint_event(self, phase: str, event_time: datetime, context: Dict) -> Dict:
        """Generate SentinelOne endpoint security events"""
        if phase == "reconnaissance":
            # Reconnaissance phase - process monitoring and network connections
            event_data = sentinelone_endpoint_log({
                "event.type": "Network Connection",
                "event.category": "Network",
                "src.process.user": random.choice(self.target_users).split('@')[0],
                "dst.ip.address": random.choice(self.attack_infrastructure[:2]),
                "indicator.category": "Reconnaissance",
                "src.process.indicatorReconnaissanceCount": random.randint(1, 5)
            })
        
        elif phase == "initial_access":
            # Initial access - malware detection and process execution
            compromised_user = random.choice(self.target_users).split('@')[0]
            if compromised_user not in [u.split('@')[0] for u in self.compromised_users]:
                self.compromised_users.append(f"{compromised_user}@financorp.com")
            
            event_data = sentinelone_endpoint_log({
                "event.type": "Malware Detection",
                "event.category": "Threats",
                "src.process.user": compromised_user,
                "indicator.category": "Malware",
                "indicator.name": "Emotet",
                "src.process.indicatorEvasionCount": random.randint(1, 3),
                "src.process.indicatorExploitationCount": random.randint(1, 2)
            })
        
        elif phase == "persistence":
            # Persistence phase - registry modifications and file operations
            event_data = sentinelone_endpoint_log({
                "event.type": "Registry Modification",
                "event.category": "Registry",
                "src.process.user": random.choice([u.split('@')[0] for u in self.compromised_users]) if self.compromised_users else "john.doe",
                "registry.keyPath": "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
                "src.process.indicatorPersistenceCount": random.randint(1, 4),
                "src.process.registryChangeCount": random.randint(5, 15)
            })
        
        elif phase == "escalation":
            # Escalation phase - privilege escalation and credential access
            event_data = sentinelone_endpoint_log({
                "event.type": "Credential Access",
                "event.category": "Credentials",
                "src.process.user": random.choice([u.split('@')[0] for u in self.compromised_users]) if self.compromised_users else "john.doe",
                "src.process.name": "mimikatz.exe",
                "indicator.category": "Credential Theft",
                "src.process.indicatorPostExploitationCount": random.randint(1, 3),
                "src.process.crossProcessCount": random.randint(10, 25)
            })
        
        elif phase == "exfiltration":
            # Exfiltration phase - file access and network transfers
            event_data = sentinelone_endpoint_log({
                "event.type": "File Access",
                "event.category": "File",
                "src.process.user": random.choice([u.split('@')[0] for u in self.compromised_users]) if self.compromised_users else "john.doe",
                "tgt.file.path": "C:\\Users\\john.doe\\Documents\\Financial_Data.xlsx",
                "tgt.file.size": random.randint(1048576, 104857600),  # 1MB to 100MB
                "src.process.netConnOutCount": random.randint(5, 15)
            })
        
        else:
            # Default endpoint activity
            event_data = sentinelone_endpoint_log()
        
        return {
            **context,
            'platform': 'sentinelone_endpoint',
            'raw_event': event_data
        }
    
    def _generate_sentinelone_identity_event(self, phase: str, event_time: datetime, context: Dict) -> Dict:
        """Generate SentinelOne identity and authentication events"""
        if phase == "reconnaissance":
            # Reconnaissance phase - failed login attempts
            event_data = sentinelone_identity_log({
                "event.type": "Failed Login",
                "event.category": "Authentication",
                "event.login.loginIsSuccessful": False,
                "event.login.userName": random.choice(self.target_users).split('@')[0],
                "src.ip.address": random.choice(self.attack_infrastructure[:2]),
                "winEventLog.id": 4625,
                "indicator.category": "Brute Force"
            })
        
        elif phase == "initial_access":
            # Initial access - successful compromise
            compromised_user = random.choice(self.target_users).split('@')[0]
            if f"{compromised_user}@financorp.com" not in self.compromised_users:
                self.compromised_users.append(f"{compromised_user}@financorp.com")
            
            event_data = sentinelone_identity_log({
                "event.type": "User Login",
                "event.category": "Authentication",
                "event.login.loginIsSuccessful": True,
                "event.login.userName": compromised_user,
                "src.ip.address": random.choice(self.attack_infrastructure),
                "winEventLog.id": 4624,
                "indicator.category": "Suspicious Login",
                "indicator.description": f"Login from suspicious IP for user {compromised_user}"
            })
        
        elif phase == "persistence":
            # Persistence phase - account modifications
            event_data = sentinelone_identity_log({
                "event.type": "Group Membership Change",
                "event.category": "Account Management",
                "event.login.userName": random.choice([u.split('@')[0] for u in self.compromised_users]) if self.compromised_users else "john.doe",
                "winEventLog.id": 4728,
                "winEventLog.description": "A member was added to a security-enabled global group"
            })
        
        elif phase == "escalation":
            # Escalation phase - privilege escalation
            event_data = sentinelone_identity_log({
                "event.type": "Privilege Escalation",
                "event.category": "Authorization",
                "event.login.userName": random.choice([u.split('@')[0] for u in self.compromised_users]) if self.compromised_users else "john.doe",
                "winEventLog.id": 4672,
                "indicator.category": "Privilege Escalation",
                "indicator.description": "Special privileges assigned to new logon"
            })
        
        elif phase == "exfiltration":
            # Exfiltration phase - suspicious access patterns
            event_data = sentinelone_identity_log({
                "event.type": "Suspicious Login Pattern",
                "event.category": "Behavioral Analytics",
                "event.login.userName": random.choice([u.split('@')[0] for u in self.compromised_users]) if self.compromised_users else "john.doe",
                "indicator.category": "Anomalous Behavior",
                "indicator.description": "Unusual access pattern detected - potential data exfiltration"
            })
        
        else:
            # Default identity activity
            event_data = sentinelone_identity_log()
        
        return {
            **context,
            'platform': 'sentinelone_identity',
            'raw_event': event_data
        }

def main():
    """Main execution function"""
    print("🚨 ATTACK SCENARIO ORCHESTRATOR")
    print("Operation Digital Heist - Advanced Persistent Threat Simulation")
    print("=" * 60)
    
    # Ask about retroactive mode
    retroactive = input("Generate retroactive scenario? (y/N): ").lower().startswith('y')
    if retroactive:
        retroactive_days = int(input("How many days in the past should the campaign start? (default 14): ") or "14")
    else:
        retroactive_days = 0
    
    # Initialize orchestrator
    orchestrator = AttackScenarioOrchestrator(retroactive_days=retroactive_days) 
    
    # Generate scenario (can customize days and events per day)
    if retroactive:
        # For retroactive scenarios, default to the number of retroactive days
        days = int(input(f"Enter campaign duration in days (default {retroactive_days}): ") or str(retroactive_days))
    else:
        days = int(input("Enter campaign duration in days (default 14): ") or "14")
    events_per_day = int(input("Enter events per day (default 50): ") or "50")
    
    # Generate the complete attack scenario
    scenario_events = orchestrator.generate_scenario(days=days, events_per_day=events_per_day)
    
    # Save scenario to file
    output_file = f"attack_scenario_{orchestrator.campaign_id}.json"
    with open(output_file, 'w') as f:
        json.dump(scenario_events, f, indent=2, default=str)
    
    print(f"\n💾 Scenario saved to: {output_file}")
    print("\n🔍 Scenario Summary:")
    print(f"   📊 Total Events: {len(scenario_events)}")
    print(f"   👤 Compromised Users: {len(orchestrator.compromised_users)}")
    print(f"   💻 Compromised Systems: {len(orchestrator.compromised_systems)}")
    print(f"   🔑 Stolen Credentials: {len(orchestrator.stolen_credentials)}")
    
    # Option to send events to HEC
    send_to_hec = input("\nSend events to HEC endpoint? (y/N): ").lower().startswith('y')
    if send_to_hec:
        print("🚀 Sending events to HEC... (This would integrate with hec_sender.py)")
        # TODO: Integrate with hec_sender.py to actually send events
    
    print("\n✅ Attack scenario generation complete!")

if __name__ == "__main__":
    main()