"""
Scenario service for managing attack scenarios
"""
from typing import Dict, Any, List, Optional
import uuid
import time
import asyncio
from datetime import datetime
import logging
import os
import sys
import importlib
from pathlib import Path

logger = logging.getLogger(__name__)


class ScenarioService:
    def __init__(self):
        self.running_scenarios = {}
        # Path works both locally and in Docker container
        api_root = Path(__file__).parent.parent.parent
        self.configs_dir = api_root / "scenarios" / "configs"
        self.scenario_templates = {
            "phishing_campaign": {
                "id": "phishing_campaign",
                "name": "Phishing Campaign",
                "description": "Multi-stage phishing attack with credential harvesting",
                "phases": [
                    {"name": "Initial Email", "generators": ["mimecast"], "duration": 5},
                    {"name": "Credential Harvest", "generators": ["okta_authentication"], "duration": 10},
                    {"name": "Lateral Movement", "generators": ["crowdstrike_falcon"], "duration": 15}
                ]
            },
            "ransomware_attack": {
                "id": "ransomware_attack",
                "name": "Ransomware Attack",
                "description": "Ransomware deployment and lateral movement",
                "phases": [
                    {"name": "Initial Compromise", "generators": ["crowdstrike_falcon"], "duration": 10},
                    {"name": "Discovery", "generators": ["microsoft_windows_eventlog"], "duration": 15},
                    {"name": "Lateral Movement", "generators": ["microsoft_windows_eventlog"], "duration": 20},
                    {"name": "Data Encryption", "generators": ["veeam_backup"], "duration": 25},
                    {"name": "Ransom Demand", "generators": ["mimecast"], "duration": 5}
                ]
            },
            "insider_threat": {
                "id": "insider_threat",
                "name": "Insider Threat",
                "description": "Malicious insider data exfiltration",
                "phases": [
                    {"name": "Data Discovery", "generators": ["microsoft_365_collaboration"], "duration": 30},
                    {"name": "Data Access", "generators": ["microsoft_365_collaboration"], "duration": 20},
                    {"name": "Data Staging", "generators": ["aws_cloudtrail"], "duration": 15},
                    {"name": "Data Exfiltration", "generators": ["netskope"], "duration": 10}
                ]
            },
            "attack_scenario_orchestrator": {
                "id": "attack_scenario_orchestrator",
                "name": "Operation Digital Heist",
                "description": "14-day APT campaign against financial services - reconnaissance, credential harvesting, lateral movement, data exfiltration",
                "phases": [
                    {"name": "Reconnaissance & Phishing", "generators": ["proofpoint", "mimecast", "microsoft_defender_email"], "duration": 60},
                    {"name": "Initial Access & Credential Harvesting", "generators": ["microsoft_azure_ad_signin", "crowdstrike_falcon", "darktrace"], "duration": 60},
                    {"name": "Persistence & Lateral Movement", "generators": ["netskope", "cyberark_pas", "beyondtrust_passwordsafe", "hashicorp_vault"], "duration": 120},
                    {"name": "Privilege Escalation & Discovery", "generators": ["microsoft_365_mgmt_api", "sentinelone_endpoint", "sentinelone_identity"], "duration": 90},
                    {"name": "Data Exfiltration & Cover-up", "generators": ["netskope", "darktrace", "crowdstrike_falcon"], "duration": 60}
                ]
            },
            "enterprise_scenario_sender": {
                "id": "enterprise_scenario_sender",
                "name": "Enterprise Attack Scenario",
                "description": "330+ event enterprise attack scenario across 18+ security platforms",
                "phases": [
                    {"name": "Perimeter Breach", "generators": ["fortinet_fortigate", "cisco_umbrella", "imperva_waf", "paloalto_firewall"], "duration": 30},
                    {"name": "Phishing & Initial Access", "generators": ["proofpoint", "zscaler", "netskope"], "duration": 30},
                    {"name": "Credential Harvesting", "generators": ["crowdstrike_falcon", "okta_authentication", "microsoft_azuread", "cisco_duo", "pingone_mfa"], "duration": 45},
                    {"name": "Lateral Movement", "generators": ["microsoft_windows_eventlog", "cisco_ise", "f5_networks"], "duration": 45},
                    {"name": "Privilege Escalation", "generators": ["aws_cloudtrail", "hashicorp_vault", "github_audit"], "duration": 30},
                    {"name": "Persistence & Exfiltration", "generators": ["harness_ci", "pingprotect"], "duration": 30}
                ]
            },
            "showcase_scenario_sender": {
                "id": "showcase_scenario_sender",
                "name": "AI-SIEM Showcase Scenario",
                "description": "Enterprise showcase attack scenario for AI-SIEM demonstration",
                "phases": [
                    {"name": "Perimeter Attack", "generators": ["fortinet_fortigate", "imperva_waf"], "duration": 20},
                    {"name": "Cloud Reconnaissance", "generators": ["aws_cloudtrail", "zscaler"], "duration": 20},
                    {"name": "Identity Compromise", "generators": ["okta_authentication", "microsoft_azuread", "cisco_duo"], "duration": 30},
                    {"name": "Email Attack", "generators": ["proofpoint"], "duration": 15},
                    {"name": "Endpoint Compromise", "generators": ["crowdstrike_falcon", "microsoft_windows_eventlog"], "duration": 30},
                    {"name": "Secrets Access", "generators": ["hashicorp_vault", "harness_ci"], "duration": 20},
                    {"name": "MFA Bypass", "generators": ["pingone_mfa", "pingprotect"], "duration": 15}
                ]
            },
            "enterprise_scenario_sender_10min": {
                "id": "enterprise_scenario_sender_10min",
                "name": "Enterprise Breach (10 min)",
                "description": "Compressed 10-minute enterprise attack scenario",
                "phases": [
                    {"name": "Perimeter Breach", "generators": ["fortinet_fortigate", "cisco_umbrella", "imperva_waf"], "duration": 2},
                    {"name": "Credential Harvesting", "generators": ["crowdstrike_falcon", "okta_authentication", "microsoft_azuread", "cisco_duo"], "duration": 3},
                    {"name": "Lateral Movement", "generators": ["microsoft_windows_eventlog", "cisco_ise", "f5_networks"], "duration": 2},
                    {"name": "Privilege Escalation", "generators": ["aws_cloudtrail", "hashicorp_vault", "github_audit", "harness_ci"], "duration": 3}
                ]
            },
            "finance_mfa_fatigue_scenario": {
                "id": "finance_mfa_fatigue_scenario",
                "name": "Finance Employee MFA Fatigue Attack",
                "description": "8-day scenario with baseline behavior, MFA fatigue attack from Russia, OneDrive exfiltration, and SOAR response",
                "phases": [
                    {"name": "Normal Behavior (Days 1-7)", "generators": ["okta_authentication", "microsoft_azuread", "microsoft_365_collaboration"], "duration": 7},
                    {"name": "MFA Fatigue Attack", "generators": ["okta_authentication"], "duration": 1},
                    {"name": "Data Exfiltration", "generators": ["microsoft_365_collaboration"], "duration": 1},
                    {"name": "Detection & Response", "generators": ["okta_authentication"], "duration": 1}
                ]
            },
            "insider_cloud_download_exfiltration": {
                "id": "insider_cloud_download_exfiltration",
                "name": "Insider Data Exfiltration via Cloud Download",
                "description": "8-day insider threat scenario with baseline, large-volume M365/SharePoint downloads, USB copy, and detection alerts",
                "phases": [
                    {"name": "Normal Behavior (Days 1-7)", "generators": ["okta_authentication", "microsoft_365_collaboration"], "duration": 7},
                    {"name": "Off-Hours Access & Mass Download", "generators": ["okta_authentication", "microsoft_365_collaboration"], "duration": 1},
                    {"name": "USB Media Copy", "generators": ["sentinelone_endpoint"], "duration": 1},
                    {"name": "Detection Alerts", "generators": ["proofpoint", "sentinelone_endpoint"], "duration": 1}
                ]
            }
            ,
            "hr_phishing_pdf_c2": {
                "id": "hr_phishing_pdf_c2",
                "name": "HR Phishing PDF -> PowerShell -> Scheduled Task -> C2",
                "description": "HR spearphish leading to PDF execution, persistence, and C2 beacons across Proofpoint, M365, SentinelOne, and Palo Alto.",
                "phases": [
                    {"name": "Normal Behavior Baseline", "generators": ["proofpoint", "microsoft_365_collaboration", "sentinelone_endpoint"], "duration": 5},
                    {"name": "Phishing Delivery", "generators": ["proofpoint"], "duration": 1},
                    {"name": "Email Interaction & Download", "generators": ["microsoft_365_collaboration", "paloalto_firewall"], "duration": 1},
                    {"name": "Execution & Persistence", "generators": ["sentinelone_endpoint"], "duration": 1},
                    {"name": "Command & Control", "generators": ["sentinelone_endpoint", "paloalto_firewall"], "duration": 1},
                    {"name": "Detection & Response", "generators": ["proofpoint", "sentinelone_endpoint"], "duration": 1}
                ]
            }
        }
        self._load_json_scenarios()
    
    def _load_json_scenarios(self):
        """Load scenario metadata from JSON files in configs directory"""
        logger.info(f"Attempting to load scenarios from: {self.configs_dir}")
        
        if not self.configs_dir.exists():
            logger.warning(f"Scenarios configs directory not found: {self.configs_dir}")
            return
        
        logger.info(f"Configs directory exists, scanning for JSON files...")
        json_files = list(self.configs_dir.glob("*.json"))
        logger.info(f"Found {len(json_files)} JSON files in configs directory")
        
        for json_file in json_files:
            try:
                scenario_id = json_file.stem
                
                # Skip if already in templates (hardcoded ones take precedence)
                if scenario_id in self.scenario_templates:
                    continue
                
                # Load JSON to get event count and metadata
                with open(json_file, 'r') as f:
                    events = json.load(f)
                
                # Extract unique phases
                phases = []
                seen_phases = set()
                for event in events:
                    phase = event.get("phase", "unknown")
                    if phase not in seen_phases:
                        seen_phases.add(phase)
                        phases.append({"name": phase.replace("_", " ").title(), "generators": [], "duration": 10})
                
                # Create scenario metadata
                self.scenario_templates[scenario_id] = {
                    "id": scenario_id,
                    "name": scenario_id.replace("_", " ").title(),
                    "description": f"Generated scenario with {len(events)} events across {len(phases)} phases",
                    "phases": phases,
                    "event_count": len(events),
                    "json_file": str(json_file),
                    "is_generated": True
                }
                
                logger.info(f"Loaded scenario: {scenario_id} ({len(events)} events)")
                
            except Exception as e:
                logger.error(f"Failed to load scenario from {json_file}: {e}")
    
    async def list_scenarios(
        self, 
        category: Optional[str] = None, 
        search: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """List available scenarios"""
        scenarios = list(self.scenario_templates.values())
        
        if search:
            search_lower = search.lower()
            scenarios = [
                s for s in scenarios 
                if search_lower in s["name"].lower() or search_lower in s["description"].lower()
            ]
        
        # Add metadata
        for scenario in scenarios:
            scenario["phase_count"] = len(scenario.get("phases", []))
            scenario["estimated_duration_minutes"] = sum(
                phase.get("duration", 0) for phase in scenario.get("phases", [])
            )
        
        return scenarios
    
    async def get_scenario(self, scenario_id: str) -> Optional[Dict[str, Any]]:
        """Get detailed scenario information"""
        return self.scenario_templates.get(scenario_id)
    
    async def start_scenario(
        self, 
        scenario_id: str, 
        speed: str = "fast", 
        dry_run: bool = False,
        background_tasks=None
    ) -> str:
        """Start scenario execution"""
        scenario = await self.get_scenario(scenario_id)
        if not scenario:
            raise ValueError(f"Scenario '{scenario_id}' not found")
        
        execution_id = str(uuid.uuid4())
        
        self.running_scenarios[execution_id] = {
            "scenario_id": scenario_id,
            "execution_id": execution_id,
            "status": "running",
            "started_at": datetime.utcnow().isoformat(),
            "speed": speed,
            "dry_run": dry_run,
            "progress": 0
        }
        
        if background_tasks:
            background_tasks.add_task(self._execute_scenario, execution_id, scenario)
        
        return execution_id
    
    async def _execute_scenario(self, execution_id: str, scenario: Dict[str, Any]):
        """Execute scenario in background"""
        try:
            # Special handling: invoke sender for HR phishing scenario to generate and send real events
            if scenario.get("id") == "hr_phishing_pdf_c2":
                # Compute repo root and add scenarios path for import
                base_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(__file__))))
                scenarios_dir = os.path.join(base_dir, "scenarios")
                if scenarios_dir not in sys.path:
                    sys.path.insert(0, scenarios_dir)
                try:
                    sender = importlib.import_module("hr_phishing_pdf_c2_sender")
                    workers_env = os.getenv("S1_HEC_WORKERS", "8")
                    workers = int(workers_env) if workers_env.isdigit() else 8
                    # Run the blocking sender in a thread to avoid blocking the event loop
                    await asyncio.to_thread(sender.send_hr_phishing_pdf_c2, workers)
                    self.running_scenarios[execution_id]["status"] = "completed"
                    self.running_scenarios[execution_id]["completed_at"] = datetime.utcnow().isoformat()
                    return
                except Exception as e:
                    logger.error(f"Failed to run HR phishing scenario sender: {e}")
                    self.running_scenarios[execution_id]["status"] = "failed"
                    self.running_scenarios[execution_id]["error"] = str(e)
                    return

            phases = scenario.get("phases", [])
            
            for i, phase in enumerate(phases):
                # Simulate phase execution
                phase_duration = phase.get("duration", 5)
                
                # Update progress
                progress = ((i + 1) / len(phases)) * 100
                self.running_scenarios[execution_id]["progress"] = progress
                self.running_scenarios[execution_id]["current_phase"] = phase["name"]
                
                # Simulate work
                await asyncio.sleep(min(phase_duration / 10, 2))  # Scaled down for demo
            
            self.running_scenarios[execution_id]["status"] = "completed"
            self.running_scenarios[execution_id]["completed_at"] = datetime.utcnow().isoformat()
            
        except Exception as e:
            logger.error(f"Scenario execution failed: {e}")
            self.running_scenarios[execution_id]["status"] = "failed"
            self.running_scenarios[execution_id]["error"] = str(e)
    
    async def get_execution_status(
        self, 
        scenario_id: str, 
        execution_id: Optional[str] = None
    ) -> Optional[Dict[str, Any]]:
        """Get execution status"""
        if execution_id:
            return self.running_scenarios.get(execution_id)
        
        # Return latest execution for scenario
        for exec_id, execution in self.running_scenarios.items():
            if execution["scenario_id"] == scenario_id:
                return execution
        
        return None
    
    async def stop_execution(self, scenario_id: str, execution_id: str) -> bool:
        """Stop scenario execution"""
        if execution_id in self.running_scenarios:
            self.running_scenarios[execution_id]["status"] = "stopped"
            self.running_scenarios[execution_id]["stopped_at"] = datetime.utcnow().isoformat()
            return True
        return False
    
    async def get_execution_results(
        self, 
        scenario_id: str, 
        execution_id: str,
        include_events: bool = False
    ) -> Optional[Dict[str, Any]]:
        """Get execution results"""
        execution = self.running_scenarios.get(execution_id)
        if not execution:
            return None
        
        results = {
            "execution_id": execution_id,
            "scenario_id": scenario_id,
            "status": execution["status"],
            "events_generated": 50,  # Mock data
            "total_time_ms": 30000,  # Mock data
            "phases_completed": execution.get("progress", 0) / 100 * len(
                self.scenario_templates.get(scenario_id, {}).get("phases", [])
            )
        }
        
        if include_events:
            # Mock event data
            results["events"] = [
                {
                    "timestamp": datetime.utcnow().isoformat(),
                    "generator": "mimecast",
                    "event_type": "phishing_email",
                    "data": {"sender": "attacker@evil.com", "recipient": "picard@starfleet.corp"}
                }
            ]
        
        return results
    
    async def get_execution_timeline(
        self, 
        scenario_id: str, 
        execution_id: str
    ) -> List[Dict[str, Any]]:
        """Get execution timeline"""
        execution = self.running_scenarios.get(execution_id)
        if not execution:
            return []
        
        # Mock timeline data
        return [
            {
                "timestamp": execution["started_at"],
                "phase": "Initial Email",
                "status": "completed",
                "events_count": 3,
                "generators_used": ["mimecast"]
            },
            {
                "timestamp": datetime.utcnow().isoformat(),
                "phase": "Credential Harvest", 
                "status": "in_progress" if execution["status"] == "running" else "completed",
                "events_count": 5,
                "generators_used": ["okta_authentication"]
            }
        ]
    
    async def create_custom_scenario(self, config: Dict[str, Any]) -> str:
        """Create custom scenario"""
        scenario_id = f"custom_{int(time.time())}"
        
        self.scenario_templates[scenario_id] = {
            "id": scenario_id,
            "name": config["name"],
            "description": config["description"],
            "phases": config["phases"],
            "custom": True
        }
        
        return scenario_id