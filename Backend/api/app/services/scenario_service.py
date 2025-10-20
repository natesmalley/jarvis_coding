"""
Scenario service for managing attack scenarios
"""
from typing import Dict, Any, List, Optional
import uuid
import time
import asyncio
from datetime import datetime
import logging

logger = logging.getLogger(__name__)


class ScenarioService:
    def __init__(self):
        self.running_scenarios = {}
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
            }
        }
    
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