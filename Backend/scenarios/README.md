# Security Scenario Creation Guide

## Overview

This guide provides step-by-step instructions for creating comprehensive security attack scenarios that can be used for testing, detection engineering, and security training. Scenarios simulate realistic attack patterns across multiple data sources and include automated detection and response.

## Table of Contents

1. [Architecture & Structure](#architecture--structure)
2. [Step-by-Step Creation Process](#step-by-step-creation-process)
3. [Available Event Generators](#available-event-generators)
4. [Scenario Components](#scenario-components)
5. [Best Practices](#best-practices)
6. [Example Scenarios](#example-scenarios)
7. [Testing & Validation](#testing--validation)

---

## Architecture & Structure

### File Structure
```
scenarios/
├── README.md                          # This guide
├── scenario_name.py                   # Your scenario script
├── configs/                           # Generated JSON output
│   └── scenario_name.json
└── scenario_hec_sender.py            # HEC sender for replay
```

### Core Dependencies
```python
from datetime import datetime, timedelta
from typing import List, Dict
import json
import sys
import os

# Import event generators from parent directory
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from event_generators.email_security.proofpoint_log import proofpoint_log
from event_generators.identity_access.microsoft_365_log import microsoft_365_log
from event_generators.endpoint_security.sentinelone_log import sentinelone_log
from event_generators.network_security.palo_alto_firewall_log import palo_alto_firewall_log
# Add other generators as needed
```

---

## Step-by-Step Creation Process

### Step 1: Define Victim and Attacker Profiles

Create dictionaries that store all relevant information about the entities in your scenario.

```python
# Victim Profile - Target of the attack
VICTIM_PROFILE = {
    "name": "Sara Mitchell",
    "email": "sara.mitchell@company.com",
    "department": "Human Resources",
    "location": "Austin, Texas",
    "ip": "10.50.25.112",
    "hostname": "HR-SARA-PC",
    "username": "smitchell",
    "title": "HR Manager",
}

# Attacker Profile - Threat actor details
ATTACKER_PROFILE = {
    "sender_email": "hr-benefits@company-update.com",
    "phishing_domain": "temp-files.cloud",
    "c2_ip": "185.234.72.156",
    "c2_port": "443",
    "backup_c2": "malware-updates.tk:8080",
    "malicious_pdf": "Benefits_Update_2024.pdf",
    "payload_url": "hxxp://temp-files.cloud/update.exe",
}
```

### Step 2: Create Helper Functions

These utilities standardize time management and event creation across your scenario.

```python
def get_scenario_time(base_time: datetime, day: int, hour: int, minute: int, second: int = 0) -> str:
    """
    Generate ISO format timestamp for scenario events.
    
    Args:
        base_time: Starting datetime for scenario
        day: Day offset from base_time (1-indexed)
        hour: Hour of day (0-23)
        minute: Minute of hour (0-59)
        second: Second of minute (0-59)
    
    Returns:
        ISO format timestamp string
    """
    target_time = base_time + timedelta(days=day-1)
    target_time = target_time.replace(hour=hour, minute=minute, second=second, microsecond=0)
    return target_time.strftime("%Y-%m-%dT%H:%M:%S.000Z")

def create_event(timestamp: str, event_type: str, phase: str, raw_log: Dict) -> Dict:
    """
    Create standardized event structure.
    
    Args:
        timestamp: ISO format timestamp
        event_type: Type/source of event (e.g., "proofpoint", "sentinelone")
        phase: Attack phase (e.g., "initial_access", "persistence")
        raw_log: The actual event data from generator
    
    Returns:
        Structured event dictionary
    """
    return {
        "timestamp": timestamp,
        "event_type": event_type,
        "phase": phase,
        "raw_log": raw_log
    }
```

### Step 3: Generate Normal Baseline Activity

Create benign activity to establish normal behavior patterns before the attack.

```python
def generate_normal_baseline(base_time: datetime, days: int = 5) -> List[Dict]:
    """
    Generate normal user activity baseline.
    
    Args:
        base_time: Starting datetime
        days: Number of days of baseline to generate
    
    Returns:
        List of normal activity events
    """
    events = []
    
    for day in range(1, days + 1):
        print(f"Day {day}: {(base_time + timedelta(days=day-1)).strftime('%Y-%m-%d')}")
        
        # Morning login (9:00 AM)
        login_time = get_scenario_time(base_time, day, 9, 0)
        m365_login = microsoft_365_log({
            "Operation": "UserLoggedIn",
            "UserId": VICTIM_PROFILE["email"],
            "ClientIP": VICTIM_PROFILE["ip"],
            "ResultStatus": "Success",
        })
        events.append(create_event(login_time, "microsoft_365", "baseline", m365_login))
        
        # File access (10:30 AM)
        file_time = get_scenario_time(base_time, day, 10, 30)
        m365_file = microsoft_365_log({
            "Operation": "FileAccessed",
            "UserId": VICTIM_PROFILE["email"],
            "SourceFileName": "Q2_Budget_Report.xlsx",
            "ClientIP": VICTIM_PROFILE["ip"],
        })
        events.append(create_event(file_time, "microsoft_365", "baseline", m365_file))
        
        # Add more normal activities as needed...
        
        print(f"   ✓ Generated {len([e for e in events if 'baseline' in e['phase']])} normal activity events")
    
    return events
```

### Step 4: Build Attack Phases

Create functions for each phase of the attack. Each phase should be self-contained and return a list of events.

#### Phase Example: Phishing Delivery

```python
def generate_phishing_delivery(base_time: datetime) -> List[Dict]:
    """
    Generate phishing email delivery events.
    
    Returns:
        List of phishing delivery events
    """
    events = []
    day = 6
    delivery_time = get_scenario_time(base_time, day, 9, 15)
    
    # Proofpoint email gateway detection
    pf = proofpoint_log({
        "recipient": [VICTIM_PROFILE["email"]],
        "sender": ATTACKER_PROFILE["sender_email"],
        "subject": "Updated Benefits Package - Action Required",
        "threatType": "attachment",
        "phishScore": 95,
        "policyRoutes": ["deliver"],
        "messageParts": [{
            "disposition": "attached",
            "filename": ATTACKER_PROFILE["malicious_pdf"],
            "contentType": "application/pdf",
            "sandboxStatus": "threat",
            "threatStatus": "malicious",
        }],
        "spf": "fail",
        "dkimv": "none",
        "dmarc": "fail",
    })
    events.append(create_event(delivery_time, "proofpoint", "phishing_delivery", pf))
    
    print(f"   ✓ Phishing email with malicious PDF delivered")
    return events
```

#### Phase Example: Process Injection & Detection

```python
def generate_process_injection(base_time: datetime) -> List[Dict]:
    """
    Generate process injection and EDR detection events.
    
    Returns:
        List of process injection events
    """
    events = []
    day = 6
    injection_time = get_scenario_time(base_time, day, 9, 19)
    
    # SentinelOne EDR detection
    s1 = sentinelone_log({
        "event.category": "malware",
        "event.type": "threat_detected",
        "process.name": "update.exe",
        "process.pid": 5432,
        "process.parent.name": "AcroRd32.exe",
        "process.command_line": "C:\\Users\\smitchell\\AppData\\Local\\Temp\\update.exe",
        "threat.name": "AsyncRAT",
        "threat.severity": "critical",
        "threat.classification": "Trojan",
        "rule.mitre_technique": "T1055 - Process Injection",
        "target.process.name": "explorer.exe",
        "target.process.pid": 2184,
        "indicators": [
            {"type": "injection", "description": "Injected code into explorer.exe"},
            {"type": "hollowing", "description": "Process hollowing detected"},
        ],
        "host.name": VICTIM_PROFILE["hostname"],
        "host.ip": VICTIM_PROFILE["ip"],
        "user.name": VICTIM_PROFILE["username"],
    })
    events.append(create_event(injection_time, "sentinelone", "execution", s1))
    
    print(f"   ✓ AsyncRAT injected into explorer.exe - HIGH PRIORITY ALERT")
    return events
```

### Step 5: Add Detection & Response

Generate SOAR alerts and automated response actions.

```python
def generate_detection_and_response(base_time: datetime) -> List[Dict]:
    """
    Generate detection alerts and automated response actions.
    
    Returns:
        List of detection and response events
    """
    events = []
    day = 6
    alert_time = get_scenario_time(base_time, day, 9, 30)
    
    # SOAR Storyline Alert - Correlates entire attack chain
    soar_alert = {
        "alert_id": "STORYLINE-2024-02-06-001",
        "alert_type": "Multi-Stage Malware Campaign",
        "severity": "critical",
        "confidence": 98,
        "attack_chain": [
            {"phase": "Initial Access", "technique": "T1566.001 - Spearphishing Attachment"},
            {"phase": "Execution", "technique": "T1203 - Exploitation for Client Execution"},
            {"phase": "Execution", "technique": "T1059.001 - PowerShell"},
            {"phase": "Defense Evasion", "technique": "T1055 - Process Injection"},
            {"phase": "Persistence", "technique": "T1053.005 - Scheduled Task"},
        ],
        "affected_assets": [
            {"hostname": VICTIM_PROFILE["hostname"], "ip": VICTIM_PROFILE["ip"]}
        ],
        "iocs": [
            {"type": "domain", "value": ATTACKER_PROFILE["phishing_domain"]},
            {"type": "ip", "value": ATTACKER_PROFILE["c2_ip"]},
            {"type": "file_hash", "value": "8a3d8f7b6e4c2a1f9d5e8c7b4a2f1e9d"},
        ],
        "recommendations": [
            "Isolate affected endpoint immediately",
            "Remove scheduled task persistence",
            "Conduct memory forensics",
            "Deploy emergency patches for CVE-2023-21608",
        ]
    }
    events.append(create_event(alert_time, "soar_alert", "detection", soar_alert))
    
    # Automated Response Actions
    response_actions = [
        {"action": "network_isolation", "status": "completed", "timestamp": alert_time},
        {"action": "scheduled_task_removal", "status": "completed", "timestamp": alert_time},
        {"action": "registry_cleanup", "status": "completed", "timestamp": alert_time},
        {"action": "forensic_imaging", "status": "in_progress", "timestamp": alert_time},
    ]
    
    for action in response_actions:
        response_time = get_scenario_time(base_time, day, 9, 30 + response_actions.index(action) * 3)
        events.append(create_event(response_time, "soar_response", "response", action))
    
    print(f"   ✓ Full attack chain correlated, {len(response_actions)} response actions")
    return events
```

### Step 6: Main Orchestration Function

Bring all phases together and generate the final scenario.

```python
def generate_scenario():
    """
    Main orchestration function to generate complete scenario.
    """
    # Print scenario header
    print("=" * 80)
    print("🎯 YOUR SCENARIO NAME")
    print("=" * 80)
    print(f"Victim: {VICTIM_PROFILE['name']} ({VICTIM_PROFILE['email']})")
    print(f"Department: {VICTIM_PROFILE['department']}")
    print(f"Location: {VICTIM_PROFILE['location']}")
    print("=" * 80)
    print()
    
    # Set base time for scenario
    base_time = datetime(2026, 1, 28, 0, 0, 0)
    all_events = []
    
    # Phase 1: Normal Baseline
    print("📊 PHASE 1: Normal Behavior Baseline (Days 1-5)")
    print("-" * 80)
    baseline_events = generate_normal_baseline(base_time, days=5)
    all_events.extend(baseline_events)
    print()
    
    # Phase 2: Phishing Delivery
    print("✉️  PHASE 2: Phishing Delivery (Day 6 - 09:15 AM)")
    print("-" * 80)
    phishing_events = generate_phishing_delivery(base_time)
    all_events.extend(phishing_events)
    print()
    
    # Phase 3: Process Injection
    print("🦠 PHASE 3: Process Injection (Day 6 - 09:19 AM)")
    print("-" * 80)
    injection_events = generate_process_injection(base_time)
    all_events.extend(injection_events)
    print()
    
    # Phase 4: Detection & Response
    print("🚨 PHASE 4: Detection & Response (Day 6 - 09:30 AM)")
    print("-" * 80)
    detection_events = generate_detection_and_response(base_time)
    all_events.extend(detection_events)
    print()
    
    # Sort all events by timestamp
    all_events.sort(key=lambda x: x["timestamp"])
    
    # Print summary
    print("=" * 80)
    print("✅ SCENARIO GENERATION COMPLETE")
    print("=" * 80)
    print(f"Total Events: {len(all_events)}")
    print(f"Timeline: {base_time.strftime('%Y-%m-%d')} to {(base_time + timedelta(days=6)).strftime('%Y-%m-%d')}")
    print("=" * 80)
    print()
    
    # Save to JSON
    output_dir = os.path.join(os.path.dirname(__file__), "configs")
    os.makedirs(output_dir, exist_ok=True)
    output_file = os.path.join(output_dir, "your_scenario_name.json")
    
    with open(output_file, "w") as f:
        json.dump(all_events, f, indent=2)
    
    print(f"💾 Scenario saved to: {output_file}")
    print("To replay this scenario, use the scenario_hec_sender.py script")

if __name__ == "__main__":
    generate_scenario()
```

---

## Available Event Generators

### Email Security
- **`proofpoint_log()`** - Email security gateway events
  - Phishing detection, malicious attachments, sender reputation
  - Fields: recipient, sender, subject, threatType, phishScore, messageParts

### Identity & Access
- **`microsoft_365_log()`** - Microsoft 365 audit logs
  - User logins, file access, email operations, admin actions
  - Fields: Operation, UserId, ClientIP, ResultStatus, SourceFileName

- **`okta_authentication_log()`** - Okta identity events
  - MFA challenges, session management, admin console access
  - Fields: eventType, actor, client, outcome, geographicalContext

- **`azure_ad_log()`** - Azure Active Directory events
  - Sign-ins, conditional access, directory operations
  - Fields: operationName, userPrincipalName, ipAddress, location

### Endpoint Security
- **`sentinelone_log()`** - SentinelOne EDR events
  - Malware detection, process injection, behavioral alerts
  - Fields: event.category, threat.name, process.*, rule.mitre_technique

- **`crowdstrike_log()`** - CrowdStrike Falcon events
  - Endpoint detections, IOAs, real-time response
  - Fields: event_simpleName, ComputerName, DetectDescription

### Network Security
- **`palo_alto_firewall_log()`** - Palo Alto firewall events
  - Traffic filtering, threat detection, URL filtering
  - Fields: src_ip, dest_ip, dest_port, action, threat_name

- **`cisco_firepower_log()`** - Cisco Firepower events
  - IPS alerts, file malware detection, connection events
  - Fields: source_ip, destination_ip, signature_name, action

### Cloud Infrastructure
- **`aws_cloudtrail_log()`** - AWS CloudTrail events
  - API calls, resource changes, authentication events
  - Fields: eventName, userIdentity, sourceIPAddress, resources

- **`azure_activity_log()`** - Azure Activity logs
  - Resource operations, subscription changes, access control
  - Fields: operationName, caller, resourceId, status

### Location
All generators located in: `/Users/joelm/CascadeProjects/jarvis_coding/Backend/event_generators/`

---

## Scenario Components

### 1. Profile Definitions
Define victim and attacker profiles with all necessary details upfront.

### 2. Time Management
- Use `get_scenario_time()` for consistent timestamp generation
- Day 1-5: Baseline activity
- Day 6+: Attack activity
- Use minute/second offsets for precise sequencing

### 3. Event Structure
Every event must include:
- **timestamp**: ISO format string
- **event_type**: Source/generator name
- **phase**: Attack phase or "baseline"
- **raw_log**: The actual event data

### 4. Attack Phases
Typical phases include:
- **Baseline**: Normal user activity (days 1-5)
- **Initial Access**: Phishing, exploitation (T1566, T1203)
- **Execution**: Malware execution, scripting (T1059, T1204)
- **Persistence**: Scheduled tasks, registry keys (T1053, T1547)
- **Defense Evasion**: Process injection, AMSI bypass (T1055, T1562)
- **Discovery**: Reconnaissance, enumeration (T1018, T1087)
- **Command & Control**: C2 beaconing (T1071)
- **Lateral Movement**: Credential dumping, SMB exploitation (T1003, T1021)
- **Exfiltration**: Data staging, keylogging (T1005, T1056)
- **Detection**: SOAR alerts and correlation
- **Response**: Automated containment actions

### 5. MITRE ATT&CK Mapping
Include relevant MITRE ATT&CK techniques in:
- Event metadata
- Detection alerts
- Documentation comments

---

## Best Practices

### 1. Realistic Timing
- Space out events naturally (seconds to minutes between related actions)
- Use business hours for user activity (9 AM - 5 PM)
- Include appropriate delays between attack stages

### 2. Data Consistency
- Use profile dictionaries to ensure consistency
- Reference the same IPs, hostnames, usernames throughout
- Maintain logical relationships between events

### 3. Detection Realism
- Not all malicious activity should be detected immediately
- Include both successful and failed detections
- Show escalation from single alerts to correlated storylines

### 4. Response Actions
- Include both automated and manual response steps
- Show progressive containment (isolation → removal → forensics)
- Document mitigation effectiveness

### 5. Code Organization
- One function per phase
- Clear comments explaining each step
- Descriptive print statements for progress tracking
- Sort events by timestamp before saving

### 6. Generator Usage
- Call generators with dictionaries of fields to override
- Parse JSON strings if generator returns string: `json.loads(log_str) if isinstance(log_str, str) else log_str`
- Validate generator output structure matches your needs

---

## Example Scenarios

### Reference Implementations

1. **`finance_mfa_fatigue_scenario.py`**
   - MFA fatigue attack on financial executive
   - Okta authentication, Azure AD, Microsoft 365
   - 15 MFA push attempts, session compromise, data exfiltration
   - Excellent example of identity-focused attacks

2. **`asyncrat_phishing_scenario.py`**
   - AsyncRAT malware campaign via weaponized PDF
   - Proofpoint, Microsoft 365, SentinelOne, Palo Alto
   - Multi-stage payload execution with process injection
   - Comprehensive detection and response automation

3. **`hr_phishing_pdf_c2_scenario.py`**
   - HR-themed phishing with PDF exploitation
   - Email delivery, exploitation, persistence, C2 communication
   - Simple but complete attack chain example

### Scenario Complexity Levels

**Simple** (50-100 events):
- Single attack vector
- 2-3 data sources
- Basic detection/response
- 1-2 days timeline

**Medium** (100-300 events):
- Multiple attack stages
- 4-6 data sources
- Correlated detections
- 3-7 days timeline

**Complex** (300+ events):
- Full attack lifecycle
- 6+ data sources
- Advanced evasion techniques
- Comprehensive response
- 7+ days timeline

---

## Testing & Validation

### 1. Run Your Scenario

```bash
cd /Users/joelm/CascadeProjects/jarvis_coding/Backend/scenarios
python3 your_scenario_name.py
```

Expected output:
- Phase-by-phase progress with emoji indicators
- Event counts per phase
- Summary statistics
- JSON file saved to `configs/` directory

### 2. Validate JSON Output

```bash
# Check file was created
ls -lh configs/your_scenario_name.json

# Validate JSON structure
python3 -m json.tool configs/your_scenario_name.json > /dev/null && echo "Valid JSON"

# Count events
jq '. | length' configs/your_scenario_name.json
```

### 3. Send to SentinelOne (Optional)

```bash
# Configure HEC token
export S1_HEC_TOKEN="your-token-here"

# Send scenario events
python3 scenario_hec_sender.py configs/your_scenario_name.json
```

### 4. Common Issues

**Issue**: `ModuleNotFoundError: No module named 'event_generators'`
- **Fix**: Verify `sys.path.append()` correctly points to Backend directory

**Issue**: Generator returns None or unexpected format
- **Fix**: Check generator function signature, test individual generators first

**Issue**: Events out of chronological order
- **Fix**: Ensure `all_events.sort(key=lambda x: x["timestamp"])` before saving

**Issue**: Missing fields in generator output
- **Fix**: Pass explicit dictionary to generator, don't rely on defaults

---

## Quick Start Template

Use this minimal template to start a new scenario:

```python
from datetime import datetime, timedelta
from typing import List, Dict
import json
import sys
import os

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from event_generators.email_security.proofpoint_log import proofpoint_log
from event_generators.endpoint_security.sentinelone_log import sentinelone_log

VICTIM_PROFILE = {
    "name": "Jane Doe",
    "email": "jane.doe@company.com",
    "ip": "10.0.0.100",
    "hostname": "JANE-LAPTOP",
}

ATTACKER_PROFILE = {
    "ip": "192.0.2.50",
    "email": "attacker@evil.com",
}

def get_scenario_time(base_time: datetime, day: int, hour: int, minute: int, second: int = 0) -> str:
    target_time = base_time + timedelta(days=day-1)
    target_time = target_time.replace(hour=hour, minute=minute, second=second, microsecond=0)
    return target_time.strftime("%Y-%m-%dT%H:%M:%S.000Z")

def create_event(timestamp: str, event_type: str, phase: str, raw_log: Dict) -> Dict:
    return {"timestamp": timestamp, "event_type": event_type, "phase": phase, "raw_log": raw_log}

def generate_scenario():
    base_time = datetime(2026, 2, 1, 0, 0, 0)
    events = []
    
    # Add your phases here
    
    events.sort(key=lambda x: x["timestamp"])
    
    output_file = os.path.join(os.path.dirname(__file__), "configs", "your_scenario.json")
    os.makedirs(os.path.dirname(output_file), exist_ok=True)
    with open(output_file, "w") as f:
        json.dump(events, f, indent=2)
    
    print(f"✅ Scenario saved: {output_file}")

if __name__ == "__main__":
    generate_scenario()
```

---

## Additional Resources

- **Event Generator Directory**: `/Users/joelm/CascadeProjects/jarvis_coding/Backend/event_generators/`
- **Existing Scenarios**: `/Users/joelm/CascadeProjects/jarvis_coding/Backend/scenarios/`
- **HEC Sender**: `scenario_hec_sender.py` for sending events to SentinelOne
- **Main Documentation**: `/Users/joelm/CascadeProjects/jarvis_coding/Backend/README.md`

---

## Summary Checklist

When creating a new scenario, ensure you have:

- [ ] Defined victim and attacker profiles
- [ ] Created helper functions for time and event generation
- [ ] Generated baseline activity (3-5 days)
- [ ] Implemented each attack phase as separate function
- [ ] Added realistic detection events
- [ ] Included response/containment actions
- [ ] Mapped techniques to MITRE ATT&CK
- [ ] Used consistent timestamps and data
- [ ] Sorted events chronologically
- [ ] Saved output to `configs/` directory
- [ ] Tested scenario generation
- [ ] Validated JSON output

Good luck creating your security scenarios! 🎯

---

## Sending to HEC and UI Integration

### Send Events Directly to SentinelOne HEC (from the script)

Most scenario scripts can also send events directly to SentinelOne HEC when environment variables are set. The runner respects parallel workers and adds correlation tags.

**Required environment:**

```bash
# Required
export S1_HEC_TOKEN="<your-hec-token>"

# Optional (used by some senders/wrappers; the low-level hec_sender infers endpoints)
export S1_HEC_URL="https://ingest.us1.sentinelone.net/services/collector"

# Parallelism and tagging (optional)
export S1_HEC_WORKERS=10           # number of parallel workers
export S1_TAG_PHASE=1              # include scenario.phase tag
export S1_TAG_TRACE=1              # include scenario.trace_id tag
export S1_TRACE_ID="demo-$(date +%s)"  # custom trace id

# Run the scenario (will generate and send)
python3 asyncrat_phishing_scenario.py
```

During send you should see dot progress (`.` for success, `E` for error), then a success/error summary.

### Expose a New Scenario in the Frontend

The current Frontend dropdown is populated by a hardcoded list and a filename mapping.

**Step 1:** Add your scenario to the list in `Frontend/log_generator_ui.py` in the `list_scenarios()` function:

```python
{
    'id': 'asyncrat_phishing_scenario',
    'name': 'AsyncRAT Phishing Campaign - Operation Silent Schedule',
    'description': 'Comprehensive multi-stage campaign with detection & response.',
    'duration_days': 6,
    'total_events': 83,
    'phases': ['Baseline', 'Phishing', 'Execution', 'Persistence', 'C2', 'Detection']
},
```

**Step 2:** Add the script filename to the `id_to_file` mapping in the same file:

```python
id_to_file = {
    # existing mappings...
    'asyncrat_phishing_scenario': 'asyncrat_phishing_scenario.py',
}
```

**Step 3:** Restart the Frontend container:

```bash
docker compose restart frontend
```

**Step 4:** Verify the scenario appears:

```bash
curl -s http://localhost:9002/scenarios | jq '.scenarios | length'
curl -s http://localhost:9002/scenarios | jq '.scenarios[] | .id, .name'
```

### Optional: Backend API Discovery of JSON Scenarios

The API can include generated JSON scenarios (in `Backend/scenarios/configs/`) in its scenarios list. To enable:

- File: `Backend/api/app/services/scenario_service.py`
- The `_load_json_scenarios()` method scans `configs/*.json` and adds metadata to `scenario_templates`
- Restart the API container after changes:

```bash
docker compose restart api
```

### Troubleshooting HEC Sending

- **No events sent:** Ensure `S1_HEC_TOKEN` is set in the environment visible to the scenario process
- **TLS/endpoint issues:** Use `safe_hec_sender.py` to configure endpoint bases and TLS compatibility
- **Frontend issues:** The UI sets HEC URL/token automatically from your selected Destination. Confirm the Destination is type `hec` and has a valid token
- **SyntaxError with nonlocal:** Fixed in latest version - uses shared dict instead of nonlocal counters
