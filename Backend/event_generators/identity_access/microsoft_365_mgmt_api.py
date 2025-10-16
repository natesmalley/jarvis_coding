#!/usr/bin/env python3
"""
Microsoft 365 Management API event generator (JSON format)
"""
from __future__ import annotations
import json
import random
import time
import uuid
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional

# Activity group names for security alerts
ACTIVITY_GROUPS = [
    "Suspicious email forwarding",
    "Mass download by a single user",
    "Anomalous file deletion",
    "Suspicious inbox manipulation rule",
    "Suspicious SharePoint file activity",
    "Anomalous file share activities",
    "Multiple users deleted",
    "Suspicious administrative activity",
    "Mass email sending",
    "Elevated permissions assigned"
]

# Alert categories
ALERT_CATEGORIES = [
    "SuspiciousActivity",
    "ThreatIntelligence", 
    "UnusualAnomaly",
    "CompromisedMailbox",
    "DataExfiltration",
    "CredentialTheft",
    "MaliciousEmail",
    "SuspiciousLogon",
    "PrivilegeEscalation",
    "DataLeakage"
]

# Malware families
MALWARE_FAMILIES = [
    "Emotet", "TrickBot", "Dridex", "IcedID", "Qakbot", "BazarLoader",
    "Cobalt Strike", "Metasploit", "Mimikatz", "BloodHound", "SharpHound"
]

# Process names and paths
PROCESSES = [
    ("powershell.exe", "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"),
    ("cmd.exe", "C:\\Windows\\System32\\cmd.exe"),
    ("wmic.exe", "C:\\Windows\\System32\\wbem\\WMIC.exe"),
    ("regsvr32.exe", "C:\\Windows\\System32\\regsvr32.exe"),
    ("rundll32.exe", "C:\\Windows\\System32\\rundll32.exe"),
    ("mshta.exe", "C:\\Windows\\System32\\mshta.exe"),
    ("cscript.exe", "C:\\Windows\\System32\\cscript.exe"),
    ("wscript.exe", "C:\\Windows\\System32\\wscript.exe")
]

# Registry keys commonly targeted
REGISTRY_KEYS = [
    "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
    "HKEY_CURRENT_USER\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
    "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
    "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services",
    "HKEY_LOCAL_MACHINE\\SOFTWARE\\Classes\\exefile\\shell\\open\\command"
]

# User names and domains
USERS = ["john.doe", "jane.smith", "admin", "bob.jones", "alice.williams", "charlie.brown", "diana.prince"]
DOMAINS = ["company.com", "corp.local", "office365.com", "internal.com"]

# Security resources
SECURITY_RESOURCES = [
    "Microsoft Defender for Endpoint",
    "Microsoft Defender for Office 365", 
    "Microsoft Cloud App Security",
    "Azure Active Directory Identity Protection",
    "Microsoft Sentinel",
    "Azure Security Center"
]

def _generate_ip(internal=True):
    """Generate an IP address"""
    if internal:
        return f"10.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"
    else:
        return f"{random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"

def _generate_user_states():
    """Generate user state information"""
    user = random.choice(USERS)
    domain = random.choice(DOMAINS)
    
    return [
        {
            "aadUserId": str(uuid.uuid4()),
            "accountName": user,
            "domainName": domain,
            "emailRole": random.choice(["sender", "recipient", "cc", "bcc"]),
            "isVpn": random.choice(["true", "false"]),
            "logonDateTime": (datetime.now(timezone.utc) - timedelta(hours=random.randint(0, 24))).strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
            "logonId": str(random.randint(100000, 999999)),
            "logonIp": _generate_ip(internal=random.choice([True, False])),
            "logonLocation": random.choice(["Seattle, WA", "New York, NY", "London, UK", "Unknown", "Remote"]),
            "logonType": random.choice(["Interactive", "Network", "Batch", "Service", "RemoteInteractive"]),
            "onPremisesSecurityIdentifier": f"S-1-5-21-{random.randint(100000000, 999999999)}-{random.randint(100000000, 999999999)}-{random.randint(1000, 9999)}-{random.randint(1000, 9999)}",
            "riskScore": str(random.randint(0, 100)),
            "userAgent": random.choice([
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                "Microsoft Office/16.0 (Windows NT 10.0; Microsoft Outlook 16.0.14326; Pro)",
                "Microsoft-WNS/10.0"
            ]),
            "userPrincipalName": f"{user}@{domain}"
        }
    ]

def _generate_malware_states():
    """Generate malware state information"""
    if random.random() < 0.3:  # 30% chance of malware
        return []
    
    return [
        {
            "category": random.choice(["Trojan", "Backdoor", "Worm", "Ransomware", "Spyware"]),
            "family": random.choice(MALWARE_FAMILIES),
            "name": f"{random.choice(MALWARE_FAMILIES)}.{random.choice(['A', 'B', 'C', 'D'])}",
            "severity": random.choice(["Low", "Medium", "High", "Critical"]),
            "wasRunning": random.choice(["true", "false"])
        }
    ]

def _generate_network_connections():
    """Generate network connection information"""
    connections = []
    num_connections = random.randint(1, 3)
    
    for _ in range(num_connections):
        connections.append({
            "applicationName": random.choice(["chrome.exe", "outlook.exe", "teams.exe", "unknown"]),
            "destinationAddress": _generate_ip(internal=False),
            "destinationDomain": random.choice([
                "login.microsoftonline.com",
                "graph.microsoft.com", 
                "suspicious-domain.com",
                "malicious-c2.net",
                "outlook.office365.com"
            ]),
            "destinationPort": str(random.choice([80, 443, 8080, 8443, 53, 993])),
            "destinationUrl": f"https://{'suspicious-' if random.random() > 0.7 else ''}domain-{random.randint(1, 100)}.com/api/data",
            "direction": random.choice(["Inbound", "Outbound"]),
            "domainRegisteredDateTime": (datetime.now(timezone.utc) - timedelta(days=random.randint(1, 365))).strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
            "localDnsName": f"workstation-{random.randint(100, 999)}.{random.choice(DOMAINS)}",
            "natDestinationAddress": _generate_ip(internal=False),
            "natDestinationPort": str(random.randint(10000, 65535)),
            "natSourceAddress": _generate_ip(internal=True),
            "natSourcePort": str(random.randint(10000, 65535)),
            "protocol": random.choice(["TCP", "UDP", "ICMP"]),
            "riskScore": str(random.randint(0, 100)),
            "sourceAddress": _generate_ip(internal=True),
            "sourcePort": str(random.randint(1024, 65535)),
            "status": random.choice(["Succeeded", "Failed", "Timeout"]),
            "urlCategory": random.choice(["Business", "Technology", "Suspicious", "Malicious", "Unknown"])
        })
    
    return connections

def _generate_processes():
    """Generate process information"""
    processes = []
    num_processes = random.randint(1, 2)
    
    for _ in range(num_processes):
        process_name, process_path = random.choice(PROCESSES)
        processes.append({
            "accountName": random.choice(USERS),
            "commandLine": f"{process_path} {random.choice(['-enc', '/c', '-Command', '-ExecutionPolicy Bypass'])} {uuid.uuid4().hex[:16]}",
            "createdDateTime": (datetime.now(timezone.utc) - timedelta(minutes=random.randint(1, 60))).strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
            "fileHash": {
                "hashType": "sha256",
                "hashValue": uuid.uuid4().hex + uuid.uuid4().hex
            },
            "integrityLevel": random.choice(["Low", "Medium", "High", "System"]),
            "isElevated": random.choice(["true", "false"]),
            "name": process_name,
            "parentProcessCreatedDateTime": (datetime.now(timezone.utc) - timedelta(minutes=random.randint(2, 120))).strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
            "parentProcessId": random.randint(100, 9999),
            "parentProcessName": "explorer.exe",
            "path": process_path,
            "processId": random.randint(1000, 9999)
        })
    
    return processes

def _generate_registry_key_states():
    """Generate registry key state information"""
    if random.random() < 0.4:  # 40% chance of registry activity
        return []
    
    return [
        {
            "hive": random.choice(["HKEY_LOCAL_MACHINE", "HKEY_CURRENT_USER", "HKEY_CLASSES_ROOT"]),
            "key": random.choice(REGISTRY_KEYS),
            "oldKey": random.choice(REGISTRY_KEYS),
            "oldValueData": "legitimate_value",
            "oldValueName": "legitimate_name",
            "operation": random.choice(["Created", "Modified", "Deleted"]),
            "processId": random.randint(1000, 9999),
            "valueData": random.choice(["malicious.exe", "C:\\Temp\\backdoor.exe", "suspicious_command"]),
            "valueName": random.choice(["Run", "RunOnce", "Services", "Shell"]),
            "valueType": random.choice(["REG_SZ", "REG_DWORD", "REG_BINARY"])
        }
    ]

def _generate_cloud_app_states():
    """Generate cloud application states"""
    return [
        {
            "destinationServiceIp": _generate_ip(internal=False),
            "destinationServiceName": random.choice([
                "Microsoft 365",
                "SharePoint Online", 
                "Exchange Online",
                "Teams",
                "OneDrive for Business",
                "Azure Active Directory"
            ]),
            "riskScore": str(random.randint(0, 100))
        }
    ]

def microsoft_365_mgmt_api_log(overrides: dict | None = None) -> Dict:
    """
    Return a single Microsoft 365 Management API event as JSON string.
    
    Pass `overrides` to force any field to a specific value:
        microsoft_365_mgmt_api_log({"category": "ThreatIntelligence"})
    """
    # Generate timestamps
    now = datetime.now(timezone.utc)
    created_time = now - timedelta(minutes=random.randint(1, 60))
    event_time = created_time + timedelta(minutes=random.randint(0, 30))
    
    # Select alert category and group
    category = random.choice(ALERT_CATEGORIES)
    activity_group = random.choice(ACTIVITY_GROUPS)
    
    # Generate base event
    event = {
        "id": str(uuid.uuid4()),
        "azureSubscriptionId": str(uuid.uuid4()),
        "azureTenantId": str(uuid.uuid4()),
        "activityGroupName": activity_group,
        "assignedTo": random.choice(["unassigned", "soc_analyst", "incident_response", "security_admin"]),
        "category": category,
        "closedDateTime": None if random.random() > 0.3 else (now + timedelta(hours=random.randint(1, 48))).strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
        "cloudAppStates": _generate_cloud_app_states(),
        "comments": [
            f"Alert generated at {created_time.strftime('%Y-%m-%d %H:%M:%S')}",
            "Under investigation" if random.random() > 0.5 else "Escalated to security team"
        ],
        "confidence": random.randint(1, 100),
        "createdDateTime": created_time.strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
        "description": f"Microsoft 365 security alert: {activity_group}. This alert indicates potential {category.lower()} activity detected in your environment.",
        "detectionIds": [str(uuid.uuid4()) for _ in range(random.randint(1, 3))],
        "eventDateTime": event_time.strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
        "feedback": random.choice(["unknown", "truePositive", "falsePositive", "benignPositive"]),
        "incidentIds": [str(uuid.uuid4())] if random.random() > 0.5 else [],
        "lastEventDateTime": (event_time + timedelta(minutes=random.randint(0, 30))).strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
        "lastModifiedDateTime": now.strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
        "malwareStates": _generate_malware_states(),
        "networkConnections": _generate_network_connections(),
        "processes": _generate_processes(),
        "recommendedActions": [
            "Investigate user activity",
            "Review mailbox rules",
            "Check for additional indicators",
            "Validate with user"
        ],
        "registryKeyStates": _generate_registry_key_states(),
        "securityResources": random.sample(SECURITY_RESOURCES, random.randint(1, 3)),
        "severity": random.choice(["low", "medium", "high", "critical"]),
        "sourceMaterials": [
            f"https://security.microsoft.com/alerts/{uuid.uuid4()}",
            f"https://portal.office.com/adminportal/home#/MessageCenter/:/messages/{uuid.uuid4()}"
        ],
        "status": random.choice(["newAlert", "inProgress", "resolved", "dismissed"]),
        "tags": [category.lower(), "m365", "security", "automated"],
        "title": f"Microsoft 365 Alert: {activity_group}",
        "triggers": [
            {
                "name": f"{category}_detection_rule",
                "type": "SecurityEvent",
                "value": str(random.randint(1, 100))
            }
        ],
        "userStates": _generate_user_states(),
        "vendorInformation": {
            "provider": "Microsoft",
            "providerVersion": "1.0",
            "subProvider": "Microsoft 365 Defender",
            "vendor": "Microsoft"
        },
        "riskScore": str(random.randint(0, 100))
    }
    
    # Add category-specific fields
    if category == "ThreatIntelligence":
        event["threatIntelligence"] = {
            "indicatorType": random.choice(["Domain", "IP", "URL", "FileHash"]),
            "source": "Microsoft Threat Intelligence",
            "confidence": random.randint(60, 100),
            "firstSeen": (created_time - timedelta(days=random.randint(1, 30))).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        }
    
    elif category == "CompromisedMailbox":
        event["emailMetadata"] = {
            "subject": random.choice([
                "Urgent: Account verification required",
                "RE: Invoice payment",
                "Security alert",
                "Document review needed"
            ]),
            "sender": f"{random.choice(USERS)}@external-domain.com",
            "recipients": [f"{user}@{random.choice(DOMAINS)}" for user in random.sample(USERS, random.randint(1, 3))],
            "attachmentCount": random.randint(0, 3),
            "hasLinks": random.choice(["true", "false"])
        }
    
    elif category == "DataExfiltration":
        event["dataTransfer"] = {
            "bytesTransferred": random.randint(1000000, 1000000000),  # 1MB to 1GB
            "fileCount": random.randint(1, 100),
            "destinations": [_generate_ip(internal=False) for _ in range(random.randint(1, 3))],
            "protocol": random.choice(["HTTPS", "FTP", "SFTP", "Email"])
        }
    
    # Apply any overrides
    if overrides:
        event.update(overrides)
    
    return event

if __name__ == "__main__":
    # Generate a few sample logs
    print("Sample Microsoft 365 Management API events:")
    for category in ["ThreatIntelligence", "CompromisedMailbox", "DataExfiltration", "SuspiciousActivity"]:
        print(f"\n{category} event:")
        print(microsoft_365_mgmt_api_log({"category": category}))
        print()