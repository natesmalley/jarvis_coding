#!/usr/bin/env python3
"""Darktrace event generator.

Generates Darktrace AI-powered cyber defense events.
Supports model breaches, analyst incidents, analyst groups, and status data.
"""

from __future__ import annotations

import json
import os
import random
import sys
from typing import Any

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'shared'))
from generator_utils import (
    generate_mac_address,
    generate_private_ip,
    generate_uuid,
    now_epoch,
)

MODEL_BREACHES: dict[str, Any] = {
    "commentCount": 0,
    "pbid": 35431,
    "time": 1698274829000,
    "creationTime": 1698274828000,
    "model": {
        "then": {
            "name": "System::System",
            "pid": 530,
            "phid": 4861,
            "uuid": "1c3f429b-ccb9-46a2-b864-868653bc780a",
            "logic": {"data": [9686], "type": "componentList", "version": 1},
            "throttle": 10,
            "sharedEndpoints": False,
            "actions": {
                "alert": True,
                "antigena": {},
                "breach": True,
                "model": True,
                "setPriority": False,
                "setTag": False,
                "setType": False,
            },
            "tags": [],
            "interval": 0,
            "delay": 0,
            "sequenced": True,
            "active": True,
            "modified": "2021-11-24 18:04:19",
            "activeTimes": {"devices": {}, "tags": {}, "type": "exclusions", "version": 2},
            "autoUpdatable": True,
            "autoUpdate": True,
            "autoSuppress": True,
            "description": "An issue with the system has been detected.",
            "behaviour": "decreasing",
            "defeats": [],
            "created": {"by": "System"},
            "edited": {"by": "System"},
            "version": 16,
            "priority": 3,
            "category": "Informational",
            "compliance": False,
        },
        "now": {
            "name": "System::System",
            "pid": 530,
            "phid": 4861,
            "uuid": "1c3f429b-ccb9-46a2-b864-868653bc780a",
            "logic": {"data": [9686], "type": "componentList", "version": 1},
            "throttle": 10,
            "sharedEndpoints": False,
            "actions": {
                "alert": True,
                "antigena": {},
                "breach": True,
                "model": True,
                "setPriority": False,
                "setTag": False,
                "setType": False,
            },
            "tags": [],
            "interval": 0,
            "delay": 0,
            "sequenced": True,
            "active": True,
            "modified": "2021-11-24 18:04:19",
            "activeTimes": {"devices": {}, "tags": {}, "type": "exclusions", "version": 2},
            "autoUpdatable": True,
            "autoUpdate": True,
            "autoSuppress": True,
            "description": "An issue with the system has been detected.",
            "behaviour": "decreasing",
            "defeats": [],
            "created": {"by": "System"},
            "edited": {"by": "System"},
            "message": "Updated model filters and logic",
            "version": 16,
            "priority": 3,
            "category": "Informational",
            "compliance": False,
        },
    },
    "triggeredComponents": [
        {
            "time": 1698274828000,
            "cbid": 35595,
            "cid": 9686,
            "chid": 15251,
            "size": 1,
            "threshold": 0,
            "interval": 3600,
            "logic": {
                "data": {
                    "left": {"left": "A", "operator": "AND", "right": "B"},
                    "operator": "OR",
                    "right": {"left": {"left": "A", "operator": "AND", "right": "C"}, "operator": "OR", "right": {}},
                },
                "version": "v0.1",
            },
            "metric": {"mlid": 206, "name": "dt_system", "label": "System"},
            "triggeredFilters": [
                {
                    "cfid": 111299,
                    "id": "A",
                    "filterType": "Event details",
                    "arguments": {"value": "analyze credential ignore list"},
                    "comparatorType": "does not contain",
                    "trigger": {
                        "value": "Probe erebus-pull-mode-v_sensor (54.155.33.146) last contact was 67 hours ago"
                    },
                },
                {
                    "cfid": 111300,
                    "id": "B",
                    "filterType": "System message",
                    "arguments": {"value": "Probe error"},
                    "comparatorType": "is",
                    "trigger": {"value": "Probe error"},
                },
            ],
        }
    ],
    "score": 0.674,
    "device": {"did": -1},
}

ANALYST_INCIDENTS: dict[str, Any] = {
    "summariser": "SmbPasswordSummary",
    "acknowledged": False,
    "pinned": True,
    "createdAt": 1646158503214,
    "attackPhases": None,
    "mitreTactics": [],
    "title": "Access of Probable Unencrypted Password File",
    "id": "27e71d96-2daf-47bc-b6cf-c59abb2b5c91",
    "children": ["27e71d96-2daf-47bc-b6cf-c59abb2b5c91"],
    "category": None,
    "currentGroup": None,
    "groupCategory": None,
    "groupScore": None,
    "groupPreviousGroups": None,
    "activityId": "da39a3ee",
    "groupingIds": ["9e6a55b6"],
    "groupByActivity": True,
    "userTriggered": False,
    "externalTriggered": False,
    "aiaScore": 50,
    "summary": "The device 192.168.19.120 was observed accessing a document over SMB on wef.local that appears to contain sensitive information.",
    "periods": [{"start": 1646154881000, "end": 1646154881000}],
    "breachDevices": [
        {
            "identifier": "wef.win",
            "hostname": "wef.wind",
            "ip": "192.168.1.3",
            "mac": "06:7b:81:5d:4b:5c",
            "subnet": None,
            "did": 18,
            "sid": 3,
        }
    ],
    "relatedBreaches": [
        {
            "modelName": "Compliance / Possible Unencrypted Password File On Server",
            "pbid": 1776,
            "threatScore": 30,
            "timestamp": 1646154882000,
        }
    ],
    "details": [
        [
            {
                "header": "SMB Details",
                "contents": [
                    {"key": "Time", "type": "timestamp", "values": [1646154881000]},
                    {
                        "key": "Source device",
                        "type": "device",
                        "values": [
                            {
                                "identifier": None,
                                "hostname": None,
                                "ip": "192.168.19.120",
                                "mac": None,
                                "subnet": None,
                                "did": 22,
                                "sid": 5,
                            }
                        ],
                    },
                ],
            }
        ]
    ],
}

ANALYST_GROUPS: dict[str, Any] = {
    "id": "g88ec2dd5-3d6d-43c4-8542-b7a872681e91",
    "active": True,
    "acknowledged": False,
    "pinned": False,
    "userTriggered": False,
    "externalTriggered": False,
    "previousIds": [],
    "incidentEvents": [
        {
            "uuid": "88ec2dd5-3d",
            "start": 1700448667453,
            "title": "Multiple DNS Requests for Algorithmically Generated Domains",
            "triggerDid": 63,
            "visible": True,
        }
    ],
    "mitreTactics": ["command-and-control"],
    "devices": [63],
    "initialDevices": [63],
    "category": "critical",
    "groupScore": 24.0020289155635,
    "start": 1700448667453,
    "end": 1701051898211,
    "edges": [
        {
            "isAction": False,
            "source": {"nodeType": "externalHost", "value": "mjj.ws"},
            "target": {"nodeType": "externalIp", "value": "64.70.19.203"},
            "start": None,
            "incidentEvent": "b6480904-c",
            "description": None,
            "details": [],
        }
    ],
}

STATUS_DATA: dict[str, Any] = {
    "excessTraffic": False,
    "time": "2023-11-29 14:53",
    "installed": "2020-09-02",
    "mobileAppConfigured": False,
    "version": "6.0.46 (ac2091)",
    "ipAddress": "10.140.11.114",
    "modelsUpdated": "2023-11-29 10:40:39",
    "modelPackageVersion": "6.0.23-3520~20231129053423~g8a0148",
    "bundleVersion": "60102",
    "bundleDate": "2023-08-31 19:20:16",
    "bundleInstalledDate": "2023-09-18 15:45:23",
    "hostname": "usw1-54655-01",
    "inoculation": False,
    "applianceOSCode": "f",
    "license": "",
    "saasConnectorLicense": "",
    "antigenaSaasLicense": "",
    "antigenaNetworkEnabled": True,
    "antigenaNetworkLicense": "",
    "antigenaNetworkRunning": False,
    "logIngestionReplicated": 0,
    "logIngestionProcessed": 11627,
    "logIngestionTCP": 0,
    "logIngestionUDP": 11627,
    "type": "master",
    "diskUtilization": 1,
    "uptime": "06:51:08",
    "systemUptime": "84:06:52",
    "load": 57,
    "cpu": 13,
    "memoryUsed": 44,
    "dataQueue": 0,
    "darkflowQueue": 0,
    "bandwidthCurrent": 0,
    "bandwidthCurrentString": "0 kbps",
    "bandwidthAverage": 0,
    "bandwidthAverageString": "0 kbps",
    "connectionsPerMinuteCurrent": 0,
    "connectionsPerMinuteAverage": 1388,
    "operatingSystems": 3,
    "newDevices4Weeks": 13,
    "newDevices7Days": 2,
    "newDevices24Hours": 0,
    "newDevicesHour": 0,
    "activeDevices4Weeks": 30,
    "activeDevices7Days": 19,
    "activeDevices24Hours": 2,
    "activeDevicesHour": 2,
    "deviceHostnames": 7,
    "deviceMACAddresses": 0,
    "deviceRecentIPChange": 0,
    "models": 1027,
    "modelsBreached": 5259,
    "modelsSuppressed": 31630,
    "devicesModeled": 19,
}

MODEL_CATEGORIES = [
    "Informational",
    "Compliance",
    "Anomalous Connection",
    "Device / Attack Tool",
    "Compromise",
    "Critical",
]

INCIDENT_TITLES = [
    "Access of Probable Unencrypted Password File",
    "Multiple DNS Requests for Algorithmically Generated Domains",
    "Unusual External Data Transfer",
    "Suspicious Beaconing Activity",
    "Potential Ransomware Activity",
    "Anomalous Server Activity",
    "Unusual Admin Behavior",
]

MITRE_TACTICS = [
    "command-and-control",
    "exfiltration",
    "lateral-movement",
    "persistence",
    "privilege-escalation",
    "defense-evasion",
    "credential-access",
]


def generate_model_breach() -> dict[str, Any]:
    """Generate a single Darktrace model breach event."""
    now_ms = now_epoch() * 1000

    breach = {**MODEL_BREACHES}
    breach["pbid"] = random.randint(10000, 99999)
    breach["time"] = now_ms
    breach["creationTime"] = now_ms - random.randint(1000, 60000)
    breach["score"] = round(random.random(), 3)

    # Update model category
    category = random.choice(MODEL_CATEGORIES)
    breach["model"] = {**MODEL_BREACHES["model"]}
    breach["model"]["then"] = {**MODEL_BREACHES["model"]["then"]}
    breach["model"]["now"] = {**MODEL_BREACHES["model"]["now"]}
    breach["model"]["then"]["category"] = category
    breach["model"]["now"]["category"] = category
    breach["model"]["then"]["uuid"] = generate_uuid()
    breach["model"]["now"]["uuid"] = breach["model"]["then"]["uuid"]

    return breach


def generate_analyst_incident() -> dict[str, Any]:
    """Generate a single Darktrace analyst incident."""
    now_ms = now_epoch() * 1000
    start_ms = now_ms - random.randint(3600000, 86400000)

    incident = {**ANALYST_INCIDENTS}
    incident["id"] = generate_uuid()
    incident["createdAt"] = now_ms
    incident["title"] = random.choice(INCIDENT_TITLES)
    incident["aiaScore"] = random.randint(10, 100)
    incident["periods"] = [{"start": start_ms, "end": now_ms}]
    incident["mitreTactics"] = random.sample(MITRE_TACTICS, k=random.randint(1, 3))

    # Update breach device
    incident["breachDevices"] = [{
        "identifier": f"device-{random.randint(1, 100)}",
        "hostname": f"host-{random.randint(1, 100)}.local",
        "ip": generate_private_ip(),
        "mac": generate_mac_address(),
        "subnet": None,
        "did": random.randint(1, 1000),
        "sid": random.randint(1, 10),
    }]

    return incident


def generate_analyst_group() -> dict[str, Any]:
    """Generate a single Darktrace analyst group."""
    now_ms = now_epoch() * 1000
    start_ms = now_ms - random.randint(3600000, 604800000)

    group = {**ANALYST_GROUPS}
    group["id"] = f"g{generate_uuid()}"
    group["active"] = random.choice([True, False])
    group["category"] = random.choice(["critical", "high", "medium", "low"])
    group["groupScore"] = round(random.uniform(1.0, 100.0), 10)
    group["start"] = start_ms
    group["end"] = now_ms
    group["mitreTactics"] = random.sample(MITRE_TACTICS, k=random.randint(1, 3))
    group["devices"] = [random.randint(1, 1000) for _ in range(random.randint(1, 5))]

    return group


def generate_status() -> dict[str, Any]:
    """Generate Darktrace status data."""
    status = {**STATUS_DATA}
    status["ipAddress"] = generate_private_ip()
    status["cpu"] = random.randint(1, 100)
    status["memoryUsed"] = random.randint(10, 90)
    status["load"] = random.randint(1, 100)
    status["diskUtilization"] = random.randint(1, 100)
    status["modelsBreached"] = random.randint(100, 10000)
    status["activeDevices24Hours"] = random.randint(1, 100)
    status["newDevices24Hours"] = random.randint(0, 20)

    return status


def darktrace_model_breach_log() -> str:
    """Return a single synthetic Darktrace model breach in JSON format."""
    return json.dumps(generate_model_breach())


def darktrace_incident_log() -> str:
    """Return a single synthetic Darktrace analyst incident in JSON format."""
    return json.dumps(generate_analyst_incident())


def darktrace_group_log() -> str:
    """Return a single synthetic Darktrace analyst group in JSON format."""
    return json.dumps(generate_analyst_group())


def darktrace_status_log() -> str:
    """Return Darktrace status data in JSON format."""
    return json.dumps(generate_status())


if __name__ == "__main__":  # pragma: no cover
    print("=== Model Breach ===")
    print(darktrace_model_breach_log())
    print("\n=== Analyst Incident ===")
    print(darktrace_incident_log())
    print("\n=== Analyst Group ===")
    print(darktrace_group_log())
    print("\n=== Status ===")
    print(darktrace_status_log())
