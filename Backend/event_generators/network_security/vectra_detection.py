#!/usr/bin/env python3
"""Vectra detection event generator.

Generates Vectra network detection and response events.
Supports both legacy API and OAuth API (v3.4) formats.
"""

from __future__ import annotations

import json
import os
import random
import sys
from datetime import timedelta
from typing import Any

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'shared'))
from generator_utils import (
    generate_ip,
    generate_private_ip,
    now_utc,
    random_iso_timestamp,
)

# Legacy API detection
VECTRA_DETECTION: dict[str, Any] = {
    "id": 13645,
    "category": "COMMAND & CONTROL",
    "detection": "Hidden HTTPS Tunnel",
    "detection_category": "COMMAND & CONTROL",
    "detection_type": "Hidden HTTPS Tunnel",
    "custom_detection": None,
    "description": None,
    "src_ip": "10.250.50.112",
    "state": "inactive",
    "certainty": 0,
    "threat": 0,
    "created_timestamp": "2023-03-24T04:55:46Z",
    "first_timestamp": "2023-03-24T04:45:45Z",
    "last_timestamp": "2023-03-24T05:16:45Z",
    "targets_key_asset": False,
    "is_targeting_key_asset": False,
    "src_account": None,
    "src_host": {
        "id": 873,
        "ip": "10.250.50.112",
        "name": "VMAL #2 windows 10.250.50.112 (endo-kao12)",
        "is_key_asset": False,
        "groups": [
            {
                "id": 144,
                "name": "Partner VLAB - User Devices",
                "description": "",
                "last_modified": "2022-01-27T12:05:24Z",
                "last_modified_by": "user (Removed)",
                "type": "ip",
            }
        ],
        "threat": 0,
        "certainty": 0,
    },
    "note": None,
    "note_modified_by": None,
    "note_modified_timestamp": None,
    "sensor": "eti2pc2s",
    "sensor_name": "Vec2c610896a947c5b5102c466a28f49a",
    "tags": [],
    "triage_rule_id": None,
    "assigned_to": "crest",
    "assigned_date": "2022-12-14T06:59:08Z",
    "groups": [
        {
            "id": 144,
            "name": "Partner VLAB - User Devices",
            "description": "",
            "type": "ip",
            "last_modified": "2022-01-27T12:05:24Z",
            "last_modified_by": "user",
        }
    ],
    "is_marked_custom": False,
    "is_custom_model": False,
    "src_linked_account": None,
    "grouped_details": [
        {
            "external_target": {"ip": "10.250.20.112", "name": ""},
            "num_sessions": 3,
            "bytes_received": 118185547,
            "bytes_sent": 6021825,
            "ja3_hashes": [""],
            "ja3s_hashes": [""],
            "sessions": [
                {
                    "tunnel_type": "Long TCP session - Command line -1",
                    "protocol": "tcp",
                    "app_protocol": "https",
                    "dst_port": 443,
                    "dst_ip": "10.250.20.113",
                    "bytes_received": 39658914,
                    "bytes_sent": 2516263,
                    "first_timestamp": "2023-03-24T05:06:45Z",
                    "last_timestamp": "2023-03-24T05:17:45Z",
                    "dst_geo": None,
                    "dst_geo_lat": None,
                    "dst_geo_lon": None,
                },
                {
                    "tunnel_type": "Long TCP session - Command line -2",
                    "protocol": "tcp",
                    "app_protocol": "https",
                    "dst_port": 443,
                    "dst_ip": "10.250.20.114",
                    "bytes_received": 39572406,
                    "bytes_sent": 2231033,
                    "first_timestamp": "2023-03-24T04:54:45Z",
                    "last_timestamp": "2023-03-24T05:05:44Z",
                    "dst_geo": None,
                    "dst_geo_lat": None,
                    "dst_geo_lon": None,
                },
            ],
            "first_timestamp": "2023-03-24T04:47:45Z",
            "last_timestamp": "2023-03-24T05:18:45Z",
            "dst_ips": ["10.250.20.116"],
            "dst_ports": [443],
            "target_domains": [""],
        }
    ],
    "campaign_summaries": [],
    "is_triaged": False,
    "filtered_by_ai": False,
    "filtered_by_user": False,
    "filtered_by_rule": False,
    "_doc_modified_ts": "2023-09-05T08:41:35.376668",
    "summary": {
        "dst_ips": ["10.250.20.117"],
        "num_sessions": 3,
        "bytes_sent": 6021825,
        "bytes_received": 118185547,
        "description": "This host communicated with an external destination using HTTPS where another protocol was running over the top of the session.",
    },
}

# OAuth API detection (v3.4)
VECTRA_DETECTION_OAUTH: dict[str, Any] = {
    "summary": {
        "dst_ips": ["54.200.5.9"],
        "num_sessions": 157,
        "bytes_sent": 372505,
        "bytes_received": 11041011,
        "description": "This host communicated with an external destination using HTTPS where another protocol was running over the top of the session.",
    },
    "is_triaged": False,
    "detection": "Hidden HTTPS Tunnel",
    "detection_url": "https://308714519558.cc1.portal.vectra.ai/api/v3.4/detections/35108",
    "created_timestamp": "2025-05-13T01:49:53Z",
    "src_account": None,
    "threat": 5,
    "sensor": "w4ftj0a8",
    "certainty": 5,
    "notes": [],
    "is_custom_model": False,
    "id": 35108,
    "groups": [],
    "filtered_by_user": False,
    "src_ip": "192.168.49.140",
    "is_marked_custom": False,
    "detection_category": "command_and_control",
    "src_host": {
        "id": 976,
        "ip": "192.168.49.140",
        "name": "IP-192.168.49.140",
        "url": "https://308714519558.cc1.portal.vectra.ai/api/v3.4/hosts/976",
        "is_key_asset": False,
        "groups": [
            {
                "id": 43,
                "name": "Test-24",
                "description": "Host",
                "last_modified": "2025-05-08T12:27:24Z",
                "last_modified_by": "vasu.beladiya@crestdata.ai",
                "type": "host",
            }
        ],
        "threat": 52,
        "certainty": 42,
    },
    "note_modified_timestamp": None,
    "state": "active",
    "sensor_name": "EDR Sensor",
    "tags": [],
    "type": "host",
    "filtered_by_rule": False,
    "data_source": {
        "type": "Unknown sensor type",
        "connection_name": "Unknown sensor name",
        "connection_id": "w4ftj0a8",
    },
    "first_timestamp": "2025-05-12T23:18:44Z",
    "triage_rule_id": None,
    "last_timestamp": "2025-05-12T23:18:44Z",
    "assigned_to": None,
    "note_modified_by": None,
    "url": "https://308714519558.cc1.portal.vectra.ai/api/v3.4/detections/35108",
    "filtered_by_ai": False,
    "assigned_date": None,
    "is_targeting_key_asset": False,
    "note": None,
    "detection_type": "Hidden HTTPS Tunnel",
    "description": None,
    "custom_detection": None,
    "reason": None,
    "investigation_pivot_link": None,
    "grouped_details": [
        {
            "external_target": {"ip": "54.200.5.9", "name": "api.vectranetworks.com"},
            "num_sessions": 157,
            "bytes_received": 11041011,
            "bytes_sent": 372505,
            "ja3_hashes": ["5fb798ffef091e3699f344d0d0895792"],
            "ja3s_hashes": ["15af977ce25de452b96affa2addb1036"],
            "sessions": [
                {
                    "tunnel_type": "Multiple short TCP sessions",
                    "protocol": "tcp",
                    "app_protocol": "https",
                    "dst_port": 443,
                    "dst_ip": "54.200.5.9",
                    "bytes_received": 11041011,
                    "bytes_sent": 372505,
                    "first_timestamp": "2025-05-12T23:18:44Z",
                    "last_timestamp": "2025-05-13T01:43:53Z",
                    "dst_geo": None,
                    "dst_geo_lat": None,
                    "dst_geo_lon": None,
                }
            ],
            "first_timestamp": "2025-05-12T23:18:44Z",
            "last_timestamp": "2025-05-13T01:43:53Z",
            "dst_ips": ["54.200.5.9"],
            "dst_ports": [443],
            "target_domains": ["api.vectranetworks.com"],
        }
    ],
}

DETECTION_TYPES = [
    "Hidden HTTPS Tunnel",
    "Hidden DNS Tunnel",
    "Suspicious Remote Desktop",
    "External Remote Access",
    "Suspicious HTTP",
    "Port Sweep",
    "Ransomware File Activity",
    "Data Smuggler",
    "Suspicious Relay",
]

DETECTION_CATEGORIES = [
    "COMMAND & CONTROL",
    "command_and_control",
    "EXFILTRATION",
    "RECONNAISSANCE",
    "LATERAL MOVEMENT",
    "BOTNET",
]


def generate_detection(use_oauth: bool = False) -> dict[str, Any]:
    """Generate a single Vectra detection event.

    Args:
        use_oauth: If True, generate OAuth API format (v3.4). Otherwise legacy format.

    Returns:
        Detection event dictionary.
    """
    template = VECTRA_DETECTION_OAUTH if use_oauth else VECTRA_DETECTION

    now = now_utc()
    start_time = now - timedelta(hours=random.randint(1, 24))
    end_time = now

    detection_id = random.randint(10000, 99999)
    host_id = random.randint(100, 9999)
    src_ip = generate_private_ip()
    dst_ip = generate_ip()
    detection_type = random.choice(DETECTION_TYPES)
    category = random.choice(DETECTION_CATEGORIES)

    detection = {**template}
    detection["id"] = detection_id
    detection["src_ip"] = src_ip
    detection["detection"] = detection_type
    detection["detection_type"] = detection_type
    detection["detection_category"] = category
    detection["created_timestamp"] = random_iso_timestamp(start_time, end_time)
    detection["first_timestamp"] = random_iso_timestamp(start_time, end_time)
    detection["last_timestamp"] = random_iso_timestamp(start_time, end_time)
    detection["threat"] = random.randint(0, 100)
    detection["certainty"] = random.randint(0, 100)
    detection["state"] = random.choice(["active", "inactive"])

    # Update src_host
    detection["src_host"] = {**template["src_host"]}
    detection["src_host"]["id"] = host_id
    detection["src_host"]["ip"] = src_ip
    detection["src_host"]["name"] = f"IP-{src_ip}"
    detection["src_host"]["threat"] = random.randint(0, 100)
    detection["src_host"]["certainty"] = random.randint(0, 100)

    # Update summary
    detection["summary"] = {**template["summary"]}
    detection["summary"]["dst_ips"] = [dst_ip]
    detection["summary"]["num_sessions"] = random.randint(1, 200)
    detection["summary"]["bytes_sent"] = random.randint(1000, 10000000)
    detection["summary"]["bytes_received"] = random.randint(1000, 100000000)

    if use_oauth:
        detection["url"] = f"https://portal.vectra.ai/api/v3.4/detections/{detection_id}"
        detection["detection_url"] = detection["url"]

    return detection


def vectra_detection_log(use_oauth: bool = False) -> str:
    """Return a single synthetic Vectra detection event in JSON format.

    Args:
        use_oauth: If True, generate OAuth API format (v3.4). Otherwise legacy format.

    Returns:
        JSON string of the detection event.
    """
    return json.dumps(generate_detection(use_oauth))


if __name__ == "__main__":  # pragma: no cover
    print("=== Legacy API Format ===")
    print(vectra_detection_log(use_oauth=False))
    print("\n=== OAuth API Format (v3.4) ===")
    print(vectra_detection_log(use_oauth=True))
