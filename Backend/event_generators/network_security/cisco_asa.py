#!/usr/bin/env python3
"""
Cisco ASA syslog event generator (flattened for S1 parser)
"""
from __future__ import annotations
import random, time
from datetime import datetime, timezone
from typing import Dict

_PRI = "<166>"                       # local4.info
_HOST = "asa-demo"

_LOG_TEMPLATES = [
    (
        "%ASA-6-302015",
        "Built outbound TCP connection {conn_id} for inside:{src_ip}/{src_port} ({src_ip}/{src_port}) "
        "to outside:{dst_ip}/{dst_port} ({dst_ip}/{dst_port})"
    ),
    (
        "%ASA-5-304001",
        "Teardown TCP connection {conn_id} for inside:{src_ip}/{src_port} "
        "to outside:{dst_ip}/{dst_port} duration 0:00:01 bytes 350 TCP FINs"
    ),
    (
        "%ASA-4-313001",
        "Deny TCP (no connection) from {src_ip}/{src_port} to {dst_ip}/{dst_port} on interface inside"
    ),
]

def _iso(t: float) -> str:
    # Include the 4‑digit year so the output matches the parser’s tsPattern (MMM DD YYYY HH:MM:SS)
    return datetime.fromtimestamp(t, timezone.utc).strftime("%b %d %Y %H:%M:%S")

def asa_log() -> str:
    """
    Return a single Cisco ASA‑style syslog line (no JSON wrapper).
    This lets downstream pipelines feed the line directly into the
    SentinelOne ASA parser without needing a payloadSelector.
    """
    now = time.time()
    ts_str = _iso(now)

    # Example addresses/ports — swap for real or larger pools as desired
    src_ip = "192.0.2.10"
    dst_ip = "203.0.113.5"
    src_port = random.randint(1024, 65535)
    dst_port = 443
    conn_id = random.randint(100000, 999999)

    tag, body_template = random.choice(_LOG_TEMPLATES)
    syslog_msg = (
        f"{_PRI}{ts_str} {_HOST} : {tag}: "
        + body_template.format(
            conn_id=conn_id,
            src_ip=src_ip,
            src_port=src_port,
            dst_ip=dst_ip,
            dst_port=dst_port,
        )
    )
    return syslog_msg