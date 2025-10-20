#!/usr/bin/env python3
"""
AWS VPC Flow Log record generator
"""
from __future__ import annotations
import json, random, time, uuid
from typing import Dict

def _flow_record() -> dict:
    """
    Create one VPC Flow Log record in JSON format matching parser expectations.
    Parser expects JSON with fields like srcaddr, dstaddr, start, end, etc.
    """
    now = int(time.time())
    start_time = now - random.randint(10, 60)
    end_time = now
    
    return {
        "version": "2",
        "account_id": f"{random.randint(10**11, 10**12 - 1)}",
        "interface_id": "eni-" + uuid.uuid4().hex[:17],
        "srcaddr": f"10.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}",
        "dstaddr": f"203.0.113.{random.randint(1,254)}",
        "srcport": random.randint(1024, 65535),
        "dstport": random.choice([22, 53, 80, 443, 3389]),
        "protocol": random.choice([6, 17]),  # 6 = TCP, 17 = UDP
        "packets": random.randint(1, 500),
        "bytes": random.randint(40, 50000),
        "start": start_time,
        "end": end_time,
        "action": random.choice(["ACCEPT", "REJECT"]),
        "flowlogstatus": "OK",
        "vpc_id": f"vpc-{uuid.uuid4().hex[:8]}",
        "subnet_id": f"subnet-{uuid.uuid4().hex[:8]}",
        "instance_id": f"i-{uuid.uuid4().hex[:8]}",
        "region": random.choice(["us-east-1", "us-west-2", "eu-central-1"]),
        "az_id": random.choice(["use1-az1", "use1-az2", "usw2-az1"]),
    }

def vpcflow_log() -> dict:
    """
    Generate a VPC Flow Log record in JSON format matching parser expectations.
    Returns a dict with VPC flow log fields that the parser can extract.
    """
    return _flow_record()