#!/usr/bin/env python3
"""
Bitdefender GravityZone - Policies API Simulated Event Generator
API Endpoint: /v1.0/jsonrpc/policies
Methods: getPoliciesList, getPolicyDetails
"""
import sys, os
sys.path.insert(0, os.path.dirname(__file__))
from gz_utils import *

POLICY_NAMES = [
    "Default Policy", "Strict Endpoint Policy", "Server Policy",
    "Developer Workstation Policy", "Finance Workstation Policy",
    "Executive Device Policy", "PCI-DSS Compliance Policy"
]

def fake_policy():
    return {
        "id": rand_policy_id(),
        "name": random.choice(POLICY_NAMES),
        "isDefault": random.choice([True, False]),
        "assignedEndpoints": random.randint(0, 100),
        "updatedAt": now_iso(),
        "modules": {
            "antimalware": {
                "enabled": True,
                "onAccess": True,
                "onDemand": True,
                "quarantine": True
            },
            "firewall": {
                "enabled": random.choice([True, False]),
                "blockAllExceptAllowed": False
            },
            "contentControl": {
                "enabled": random.choice([True, False]),
                "webCategories": ["malware", "phishing"]
            },
            "deviceControl": {
                "enabled": random.choice([True, False])
            },
            "advancedThreatControl": {
                "enabled": True,
                "level": random.choice(["permissive", "normal", "aggressive"])
            },
            "hvi": {
                "enabled": random.choice([True, False])
            }
        }
    }

def sim_getPoliciesList():
    policies = [fake_policy() for _ in range(random.randint(2, 7))]
    log_event("policies", "getPoliciesList", {
        "total": len(policies),
        "page": 1,
        "perPage": 30,
        "pagesCount": 1,
        "items": policies
    })

def sim_getPolicyDetails():
    log_event("policies", "getPolicyDetails", fake_policy())

if __name__ == "__main__":
    for _ in range(random.randint(3, 7)):
        random.choice([sim_getPoliciesList, sim_getPolicyDetails])()
