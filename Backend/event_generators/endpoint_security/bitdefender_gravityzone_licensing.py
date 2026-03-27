#!/usr/bin/env python3
"""
Bitdefender GravityZone - Licensing API Simulated Event Generator
API Endpoint: /v1.0/jsonrpc/licensing
Methods: getLicenseInfo, setLicenseKey, getMonthlyUsage
"""
import sys, os
sys.path.insert(0, os.path.dirname(__file__))
from gz_utils import *

def sim_getLicenseInfo():
    log_event("licensing", "getLicenseInfo", {
        "licenseKey": f"GZ-{random.randint(100000,999999)}-{random.randint(1000,9999)}",
        "type": random.choice(["BusinessSecurity", "BusinessSecurityPremium", "Enterprise"]),
        "status": random.choice(["active", "expired", "trial"]),
        "startDate": "2024-01-01",
        "endDate": "2025-12-31",
        "seats": random.randint(50, 500),
        "usedSeats": random.randint(10, 49),
        "modules": {
            "advancedThreatControl": True,
            "patchManagement": random.choice([True, False]),
            "fullDiskEncryption": random.choice([True, False]),
            "edr": random.choice([True, False]),
            "networkSandboxAnalyzer": random.choice([True, False])
        }
    })

def sim_setLicenseKey():
    log_event("licensing", "setLicenseKey", {"result": True})

def sim_getMonthlyUsage():
    months = []
    for m in range(1, 13):
        months.append({
            "month": f"2024-{m:02d}",
            "slots": random.randint(40, 500)
        })
    log_event("licensing", "getMonthlyUsage", {"usageData": months})

if __name__ == "__main__":
    for _ in range(random.randint(3, 6)):
        random.choice([sim_getLicenseInfo, sim_setLicenseKey, sim_getMonthlyUsage])()
