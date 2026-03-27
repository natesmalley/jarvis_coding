#!/usr/bin/env python3
"""
Bitdefender GravityZone - Packages API Simulated Event Generator
API Endpoint: /v1.0/jsonrpc/packages
Methods: getInstallationLinks, createPackage, getPackagesList,
         deletePackage, getPackageDetails
"""
import sys, os
sys.path.insert(0, os.path.dirname(__file__))
from gz_utils import *

OS_PLATFORMS = ["windows", "linux", "mac"]

def fake_package():
    return {
        "id": rand_id(),
        "name": f"BEST-Package-{random.randint(1,20)}",
        "description": "Auto-generated deployment package",
        "language": "en_US",
        "modules": {
            "antimalware": True,
            "advancedThreatControl": True,
            "firewall": random.choice([True, False]),
            "contentControl": random.choice([True, False]),
            "deviceControl": random.choice([True, False]),
            "patchManagement": random.choice([True, False]),
            "fullDiskEncryption": random.choice([True, False])
        },
        "scanMode": random.choice([1, 2, 3]),
        "deploymentOptions": {
            "downloadFromCloud": True,
            "uninstallPassword": random.choice([True, False])
        },
        "platform": random.choice(OS_PLATFORMS),
        "version": f"7.{random.randint(5,9)}.{random.randint(0,9)}.{random.randint(100,200)}"
    }

def sim_getInstallationLinks():
    log_event("packages", "getInstallationLinks", {
        "installationLinks": [
            {
                "id": rand_id(),
                "packageName": f"BEST-Package-{random.randint(1,10)}",
                "installLink": f"https://cloud.gravityzone.bitdefender.com/Packages/STD/0/{rand_id()}/gravityzone_business_security.exe",
                "osType": random.choice(OS_PLATFORMS)
            }
            for _ in range(random.randint(1, 3))
        ]
    })

def sim_createPackage():
    log_event("packages", "createPackage", {"id": rand_id()})

def sim_getPackagesList():
    pkgs = [fake_package() for _ in range(random.randint(2, 6))]
    log_event("packages", "getPackagesList", {"total": len(pkgs), "items": pkgs})

def sim_deletePackage():
    log_event("packages", "deletePackage", {"result": True})

def sim_getPackageDetails():
    log_event("packages", "getPackageDetails", fake_package())

if __name__ == "__main__":
    sims = [sim_getInstallationLinks, sim_createPackage, sim_getPackagesList,
            sim_deletePackage, sim_getPackageDetails]
    for _ in range(random.randint(3, 8)):
        random.choice(sims)()
