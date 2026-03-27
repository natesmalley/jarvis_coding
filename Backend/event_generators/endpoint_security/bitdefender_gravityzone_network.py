#!/usr/bin/env python3
"""
Bitdefender GravityZone - Network API Simulated Event Generator
API Endpoint: /v1.0/jsonrpc/network
Methods: getEndpointsList, getManagedEndpointDetails, createCustomGroup,
         deleteCustomGroup, getCustomGroupsList, moveEndpoints, deleteEndpoint,
         moveCustomGroup, getNetworkInventoryItems, createScanTask,
         getScanTasksList, setEndpointLabel
"""
import sys, os
sys.path.insert(0, os.path.dirname(__file__))
from gz_utils import *

OS_TYPES = ["Windows 10", "Windows 11", "Windows Server 2019", "Ubuntu 22.04", "macOS 13"]
AGENT_VERSIONS = ["7.9.5.177", "7.8.4.160", "7.7.3.140"]
SCAN_TYPES = [1, 2, 3]  # 1=quick, 2=full, 3=custom

def fake_endpoint():
    return {
        "id": rand_endpoint_id(),
        "name": rand_hostname(),
        "fqdn": f"{rand_hostname().lower()}.corp.example.com",
        "groupId": rand_id(),
        "isManaged": True,
        "operatingSystemVersion": random.choice(OS_TYPES),
        "ip": rand_ip(),
        "macs": [rand_mac()],
        "agentVersion": random.choice(AGENT_VERSIONS),
        "state": random.choice([1, 2, 3]),  # 1=managed, 2=unmanaged, 3=deleted
        "lastSeen": now_iso(),
        "policy": {
            "id": rand_policy_id(),
            "name": random.choice(["Default Policy", "Strict Policy", "Server Policy"])
        },
        "modules": {
            "antimalware": {"installed": True, "running": True},
            "firewall": {"installed": random.choice([True, False]), "running": True},
            "advancedThreatControl": {"installed": True, "running": True},
            "contentControl": {"installed": random.choice([True, False]), "running": True}
        },
        "riskScore": round(random.uniform(0.0, 10.0), 2),
        "label": random.choice(["", "critical-server", "dev-machine", "finance"])
    }

def sim_getEndpointsList():
    endpoints = [fake_endpoint() for _ in range(random.randint(3, 10))]
    log_event("network", "getEndpointsList", {
        "total": len(endpoints),
        "page": 1,
        "perPage": 30,
        "pagesCount": 1,
        "items": endpoints
    })

def sim_getManagedEndpointDetails():
    log_event("network", "getManagedEndpointDetails", fake_endpoint())

def sim_createCustomGroup():
    log_event("network", "createCustomGroup", {"id": rand_id()})

def sim_deleteCustomGroup():
    log_event("network", "deleteCustomGroup", {"result": True})

def sim_getCustomGroupsList():
    groups = [{"id": rand_id(), "name": f"Group-{random.randint(1,50)}", "parentId": None}
              for _ in range(random.randint(2, 6))]
    log_event("network", "getCustomGroupsList", {"items": groups})

def sim_moveEndpoints():
    log_event("network", "moveEndpoints", {"result": True})

def sim_deleteEndpoint():
    log_event("network", "deleteEndpoint", {"result": True})

def sim_moveCustomGroup():
    log_event("network", "moveCustomGroup", {"result": True})

def sim_getNetworkInventoryItems():
    items = [{
        "id": rand_id(),
        "name": rand_hostname(),
        "type": random.choice(["computer", "virtualMachine", "mobileDevice"]),
        "ip": rand_ip(),
        "operatingSystem": random.choice(OS_TYPES),
        "lastSeen": now_iso()
    } for _ in range(random.randint(3, 10))]
    log_event("network", "getNetworkInventoryItems", {
        "total": len(items),
        "items": items
    })

def sim_createScanTask():
    log_event("network", "createScanTask", {"id": rand_id()})

def sim_getScanTasksList():
    tasks = [{
        "id": rand_id(),
        "name": f"ScanTask-{random.randint(100,999)}",
        "status": random.choice([1, 2, 3]),  # 1=pending, 2=running, 3=finished
        "scanType": random.choice(SCAN_TYPES),
        "startDate": now_iso(),
        "endDate": now_iso() if random.choice([True, False]) else None,
        "targetEndpoints": [rand_endpoint_id() for _ in range(random.randint(1, 5))]
    } for _ in range(random.randint(1, 5))]
    log_event("network", "getScanTasksList", {"total": len(tasks), "items": tasks})

def sim_setEndpointLabel():
    log_event("network", "setEndpointLabel", {"result": True})

if __name__ == "__main__":
    sims = [
        sim_getEndpointsList, sim_getManagedEndpointDetails,
        sim_createCustomGroup, sim_deleteCustomGroup, sim_getCustomGroupsList,
        sim_moveEndpoints, sim_deleteEndpoint, sim_moveCustomGroup,
        sim_getNetworkInventoryItems, sim_createScanTask,
        sim_getScanTasksList, sim_setEndpointLabel
    ]
    for _ in range(random.randint(6, 15)):
        random.choice(sims)()
