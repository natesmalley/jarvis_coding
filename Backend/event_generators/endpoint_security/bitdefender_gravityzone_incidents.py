#!/usr/bin/env python3
"""
Bitdefender GravityZone - Incidents API Simulated Event Generator
API Endpoint: /v1.0/jsonrpc/incidents
Methods: addToBlocklist, getBlocklistItems, removeFromBlocklist,
         createIsolateEndpointTask, createRestoreEndpointFromIsolationTask
"""
import sys, os
sys.path.insert(0, os.path.dirname(__file__))
from gz_utils import *

HASH_TYPES = ["md5", "sha256"]
BLOCKLIST_REASONS = ["malware", "suspicious-activity", "policy-violation", "user-request"]

def random_hash(hash_type="sha256"):
    length = 64 if hash_type == "sha256" else 32
    return f"{random.randint(0, 16**length - 1):0{length}x}"

def sim_addToBlocklist():
    hash_type = random.choice(HASH_TYPES)
    log_event("incidents", "addToBlocklist", {
        "hashType": hash_type,
        "hashList": [random_hash(hash_type) for _ in range(random.randint(1, 5))],
        "sourceInfo": {
            "type": random.choice(["file", "process"]),
            "computerName": rand_hostname(),
            "filePath": "C:\\Windows\\Temp\\malware.exe"
        },
        "reason": random.choice(BLOCKLIST_REASONS),
        "result": True
    })

def sim_getBlocklistItems():
    items = [{
        "id": rand_id(),
        "hash": random_hash(),
        "hashType": "sha256",
        "addedAt": now_iso(),
        "addedBy": f"user{random.randint(1,10)}@example.com",
        "reason": random.choice(BLOCKLIST_REASONS),
        "status": random.choice(["active", "pending"])
    } for _ in range(random.randint(2, 10))]
    log_event("incidents", "getBlocklistItems", {
        "total": len(items),
        "items": items
    })

def sim_removeFromBlocklist():
    log_event("incidents", "removeFromBlocklist", {"result": True})

def sim_createIsolateEndpointTask():
    endpoint_id = rand_endpoint_id()
    log_event("incidents", "createIsolateEndpointTask", {
        "taskId": rand_id(),
        "endpointId": endpoint_id,
        "computerName": rand_hostname(),
        "isolationReason": random.choice([
            "ransomware-detected", "lateral-movement-suspected",
            "active-incident", "threat-investigation"
        ]),
        "status": "pending",
        "createdAt": now_iso()
    })

def sim_createRestoreEndpointFromIsolationTask():
    endpoint_id = rand_endpoint_id()
    log_event("incidents", "createRestoreEndpointFromIsolationTask", {
        "taskId": rand_id(),
        "endpointId": endpoint_id,
        "computerName": rand_hostname(),
        "status": "pending",
        "createdAt": now_iso()
    })

if __name__ == "__main__":
    sims = [
        sim_addToBlocklist, sim_getBlocklistItems, sim_removeFromBlocklist,
        sim_createIsolateEndpointTask, sim_createRestoreEndpointFromIsolationTask
    ]
    for _ in range(random.randint(4, 10)):
        random.choice(sims)()
