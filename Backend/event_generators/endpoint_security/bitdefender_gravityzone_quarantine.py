#!/usr/bin/env python3
"""
Bitdefender GravityZone - Quarantine API Simulated Event Generator
API Endpoint: /v1.0/jsonrpc/quarantine
Methods: getQuarantineItemsList, createRemoveQuarantineItemTask,
         createRestoreQuarantineItemTask, createRemoveQuarantineExchangeItemTask,
         createRestoreQuarantineExchangeItemTask
"""
import sys, os
sys.path.insert(0, os.path.dirname(__file__))
from gz_utils import *

QUARANTINE_REASONS = [
    "on-access-scan", "on-demand-scan", "real-time-scan",
    "manual", "exchange-scan", "policy-action"
]
MALWARE_NAMES = [
    "Trojan.GenericKD.123456", "Ransomware.WannaCry", "Adware.BrowseFox",
    "Exploit.CVE-2021-44228", "Backdoor.Cobalt.Strike", "PUA.CoinMiner"
]

def fake_quarantine_item(exchange=False):
    item = {
        "id": rand_id(),
        "endpointId": rand_endpoint_id(),
        "computerName": rand_hostname(),
        "malwareName": random.choice(MALWARE_NAMES),
        "malwareType": random.choice(["virus", "trojan", "ransomware", "adware"]),
        "hash": f"{random.randint(0, 16**64 - 1):064x}",
        "quarantineDate": now_iso(),
        "reason": random.choice(QUARANTINE_REASONS),
        "status": random.choice(["quarantined", "pending-delete", "pending-restore"])
    }
    if exchange:
        item["senderEmail"] = f"attacker{random.randint(1,99)}@malicious.com"
        item["recipientEmail"] = f"user{random.randint(1,100)}@example.com"
        item["subject"] = random.choice(["Invoice", "Urgent Notice", "Account Suspended"])
    else:
        item["filePath"] = random.choice([
            "C:\\Users\\user\\Downloads\\infected.exe",
            "C:\\Windows\\Temp\\payload.dll",
            "/tmp/.malware"
        ])
        item["fileSize"] = random.randint(1024, 10485760)
    return item

def sim_getQuarantineItemsList():
    items = [fake_quarantine_item(exchange=random.choice([True, False]))
             for _ in range(random.randint(2, 8))]
    log_event("quarantine", "getQuarantineItemsList", {
        "total": len(items),
        "page": 1,
        "perPage": 30,
        "pagesCount": 1,
        "items": items
    })

def sim_createRemoveQuarantineItemTask():
    log_event("quarantine", "createRemoveQuarantineItemTask", {
        "taskId": rand_id(),
        "status": "pending",
        "targetItems": [rand_id() for _ in range(random.randint(1, 3))],
        "createdAt": now_iso()
    })

def sim_createRestoreQuarantineItemTask():
    log_event("quarantine", "createRestoreQuarantineItemTask", {
        "taskId": rand_id(),
        "status": "pending",
        "targetItems": [rand_id() for _ in range(random.randint(1, 3))],
        "restorePath": "C:\\Users\\user\\Desktop\\restored\\",
        "createdAt": now_iso()
    })

def sim_createRemoveQuarantineExchangeItemTask():
    log_event("quarantine", "createRemoveQuarantineExchangeItemTask", {
        "taskId": rand_id(),
        "status": "pending",
        "targetItems": [rand_id() for _ in range(random.randint(1, 3))],
        "createdAt": now_iso()
    })

def sim_createRestoreQuarantineExchangeItemTask():
    log_event("quarantine", "createRestoreQuarantineExchangeItemTask", {
        "taskId": rand_id(),
        "status": "pending",
        "targetItems": [rand_id() for _ in range(random.randint(1, 2))],
        "createdAt": now_iso()
    })

if __name__ == "__main__":
    sims = [
        sim_getQuarantineItemsList,
        sim_createRemoveQuarantineItemTask,
        sim_createRestoreQuarantineItemTask,
        sim_createRemoveQuarantineExchangeItemTask,
        sim_createRestoreQuarantineExchangeItemTask
    ]
    for _ in range(random.randint(4, 10)):
        random.choice(sims)()
