#!/usr/bin/env python3
"""
Bitdefender GravityZone - Reports API Simulated Event Generator
API Endpoint: /v1.0/jsonrpc/reports
Methods: createReport, getReportsList, getDownloadLinks, deleteReport
"""
import sys, os
sys.path.insert(0, os.path.dirname(__file__))
from gz_utils import *

REPORT_TYPES = [
    "malwareStatus", "networkStatus", "policyCompliance",
    "updateStatus", "licenseUsage", "executiveSummary",
    "topMalware", "topTargetedEndpoints", "deviceControl",
    "webCategoryTraffic", "firewallActivity", "scanTaskStatus"
]
REPORT_FORMATS = ["pdf", "csv", "xlsx"]
REPORT_FREQUENCIES = ["once", "daily", "weekly", "monthly"]

def sim_createReport():
    log_event("reports", "createReport", {"id": rand_id()})

def sim_getReportsList():
    reports = [{
        "id": rand_id(),
        "name": f"{random.choice(REPORT_TYPES)}-{random.randint(1,100)}",
        "type": random.choice(REPORT_TYPES),
        "format": random.choice(REPORT_FORMATS),
        "frequency": random.choice(REPORT_FREQUENCIES),
        "status": random.choice(["pending", "running", "finished", "error"]),
        "scheduledDate": now_iso(),
        "createdAt": now_iso(),
        "size": random.randint(50000, 5000000)
    } for _ in range(random.randint(2, 8))]
    log_event("reports", "getReportsList", {
        "total": len(reports),
        "page": 1,
        "perPage": 30,
        "pagesCount": 1,
        "items": reports
    })

def sim_getDownloadLinks():
    log_event("reports", "getDownloadLinks", {
        "downloadLinks": [
            {
                "id": rand_id(),
                "link": f"https://cloud.gravityzone.bitdefender.com/reports/{rand_id()}/download",
                "expiresAt": now_iso()
            }
            for _ in range(random.randint(1, 3))
        ]
    })

def sim_deleteReport():
    log_event("reports", "deleteReport", {"result": True})

if __name__ == "__main__":
    sims = [sim_createReport, sim_getReportsList, sim_getDownloadLinks, sim_deleteReport]
    for _ in range(random.randint(3, 8)):
        random.choice(sims)()
