#!/usr/bin/env python3
"""
Bitdefender GravityZone - Companies API Simulated Event Generator
API Endpoint: /v1.0/jsonrpc/companies
Methods: getCompanyDetails, updateCompanyDetails
"""
import sys, os
sys.path.insert(0, os.path.dirname(__file__))
from gz_utils import *

COUNTRIES = ["US", "GB", "DE", "FR", "CA", "AU"]

def sim_getCompanyDetails():
    log_event("companies", "getCompanyDetails", {
        "id": rand_id(),
        "name": random.choice(["Acme Corp", "Globex Inc", "Initech", "Umbrella LLC"]),
        "address": f"{random.randint(1,999)} Main St",
        "city": random.choice(["New York", "London", "Berlin", "Toronto"]),
        "country": random.choice(COUNTRIES),
        "phone": f"+1-{random.randint(200,999)}-{random.randint(100,999)}-{random.randint(1000,9999)}",
        "licenseType": random.choice(["business", "enterprise"]),
        "parentId": None
    })

def sim_updateCompanyDetails():
    log_event("companies", "updateCompanyDetails", {"result": True})

if __name__ == "__main__":
    for _ in range(random.randint(2, 5)):
        random.choice([sim_getCompanyDetails, sim_updateCompanyDetails])()
