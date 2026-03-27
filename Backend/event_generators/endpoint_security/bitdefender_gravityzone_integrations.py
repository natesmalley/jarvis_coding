#!/usr/bin/env python3
"""
Bitdefender GravityZone - Integrations API Simulated Event Generator
API Endpoint: /v1.0/jsonrpc/integrations
Methods: getHourlyUsageForAmazonEC2Instances,
         configureAmazonEC2IntegrationUsingCrossAccountRole,
         generateAmazonEC2ExternalIdForCrossAccountRole,
         getAmazonEC2ExternalIdForCrossAccountRole,
         disableAmazonEC2Integration
"""
import sys, os
sys.path.insert(0, os.path.dirname(__file__))
from gz_utils import *

AWS_REGIONS = ["us-east-1", "us-west-2", "eu-west-1", "ap-southeast-1", "ca-central-1"]
INSTANCE_TYPES = ["t3.micro", "t3.small", "t3.medium", "m5.large", "c5.xlarge"]

def sim_getHourlyUsageForAmazonEC2Instances():
    instances = [{
        "instanceId": f"i-{random.randint(0x100000000000, 0xffffffffffff):012x}",
        "instanceType": random.choice(INSTANCE_TYPES),
        "region": random.choice(AWS_REGIONS),
        "usageHours": random.randint(1, 744),
        "startDate": now_iso(),
        "endDate": now_iso(),
        "licenseConsumed": random.choice([True, False])
    } for _ in range(random.randint(2, 8))]
    log_event("integrations", "getHourlyUsageForAmazonEC2Instances", {
        "total": len(instances),
        "items": instances
    })

def sim_configureAmazonEC2IntegrationUsingCrossAccountRole():
    log_event("integrations", "configureAmazonEC2IntegrationUsingCrossAccountRole", {
        "result": True,
        "roleArn": f"arn:aws:iam::{random.randint(100000000000, 999999999999)}:role/BitdefenderGZRole",
        "regions": random.sample(AWS_REGIONS, random.randint(1, 3))
    })

def sim_generateAmazonEC2ExternalIdForCrossAccountRole():
    log_event("integrations", "generateAmazonEC2ExternalIdForCrossAccountRole", {
        "externalId": str(uuid.uuid4()).replace("-", "")
    })

def sim_getAmazonEC2ExternalIdForCrossAccountRole():
    log_event("integrations", "getAmazonEC2ExternalIdForCrossAccountRole", {
        "externalId": str(uuid.uuid4()).replace("-", "")
    })

def sim_disableAmazonEC2Integration():
    log_event("integrations", "disableAmazonEC2Integration", {"result": True})

if __name__ == "__main__":
    sims = [
        sim_getHourlyUsageForAmazonEC2Instances,
        sim_configureAmazonEC2IntegrationUsingCrossAccountRole,
        sim_generateAmazonEC2ExternalIdForCrossAccountRole,
        sim_getAmazonEC2ExternalIdForCrossAccountRole,
        sim_disableAmazonEC2Integration
    ]
    for _ in range(random.randint(3, 7)):
        random.choice(sims)()
