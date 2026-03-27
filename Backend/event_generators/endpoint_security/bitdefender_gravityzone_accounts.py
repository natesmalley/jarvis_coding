#!/usr/bin/env python3
"""
Bitdefender GravityZone - Accounts API Simulated Event Generator
API Endpoint: /v1.0/jsonrpc/accounts
Methods: getAccountsList, deleteAccount, createAccount, updateAccount,
         configureNotificationsSettings, getNotificationsSettings
"""
import sys, os
sys.path.insert(0, os.path.dirname(__file__))
from gz_utils import *

ROLES = [1, 2, 3, 4, 5]  # 1=company admin, 2=network admin, 3=reporter, etc.
LANGUAGES = ["en_US", "en_GB", "de_DE", "fr_FR", "es_ES"]

def fake_account():
    uid = rand_id()
    name = random.choice(["alice", "bob", "carol", "dave", "eve", "frank"])
    return {
        "id": uid,
        "email": f"{name}.{random.randint(10,99)}@example.com",
        "profile": {
            "fullName": name.capitalize() + " Smith",
            "timezone": "UTC",
            "preferredLanguage": random.choice(LANGUAGES)
        },
        "role": random.choice(ROLES),
        "isActive": random.choice([True, True, True, False]),
        "twoFactorAuthEnabled": random.choice([True, False]),
        "lastLogin": now_iso()
    }

def sim_getAccountsList():
    accounts = [fake_account() for _ in range(random.randint(2, 6))]
    log_event("accounts", "getAccountsList", {
        "total": len(accounts),
        "page": 1,
        "perPage": 30,
        "pagesCount": 1,
        "items": accounts
    })

def sim_createAccount():
    acc = fake_account()
    log_event("accounts", "createAccount", {"id": acc["id"]})

def sim_updateAccount():
    log_event("accounts", "updateAccount", {"result": True})

def sim_deleteAccount():
    log_event("accounts", "deleteAccount", {"result": True})

def sim_configureNotificationsSettings():
    log_event("accounts", "configureNotificationsSettings", {"result": True})

def sim_getNotificationsSettings():
    log_event("accounts", "getNotificationsSettings", {
        "notifications": {
            "malwareDetectionAlert": {"sendEmail": True, "emailAddresses": ["soc@example.com"]},
            "blocklistThreats": {"sendEmail": False, "emailAddresses": []},
            "productRegistration": {"sendEmail": True, "emailAddresses": ["admin@example.com"]},
            "licenseExpiration": {"sendEmail": True, "emailAddresses": ["admin@example.com"]}
        }
    })

if __name__ == "__main__":
    for _ in range(random.randint(3, 8)):
        random.choice([
            sim_getAccountsList,
            sim_createAccount,
            sim_updateAccount,
            sim_deleteAccount,
            sim_configureNotificationsSettings,
            sim_getNotificationsSettings,
        ])()
