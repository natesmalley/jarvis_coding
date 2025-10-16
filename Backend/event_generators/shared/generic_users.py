#!/usr/bin/env python3
"""
Generic Users for Consistent Scenario Generation
================================================

Shared user data for all event generators to create consistent
attack scenarios with realistic corporate users.
"""

import random

# Generic corporate users
CORPORATE_USERS = [
    "john.smith@company.com",
    "sarah.johnson@company.com",
    "michael.chen@company.com",
    "jennifer.davis@company.com",
    "robert.wilson@company.com",
    "lisa.anderson@company.com",
    "david.thompson@company.com",
    "mary.garcia@company.com",
    "james.martinez@company.com",
    "patricia.jones@company.com",
    "william.brown@company.com",
    "elizabeth.taylor@company.com",
    "richard.moore@company.com",
    "susan.jackson@company.com",
    "joseph.white@company.com",
    "jessica.harris@company.com",
    "thomas.clark@company.com",
    "nancy.lewis@company.com",
    "charles.walker@company.com",
    "karen.hall@company.com",
    "daniel.allen@company.com",
    "amy.young@company.com",
    "matthew.king@company.com",
    "laura.scott@company.com",
    "mark.green@company.com",
    "emily.adams@company.com",
    "paul.baker@company.com",
    "donna.nelson@company.com",
    "andrew.hill@company.com",
    "michelle.campbell@company.com",
    "admin@company.com",
    "security@company.com",
    "it-support@company.com",
    "hr@company.com",
    "finance@company.com"
]

# High value targets
HIGH_VALUE_USERS = [
    "admin@company.com",
    "security@company.com",
    "john.smith@company.com",  # CEO
    "sarah.johnson@company.com",  # CFO
    "michael.chen@company.com"  # CTO
]

# Department mapping
USER_DEPARTMENTS = {
    "engineering": ["michael.chen@company.com", "david.thompson@company.com", "william.brown@company.com"],
    "security": ["security@company.com", "robert.wilson@company.com", "charles.walker@company.com"],
    "finance": ["finance@company.com", "sarah.johnson@company.com", "susan.jackson@company.com"],
    "hr": ["hr@company.com", "jennifer.davis@company.com", "nancy.lewis@company.com"],
    "it": ["it-support@company.com", "james.martinez@company.com", "daniel.allen@company.com"],
    "executive": ["john.smith@company.com", "sarah.johnson@company.com", "michael.chen@company.com"]
}

# Organization details
ORGANIZATION = {
    "name": "Example Corporation",
    "domain": "company.com",
    "headquarters": "New York, NY",
    "industry": "Technology"
}

def get_random_user():
    """Get a random user from the corporate users list"""
    return random.choice(CORPORATE_USERS)

def get_compromised_user():
    """Get a user that would be the target of compromise"""
    return random.choice(HIGH_VALUE_USERS)

def get_user_by_department(department: str):
    """Get a random user from a specific department"""
    if department in USER_DEPARTMENTS:
        return random.choice(USER_DEPARTMENTS[department])
    return get_random_user()

def get_high_value_targets():
    """Get list of high value targets"""
    return HIGH_VALUE_USERS

def get_username_from_email(email: str) -> str:
    """Extract username from email address"""
    return email.split('@')[0] if '@' in email else email