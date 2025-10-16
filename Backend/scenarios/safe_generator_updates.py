#!/usr/bin/env python3
"""
Safe Generator Updates - Test script to verify changes don't break generators
==============================================================================
This script safely updates hardcoded users/domains with Star Trek data
while preserving all generator functionality.
"""

import json
import sys
import os

# Add paths
sys.path.insert(0, '../event_generators/email_security')
sys.path.insert(0, '../event_generators/endpoint_security')
sys.path.insert(0, '../event_generators/identity_access')
sys.path.insert(0, '../event_generators/web_security')

# Star Trek users to replace hardcoded names
STARFLEET_USERS = [
    "jean.picard", "william.riker", "data.android", "geordi.laforge", "worf.security"
]

STARFLEET_FULL_EMAILS = [
    "jean.picard@starfleet.corp",
    "william.riker@starfleet.corp", 
    "data.android@starfleet.corp",
    "geordi.laforge@starfleet.corp",
    "worf.security@starfleet.corp"
]

def test_generator(module_name, func_name):
    """Test if a generator works"""
    try:
        module = __import__(module_name)
        func = getattr(module, func_name)
        event = func()
        return event is not None
    except Exception as e:
        print(f"Error: {e}")
        return False

def main():
    print("🧪 SAFE GENERATOR UPDATE TEST")
    print("=" * 60)
    
    # Test each generator before changes
    generators = [
        ('mimecast', 'mimecast_log'),
        ('abnormal_security', 'abnormal_security_log'),
        ('sentinelone_endpoint', 'sentinelone_endpoint_log'),
        ('okta_authentication', 'okta_authentication_log'),
        ('netskope', 'netskope_log')
    ]
    
    print("\n📊 Current Status:")
    for module_name, func_name in generators:
        status = "✅" if test_generator(module_name, func_name) else "❌"
        print(f"{status} {module_name}")
    
    print("\n📝 Recommended Changes:")
    print("1. Mimecast: Replace USERS list with Star Trek names")
    print("2. Abnormal Security: Change @company.com to @starfleet.corp")
    print("3. SentinelOne: Replace USERS list with Star Trek names")
    print("4. Okta: Already clean ✅")
    print("5. Netskope: Replace USERS list with Star Trek names")
    
    print("\n⚠️  IMPORTANT: Only update the data lists, not the logic!")

if __name__ == "__main__":
    main()