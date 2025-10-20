#!/usr/bin/env python3
#WORKING
"""
okta_authentication.py
================================

This module generates synthetic Okta System Log events for testing
SentinelOne AI‑SIEM parsers.  The implementation follows the pattern
established in ``aws_cloudtrail_generator.py``: it defines a set of
static attributes identifying the data source and a function that
returns a fully‑populated event record serialized as JSON.  These
events mimic Okta authentication activity and should exercise most of
the common fields referenced by SentinelOne's Okta parser.

Usage example
-------------

>>> from okta_authentication_generator import okta_authentication_log
>>> print(okta_authentication_log())

The returned string contains a single Okta System Log event.  You can
wrap it alongside the ``ATTR_FIELDS`` dictionary (defined below) when
sending data to the SentinelOne ingestion endpoint.  See
``test_cloudtrail_ingest.py`` for an example of how to submit events.

"""

from __future__ import annotations

import json
import random
import uuid
from datetime import datetime, timezone
from ipaddress import IPv4Address
from typing import Dict, Any, List

# --------------------------------------------------------------------------- #
#  Static fields
# --------------------------------------------------------------------------- #

#: Attributes injected alongside each event.  These mirror the values
#: expected by the SentinelOne AI‑SIEM Okta parser and identify
#: the source of the data.  Update vendor/product names as needed.
# Helper lambdas for brevity
_NOW = lambda: datetime.now(timezone.utc)
_ISO = lambda dt: dt.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
_IP = lambda: str(IPv4Address(random.getrandbits(32)))

# Possible outcome statuses and reasons
_OUTCOMES: List[Dict[str, str]] = [
    {"result": "SUCCESS", "reason": "User logged in successfully"},
    {"result": "FAILURE", "reason": "Invalid credentials"},
    {"result": "FAILURE", "reason": "MFA challenge failed"},
    {"result": "FAILURE", "reason": "Account locked"},
]

# Possible authentication contexts (e.g. login via web, API, mobile)
_AUTH_CONTEXTS = [
    "WEB", "MOBILE", "API", "SAML", "OIDC",
]

# Common Okta event types for authentication
_EVENT_TYPES = [
    "user.authentication.sso",         # Single sign‑on
    "user.authentication.auth_via_mfa",# MFA challenge passed
    "user.session.start",             # Session creation
    "user.session.end",               # Session termination
    "system.api_token.verify",        # API token verification
]

def _random_user() -> Dict[str, Any]:
    """Generate a pseudo‑random Okta user profile for the event.

    Returns a dictionary containing typical user identifiers used in
    Okta System Log entries.  These values are synthetic and do not
    correspond to real people.

    Returns
    -------
    Dict[str, Any]
        A dictionary with ``id``, ``type`` and ``displayName`` fields.
    """
    # Import starfleet characters
    import sys
    import os
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'shared'))
    from starfleet_characters import get_random_user, get_display_name_from_email
    
    user_id = str(uuid.uuid4())
    username = get_random_user()
    return {
        "id": user_id,
        "type": "User",
        "alternateId": username,
        "displayName": get_display_name_from_email(username),
    }

def _random_client() -> Dict[str, Any]:
    """Generate client information for the event.

    This includes network and user agent details typically present in
    Okta System Log records.

    Returns
    -------
    Dict[str, Any]
        A dictionary with keys for ``userAgent`` and ``ipAddress``.
    """
    return {
        "userAgent": {
            "rawUserAgent": random.choice([
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
                " (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36",
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15"
                " (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
                "okta-authenticator/6.1.0 (iOS) CFNetwork/1333.0.4"
            ]),
            "os": {
                "family": random.choice(["Windows", "macOS", "iOS", "Android", "Linux"]),
            },
            "browser": {
                "family": random.choice(["Chrome", "Safari", "Firefox", "Edge", "Opera"]),
            },
        },
        "ipAddress": _IP(),
    }

def okta_authentication_log() -> str:
    """
    Return a single synthetic Okta System Log event in JSON format
    that matches what the parser expects (native Okta JSON format).
    """
    now = _NOW()
    original_time = _ISO(now)
    user = _random_user()
    client = _random_client()
    outcome = random.choice(_OUTCOMES)
    event_type = random.choice(_EVENT_TYPES)
    
    event = {
        "uuid": str(uuid.uuid4()),
        "published": original_time,
        "eventType": event_type,
        "version": "0",
        "severity": random.choice(["INFO", "WARN", "ERROR"]),
        "legacyEventType": f"{event_type}_{'success' if outcome['result'] == 'SUCCESS' else 'failure'}",
        "displayMessage": outcome["reason"],
        "actor": {
            "id": user["id"],
            "type": "User",
            "alternateId": user["alternateId"],
            "displayName": user["displayName"]
        },
        "client": {
            "userAgent": client["userAgent"],
            "zone": "PUBLIC",
            "device": "Computer",
            "ipAddress": client["ipAddress"],
            "geographicalContext": {
                "city": random.choice(["New York", "San Francisco", "Chicago", "Austin", "Denver"]),
                "state": random.choice(["New York", "California", "Illinois", "Texas", "Colorado"]),
                "country": "United States",
                "postalCode": f"{random.randint(10000, 99999)}",
                "geolocation": {
                    "lat": round(random.uniform(25.0, 48.0), 4),
                    "lon": round(random.uniform(-125.0, -65.0), 4)
                }
            }
        },
        "outcome": {
            "result": outcome["result"],
            "reason": outcome["reason"]
        },
        "transaction": {
            "type": random.choice(_AUTH_CONTEXTS),
            "id": str(uuid.uuid4())
        },
        "debugContext": {
            "debugData": {
                "requestId": str(uuid.uuid4()),
                "requestUri": f"/api/v1/{event_type.replace('.', '/')}",
                "threatSuspected": str(random.choice([True, False])).lower(),
                "url": f"/api/v1/{event_type.replace('.', '/')}?limit=20"
            }
        },
        "authenticationContext": {
            "authenticationStep": random.randint(0, 2),
            "externalSessionId": str(uuid.uuid4()),
            "rootSessionId": str(uuid.uuid4())
        },
        "securityContext": {
            "asNumber": random.randint(100, 999),
            "asOrg": random.choice(["comcast cable", "verizon", "att", "cogent communications"]),
            "isp": random.choice(["Comcast", "Verizon", "AT&T", "Cogent"]),
            "domain": random.choice(["comcast.net", "verizon.net", "att.net", "example.com"]),
            "isProxy": random.choice([True, False])
        }
    }
    
    # Add targets for some event types
    if "session" in event_type:
        event["target"] = [{
            "id": str(uuid.uuid4()),
            "type": "AppInstance",
            "alternateId": f"app_{random.randint(1000, 9999)}",
            "displayName": random.choice(["Salesforce", "Office 365", "Google Workspace", "Slack"])
        }]
    
    return json.dumps(event)

if __name__ == "__main__":  # pragma: no cover
    # Simple demo: print a few sample events to stdout
    for _ in range(3):
        print(okta_authentication_log())
