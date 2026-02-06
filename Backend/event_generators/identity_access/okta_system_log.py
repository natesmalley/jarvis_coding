#!/usr/bin/env python3
"""Okta System Log event generator.

Generates Okta System Log events with weighted distribution.
Supports multiple event types including normal logs, MFA failures,
rate limiting, suspicious activity, and account lockouts.
"""

from __future__ import annotations

import json
import os
import random
import sys
import uuid
from datetime import datetime, timedelta
from typing import Any

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'shared'))
from generator_utils import (
    generate_email,
    generate_ip,
    now_utc,
    random_iso_timestamp,
    weighted_choice_from_dict,
)

# Log type weights
# 70% normal, 10% MFA failure, 10% rate limited, 5% suspicious, 5% lockout
LOG_WEIGHTS: dict[str, float] = {
    "raw_log": 0.70,
    "mfa_failure": 0.10,
    "rate_limited": 0.10,
    "suspicious_activity": 0.05,
    "account_lockout": 0.05,
}

# Base successful API token creation event
SAMPLE_RAW_LOG: dict[str, Any] = {
    "actor": {
        "id": "00u4729hjsVRU197Y5d7",
        "type": "User",
        "alternateId": "dummy@example.com",
        "displayName": "Dummy User",
        "detailEntry": None,
    },
    "client": {
        "userAgent": {
            "rawUserAgent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
            "os": "Linux",
            "browser": "CHROME",
        },
        "zone": "null",
        "device": "Computer",
        "id": None,
        "ipAddress": "103.99.111.142",
        "geographicalContext": {
            "city": "Hyderabad",
            "state": "Telangana",
            "country": "India",
            "postalCode": "500004",
            "geolocation": {"lat": 17.3724, "lon": 78.4378},
        },
    },
    "device": None,
    "authenticationContext": {
        "authenticationProvider": None,
        "credentialProvider": None,
        "credentialType": None,
        "issuer": None,
        "interface": None,
        "authenticationStep": 0,
        "rootSessionId": "102eA1R",
        "externalSessionId": "102eA1R2M",
    },
    "displayMessage": "Create API token",
    "eventType": "system.api_token.create",
    "outcome": {"result": "SUCCESS", "reason": None},
    "published": "2024-11-06T06:34:37.964Z",
    "securityContext": {
        "asNumber": 150008,
        "asOrg": "s r fibernet",
        "isp": "pioneer elabs ltd.",
        "domain": None,
        "isProxy": False,
    },
    "severity": "INFO",
    "debugContext": {
        "debugData": {
            "concurrencyPercentage": "50",
            "requestId": "7d2ec1766f1090c38561a0436a628ef4",
            "dtHash": "43fa03767e62cd45bf1b9ecf03ca2ee6f8d42c1248d6c3d5adcf990c055128a0",
            "rateLimitPercentage": "50",
            "networkConnection": "ANYWHERE",
            "requestUri": "/api/internal/tokens",
            "url": "/api/internal/tokens?expand=user",
        }
    },
    "legacyEventType": "api.token.create",
    "transaction": {"type": "WEB", "id": "7d2ec1766f1090c38561a0436a628ef4", "detail": {}},
    "uuid": "320594ef-9c09-11ef-9a76-3d99f8f332b8",
    "version": "0",
    "request": {
        "ipChain": [
            {
                "ip": "103.99.111.142",
                "geographicalContext": {
                    "city": "Hyderabad",
                    "state": "Telangana",
                    "country": "India",
                    "postalCode": "500004",
                    "geolocation": {"lat": 17.3724, "lon": 78.4378},
                },
                "version": "V4",
                "source": None,
            }
        ]
    },
    "target": [
        {
            "id": "00T2lyn19",
            "type": "Token",
            "alternateId": "unknown",
            "displayName": "Test",
            "detailEntry": None,
        }
    ],
}

# MFA Failure event
SAMPLE_MFA_FAILURE: dict[str, Any] = {
    "actor": {
        "id": "00u9823hjkLMN456P7q8",
        "type": "User",
        "alternateId": "alice.wonder@acmecorp.com",
        "displayName": "Alice Wonder",
        "detailEntry": None,
    },
    "client": {
        "userAgent": {
            "rawUserAgent": "Mozilla/5.0 (iPhone; CPU iPhone OS 16_0 like Mac OS X) AppleWebKit/605.1.15",
            "os": "iOS",
            "browser": "MOBILE_SAFARI",
        },
        "zone": "null",
        "device": "Mobile",
        "id": None,
        "ipAddress": "203.0.113.89",
        "geographicalContext": {
            "city": "Amsterdam",
            "state": "North Holland",
            "country": "Netherlands",
            "postalCode": "1012",
            "geolocation": {"lat": 52.3702, "lon": 4.8952},
        },
    },
    "device": None,
    "authenticationContext": {
        "authenticationProvider": "OKTA_AUTHENTICATION_PROVIDER",
        "credentialProvider": "OKTA_CREDENTIAL_PROVIDER",
        "credentialType": "OTP",
        "issuer": None,
        "interface": None,
        "authenticationStep": 1,
        "rootSessionId": "trs9MfA2Bx",
        "externalSessionId": "trs9MfA2BxK8pL",
    },
    "displayMessage": "User denied MFA verification",
    "eventType": "user.authentication.auth_via_mfa",
    "outcome": {"result": "FAILURE", "reason": "OKTA_VERIFY_DENIED_ACCESS"},
    "published": "2024-12-03T08:42:17.328Z",
    "securityContext": {
        "asNumber": 20473,
        "asOrg": "The Constant Company, LLC",
        "isp": "AS-CHOOPA",
        "domain": None,
        "isProxy": False,
    },
    "severity": "WARN",
    "debugContext": {
        "debugData": {
            "concurrencyPercentage": "10",
            "requestId": "beef-cafe-1337-okta-mfa-fail-01",
            "dtHash": "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2w3x4y5z6",
            "rateLimitPercentage": "5",
            "networkConnection": "ANYWHERE",
            "requestUri": "/api/v1/authn/factors/verify",
            "url": "/api/v1/authn/factors/verify?rememberDevice=true",
        }
    },
    "legacyEventType": "core.user.auth.mfa.verify_fail",
    "transaction": {
        "type": "WEB",
        "id": "beef-cafe-1337-okta-mfa-fail-01",
        "detail": {},
    },
    "uuid": "f8a9b7c6-4e3d-2a1b-0c9d-8e7f6a5b4c3d",
    "version": "0",
    "request": {
        "ipChain": [
            {
                "ip": "203.0.113.89",
                "geographicalContext": {
                    "city": "Amsterdam",
                    "state": "North Holland",
                    "country": "Netherlands",
                    "postalCode": "1012",
                    "geolocation": {"lat": 52.3702, "lon": 4.8952},
                },
                "version": "V4",
                "source": None,
            }
        ]
    },
    "target": [
        {
            "id": "00u9823hjkLMN456P7q8",
            "type": "User",
            "alternateId": "alice.wonder@acmecorp.com",
            "displayName": "Alice Wonder",
            "detailEntry": None,
        }
    ],
}

# Suspicious Activity - Impossible Travel
SAMPLE_SUSPICIOUS_ACTIVITY: dict[str, Any] = {
    "actor": {
        "id": "00uXYZ789012345678",
        "type": "User",
        "alternateId": "john.traveler@corp.example",
        "displayName": "John Traveler",
        "detailEntry": None,
    },
    "client": {
        "userAgent": {
            "rawUserAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0",
            "os": "Windows",
            "browser": "CHROME",
        },
        "zone": "null",
        "device": "Computer",
        "id": None,
        "ipAddress": "45.77.240.15",
        "geographicalContext": {
            "city": "Tokyo",
            "state": "Tokyo",
            "country": "Japan",
            "postalCode": "100-0001",
            "geolocation": {"lat": 35.6762, "lon": 139.6503},
        },
    },
    "device": None,
    "authenticationContext": {
        "authenticationProvider": "OKTA_AUTHENTICATION_PROVIDER",
        "credentialProvider": "OKTA_CREDENTIAL_PROVIDER",
        "credentialType": "PASSWORD",
        "issuer": None,
        "interface": None,
        "authenticationStep": 0,
        "rootSessionId": "impTravel99",
        "externalSessionId": "impTravel99Z",
    },
    "displayMessage": "User login to Okta",
    "eventType": "security.threat.detected",
    "outcome": {"result": "SUCCESS", "reason": "ANOMALOUS_LOCATION"},
    "published": "2024-12-03T11:47:02.157Z",
    "securityContext": {
        "asNumber": 136800,
        "asOrg": "Choopa, LLC",
        "isp": "Vultr Holdings LLC",
        "domain": None,
        "isProxy": False,
    },
    "severity": "WARN",
    "debugContext": {
        "debugData": {
            "concurrencyPercentage": "25",
            "requestId": "beef-cafe-1337-okta-impossible-travel-01",
            "dtHash": "threat999888777666555444333222111000aaabbbcccdddeeefff",
            "rateLimitPercentage": "15",
            "networkConnection": "ANYWHERE",
            "requestUri": "/api/v1/authn",
            "url": "/api/v1/authn",
            "threatDetected": "NewCountry",
            "previousLocation": "San Francisco, CA, US - 30 minutes ago",
        }
    },
    "legacyEventType": "security.threat.detected",
    "transaction": {
        "type": "WEB",
        "id": "beef-cafe-1337-okta-impossible-travel-01",
        "detail": {},
    },
    "uuid": "9f8e7d6c-5b4a-3f2e-1d0c-9b8a7f6e5d4c",
    "version": "0",
    "request": {
        "ipChain": [
            {
                "ip": "45.77.240.15",
                "geographicalContext": {
                    "city": "Tokyo",
                    "state": "Tokyo",
                    "country": "Japan",
                    "postalCode": "100-0001",
                    "geolocation": {"lat": 35.6762, "lon": 139.6503},
                },
                "version": "V4",
                "source": None,
            }
        ]
    },
    "target": [
        {
            "id": "00uXYZ789012345678",
            "type": "User",
            "alternateId": "john.traveler@corp.example",
            "displayName": "John Traveler",
            "detailEntry": None,
        }
    ],
}

# Account Lockout event
SAMPLE_ACCOUNT_LOCKOUT: dict[str, Any] = {
    "actor": {
        "id": "00uPWDSPRAY123456",
        "type": "User",
        "alternateId": "victim.user@targetcorp.com",
        "displayName": "Victim User",
        "detailEntry": None,
    },
    "client": {
        "userAgent": {"rawUserAgent": "curl/7.68.0", "os": "Unknown", "browser": "UNKNOWN"},
        "zone": "null",
        "device": "Unknown",
        "id": None,
        "ipAddress": "185.220.101.47",
        "geographicalContext": {
            "city": "Unknown",
            "state": "Unknown",
            "country": "Russia",
            "postalCode": None,
            "geolocation": {"lat": 55.7558, "lon": 37.6173},
        },
    },
    "device": None,
    "authenticationContext": {
        "authenticationProvider": "OKTA_AUTHENTICATION_PROVIDER",
        "credentialProvider": "OKTA_CREDENTIAL_PROVIDER",
        "credentialType": "PASSWORD",
        "issuer": None,
        "interface": None,
        "authenticationStep": 0,
        "rootSessionId": "pwdSpray777",
        "externalSessionId": "pwdSpray777ABC",
    },
    "displayMessage": "User account locked out",
    "eventType": "user.account.lock",
    "outcome": {"result": "SUCCESS", "reason": "VERIFICATION_ERROR"},
    "published": "2024-12-03T14:23:48.672Z",
    "securityContext": {
        "asNumber": 209605,
        "asOrg": "UAB Host Baltic",
        "isp": "UAB Host Baltic",
        "domain": None,
        "isProxy": False,
    },
    "severity": "WARN",
    "debugContext": {
        "debugData": {
            "concurrencyPercentage": "5",
            "requestId": "beef-cafe-1337-okta-lockout-01",
            "dtHash": "lockout112233445566778899aabbccddeeff00112233445566778",
            "rateLimitPercentage": "3",
            "networkConnection": "ANYWHERE",
            "requestUri": "/api/v1/authn",
            "url": "/api/v1/authn",
            "failedLoginCount": "5",
            "lockoutDuration": "15 minutes",
        }
    },
    "legacyEventType": "core.user.account.lock",
    "transaction": {
        "type": "WEB",
        "id": "beef-cafe-1337-okta-lockout-01",
        "detail": {},
    },
    "uuid": "5c4d3e2f-1a0b-9c8d-7e6f-5a4b3c2d1e0f",
    "version": "0",
    "request": {
        "ipChain": [
            {
                "ip": "185.220.101.47",
                "geographicalContext": {
                    "city": "Unknown",
                    "state": "Unknown",
                    "country": "Russia",
                    "postalCode": None,
                    "geolocation": {"lat": 55.7558, "lon": 37.6173},
                },
                "version": "V4",
                "source": None,
            }
        ]
    },
    "target": [
        {
            "id": "00uPWDSPRAY123456",
            "type": "User",
            "alternateId": "victim.user@targetcorp.com",
            "displayName": "Victim User",
            "detailEntry": None,
        }
    ],
}

SAMPLE_RATE_LIMITED: dict[str, Any] = {
    "actor": {
        "id": "00uRATELIMIT123456",
        "type": "User",
        "alternateId": "api.user@company.com",
        "displayName": "API User",
        "detailEntry": None,
    },
    "client": {
        "userAgent": {"rawUserAgent": "python-requests/2.28.0", "os": "Unknown", "browser": "UNKNOWN"},
        "zone": "null",
        "device": "Unknown",
        "id": None,
        "ipAddress": "10.0.0.50",
        "geographicalContext": {
            "city": "San Francisco",
            "state": "California",
            "country": "United States",
            "postalCode": "94105",
            "geolocation": {"lat": 37.7749, "lon": -122.4194},
        },
    },
    "device": None,
    "authenticationContext": {
        "authenticationProvider": None,
        "credentialProvider": None,
        "credentialType": None,
        "issuer": None,
        "interface": None,
        "authenticationStep": 0,
        "rootSessionId": "rateLimit99",
        "externalSessionId": "rateLimit99ABC",
    },
    "displayMessage": "Rate limit exceeded",
    "eventType": "system.rate_limit.exceeded",
    "outcome": {"result": "FAILURE", "reason": "RATE_LIMIT_EXCEEDED"},
    "published": "2024-12-04T10:15:00.000Z",
    "securityContext": {
        "asNumber": 15169,
        "asOrg": "Google LLC",
        "isp": "Google LLC",
        "domain": None,
        "isProxy": False,
    },
    "severity": "WARN",
    "debugContext": {
        "debugData": {
            "concurrencyPercentage": "100",
            "requestId": "rate-limit-request-001",
            "rateLimitPercentage": "100",
            "networkConnection": "ANYWHERE",
            "requestUri": "/api/v1/users",
            "url": "/api/v1/users?limit=200",
        }
    },
    "legacyEventType": "system.rate_limit.exceeded",
    "transaction": {"type": "WEB", "id": "rate-limit-request-001", "detail": {}},
    "uuid": "rate-limit-uuid-001",
    "version": "0",
    "request": {
        "ipChain": [
            {
                "ip": "10.0.0.50",
                "geographicalContext": {
                    "city": "San Francisco",
                    "state": "California",
                    "country": "United States",
                    "postalCode": "94105",
                    "geolocation": {"lat": 37.7749, "lon": -122.4194},
                },
                "version": "V4",
                "source": None,
            }
        ]
    },
    "target": [],
}

ALL_SAMPLE_LOGS: dict[str, dict[str, Any]] = {
    "raw_log": SAMPLE_RAW_LOG,
    "mfa_failure": SAMPLE_MFA_FAILURE,
    "rate_limited": SAMPLE_RATE_LIMITED,
    "suspicious_activity": SAMPLE_SUSPICIOUS_ACTIVITY,
    "account_lockout": SAMPLE_ACCOUNT_LOCKOUT,
}


def _generate_dynamic_fields(start_time: datetime, end_time: datetime) -> dict[str, Any]:
    """Generate dynamic fields for a log entry."""
    published = random_iso_timestamp(start_time, end_time)
    email = generate_email()
    ip = generate_ip()
    hex_id = uuid.uuid4().hex
    uuid_val = f"{hex_id[:8]}-{hex_id[8:12]}-{hex_id[12:16]}-{hex_id[16:20]}-{hex_id[20:]}"
    hex_id2 = uuid.uuid4().hex
    request_id = f"{hex_id2[:8]}-{hex_id2[8:12]}-{hex_id2[12:16]}-{hex_id2[16:20]}-{hex_id2[20:]}"
    transaction_id = f"{hex_id2[16:]}{hex_id2[:16]}"
    severity = random.choice(["DEBUG", "INFO", "WARN", "ERROR", "OTHER"])

    return {
        "uuid": uuid_val,
        "published": published,
        "severity": severity,
        "actor": {
            "alternateId": email,
            "displayName": email.split("@")[0].replace(".", " ").title(),
        },
        "client": {
            "ipAddress": ip,
        },
        "debugContext": {
            "debugData": {
                "requestId": request_id,
            }
        },
        "transaction": {
            "id": transaction_id,
        },
    }


def generate_log(start_time: datetime | None = None, end_time: datetime | None = None) -> dict[str, Any]:
    """Generate a single log with weighted template selection and dynamic fields."""
    if end_time is None:
        end_time = now_utc()
    if start_time is None:
        start_time = end_time - timedelta(hours=2)

    template = weighted_choice_from_dict(ALL_SAMPLE_LOGS, LOG_WEIGHTS)
    dynamic_fields = _generate_dynamic_fields(start_time, end_time)

    # Shallow copy top-level, then shallow copy only the nested dicts we modify
    log = {**template}
    log["actor"] = {**template["actor"]}
    log["client"] = {**template["client"]}
    log["debugContext"] = {**template["debugContext"], "debugData": {**template["debugContext"]["debugData"]}}
    log["transaction"] = {**template["transaction"]}

    # Update nested fields
    log["uuid"] = dynamic_fields["uuid"]
    log["published"] = dynamic_fields["published"]
    log["severity"] = dynamic_fields["severity"]
    log["actor"]["alternateId"] = dynamic_fields["actor"]["alternateId"]
    log["actor"]["displayName"] = dynamic_fields["actor"]["displayName"]
    log["client"]["ipAddress"] = dynamic_fields["client"]["ipAddress"]
    log["debugContext"]["debugData"]["requestId"] = dynamic_fields["debugContext"]["debugData"]["requestId"]
    log["transaction"]["id"] = dynamic_fields["transaction"]["id"]

    return log


def generate_logs(
    count: int = 1000,
    since: str | None = None,
) -> list[dict[str, Any]]:
    """Generate multiple logs with weighted distribution.

    Args:
        count: Number of logs to generate.
        since: ISO timestamp for start time (default: 2 hours ago).

    Returns:
        List of generated logs sorted by published timestamp descending.
    """
    end_time = now_utc()
    start_time = datetime.fromisoformat(since.replace("Z", "+00:00")) if since else end_time - timedelta(hours=2)

    logs = [generate_log(start_time, end_time) for _ in range(count)]
    return sorted(logs, key=lambda x: x["published"], reverse=True)


def okta_system_log() -> str:
    """Return a single synthetic Okta System Log event in JSON format.

    This is the main entry point for the generator, matching the pattern
    used by other generators in the repository.
    """
    return json.dumps(generate_log())


if __name__ == "__main__":  # pragma: no cover
    # Simple demo: print a few sample events to stdout
    for _ in range(3):
        print(okta_system_log())
