#!/usr/bin/env python3
"""Proofpoint TAP event generator.

Generates Proofpoint email security events with weighted distribution.
Supports multiple event types including normal logs, ransomware retro,
double-wrapped URLs, blocked but clicked, false positives, and polymorphic malware.
"""

from __future__ import annotations

import json
import os
import random
import sys
from datetime import timedelta
from typing import Any

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'shared'))
from generator_utils import (
    generate_email,
    generate_ip,
    generate_uuid,
    now_utc,
    random_iso_timestamp,
    weighted_choice_from_dict,
)

# Log type weights
# 60% normal, 15% ransomware retro, 10% double-wrapped URL, 8% blocked but clicked, 5% false positive, 2% polymorphic
LOG_WEIGHTS: dict[str, float] = {
    "raw_log": 0.60,
    "ransomware_retro": 0.15,
    "double_wrapped_url": 0.10,
    "blocked_but_clicked": 0.08,
    "false_positive": 0.05,
    "polymorphic": 0.02,
}

SAMPLE_RAW_LOG: dict[str, Any] = {
    "clicksPermitted": [
        {
            "campaignId": "46e01b8a-c899-404d-bcd9-189bb393d1a7",
            "classification": "MALWARE",
            "clickIP": "192.0.2.1",
            "clickTime": "2016-06-24T19:17:44.000Z",
            "GUID": "b27dbea0-87d5-463b-b93c-4e8b708289ce",
            "id": "8c8b4895-a277-449f-r797-547e3c89b25a",
            "messageID": "8c6cfedd-3050-4d65-8c09-c5f65c38da81",
            "recipient": "bruce.wayne@pharmtech.zz",
            "sender": "9facbf452def2d7efc5b5c48cdb837fa@badguy.zz",
            "senderIP": "192.0.2.255",
            "threatID": "61f7622167144dba5e3ae4480eeee78b23d66f7dfed970cfc3d086cc0dabdf50",
            "threatTime": "2016-06-24T19:17:46.000Z",
            "threatURL": "https://threatinsight.proofpoint.com/#/threat_id",
            "threatStatus": "active",
            "url": "http://badguy.zz/",
            "userAgent": "Mozilla/5.0(WindowsNT6.1;WOW64;rv:27.0)Gecko/20100101Firefox/27.0",
        }
    ],
    "messagesBlocked": [],
    "clicksBlocked": [],
    "messagesDelivered": [],
}

SAMPLE_RANSOMWARE_RETRO: dict[str, Any] = {
    "clicksPermitted": [],
    "messagesBlocked": [],
    "clicksBlocked": [],
    "messagesDelivered": [
        {
            "campaignId": "beef-cafe-1337-proofpoint-retro-01",
            "classification": "RANSOMWARE",
            "GUID": "c1a2b3d4-e5f6-7890-a1b2-c3d4e5f67890",
            "id": "retro-msg-ransomware-001",
            "messageID": "<msg-id-987654321@badactor.evil>",
            "recipient": "finance.dept@victimcorp.com",
            "sender": "urgent_invoice@legitimate-looking.biz",
            "senderIP": "45.155.205.33",
            "threatID": "beef-cafe-1337-proofpoint-retro-01",
            "threatTime": "2024-12-04T06:45:23.000Z",
            "threatURL": "https://threatinsight.proofpoint.com/#/threat_id",
            "threatStatus": "active",
            "url": "https://storage.dropbox-secure.xyz/invoice_Q4_2024.zip",
            "userAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
            "messageTime": "2024-12-04T03:12:10.000Z",
            "initialClassification": "clean",
            "reclassificationTime": "2024-12-04T06:45:23.000Z",
            "reclassificationReason": "Sandbox detonation revealed ransomware payload",
            "deliveryStatus": "delivered_then_quarantined",
        }
    ],
}

SAMPLE_DOUBLE_WRAPPED_URL: dict[str, Any] = {
    "clicksPermitted": [
        {
            "campaignId": "phish-campaign-2024-Q4-567",
            "classification": "PHISH",
            "clickIP": "198.51.100.199",
            "clickTime": "2024-12-04T09:33:17.000Z",
            "GUID": "beef-cafe-1337-proofpoint-url-wrap-01",
            "id": "url-wrap-click-001",
            "messageID": "<nested-url-msg@phisher.xyz>",
            "recipient": "hr.manager@targetcorp.com",
            "sender": "linkedin-notifications@link3din.co",
            "senderIP": "103.21.244.77",
            "threatID": "beef-cafe-1337-proofpoint-url-wrap-01",
            "threatTime": "2024-12-04T09:33:20.000Z",
            "threatURL": "https://threatinsight.proofpoint.com/#/threat_id",
            "threatStatus": "active",
            "url": "https://urldefense.proofpoint.com/v2/url?u=https://safelinks.protection.outlook.com/?url=http%3A%2F%2Fphisher.xyz%2Fsteal-creds",
            "userAgent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
            "originalURL": "http://phisher.xyz/steal-creds",
            "rewriteLayers": "Proofpoint > O365 SafeLinks > Original",
        }
    ],
    "messagesBlocked": [],
    "clicksBlocked": [],
    "messagesDelivered": [],
}

SAMPLE_BLOCKED_BUT_CLICKED: dict[str, Any] = {
    "clicksPermitted": [
        {
            "campaignId": "vishing-campaign-nov-2024",
            "classification": "PHISH",
            "clickIP": "10.50.75.23",
            "clickTime": "2024-12-04T11:22:45.000Z",
            "GUID": "beef-cafe-1337-proofpoint-gap-01",
            "id": "gap-click-001",
            "messageID": "<blocked-but-clicked@attacker.xyz>",
            "recipient": "victim@corp.com",
            "sender": "ceo@c0rp.com",
            "senderIP": "192.0.2.88",
            "threatID": "beef-cafe-1337-proofpoint-gap-01",
            "threatTime": "2024-12-04T11:22:48.000Z",
            "threatURL": "https://threatinsight.proofpoint.com/#/threat_id",
            "threatStatus": "active",
            "url": "https://urgent-payroll-update.phisher.site",
            "userAgent": "Outlook/16.0 (Windows)",
            "messageStatus": "blocked",
            "clickSource": "mobile_forward",
        }
    ],
    "messagesBlocked": [
        {
            "campaignId": "vishing-campaign-nov-2024",
            "classification": "PHISH",
            "GUID": "beef-cafe-1337-proofpoint-gap-01",
            "id": "gap-block-001",
            "messageID": "<blocked-but-clicked@attacker.xyz>",
            "recipient": "victim@corp.com",
            "sender": "ceo@c0rp.com",
            "senderIP": "192.0.2.88",
            "threatID": "beef-cafe-1337-proofpoint-gap-01",
            "threatTime": "2024-12-04T08:15:12.000Z",
            "threatURL": "https://threatinsight.proofpoint.com/#/threat_id",
            "threatStatus": "active",
            "url": "https://urgent-payroll-update.phisher.site",
            "userAgent": "",
        }
    ],
    "clicksBlocked": [],
    "messagesDelivered": [],
}

SAMPLE_FALSE_POSITIVE: dict[str, Any] = {
    "clicksPermitted": [
        {
            "campaignId": "false-positive-campaign-001",
            "classification": "SPAM",
            "clickIP": "10.0.0.100",
            "clickTime": "2024-12-04T14:00:00.000Z",
            "GUID": "false-positive-guid-001",
            "id": "false-positive-id-001",
            "messageID": "<legitimate-newsletter@marketing.com>",
            "recipient": "user@company.com",
            "sender": "newsletter@marketing.com",
            "senderIP": "52.96.165.44",
            "threatID": "false-positive-threat-001",
            "threatTime": "2024-12-04T14:00:05.000Z",
            "threatURL": "https://threatinsight.proofpoint.com/#/threat_id",
            "threatStatus": "cleared",
            "url": "https://marketing.com/unsubscribe",
            "userAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
        }
    ],
    "messagesBlocked": [],
    "clicksBlocked": [],
    "messagesDelivered": [],
}

SAMPLE_POLYMORPHIC: dict[str, Any] = {
    "clicksPermitted": [],
    "messagesBlocked": [
        {
            "campaignId": "polymorphic-malware-campaign",
            "classification": "MALWARE",
            "GUID": "polymorphic-guid-001",
            "id": "polymorphic-id-001",
            "messageID": "<polymorphic-malware@attacker.xyz>",
            "recipient": "target@company.com",
            "sender": "invoice@supplier-corp.biz",
            "senderIP": "185.220.101.47",
            "threatID": "polymorphic-threat-001",
            "threatTime": "2024-12-04T15:30:00.000Z",
            "threatURL": "https://threatinsight.proofpoint.com/#/threat_id",
            "threatStatus": "active",
            "url": "https://malware-host.xyz/payload.exe",
            "userAgent": "",
            "malwareFamily": "Emotet",
            "hashVariant": "unique_per_recipient",
        }
    ],
    "clicksBlocked": [],
    "messagesDelivered": [],
}

ALL_SAMPLE_LOGS: dict[str, dict[str, Any]] = {
    "raw_log": SAMPLE_RAW_LOG,
    "ransomware_retro": SAMPLE_RANSOMWARE_RETRO,
    "double_wrapped_url": SAMPLE_DOUBLE_WRAPPED_URL,
    "blocked_but_clicked": SAMPLE_BLOCKED_BUT_CLICKED,
    "false_positive": SAMPLE_FALSE_POSITIVE,
    "polymorphic": SAMPLE_POLYMORPHIC,
}

CLASSIFICATIONS = ["MALWARE", "PHISH", "SPAM", "RANSOMWARE", "IMPOSTOR"]
THREAT_STATUSES = ["active", "cleared", "falsePositive"]


def _generate_dynamic_click(start_time, end_time) -> dict[str, Any]:
    """Generate dynamic fields for a click event."""
    return {
        "campaignId": generate_uuid(),
        "clickIP": generate_ip(),
        "clickTime": random_iso_timestamp(start_time, end_time),
        "GUID": generate_uuid(),
        "id": generate_uuid(),
        "messageID": f"<{generate_uuid()}@mail.example>",
        "recipient": generate_email("company.com"),
        "sender": generate_email("external.com"),
        "senderIP": generate_ip(),
        "threatID": generate_uuid(),
        "threatTime": random_iso_timestamp(start_time, end_time),
        "classification": random.choice(CLASSIFICATIONS),
        "threatStatus": random.choice(THREAT_STATUSES),
    }


def generate_log(start_time=None, end_time=None) -> dict[str, Any]:
    """Generate a single Proofpoint log with weighted template selection."""
    if end_time is None:
        end_time = now_utc()
    if start_time is None:
        start_time = end_time - timedelta(hours=2)

    template = weighted_choice_from_dict(ALL_SAMPLE_LOGS, LOG_WEIGHTS)
    log = {
        "clicksPermitted": [],
        "messagesBlocked": [],
        "clicksBlocked": [],
        "messagesDelivered": [],
    }

    # Copy and update template structure
    for key in ["clicksPermitted", "messagesBlocked", "clicksBlocked", "messagesDelivered"]:
        if template.get(key):
            for item in template[key]:
                new_item = {**item}
                dynamic = _generate_dynamic_click(start_time, end_time)
                new_item.update({
                    "campaignId": dynamic["campaignId"],
                    "GUID": dynamic["GUID"],
                    "id": dynamic["id"],
                    "messageID": dynamic["messageID"],
                    "recipient": dynamic["recipient"],
                    "sender": dynamic["sender"],
                    "senderIP": dynamic["senderIP"],
                    "threatID": dynamic["threatID"],
                    "threatTime": dynamic["threatTime"],
                })
                if "clickIP" in item:
                    new_item["clickIP"] = dynamic["clickIP"]
                    new_item["clickTime"] = dynamic["clickTime"]
                log[key].append(new_item)

    return log


def generate_logs(count: int = 100) -> list[dict[str, Any]]:
    """Generate multiple Proofpoint logs.

    Args:
        count: Number of logs to generate.

    Returns:
        List of generated logs.
    """
    end_time = now_utc()
    start_time = end_time - timedelta(hours=2)
    return [generate_log(start_time, end_time) for _ in range(count)]


def proofpoint_log() -> str:
    """Return a single synthetic Proofpoint log in JSON format.

    This is the main entry point for the generator, matching the pattern
    used by other generators in the repository.
    """
    return json.dumps(generate_log())


if __name__ == "__main__":  # pragma: no cover
    for _ in range(3):
        print(proofpoint_log())
