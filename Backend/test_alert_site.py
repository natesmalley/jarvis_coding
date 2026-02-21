#!/usr/bin/env python3
"""
Test script for sending UAM alerts to SentinelOne at site scope.
Used for experimenting with resource/asset fields and payload structure.

Usage:
  python3 test_alert_site.py --template api/app/alerts/templates/advanced_sample_alert.json
  python3 test_alert_site.py --minimal
  python3 test_alert_site.py --minimal --resource-name "jeanluc@starfleet.com" --resource-type "user"
  python3 test_alert_site.py --minimal --resource-name "bridge-workstation" --resource-type "endpoint"
"""

import argparse
import gzip
import json
import os
import sys
import uuid
import time
from datetime import datetime, timezone
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError


def load_template(path: str) -> dict:
    """Load a JSON alert template and inject dynamic fields."""
    with open(path) as f:
        alert = json.load(f)

    now_ms = int(datetime.now(timezone.utc).timestamp() * 1000)

    # Inject fresh finding UID
    if "finding_info" not in alert:
        alert["finding_info"] = {}
    alert["finding_info"]["uid"] = str(uuid.uuid4())

    # Inject timestamps
    alert["time"] = now_ms
    if "metadata" not in alert:
        alert["metadata"] = {}
    alert["metadata"]["logged_time"] = now_ms
    alert["metadata"]["modified_time"] = now_ms

    # Generate UIDs for related events
    if "related_events" in alert.get("finding_info", {}):
        for event in alert["finding_info"]["related_events"]:
            event["uid"] = str(uuid.uuid4())

    # Generate UIDs for resources with placeholder
    for resource in alert.get("resources", []):
        if resource.get("uid") == "DYNAMIC_RESOURCE_UID":
            resource["uid"] = str(uuid.uuid4())

    return alert


def build_minimal_alert(
    title: str = "Test Alert",
    desc: str = "Test alert from CLI script",
    resource_name: str = "test-endpoint",
    resource_uid: str = None,
    resource_type: str = None,
    severity: str = None,
    severity_id: int = None,
    product_name: str = "HELIOS Test",
    vendor_name: str = "RoarinPenguin",
    extra_resource_fields: dict = None,
) -> dict:
    """Build a minimal OCSF alert payload for testing."""
    now_ms = int(datetime.now(timezone.utc).timestamp() * 1000)

    resource = {
        "uid": resource_uid or str(uuid.uuid4()),
        "name": resource_name,
    }
    if resource_type:
        resource["type"] = resource_type
    if extra_resource_fields:
        resource.update(extra_resource_fields)

    alert = {
        "finding_info": {
            "uid": str(uuid.uuid4()),
            "title": title,
            "desc": desc,
        },
        "resources": [resource],
        "category_uid": 2,
        "class_uid": 99602001,
        "class_name": "S1 Security Alert",
        "type_uid": 9960200101,
        "type_name": "S1 Security Alert: Create",
        "category_name": "Findings",
        "activity_id": 1,
        "metadata": {
            "version": "1.1.0",
            "extension": {
                "name": "s1",
                "uid": "998",
                "version": "0.1.0",
            },
            "product": {
                "name": product_name,
                "vendor_name": vendor_name,
            },
            "logged_time": now_ms,
            "modified_time": now_ms,
        },
        "time": now_ms,
        "attack_surface_ids": [1],
        "severity_id": severity_id or 4,
        "state_id": 1,
        "s1_classification_id": 1,
    }

    if severity:
        alert["severity"] = severity

    return alert


def send_alert(alert: dict, ingest_url: str, token: str, account_id: str, site_id: str = None) -> dict:
    """Send an alert via UAM ingest API. Returns response info."""
    url = ingest_url.rstrip("/") + "/v1/alerts"
    scope = account_id
    if site_id:
        scope = f"{account_id}:{site_id}"

    payload = json.dumps(alert).encode("utf-8")
    gzipped = gzip.compress(payload)

    headers = {
        "Authorization": f"Bearer {token}",
        "S1-Scope": scope,
        "Content-Encoding": "gzip",
        "Content-Type": "application/json",
        "S1-Trace-Id": "helios-ingest-uam:alwayslog",
    }

    req = Request(url, data=gzipped, headers=headers, method="POST")
    try:
        with urlopen(req) as resp:
            body = resp.read().decode("utf-8")
            return {"status": resp.status, "body": body}
    except HTTPError as e:
        body = e.read().decode("utf-8")
        return {"status": e.code, "body": body, "error": str(e)}
    except URLError as e:
        return {"status": 0, "body": "", "error": str(e)}


def print_alert_summary(alert: dict, label: str = ""):
    """Pretty-print alert summary."""
    if label:
        print(f"\n{'='*60}")
        print(f"  {label}")
        print(f"{'='*60}")
    print(f"  Title:    {alert.get('finding_info', {}).get('title', 'N/A')}")
    print(f"  Desc:     {alert.get('finding_info', {}).get('desc', 'N/A')[:80]}")
    resources = alert.get("resources", [])
    for i, r in enumerate(resources):
        print(f"  Resource[{i}]:")
        for k, v in r.items():
            print(f"    {k}: {v}")
    print(f"  Severity: {alert.get('severity', 'N/A')} (id={alert.get('severity_id', 'N/A')})")
    ts = alert.get("time", 0)
    print(f"  Time:     {ts} ({datetime.fromtimestamp(ts/1000, tz=timezone.utc).isoformat()})")
    payload = json.dumps(alert).encode("utf-8")
    gzipped = gzip.compress(payload)
    print(f"  Size:     {len(payload)} bytes -> {len(gzipped)} bytes (gzip)")
    print(f"\n  Full JSON:\n{json.dumps(alert, indent=2)}")


def main():
    parser = argparse.ArgumentParser(description="Test UAM alert sending to SentinelOne")
    parser.add_argument("--ingest-url", default=os.environ.get("UAM_INGEST_URL", "https://ingest.us1.sentinelone.net"))
    parser.add_argument("--token", default=os.environ.get("UAM_TOKEN"))
    parser.add_argument("--account-id", default=os.environ.get("UAM_ACCOUNT_ID", "1908275390083300395"))
    parser.add_argument("--site-id", default=os.environ.get("UAM_SITE_ID", "2178041589156878742"))
    parser.add_argument("--no-site", action="store_true", help="Send to account scope only")

    # Template mode
    parser.add_argument("--template", help="Path to JSON alert template file")

    # Minimal mode
    parser.add_argument("--minimal", action="store_true", help="Use minimal alert payload")
    parser.add_argument("--title", default="Test Alert")
    parser.add_argument("--desc", default="Test alert from CLI script")
    parser.add_argument("--resource-name", default="test-endpoint")
    parser.add_argument("--resource-uid", default=None, help="Resource UID (default: auto UUID)")
    parser.add_argument("--resource-type", default=None, help="Resource type field")
    parser.add_argument("--severity", default=None)
    parser.add_argument("--severity-id", type=int, default=4)
    parser.add_argument("--product", default="HELIOS Test")
    parser.add_argument("--vendor", default="RoarinPenguin")

    # Batch experiment mode
    parser.add_argument("--experiment", action="store_true", help="Run a batch of resource experiments")
    parser.add_argument("--delay", type=float, default=3.0, help="Delay between sends (seconds)")

    # Output
    parser.add_argument("--dry-run", action="store_true", help="Print payload but don't send")
    parser.add_argument("--json-field", help="Add arbitrary JSON field as key=value (can repeat)", action="append", default=[])

    args = parser.parse_args()

    if not args.token:
        print("ERROR: No token. Set UAM_TOKEN env var or use --token")
        sys.exit(1)

    site_id = None if args.no_site else args.site_id

    if args.experiment:
        run_experiments(args, site_id)
        return

    # Build alert
    if args.template:
        alert = load_template(args.template)
        label = f"Template: {args.template}"
    elif args.minimal:
        alert = build_minimal_alert(
            title=args.title,
            desc=args.desc,
            resource_name=args.resource_name,
            resource_uid=args.resource_uid,
            resource_type=args.resource_type,
            severity=args.severity,
            severity_id=args.severity_id,
            product_name=args.product,
            vendor_name=args.vendor,
        )
        label = "Minimal Alert"
    else:
        print("ERROR: Specify --template <path> or --minimal")
        sys.exit(1)

    # Apply extra JSON fields
    for field in args.json_field:
        key, _, value = field.partition("=")
        keys = key.split(".")
        current = alert
        for k in keys[:-1]:
            if k not in current:
                current[k] = {}
            current = current[k]
        # Try to parse as JSON, fall back to string
        try:
            current[keys[-1]] = json.loads(value)
        except (json.JSONDecodeError, ValueError):
            current[keys[-1]] = value

    print_alert_summary(alert, label)

    if args.dry_run:
        print("\n  [DRY RUN - not sending]")
        return

    print(f"\n  Sending to {'site' if site_id else 'account'} scope...")
    result = send_alert(alert, args.ingest_url, args.token, args.account_id, site_id)
    print(f"  Response: {result['status']} {result['body']}")
    if result.get("error"):
        print(f"  Error: {result['error']}")


def run_experiments(args, site_id):
    """Run a batch of resource field experiments to see what lands in SDL."""
    # Real bridge agent identifiers from S1 console:
    # Agent UUID: a0a693e2-f325-4a47-a80e-798f97bbd96d
    # Agent Asset ID: eimvmdpvax6mtmbpdbxtoaem5q
    # UAM Asset ID (created by alerts): ivhhhtkbinovgccxxjk53zwnje
    # Serial: 02J2ZH-PBPTK27Z
    # Domain: STARFLEET
    # GW IP: 206.198.150.53
    AGENT_UUID = "a0a693e2-f325-4a47-a80e-798f97bbd96d"
    AGENT_ASSET_ID = "eimvmdpvax6mtmbpdbxtoaem5q"
    UAM_ASSET_ID = "ivhhhtkbinovgccxxjk53zwnje"
    SERIAL = "02J2ZH-PBPTK27Z"

    experiments = [
        {
            "label": "E1: Agent UUID as resource uid",
            "resource_name": "bridge",
            "resource_uid": AGENT_UUID,
            "resource_type": None,
            "extra": {},
        },
        {
            "label": "E2: Agent Asset ID as resource uid",
            "resource_name": "bridge",
            "resource_uid": AGENT_ASSET_ID,
            "resource_type": None,
            "extra": {},
        },
        {
            "label": "E3: UAM Asset ID as resource uid",
            "resource_name": "bridge",
            "resource_uid": UAM_ASSET_ID,
            "resource_type": None,
            "extra": {},
        },
        {
            "label": "E4: Agent UUID + type=endpoint",
            "resource_name": "bridge",
            "resource_uid": AGENT_UUID,
            "resource_type": "endpoint",
            "extra": {},
        },
        {
            "label": "E5: Agent UUID + serial_number",
            "resource_name": "bridge",
            "resource_uid": AGENT_UUID,
            "resource_type": None,
            "extra": {"serial_number": SERIAL},
        },
        {
            "label": "E6: Agent UUID + domain + ip",
            "resource_name": "bridge",
            "resource_uid": AGENT_UUID,
            "resource_type": None,
            "extra": {"domain": "STARFLEET", "ip": "206.198.150.53"},
        },
        {
            "label": "E7: Agent UUID + agent_id field",
            "resource_name": "bridge",
            "resource_uid": AGENT_UUID,
            "resource_type": None,
            "extra": {"agent_id": AGENT_UUID},
        },
        {
            "label": "E8: UAM Asset ID + type=endpoint + name=bridge",
            "resource_name": "bridge",
            "resource_uid": UAM_ASSET_ID,
            "resource_type": "endpoint",
            "extra": {},
        },
        {
            "label": "E9: Random UUID + agent_id=Agent UUID",
            "resource_name": "bridge",
            "resource_uid": None,
            "resource_type": None,
            "extra": {"agent_id": AGENT_UUID},
        },
        {
            "label": "E10: Random UUID + ext.s1.agent_id",
            "resource_name": "bridge",
            "resource_uid": None,
            "resource_type": None,
            "extra": {"ext": {"s1": {"agent_id": AGENT_UUID}}},
        },
    ]

    print(f"\n{'='*60}")
    print(f"  RESOURCE FIELD EXPERIMENTS ({len(experiments)} tests)")
    print(f"  Scope: {'site ' + site_id if site_id else 'account'}")
    print(f"  Delay: {args.delay}s between sends")
    print(f"{'='*60}")

    for i, exp in enumerate(experiments):
        alert = build_minimal_alert(
            title=f"Asset Test - {exp['label']}",
            desc=f"Testing resource fields: {exp['label']}",
            resource_name=exp["resource_name"],
            resource_uid=exp["resource_uid"],
            resource_type=exp.get("resource_type"),
            severity_id=4,
            extra_resource_fields=exp.get("extra", {}),
        )

        print(f"\n--- {exp['label']} ---")
        print(f"  Resources: {json.dumps(alert['resources'], indent=4)}")

        if args.dry_run:
            print("  [DRY RUN]")
        else:
            result = send_alert(alert, args.ingest_url, args.token, args.account_id, site_id)
            print(f"  Response: {result['status']} {result['body']}")
            if result.get("error"):
                print(f"  Error: {result['error']}")

        if i < len(experiments) - 1 and not args.dry_run:
            print(f"  Waiting {args.delay}s...")
            time.sleep(args.delay)

    print(f"\n{'='*60}")
    print(f"  Done! Check SDL for {len(experiments)} alerts.")
    print(f"  Search: tag = 'alert' in the last 15 minutes")
    print(f"{'='*60}")


if __name__ == "__main__":
    main()
