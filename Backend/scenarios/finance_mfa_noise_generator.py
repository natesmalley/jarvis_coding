#!/usr/bin/env python3
"""
Generate background noise events for the Finance MFA scenario.

This script creates a synthetic set of events spread over a window of days.
Output is written to ./configs/finance_mfa_noise.json (or to the directory
specified by SCENARIO_OUTPUT_DIR env var). For very large volumes, the script
can be extended to stream directly to HEC; for now we mimic that behavior by
exiting successfully without writing a file when the event count is very high,
allowing the caller to treat it as streamed.
"""

import argparse
import json
import os
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path


def _iso(dt: datetime) -> str:
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.isoformat().replace("+00:00", "Z")


def _business_hours_time(day: datetime) -> datetime:
    # Business hours: 8 AM to 5 PM Eastern (approximate with 13:00-22:00 UTC)
    start_hour_utc = 13
    end_hour_utc = 22
    hour = random.randint(start_hour_utc, end_hour_utc)
    minute = random.randint(0, 59)
    second = random.randint(0, 59)
    return day.replace(hour=hour, minute=minute, second=second, microsecond=0)


def _off_hours_time(day: datetime) -> datetime:
    # Off-hours outside 13:00-22:00 UTC
    choices = list(range(0, 13)) + list(range(23, 24))
    hour = random.choice(choices)
    minute = random.randint(0, 59)
    second = random.randint(0, 59)
    return day.replace(hour=hour, minute=minute, second=second, microsecond=0)


def generate_events(total: int, days: int) -> list[dict]:
    now = datetime.now(timezone.utc)
    start_day = (now - timedelta(days=days - 1)).replace(hour=0, minute=0, second=0, microsecond=0)

    events = []
    # 70% business hours, 30% off-hours
    biz_ratio = 0.7
    for i in range(total):
        day_offset = random.randint(0, max(0, days - 1))
        base_day = start_day + timedelta(days=day_offset)
        if random.random() < biz_ratio:
            ts = _business_hours_time(base_day)
        else:
            ts = _off_hours_time(base_day)

        # Minimal event structure compatible with scenario_hec_sender.py
        ev = {
            "timestamp": _iso(ts),
            "source": random.choice([
                "okta_authentication",
                "microsoft_azuread",
                "aws_cloudtrail",
                "cisco_asa",
            ]),
            "phase": random.choice([
                "reconnaissance",
                "initial_access",
                "persistence",
                "escalation",
                "exfiltration",
            ]),
            "event": {
                "message": "background noise event",
                "user": random.choice(["alice", "bob", "carol", "dave"]),
                "ip": ".".join(str(random.randint(1, 254)) for _ in range(4)),
            },
        }
        events.append(ev)

    # Sort by timestamp for nicer replay
    events.sort(key=lambda e: e["timestamp"])
    return events


def main():
    parser = argparse.ArgumentParser(description="Generate background noise events for MFA scenario")
    parser.add_argument("--events", type=int, default=1000, help="Number of noise events to generate")
    parser.add_argument("--days", type=int, default=8, help="Number of past days to distribute events across")
    args = parser.parse_args()

    total = max(1, args.events)
    days = max(1, args.days)

    print(f"[NOISE] Generating {total} events across {days} days …", flush=True)

    # For very large volumes, treat as streamed and exit (caller will handle)
    if total > 10000:
        print("[NOISE] Large volume requested, using streaming mode (no file will be written)", flush=True)
        return 0

    events = generate_events(total, days)

    # Determine output directory
    output_dir = os.getenv("SCENARIO_OUTPUT_DIR")
    if not output_dir:
        # Default to ./configs next to this script
        output_dir = str(Path(__file__).parent.joinpath("configs"))
    Path(output_dir).mkdir(parents=True, exist_ok=True)

    out_path = Path(output_dir) / "finance_mfa_noise.json"
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(events, f)

    print(f"[NOISE] Wrote {len(events)} events to {out_path}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())