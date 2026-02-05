#!/usr/bin/env python3
"""
HR Phishing PDF -> PowerShell -> Scheduled Task -> C2 Scenario Sender
Sends the HR phishing scenario events to SentinelOne AI-SIEM (HEC) with proper routing.
"""
import os
import sys
import time
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Dict

# Add path to shared utilities and scenarios
this_dir = os.path.dirname(__file__)
repo_root = os.path.abspath(os.path.join(this_dir, '..'))
shared_dir = os.path.join(repo_root, 'event_generators', 'shared')
if shared_dir not in sys.path:
    sys.path.insert(0, shared_dir)

# Optional env loader used by enterprise sender
try:
    from env_loader import load_env_if_present  # type: ignore
except Exception:
    def load_env_if_present(_p: str) -> None:
        return

# Load .env if present (check scenarios/ and repo root)
load_env_if_present(os.path.join(this_dir, '.env'))
load_env_if_present(os.path.join(repo_root, '.env'))

# Import HEC sender and scenario generator
from hec_sender import send_one  # type: ignore
from hr_phishing_pdf_c2_scenario import generate_hr_phishing_pdf_c2_scenario  # type: ignore


def _attr_fields(source: str, trace_id: str, phase: str, scenario_name: str) -> Dict[str, Any]:
    fields = {
        "dataSource.vendor": source.split('_')[0].title() if '_' in source else source,
        "dataSource.name": source.replace('_', ' ').title(),
        "dataSource.category": "security",
        "scenario.trace_id": trace_id,
        "scenario.phase": phase,
        "scenario.name": scenario_name,
    }
    return fields


def _send_event(entry: Dict[str, Any], trace_id: str, scenario_name: str) -> bool:
    source = entry.get("source", "unknown")
    phase = entry.get("phase", "unknown")
    event = entry.get("event")

    # Palo Alto events in this scenario are wrapped as {"raw": "csv line"}
    if source == "paloalto_firewall" and isinstance(event, dict) and "raw" in event:
        payload = event["raw"]
    else:
        payload = event

    fields = _attr_fields(source, trace_id, phase, scenario_name)
    send_one(payload, source, fields)
    return True


def send_hr_phishing_pdf_c2(worker_count: int = 8) -> None:
    scenario = generate_hr_phishing_pdf_c2_scenario()
    events = scenario.get("events", [])
    scenario_name = scenario.get("scenario_name", "HR Phishing PDF -> PowerShell -> Scheduled Task -> C2")
    trace_id = os.getenv('S1_TRACE_ID') or str(uuid.uuid4())

    print("\n" + "=" * 80)
    print(f"🚀 SENDING HR PHISHING SCENARIO | Events: {len(events)} | Workers: {worker_count}")
    print(f"🔗 Trace ID: {trace_id}")
    print("=" * 80)

    start = time.time()
    sent = 0

    def worker(i: int, e: Dict[str, Any]):
        ok = _send_event(e, trace_id, scenario_name)
        return (i, ok, e.get("source"), e.get("phase"))

    with ThreadPoolExecutor(max_workers=worker_count) as ex:
        futures = {ex.submit(worker, i, e): i for i, e in enumerate(events, 1)}
        for fut in as_completed(futures):
            i, ok, source, phase = fut.result()
            sent += 1 if ok else 0
            if sent % 25 == 0 or sent == len(events):
                elapsed = time.time() - start
                eps = sent / elapsed if elapsed > 0 else 0
                print(f"[{sent:3d}/{len(events)}] EPS: {eps:6.1f} | Last: {source} | {phase}")

    print("\n" + "=" * 80)
    print(f"✅ COMPLETE | Delivered: {sent}/{len(events)} | Trace: {trace_id}")


if __name__ == "__main__":
    workers = int(os.getenv('S1_HEC_WORKERS', '8'))
    send_hr_phishing_pdf_c2(workers)
