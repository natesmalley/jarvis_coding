#!/usr/bin/env python3
# WORKING 
"""
zscaler.py
==========

Generate synthetic Zscaler Internet Access (NSS‑Web) JSON events
formatted for SentinelOne AI‑SIEM’s “zscalernss-web” sourcetype.

Usage examples
--------------
>>> from zscaler import zscaler_log
>>> print(zscaler_log())                       # one default event
>>> print(zscaler_log({"protocol": "FTP"}))    # override any field
"""

from datetime import datetime, timezone
from ipaddress import IPv4Address
import json
import random
from typing import Dict

# ────────────────── threat & auxiliary lookup tables ────────────────────
_THREATS = [
    "", "Eicar-Test-Signature", "Trojan.Generic", "Spyware.Agent",
    "Phishing.Site", "Ransomware.Locky"
]
_THREAT_CLASSES = ["", "Malware", "Spyware", "Phishing", "Ransomware"]
_FILE_CLASSES = ["", "Executable", "Document", "Archive", "Script"]
_DLP_ENGINES = ["", "Exact Data Match", "Indexed Document Match", "ML DLP"]
_UNSCANNABLES = ["", "Corrupted archive", "Encrypted file",
                 "Unsupported format", "Password protected"]

# ───────────────────────── static OCSF attribute block ────────────────────
# ───────────────────────── helpers ──────────────────────────
def _now_iso() -> str:
    """Return current UTC time in Zscaler/ISO format."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

def _rand_ip() -> str:
    """Return a pseudo‑random IPv4 address."""
    return str(IPv4Address(random.getrandbits(32)))

# ───────────────────── base template ───────────────────────
_ZS_TEMPLATE: dict[str, object] = {
    "datetime": _now_iso(),
    "protocol": "HTTPS",
    "action": "Allowed",
    "requestmethod": "GET",
    "urlsupercategory": "Technology",
    "urlcategory": "Search Engines",
    "urlclass": "Information Technology",
    "serverip": _rand_ip(),
    "clientpublicIP": _rand_ip(),
    "location": "US‑West",
    "devicehostname": "laptop‑demo",
    "deviceowner": "jsmith",
    "department": "Engineering",
    "requestsize": 512,
    "responsesize": 2048,
    "clienttranstime": 45,
    "servertranstime": 92,
    "reason": "Allowed",
    "appname": "Google Search",
    "appclass": "Web Search",
    "contenttype": "text/html",
    "useragent": "Mozilla/5.0 Demo",
    "refererURL": "https://www.google.com",
    "filetype": "html",
    "threatname": "",
    "bwthrottle": "",
    "dlpdictionaries": "",
    "dlpengine": "",
    "fileclass": "",
    "threatclass": "",
    "unscannabletype": "",
    "url": "https://www.google.com/search?q=demo",
}

# Potentially malicious URL samples
_BAD_URLS = [
    {
        "url": "http://malware-downloads.biz/evil.exe",
        "urlcategory": "Malware",
        "urlsupercategory": "Security",
        "urlclass": "Malicious Downloads",
        "appname": "Unknown",
        "appclass": "Unknown",
        "contenttype": "application/x-msdownload",
        "reason": "Blocked",
    },
    {
        "url": "https://phish-login.ru/index.html",
        "urlcategory": "Phishing",
        "urlsupercategory": "Security",
        "urlclass": "Credential Phishing",
        "appname": "Unknown",
        "appclass": "Unknown",
        "contenttype": "text/html",
        "reason": "Blocked",
    },
    {
        "url": "ftp://spyware.example.com/steal.dat",
        "urlcategory": "Spyware",
        "urlsupercategory": "Security",
        "urlclass": "Spyware / Keylogger",
        "appname": "Unknown",
        "appclass": "Unknown",
        "contenttype": "application/octet-stream",
        "reason": "Blocked",
    },
]

# ───────────────────── public factory ──────────────────────
def zscaler_log(overrides: dict | None = None) -> str:
    """
    Return a single Zscaler NSS‑Web event as a JSON string.

    Pass a dict of overrides to customise any field:
        zscaler_log({"protocol": "FTP", "action": "Blocked"})
    """
    record = {**_ZS_TEMPLATE, "datetime": _now_iso()}
    if overrides:
        record.update(overrides)

    # Ensure request/response sizes exist & recompute transactionsize
    record["requestsize"] = record.get("requestsize", random.randint(200, 3000))
    record["responsesize"] = record.get("responsesize", random.randint(500, 10000))
    record["transactionsize"] = record["requestsize"] + record["responsesize"]

    # Decide if we emit a malicious sample (30%)
    if random.random() < 0.30:
        bad = random.choice(_BAD_URLS)
        record.update(bad)
        if bad["url"].startswith("ftp://"):
            record["protocol"] = "FTP"
            record["requestmethod"] = "RETR"
    else:
        # Otherwise, 20% chance to be generic FTP
        if random.random() < 0.20:
            record["protocol"] = "FTP"
            record["requestmethod"] = "RETR"
            record["url"] = f"ftp://files.example.{_rand_ip()}/sample.bin"
            record["urlcategory"] = "Technology"
        else:
            record["url"] = f"https://safe.example.com/{random.randint(100,999)}/index.html"

    # Adjust refererURL based on protocol
    record["refererURL"] = "" if record["protocol"] == "FTP" else "https://www.bing.com"

    # Randomise threat‑related vectors
    record["threatname"]       = random.choice(_THREATS)
    record["threatclass"]      = random.choice(_THREAT_CLASSES)
    record["fileclass"]        = random.choice(_FILE_CLASSES)
    record["dlpengine"]        = random.choice(_DLP_ENGINES)
    record["unscannabletype"]  = random.choice(_UNSCANNABLES)

    # Guarantee presence of every parser key (add defaults if missing)
    defaults = {
        "urlclass": "Information Technology",
        "bwthrottle": "",
        "dlpdictionaries": "",
    }
    for k, v in defaults.items():
        record.setdefault(k, v)

    # Randomise bandwidth throttle flag (10 % chance)
    if random.random() < 0.10:
        record["bwthrottle"] = "Throttled"

    return json.dumps(record)

def zscaler_nss_log(overrides: dict | None = None) -> str:
    """
    Return a single Zscaler NSS-Web event in URL-encoded format for marketplace parser.
    This format is required by marketplace-zscalerinternetaccess-latest parser.
    """
    # Get the base record
    record = zscaler_log(overrides)
    
    # Convert to URL-encoded format as expected by marketplace parser
    import urllib.parse
    
    # Build the URL-encoded string
    params = []
    for key, value in record.items():
        if value is not None and value != "":
            # URL encode both key and value
            encoded_key = urllib.parse.quote_plus(str(key))
            encoded_value = urllib.parse.quote_plus(str(value))
            params.append(f"{encoded_key}={encoded_value}")
    
    return "&".join(params)

# ─────────────────── standalone sanity run ──────────────────
if __name__ == "__main__":
    print(zscaler_log())