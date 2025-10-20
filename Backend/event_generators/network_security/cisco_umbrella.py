#!/usr/bin/env python3
"""
Cisco Umbrella synthetic log generator
"""
import json
import csv, io, random, time, uuid
from datetime import datetime, timezone, timedelta

def _ts():
    return time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime())

def umbrella_proxy_log():
    row = [
        _ts(), "Finance‑Dept", "10.0.1.55", "8.8.8.8", "93.184.216.34", "text/html",
        random.choice(["Allowed", "Blocked"]),
        "http://example.com/pdf", "http://ref.example.com",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
        str(random.choice([200, 302, 403])), str(random.randint(200, 2000)),
        str(random.randint(500, 50000)), str(random.randint(100, 48000)),
        uuid.uuid4().hex,
        random.choice(["Malware", "Phishing", "None"]),
        str(random.randint(0, 3)), str(random.randint(0, 2)),
        random.choice(["Malicious", "Clean"]),
        "" if random.random() < 0.8 else "Eicar-Test-File",
        str(random.randint(0, 100)),
        "Roaming Computer",
        "" if random.random() < 0.7 else "Malware",
        "ACME‑Laptop42;Finance", "Roaming Computer;Group",
        random.choice(["GET", "POST"]), random.choice(["Clean", "Violation"]),
        "" if random.random() < 0.85 else "CertError",
        "download.exe",
        str(random.randint(1000, 9999)), str(random.randint(100000, 999999)),
        "123;456",
    ]
    buf = io.StringIO()
    csv.writer(buf, quoting=csv.QUOTE_ALL).writerow(row)
    return buf.getvalue().strip()

def umbrella_dns_log():
    row = [
        _ts(), f"ACME-Laptop{random.randint(10,99)}", f"ACME-Laptop{random.randint(10,99)};Finance", f"10.0.1.{random.randint(1,254)}", "8.8.8.8",
        random.choice(["Allowed", "Blocked"]),
        random.choice(["A", "AAAA", "CNAME", "TXT"]),
        random.choice(["NOERROR", "NXDOMAIN"]),
        random.choice(["example.com", "malware.test", "phishing.example"]),
        random.choice(["Malware", "Phishing;Malware", "None"]),
        "Roaming Computer", "Roaming Computer;Group",
        "" if random.random() < 0.8 else "Malware",
    ]
    buf = io.StringIO()
    csv.writer(buf, quoting=csv.QUOTE_ALL).writerow(row)
    return buf.getvalue().strip()

def umbrella_audit_log():
    row = [
        str(uuid.uuid4()), _ts(),
        f"user{random.randint(1000,9999)}@example.com",
        random.choice(["alice", "bob", "charlie"]),
        random.choice(["LOGIN", "POLICY_UPDATE"]),
        random.choice(["SUCCESS", "FAILURE"]),
        f"203.0.113.{random.randint(1,254)}",
        "{}", "{}"
    ]
    buf = io.StringIO()
    csv.writer(buf, quoting=csv.QUOTE_ALL).writerow(row)
    return buf.getvalue().strip()

def cisco_umbrella_log():
    """
    Main function returning CSV format compatible with Cisco Umbrella parser.
    
    Returns DNS logs in CSV format with 13 quoted fields:
    timestamp, MostGranularIdentity, Identities, InternalIP, ExternalIP, 
    Action, QueryType, ResponseCode, Domain, Categories, 
    MostGranularIdentityType, IdentityTypes, BlockedCategories
    """
    # Generate DNS log in the correct CSV format for the parser
    return umbrella_dns_log()

if __name__ == "__main__":
    # Test the generator
    for _ in range(3):
        print(cisco_umbrella_log())
        print()
