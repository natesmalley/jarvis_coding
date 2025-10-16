#!/usr/bin/env python3
#WORKING

"""Generate FortiGate-style log lines for SentinelOne demos."""
from datetime import datetime
from ipaddress import IPv4Address
from time import time_ns
import random

# ───────────────────────── static OCSF attribute block ────────────────────
# ───────────────────────── helpers ──────────────────────────
def _eventtime() -> str:
    """19-digit epoch-microseconds string."""
    return f"{time_ns() // 1_000:019d}"

def _rand_ip() -> str:
    return str(IPv4Address(random.getrandbits(32)))

def _rand_mac() -> str:
    return ":".join(f"{random.randint(0, 255):02x}" for _ in range(6))

def _ts() -> dict[str, str]:
    now = datetime.utcnow()
    return {"date": now.strftime("%Y-%m-%d"), "time": now.strftime("%H:%M:%S")}

def _line(template: dict, overrides=None) -> str:
    rec = {**template, **_ts(), "eventtime": _eventtime()}
    if overrides:
        rec.update(overrides)
    return " ".join(f"{k}={v}" for k, v in rec.items())

# ───────────────────── base templates ──────────────────────
BASE_IDS = {
    "devname": "FortiGate-40F",
    "devid":   "FGT40FTK23099XSK",
}

TRAFFIC_LOCAL = {
    **BASE_IDS,
    "logid": "0001000014",
    "identifier": 3,
    "type": "traffic",
    "subtype": "local",
    "level": "notice",
    "vd": "root",
    "srcip": "44.221.84.105",
    "dstip": "70.48.255.88",
    "srcintf": "wan",
    "srcintfrole": "wan",
    "dstintf": "root",
    "dstintfrole": "undefined",
    "srccountry": "Japan",
    "dstcountry": "Canada",
    "sessionid": 11109808,
    "proto": 1,
    "action": "accept",
    "policyid": 0,
    "policytype": "local-in-policy",
    "service": "PING",
    "trandisp": "noop",
    "app": "PING",
    "duration": 60,
    "sentbyte": 68,
    "rcvdbyte": 68,
    "sentpkt": 1,
    "rcvdpkt": 1,
    "appcat": "unscanned",
    "tz": "-0400",
}

TRAFFIC_FORWARD = {
    **BASE_IDS,
    "logid": "0000000013",
    "identifier": 3750,
    "type": "traffic",
    "subtype": "forward",
    "level": "notice",
    "vd": "root",
    "srcip": "192.168.1.121",
    "dstip": "8.8.8.8",
    "srcport": 56789,
    "dstport": 443,
    "srcintf": "lan",
    "srcintfrole": "lan",
    "dstintf": "wan",
    "dstintfrole": "wan",
    "srccountry": "Reserved",
    "dstcountry": "United States",
    "sessionid": 11109805,
    "proto": 6,
    "action": "accept",
    "policyid": 1,
    "policytype": "policy",
    "policyname": "\"LAN to WAN\"",
    "trandisp": "snat",
    "transip": "70.48.255.88",
    "transport": 56789,
    "duration": 120,
    "sentbyte": 1228,
    "rcvdbyte": 0,
    "sentpkt": 10,
    "rcvdpkt": 0,
    "appcat": "unscanned",
    "devtype": "Phone",
    "srchwvendor": "Apple",
    "srcfamily": "iPhone",
    "osname": "iOS",
    "srcmac": _rand_mac(),
    "dstmac": _rand_mac(),
    "tz": "-0400",
}

RESTAPI = {
    **BASE_IDS,
    "logid": "0415010001",
    "identifier": "0415010001",
    "type": "event",
    "subtype": "rest-api",
    "level": "information",
    "vd": "root",
    "user": "admin",
    "ui": "API(203.0.113.10)",
    "method": "POST",
    "path": "/api/v2/cmdb/firewall/address",
    "status": 200,
    "url": "\"https://fg-demo/api/v2/cmdb/firewall/address\"",
    "msg": "\"Policy object created\"",
}

VPN = {
    **BASE_IDS,
    "logid": "0103020003",
    "identifier": "0103020003",
    "type": "event",
    "subtype": "vpn",
    "level": "warning",
    "vd": "root",
    "vpntunnel": "siteA-siteB",
    "dstip": "198.51.100.1",
    "srcip": "203.0.113.1",
    "status": "tunnel_down",
    "duration": 0,
    "msg": "\"IPSec tunnel down\"",
}

VIRUS = {
    **BASE_IDS,
    "logid": "0200020004",
    "identifier": "0200020004",
    "type": "utm",
    "subtype": "virus",
    "level": "critical",
    "vd": "root",
    "action": "blocked",
    "srcip": "10.0.0.10",
    "dstip": "44.221.84.105",
    "filename": "\"invoice.exe\"",
    "filesize": 234567,
    "virus": "\"EICAR-Test-Signature\"",
    "userid": "jeanluc",
    "virusid": "123456",
    "crscore": 95,
    "profile": "default",
    "msg": "\"Malware detected and blocked\"",
}

# ───────────────────── public helpers ──────────────────────
def local_log(ov=None):    return _line(TRAFFIC_LOCAL,   ov)
def forward_log(ov=None):  return _line(TRAFFIC_FORWARD, ov)
def rest_api_log(ov=None): return _line(RESTAPI,         ov)
def vpn_log(ov=None):      return _line(VPN,             ov)
def virus_log(ov=None):    return _line(VIRUS,           ov)

if __name__ == "__main__":
    print(local_log())
    print(forward_log())
    print(rest_api_log())
    print(vpn_log())
    print(virus_log())