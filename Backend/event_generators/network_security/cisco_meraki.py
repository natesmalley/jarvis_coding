#!/usr/bin/env python3
"""
Cisco Meraki MX syslog event generator (vpn_firewall, ip_flow, flows)
"""
from __future__ import annotations
import random, time, uuid
from typing import Dict

_PRI = "<134>"       # local0.notice
_DEV = "meraki-mx64"

def cisco_meraki_log(log_type: str | None = None) -> dict:
    """
    Generate a Meraki syslog event that matches one of the parser's
    three accepted formats:

      • vpn_firewall
      • ip_flow
      • flows

    Pass `log_type` to force a specific format, otherwise one is chosen at random.
    """
    log_type = log_type or random.choice(["vpn_firewall", "ip_flow", "flows"])
    now_unix = int(time.time())
    host = _DEV
    priority_code = random.choice([134, 135])  # informational / notice

    src_ip = f"10.0.{random.randint(0, 255)}.{random.randint(1, 254)}"
    dst_ip = f"93.184.{random.randint(0, 255)}.{random.randint(1, 254)}"
    sport = random.randint(1024, 65535)
    dport = random.choice([80, 443, 500, 4500, 53])
    proto = random.choice(["tcp", "udp", "icmp"])
    connection_status = random.choice(["start", "allowed", "tear"])

    # Base log structure
    log_entry = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now_unix)),
        "syslog_priority": priority_code,
        "unix_timestamp": now_unix,
        "hostname": host,
        "log_type": log_type,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "protocol": proto,
        "src_port": sport,
        "dst_port": dport
    }

    if log_type == "vpn_firewall":
        pattern_val = random.choice(["allowed 12345", "blocked 443"])
        log_entry.update({
            "vpn_firewall_pattern": pattern_val,
            "message": f"<{priority_code}> {now_unix} {host} vpn_firewall src={src_ip} dst={dst_ip} protocol={proto} sport={sport} dport={dport} pattern: {pattern_val}"
        })
    elif log_type == "ip_flow":
        trans_src = f"172.16.{random.randint(0,255)}.{random.randint(1,254)}"
        trans_port = dport
        log_entry.update({
            "translated_src_ip": trans_src,
            "translated_port": trans_port,
            "message": f"<{priority_code}> {now_unix} {host} ip_flow src={src_ip} dst={dst_ip} protocol={proto} sport={sport} dport={dport} translated_src_ip={trans_src} translated_port={trans_port}"
        })
    else:  # flows
        mac = "00:11:22:33:44:{:02x}".format(random.randint(0, 255))
        log_entry.update({
            "connection_status": connection_status,
            "mac_address": mac,
            "message": f"<{priority_code}> {now_unix} {host} flows {connection_status} src={src_ip} dst={dst_ip} mac={mac} protocol={proto} sport={sport} dport={dport}"
        })

    return log_entry

if __name__ == "__main__":
    import json
    print("Sample Cisco Meraki Events:")
    print("=" * 50)
    for i, log_type in enumerate(["vpn_firewall", "ip_flow", "flows"], 1):
        print(f"\nEvent {i} ({log_type}):")
        print(json.dumps(cisco_meraki_log(log_type), indent=2))