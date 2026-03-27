#!/usr/bin/env python3
"""
Bitdefender GravityZone - Push Events API Simulated Event Generator
API Endpoint: /v1.0/jsonrpc/push
Methods: setPushEventSettings, getPushEventSettings, sendTestPushEvent,
         getPushEventStats, resetPushEventStats

Also generates all documented push event types:
  av, fw, aph, hd, dp, avc, antiexploit, network-sandboxing,
  uc, adcloud, registration, modules, exchange-malware,
  exchange-user-credentials, endpoint-moved-in, endpoint-moved-out,
  sva, sva-load, avc-detections, network-monitor
"""
import sys, os
sys.path.insert(0, os.path.dirname(__file__))
from gz_utils import *

MALWARE_NAMES = [
    "Trojan.GenericKD.123456", "Ransomware.WannaCry", "Adware.BrowseFox",
    "Exploit.CVE-2021-44228", "Backdoor.Cobalt.Strike", "PUA.CoinMiner",
    "Worm.Conficker", "Spyware.AgentTesla", "Rootkit.NecursDropper"
]
DETECTION_TYPES = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]
FW_PROTOCOLS = ["TCP", "UDP", "ICMP"]
FW_DIRECTIONS = ["in", "out"]
FW_ACTIONS = ["blocked", "allowed"]

def push_event_envelope(event_type, data):
    """Wraps a push event in the GravityZone JSON-RPC push notification format."""
    entry = {
        "timestamp": now_iso(),
        "api": "push",
        "eventType": event_type,
        "jsonrpc": "2.0",
        "method": "push",
        "id": rand_id(),
        "params": {
            "events": [data]
        }
    }
    print(json.dumps(entry))

# ── AV (Antivirus / Antimalware) ──────────────────────────────────────────────
def sim_av_event():
    push_event_envelope("av", {
        "module": "av",
        "computerName": rand_hostname(),
        "computerFQDN": f"{rand_hostname().lower()}.corp.example.com",
        "computerIp": rand_ip(),
        "endpointId": rand_endpoint_id(),
        "malwareName": random.choice(MALWARE_NAMES),
        "malwareType": random.choice(["virus", "trojan", "ransomware", "adware", "spyware"]),
        "filePath": random.choice([
            "C:\\Users\\user\\Downloads\\malware.exe",
            "C:\\Windows\\Temp\\payload.dll",
            "/tmp/malicious_script.sh"
        ]),
        "hash": f"{random.randint(0, 0xffffffffffffffffffffffffffffffff):032x}",
        "detectionType": random.choice(DETECTION_TYPES),
        "action": random.choice(["quarantine", "block", "remove", "ignore"]),
        "status": random.choice(["resolved", "pending", "failed"]),
        "timestamp": now_iso(),
        "username": f"DOMAIN\\user{random.randint(1,100)}"
    })

# ── Firewall (fw) ─────────────────────────────────────────────────────────────
def sim_fw_event():
    push_event_envelope("fw", {
        "module": "fw",
        "computerName": rand_hostname(),
        "computerIp": rand_ip(),
        "endpointId": rand_endpoint_id(),
        "localAddress": rand_ip(),
        "localPort": random.randint(1024, 65535),
        "remoteAddress": rand_ip(),
        "remotePort": random.randint(1, 65535),
        "protocol": random.choice(FW_PROTOCOLS),
        "direction": random.choice(FW_DIRECTIONS),
        "action": random.choice(FW_ACTIONS),
        "applicationPath": random.choice([
            "C:\\Program Files\\App\\app.exe",
            "/usr/bin/python3",
            "C:\\Windows\\System32\\svchost.exe"
        ]),
        "timestamp": now_iso()
    })

# ── Advanced Anti-Exploit (aph) ───────────────────────────────────────────────
def sim_aph_event():
    push_event_envelope("aph", {
        "module": "aph",
        "computerName": rand_hostname(),
        "computerIp": rand_ip(),
        "endpointId": rand_endpoint_id(),
        "processName": random.choice(["chrome.exe", "iexplore.exe", "winword.exe", "excel.exe"]),
        "processPath": "C:\\Program Files\\...",
        "exploitTechnique": random.choice([
            "ROP Chain", "Heap Spray", "Stack Pivot", "VBScript God Mode", "NULL Dereference"
        ]),
        "action": random.choice(["block", "report"]),
        "timestamp": now_iso()
    })

# ── Hyper Detect (hd) ────────────────────────────────────────────────────────
def sim_hd_event():
    push_event_envelope("hd", {
        "module": "hd",
        "computerName": rand_hostname(),
        "computerIp": rand_ip(),
        "endpointId": rand_endpoint_id(),
        "threatName": random.choice(MALWARE_NAMES),
        "threatType": random.choice(["fileless", "script", "powershell", "wmi", "macro"]),
        "filePath": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "commandLine": "powershell.exe -encodedcommand " + "A" * random.randint(50, 150),
        "detectionLevel": random.choice(["permissive", "normal", "aggressive"]),
        "action": random.choice(["block", "quarantine", "report"]),
        "timestamp": now_iso()
    })

# ── Data Protection (dp) ─────────────────────────────────────────────────────
def sim_dp_event():
    push_event_envelope("dp", {
        "module": "dp",
        "computerName": rand_hostname(),
        "computerIp": rand_ip(),
        "endpointId": rand_endpoint_id(),
        "dataType": random.choice(["credit-card", "ssn", "iban", "custom"]),
        "applicationName": random.choice(["chrome.exe", "outlook.exe", "filezilla.exe"]),
        "action": random.choice(["block", "report"]),
        "ruleId": rand_id(),
        "ruleName": random.choice(["PCI Data Rule", "PII Protection Rule", "Custom DLP Rule"]),
        "timestamp": now_iso()
    })

# ── Advanced Threat Control / ATC (avc) ──────────────────────────────────────
def sim_avc_event():
    push_event_envelope("avc", {
        "module": "avc",
        "computerName": rand_hostname(),
        "computerIp": rand_ip(),
        "endpointId": rand_endpoint_id(),
        "processPath": random.choice([
            "C:\\Windows\\Temp\\loader.exe",
            "C:\\Users\\Public\\Documents\\updater.exe"
        ]),
        "processHash": f"{random.randint(0, 0xffffffffffffffffffffffffffffffff):032x}",
        "detectionName": random.choice(MALWARE_NAMES),
        "action": random.choice(["block", "report", "allow"]),
        "parentProcess": "explorer.exe",
        "commandLine": f"cmd.exe /c whoami & ipconfig /all",
        "timestamp": now_iso()
    })

# ── Anti-Exploit (antiexploit) ────────────────────────────────────────────────
def sim_antiexploit_event():
    push_event_envelope("antiexploit", {
        "module": "antiexploit",
        "computerName": rand_hostname(),
        "computerIp": rand_ip(),
        "endpointId": rand_endpoint_id(),
        "exploitedProcess": random.choice(["acrobat.exe", "flash.exe", "java.exe", "office.exe"]),
        "exploitType": random.choice(["CVE-2021-40444", "CVE-2022-30190", "Log4Shell"]),
        "action": random.choice(["block", "disinfect"]),
        "timestamp": now_iso()
    })

# ── Network Sandbox Analyzer ──────────────────────────────────────────────────
def sim_network_sandboxing_event():
    push_event_envelope("network-sandboxing", {
        "module": "network-sandboxing",
        "computerName": rand_hostname(),
        "computerIp": rand_ip(),
        "endpointId": rand_endpoint_id(),
        "filePath": "C:\\Downloads\\suspicious.pdf",
        "fileHash": f"{random.randint(0, 0xffffffffffffffffffffffffffffffff):032x}",
        "threatName": random.choice(MALWARE_NAMES),
        "sandboxVerdict": random.choice(["malicious", "suspicious", "clean"]),
        "action": random.choice(["block", "quarantine"]),
        "timestamp": now_iso()
    })

# ── User Control / Web Filtering (uc) ────────────────────────────────────────
def sim_uc_event():
    push_event_envelope("uc", {
        "module": "uc",
        "computerName": rand_hostname(),
        "computerIp": rand_ip(),
        "endpointId": rand_endpoint_id(),
        "username": f"DOMAIN\\user{random.randint(1,100)}",
        "url": random.choice([
            "http://malware-domain.ru/payload.exe",
            "https://phishing-bank.com/login",
            "http://gambling-site.com"
        ]),
        "category": random.choice(["malware", "phishing", "gambling", "social-networking"]),
        "action": random.choice(["block", "allow"]),
        "timestamp": now_iso()
    })

# ── Registration ──────────────────────────────────────────────────────────────
def sim_registration_event():
    push_event_envelope("registration", {
        "module": "registration",
        "computerName": rand_hostname(),
        "computerFQDN": f"{rand_hostname().lower()}.corp.example.com",
        "computerIp": rand_ip(),
        "endpointId": rand_endpoint_id(),
        "action": random.choice(["new-endpoint", "re-registered", "unregistered"]),
        "operatingSystem": random.choice(["Windows 10", "Windows 11", "Ubuntu 22.04"]),
        "agentVersion": f"7.{random.randint(5,9)}.{random.randint(0,5)}.{random.randint(100,200)}",
        "timestamp": now_iso()
    })

# ── Modules Status ─────────────────────────────────────────────────────────────
def sim_modules_event():
    push_event_envelope("modules", {
        "module": "modules",
        "computerName": rand_hostname(),
        "computerIp": rand_ip(),
        "endpointId": rand_endpoint_id(),
        "moduleStatuses": {
            "antimalware": random.choice(["running", "stopped", "error"]),
            "firewall": random.choice(["running", "stopped", "not-installed"]),
            "advancedThreatControl": random.choice(["running", "stopped"]),
            "contentControl": random.choice(["running", "stopped", "not-installed"]),
            "deviceControl": random.choice(["running", "not-installed"]),
            "patchManagement": random.choice(["running", "stopped", "not-installed"])
        },
        "timestamp": now_iso()
    })

# ── Exchange Malware ───────────────────────────────────────────────────────────
def sim_exchange_malware_event():
    push_event_envelope("exchange-malware", {
        "module": "exchange-malware",
        "serverName": f"EXCH-{random.randint(1,5)}",
        "serverIp": rand_ip(),
        "senderEmail": f"attacker{random.randint(1,100)}@evil.com",
        "recipientEmail": f"user{random.randint(1,100)}@example.com",
        "subject": random.choice(["Invoice #12345", "Urgent: Your account", "RE: Meeting"]),
        "malwareName": random.choice(MALWARE_NAMES),
        "attachmentName": random.choice(["invoice.pdf.exe", "document.docm", "report.zip"]),
        "action": random.choice(["deleted", "quarantine", "blocked"]),
        "timestamp": now_iso()
    })

# ── Exchange User Credentials ─────────────────────────────────────────────────
def sim_exchange_user_credentials_event():
    push_event_envelope("exchange-user-credentials", {
        "module": "exchange-user-credentials",
        "serverName": f"EXCH-{random.randint(1,5)}",
        "serverIp": rand_ip(),
        "username": f"DOMAIN\\user{random.randint(1,100)}",
        "action": random.choice(["suspicious-login", "brute-force", "credential-stuffing"]),
        "sourceIp": rand_ip(),
        "timestamp": now_iso()
    })

# ── Endpoint Moved In / Out ───────────────────────────────────────────────────
def sim_endpoint_moved_in_event():
    push_event_envelope("endpoint-moved-in", {
        "module": "endpoint-moved-in",
        "computerName": rand_hostname(),
        "computerIp": rand_ip(),
        "endpointId": rand_endpoint_id(),
        "sourceGroupId": rand_id(),
        "destinationGroupId": rand_id(),
        "timestamp": now_iso()
    })

def sim_endpoint_moved_out_event():
    push_event_envelope("endpoint-moved-out", {
        "module": "endpoint-moved-out",
        "computerName": rand_hostname(),
        "computerIp": rand_ip(),
        "endpointId": rand_endpoint_id(),
        "sourceGroupId": rand_id(),
        "destinationGroupId": rand_id(),
        "timestamp": now_iso()
    })

# ── SVA / Security Virtual Appliance ─────────────────────────────────────────
def sim_sva_event():
    push_event_envelope("sva", {
        "module": "sva",
        "svaName": f"SVA-{random.randint(1,5)}",
        "svaIp": rand_ip(),
        "status": random.choice(["online", "offline", "degraded"]),
        "version": f"6.{random.randint(1,9)}.{random.randint(0,9)}.{random.randint(100,500)}",
        "protectedEndpoints": random.randint(10, 200),
        "timestamp": now_iso()
    })

def sim_sva_load_event():
    push_event_envelope("sva-load", {
        "module": "sva-load",
        "svaName": f"SVA-{random.randint(1,5)}",
        "svaIp": rand_ip(),
        "cpuUsage": round(random.uniform(10.0, 95.0), 1),
        "memoryUsage": round(random.uniform(20.0, 90.0), 1),
        "loadLevel": random.choice(["low", "medium", "high", "critical"]),
        "timestamp": now_iso()
    })

# ── Network Monitor ───────────────────────────────────────────────────────────
def sim_network_monitor_event():
    push_event_envelope("network-monitor", {
        "module": "network-monitor",
        "computerName": rand_hostname(),
        "computerIp": rand_ip(),
        "endpointId": rand_endpoint_id(),
        "remoteIp": rand_ip(),
        "remotePort": random.randint(1, 65535),
        "protocol": random.choice(FW_PROTOCOLS),
        "attackType": random.choice([
            "PortScan", "BruteForce", "ARP Poisoning", "DNS Spoofing", "SYN Flood"
        ]),
        "action": random.choice(["block", "report"]),
        "timestamp": now_iso()
    })

# ── Push Settings / Stats Methods ─────────────────────────────────────────────
def sim_setPushEventSettings():
    log_event("push", "setPushEventSettings", {"result": True})

def sim_getPushEventSettings():
    log_event("push", "getPushEventSettings", {
        "status": 1,
        "serviceType": "json",
        "serviceSettings": {
            "url": "https://siem.example.com:8080/gz/events",
            "requireValidSslCertificate": True
        },
        "subscribeToEventTypes": {
            "av": True, "fw": True, "aph": True, "hd": True, "dp": True,
            "avc": True, "antiexploit": True, "network-sandboxing": True,
            "uc": True, "registration": True, "modules": True,
            "exchange-malware": True, "exchange-user-credentials": True,
            "endpoint-moved-in": True, "endpoint-moved-out": True,
            "sva": True, "sva-load": True, "network-monitor": True
        }
    })

def sim_getPushEventStats():
    log_event("push", "getPushEventStats", {
        "totalSent": random.randint(1000, 100000),
        "totalFailed": random.randint(0, 50),
        "lastSuccessfulDelivery": now_iso()
    })

def sim_resetPushEventStats():
    log_event("push", "resetPushEventStats", {"result": True})

def sim_sendTestPushEvent():
    log_event("push", "sendTestPushEvent", {"result": True})


if __name__ == "__main__":
    # Simulate push API management calls
    for fn in [sim_getPushEventSettings, sim_setPushEventSettings, sim_getPushEventStats]:
        fn()

    # Simulate a realistic stream of push events
    event_sims = [
        sim_av_event, sim_fw_event, sim_aph_event, sim_hd_event,
        sim_dp_event, sim_avc_event, sim_antiexploit_event,
        sim_network_sandboxing_event, sim_uc_event,
        sim_registration_event, sim_modules_event,
        sim_exchange_malware_event, sim_exchange_user_credentials_event,
        sim_endpoint_moved_in_event, sim_endpoint_moved_out_event,
        sim_sva_event, sim_sva_load_event, sim_network_monitor_event
    ]
    for _ in range(random.randint(20, 40)):
        random.choice(event_sims)()
