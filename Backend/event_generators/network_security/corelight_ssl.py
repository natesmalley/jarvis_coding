#!/usr/bin/env python3
"""
Corelight SSL/TLS Logs event generator (JSON format)
Generates Zeek/Corelight SSL/TLS activity events
"""
from __future__ import annotations
import json
import random
import time
import uuid
from datetime import datetime, timezone, timedelta
from typing import Dict, List

# TLS versions
TLS_VERSIONS = [
    "TLSv1",
    "TLSv1.1",
    "TLSv1.2",
    "TLSv1.3",
    "SSLv3"  # Rare, insecure
]

# Common cipher suites
CIPHER_SUITES = [
    "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
    "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
    "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384",
    "TLS_RSA_WITH_AES_128_GCM_SHA256",
    "TLS_RSA_WITH_AES_256_GCM_SHA384",
    "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
    "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
    "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
    "TLS_DHE_RSA_WITH_AES_128_CBC_SHA",  # Older
    "TLS_RSA_WITH_3DES_EDE_CBC_SHA"  # Very old, insecure
]

# Elliptic curves
CURVES = [
    "x25519",
    "secp256r1",
    "secp384r1",
    "secp521r1"
]

# Common server names (SNI)
SERVER_NAMES = [
    "www.google.com",
    "www.github.com",
    "api.slack.com",
    "www.microsoft.com",
    "update.microsoft.com",
    "www.amazon.com",
    "www.cloudflare.com",
    "api.example.com",
    "app.internal.local",
    "mail.internal.local",
    "vpn.company.com",
    "remote.company.com",
    "-"  # No SNI
]

# Certificate subjects
CERT_SUBJECTS = [
    "CN=*.google.com,O=Google LLC,L=Mountain View,ST=California,C=US",
    "CN=*.github.com,O=GitHub Inc.,L=San Francisco,ST=California,C=US",
    "CN=*.slack.com,O=Slack Technologies Inc.,L=San Francisco,ST=California,C=US",
    "CN=*.microsoft.com,O=Microsoft Corporation,L=Redmond,ST=Washington,C=US",
    "CN=*.amazon.com,O=Amazon.com Inc.,L=Seattle,ST=Washington,C=US",
    "CN=*.cloudflare.com,O=Cloudflare Inc.,L=San Francisco,ST=California,C=US",
    "CN=*.example.com,O=Example Corp,L=New York,ST=New York,C=US",
    "CN=*.internal.local,O=Internal CA,L=Local,ST=Local,C=US",
    "CN=self-signed,O=Self,L=Local,ST=Local,C=US"
]

# Certificate issuers
CERT_ISSUERS = [
    "CN=GTS CA 1O1,O=Google Trust Services,C=US",
    "CN=DigiCert SHA2 High Assurance Server CA,O=DigiCert Inc,C=US",
    "CN=Let's Encrypt Authority X3,O=Let's Encrypt,C=US",
    "CN=Amazon,O=Amazon,C=US",
    "CN=CloudFlare Inc ECC CA-3,O=CloudFlare Inc.,C=US",
    "CN=Internal Root CA,O=Internal CA,C=US",
    "CN=self-signed,O=Self,L=Local,ST=Local,C=US"
]

def _generate_ip(internal: bool = True) -> str:
    """Generate an IP address"""
    if internal:
        return random.choice([
            f"10.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}",
            f"172.{random.randint(16, 31)}.{random.randint(0, 255)}.{random.randint(1, 254)}",
            f"192.168.{random.randint(0, 255)}.{random.randint(1, 254)}"
        ])
    else:
        return f"{random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"

def _generate_uid() -> str:
    """Generate a Zeek connection UID"""
    chars = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
    return 'C' + ''.join(random.choices(chars, k=17))

def _generate_cert_chain_fuids() -> List[str]:
    """Generate certificate chain file UIDs"""
    num_certs = random.choices([1, 2, 3], weights=[0.3, 0.6, 0.1])[0]
    return [f"F{_generate_uid()[1:]}" for _ in range(num_certs)]

def corelight_ssl_log(overrides: dict | None = None) -> Dict:
    """
    Return a single Corelight SSL/TLS log event as JSON string.
    
    Pass `overrides` to force any field to a specific value:
        corelight_ssl_log({"version": "TLSv1.3", "established": True})
    """
    # Generate timestamps
    now = datetime.now(timezone.utc)
    timestamp = now - timedelta(seconds=random.randint(0, 300))
    
    # Select server name and determine if internal
    server_name = random.choice(SERVER_NAMES)
    is_internal = "internal" in server_name or "company" in server_name or random.random() < 0.3
    
    # Determine TLS version based on context
    if server_name == "-" or "internal" in server_name:
        # Internal or no SNI might use older versions
        version = random.choices(
            TLS_VERSIONS,
            weights=[0.1, 0.2, 0.5, 0.15, 0.05]
        )[0]
    else:
        # External sites typically use newer versions
        version = random.choices(
            TLS_VERSIONS,
            weights=[0.02, 0.08, 0.6, 0.3, 0]
        )[0]
    
    # Select cipher based on version
    if version == "TLSv1.3":
        cipher = random.choice([c for c in CIPHER_SUITES if "TLS_" in c and "ECDHE" in c])
    elif version == "SSLv3":
        cipher = "TLS_RSA_WITH_3DES_EDE_CBC_SHA"
    else:
        cipher = random.choice(CIPHER_SUITES)
    
    # Determine if connection was established
    if version == "SSLv3" or (server_name == "-" and random.random() < 0.3):
        established = random.random() < 0.5  # More failures for old/suspicious
    else:
        established = random.random() < 0.95  # Most connections succeed
    
    # Generate ports
    src_port = random.randint(1024, 65535)
    dst_port = 443 if random.random() < 0.9 else random.choice([8443, 9443, 443, 636, 993, 995])
    
    event = {
        "ts": timestamp.timestamp(),
        "uid": _generate_uid(),
        "id": {
            "orig_h": _generate_ip(internal=True),
            "orig_p": src_port,
            "resp_h": _generate_ip(internal=is_internal),
            "resp_p": dst_port
        },
        "version": version,
        "cipher": cipher,
        "server_name": server_name if server_name != "-" else None,
        "resumed": random.random() < 0.2,  # 20% are resumed sessions
        "established": established
    }
    
    # Add curve for ECDHE ciphers
    if "ECDHE" in cipher:
        event["curve"] = random.choice(CURVES)
    
    # Add certificate details if established
    if established and random.random() < 0.8:
        # Match subject/issuer to server name
        if "google" in server_name:
            subject = CERT_SUBJECTS[0]
            issuer = CERT_ISSUERS[0]
        elif "github" in server_name:
            subject = CERT_SUBJECTS[1]
            issuer = CERT_ISSUERS[1]
        elif "internal" in server_name:
            subject = CERT_SUBJECTS[7]
            issuer = CERT_ISSUERS[5]
        elif server_name == "-":
            subject = CERT_SUBJECTS[8]  # Self-signed
            issuer = CERT_ISSUERS[6]
        else:
            subject = random.choice(CERT_SUBJECTS)
            issuer = random.choice(CERT_ISSUERS)
        
        event["subject"] = subject
        event["issuer"] = issuer
        event["cert_chain_fuids"] = _generate_cert_chain_fuids()
        event["client_cert_chain_fuids"] = []  # Client certs are rare
        
        # Certificate validation status
        if "self-signed" in subject or server_name == "-":
            event["validation_status"] = "self signed certificate"
        elif random.random() < 0.02:
            event["validation_status"] = random.choice([
                "unable to get local issuer certificate",
                "certificate has expired",
                "unable to verify the first certificate"
            ])
        else:
            event["validation_status"] = "ok"
    
    # Add JA3 fingerprints for established connections
    if established and random.random() < 0.7:
        event["ja3"] = f"{uuid.uuid4().hex}"[:32]
        event["ja3s"] = f"{uuid.uuid4().hex}"[:32]
    
    # Apply any overrides
    if overrides:
        event.update(overrides)
    
    return event

if __name__ == "__main__":
    # Generate sample logs
    print("Sample Corelight SSL logs:")
    for i in range(3):
        print(corelight_ssl_log())
        print()