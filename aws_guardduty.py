from __future__ import annotations
import json, random, time, uuid
from typing import Dict, Any

# Metadata used by hec_sender.py
ATTR_FIELDS: Dict[str, str] = {
    "dataSource.category": "security",
    "dataSource.name": "AWS",
    "dataSource.vendor": "AWS Guard Duty",
}

def _ipv4() -> str:
    """Return a random IPv4 address."""
    return ".".join(str(random.randint(1, 254)) for _ in range(4))

def _ts_iso() -> str:
    """Return current UTC time in ISO format."""
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

def _sample_finding() -> Dict[str, Any]:
    """
    Return a minimal yet valid GuardDuty finding that matches the user‑supplied
    example.  Only the fields required by the parser are included.
    """
    finding_id   = str(uuid.uuid4())
    account_id   = str(random.randint(111111111111, 999999999999))
    detector_id  = uuid.uuid4().hex
    region       = random.choice(["us-east-1", "us-west-2", "ap-south-1"])
    now          = _ts_iso()

    return {
        "schemaVersion": "2.0",
        "accountId": account_id,
        "region": region,
        "partition": "aws",
        "id": finding_id,
        "arn": f"arn:aws:guardduty:{region}::{detector_id}:detector/{detector_id}/finding/{finding_id}",
        "type": random.choice([
            "Trojan:EC2/BlackholeTraffic",
            "Recon:EC2/PortProbeUnprotectedPort",
            "UnauthorizedAccess:IAMUser/ConsoleLogin",
        ]),
        "title": "EC2 instance attempting connection to a blackholed IP address.",
        "description": "EC2 instance is attempting to communicate with a blackholed IP on port 80.",
        "severity": round(random.uniform(2.0, 8.9), 1),
        "createdAt": now,
        "updatedAt": now,
        "resource": {
            "resourceType": "Instance",
            "instanceDetails": {
                "instanceId": f"i-{uuid.uuid4().hex[:8]}",
                "instanceType": "m5.large",
                "platform": None,
                "networkInterfaces": [{
                    "networkInterfaceId": f"eni-{uuid.uuid4().hex[:8]}",
                    "privateIpAddress": _ipv4(),
                    "publicIp": _ipv4(),
                    "ipv6Addresses": [],
                }],
                "tags": [],
            },
        },
        "service": {
            "serviceName": "guardduty",
            "detectorId": detector_id,
            "eventFirstSeen": now,
            "eventLastSeen": now,
            "count": random.randint(1, 3),
            "action": {
                "actionType": "NETWORK_CONNECTION",
                "networkConnectionAction": {
                    "connectionDirection": "OUTBOUND",
                    "protocol": "TCP",
                    "port": 80,
                    "remoteIpDetails": {
                        "ipAddressV4": _ipv4(),
                        "organization": {
                            "asn": "-1",
                            "asnOrg": "GeneratedASNOrg",
                            "isp": "GeneratedISP",
                            "org": "GeneratedORG",
                        },
                    },
                },
            },
        },
    }

# ---------------------------------------------------------------------------#
# Public API
# ---------------------------------------------------------------------------#
def guardduty_log() -> str:
    """
    Return the GuardDuty finding as a compact JSON string.  This will be sent
    through the /raw endpoint, so the parser receives the flattened JSON
    without the extra "message." prefix.
    """
    return json.dumps(_sample_finding(), separators=(',', ':'), ensure_ascii=False)