#!/usr/bin/env python3
"""
cloudtrail.py
=============

Generate synthetic AWS CloudTrail JSON events that satisfy every
field referenced by SentinelOne AI-SIEM's CloudTrail parser.

Example
-------
>>> from cloudtrail import cloudtrail_log
>>> print(cloudtrail_log())                     # one default event
>>> print(cloudtrail_log({"eventName": "PutObject"}))
"""

from __future__ import annotations
from datetime import datetime, timezone, timedelta
from ipaddress import IPv4Address
import json
import random
import uuid

# ────────────────────── AI‑SIEM attributes ─────────────────────
# These attributes are injected by hec_sender.py under the `fields`
# envelope key so the CloudTrail parser can populate constant values.
# ───────────────────────── helpers ─────────────────────────
_NOW   = lambda: datetime.now(timezone.utc)
_ISO   = lambda dt: dt.strftime("%Y-%m-%dT%H:%M:%SZ")
_IP    = lambda: str(IPv4Address(random.getrandbits(32)))

# AWS regions
_REGIONS   = ["us-east-1", "us-west-2", "eu-central-1", "ap-southeast-2", "us-west-1", "eu-west-1"]

# Corporate users with roles
_CORPORATE_USERS = [
    {"name": "john.smith", "role": "admin", "department": "it", "clearance": "high", "account": "123456789012"},
    {"name": "jane.doe", "role": "manager", "department": "finance", "clearance": "medium", "account": "123456789012"},
    {"name": "bob.johnson", "role": "engineer", "department": "engineering", "clearance": "medium", "account": "123456789012"},
    {"name": "alice.williams", "role": "security-admin", "department": "security", "clearance": "high", "account": "123456789012"},
    {"name": "mike.davis", "role": "operator", "department": "operations", "clearance": "low", "account": "123456789012"},
    {"name": "sarah.brown", "role": "doctor", "department": "medical", "clearance": "medium", "account": "123456789012"},
    {"name": "tom.wilson", "role": "analyst", "department": "analytics", "clearance": "low", "account": "123456789012"},
    {"name": "lisa.taylor", "role": "director", "department": "executive", "clearance": "high", "account": "987654321098"},
    {"name": "david.clark", "role": "scientist", "department": "research", "clearance": "high", "account": "987654321098"},
    {"name": "karen.martinez", "role": "nurse", "department": "medical", "clearance": "medium", "account": "987654321098"},
    {"name": "steve.garcia", "role": "technician", "department": "maintenance", "clearance": "low", "account": "987654321098"},
    {"name": "nancy.rodriguez", "role": "coordinator", "department": "communications", "clearance": "low", "account": "987654321098"},
    {"name": "paul.lee", "role": "navigator", "department": "logistics", "clearance": "low", "account": "987654321098"},
    {"name": "maria.gonzalez", "role": "pilot", "department": "transportation", "clearance": "low", "account": "987654321098"},
    {"name": "james.anderson", "role": "supervisor", "department": "operations", "clearance": "high", "account": "456789012345"},
    {"name": "jennifer.thomas", "role": "captain", "department": "leadership", "clearance": "high", "account": "567890123456"},
]

# Corporate S3 buckets and resources
_CORPORATE_BUCKETS = [
    "company-logs-production",
    "application-telemetry-data",
    "confidential-documents",
    "research-academy-data",
    "datacenter-maintenance-logs",
    "backup-sensor-data",
    "analytics-charts",
    "security-analysis",
    "partner-zone-intel",
    "vendor-alliance-comms",
    "compliance-directive-files",
    "restricted-access",
    "hr-medical-records",
    "system-diagnostics",
    "training-program-library",
]

# Separate API sets so we can bias toward normal vs malicious traffic
_NORMAL_APIS = [
    ("s3.amazonaws.com",      "PutObject"),
    ("s3.amazonaws.com",      "GetObject"),
    ("iam.amazonaws.com",     "CreateUser"),
    ("ec2.amazonaws.com",     "StartInstances"),
    ("ec2.amazonaws.com",     "DescribeInstances"),
    ("lambda.amazonaws.com",  "Invoke"),
    ("logs.amazonaws.com",    "CreateLogGroup"),
    ("athena.amazonaws.com",  "StartQueryExecution"),
    ("rds.amazonaws.com",     "CreateDBInstance"),
    ("cloudformation.amazonaws.com", "CreateStack"),
]

# Suspicious / high-risk behavior patterns
_MALICIOUS_APIS = [
    ("bedrock.amazonaws.com",  "CreateModel"),                 # Suspicious AI model creation
    ("bedrock.amazonaws.com",  "CreateModelCustomizationJob"), # Training on unauthorized data
    ("sagemaker.amazonaws.com","CreateApp"),                   # Data exfiltration endpoint
    ("dynamodb.amazonaws.com", "Scan"),                        # Scanning sensitive databases
    ("dynamodb.amazonaws.com", "BatchGetItem"),                # Bulk extraction of sensitive data
    ("sts.amazonaws.com",      "AssumeRole"),                  # Privilege escalation attempts
    ("guardduty.amazonaws.com","GetFindings"),                 # Checking security alerts
    ("secretsmanager.amazonaws.com", "GetSecretValue"),        # Accessing sensitive secrets
    ("kms.amazonaws.com",      "Decrypt"),                     # Decrypting confidential files
]

# Roughly 30 % of events will be malicious
_MALICIOUS_PCT = 0.30

def _get_api_extra(api_name, bucket_list):
    """Generate API-specific parameters for realistic AWS API calls"""
    extras = {
        "PutObject": {
            "requestParameters": {
                "bucketName": random.choice(bucket_list),
                "key": random.choice([
                    "application-installer.exe",
                    "financial-report.pdf",
                    "security-protocol.bin",
                    "user-activity-data.csv",
                    "system-analysis.json"
                ]),
                "Host": f"{random.choice(bucket_list)}.s3.amazonaws.com",
                "acl": "private",
                "encryption": "AES256",
            },
            "additionalEventData": {
                "bytesTransferredIn": random.randint(1024, 10485760),
                "bytesTransferredOut": 0,
            },
        },
        "GetObject": {
            "requestParameters": {
                "bucketName": random.choice(bucket_list),
                "key": random.choice([
                    "security-configs/firewall-rules.json",
                    "analysis-reports/threat-assessment.xml", 
                    "user-manifests/employee-list.csv",
                    "network-configs/security.dat",
                    "access-logs/remote-users.log"
                ]),
                "Host": f"{random.choice(bucket_list)}.s3.amazonaws.com",
            }
        },
        "StartQueryExecution": {
            "requestParameters": {
                "workGroup": "corporate-analytics",
                "queryString": random.choice([
                    "SELECT * FROM security_events WHERE severity = 'high';",
                    "SELECT * FROM user_sessions WHERE status = 'active';",
                    "SELECT employee_id FROM users WHERE clearance = 'confidential';",
                    "SELECT * FROM audit_logs WHERE timestamp > '2024-01-01';"
                ]),
            }
        },
        "GetFindings": {
            "requestParameters": {
                "detectorId": f"corporate-security-{random.choice(['prod', 'stage', 'dev'])}-{random.randint(1, 999):03d}",
                "maxResults": random.randint(5, 50),
            }
        },
        "DeleteItem": {
            "requestParameters": {
                "tableName": random.choice([
                    "CorporatePersonnel",
                    "AssetRegistry",
                    "ComplianceViolations",
                    "SecurityIncidents"
                ]),
                "key": {"EmployeeId": {"S": f"EMP-{random.randint(1000, 9999)}-{random.choice(['A', 'B', 'C', 'D', 'E'])}-{random.randint(1, 999):03d}"}},
            }
        },
        "CreateModel": {
            "requestParameters": {
                "modelName": random.choice([
                    "threat-detection-ai",
                    "security-analyzer",
                    "behavioral-simulator",
                    "compliance-monitoring-model"
                ]),
                "inferenceType": "EXTRACT_SECURITY_INSIGHTS",
            }
        },
        "CreateModelCustomizationJob": {
            "requestParameters": {
                "baseModel": "bedrock/corporate-llm",
                "trainingDataS3Uri": f"s3://{random.choice(['restricted-access', 'compliance-directive-files', 'confidential-documents'])}/classified/",
            }
        },
        "CreateApp": {
            "requestParameters": {
                "appName": random.choice([
                    "data-analysis-portal",
                    "business-intelligence-suite",
                    "analytics-platform",
                    "monitoring-dashboard"
                ]),
                "domainId": f"d-{random.choice(['prod', 'stage', 'dev'])}-analytics-{random.randint(1, 999):03d}",
                "userProfileName": random.choice([
                    "data-analyst",
                    "business-analyst",
                    "security-analyst"
                ]),
            }
        },
        "Scan": {
            "requestParameters": {
                "tableName": random.choice([
                    "CorporateClassifiedData",
                    "SecurityDatabase",
                    "SystemSpecifications",
                    "ComplianceFiles"
                ]),
                "limit": 1000000,
            },
            "additionalEventData": {
                "bytesTransferredOut": random.randint(10000000, 100000000),
            },
        },
        "BatchGetItem": {
            "requestParameters": {
                "requestItems": {
                    random.choice([
                        "CorporateSecurityDatabase",
                        "BusinessAssetManifest",
                        "ComplianceDirective",
                        "FinancialProjectData"
                    ]): {
                        "Keys": [{"id": {"S": random.choice(["CONFIDENTIAL-DIRECTIVE", "BUSINESS-PROTOCOL", "SECURITY-ALPHA"])}}]
                    }
                }
            }
        },
        "GetSecretValue": {
            "requestParameters": {
                "secretId": random.choice([
                    "database-connection-strings",
                    "api-access-tokens",
                    "encryption-keys",
                    "service-account-credentials",
                    "ssl-certificates"
                ]),
                "versionStage": "AWSCURRENT",
            }
        },
        "Decrypt": {
            "requestParameters": {
                "ciphertextBlob": random.choice([
                    "confidential-encrypted-files",
                    "audit-investigations-data",
                    "research-data",
                    "system-blueprints"
                ]),
                "keyId": f"arn:aws:kms:us-east-1:corporate:key/{random.choice(['compliance-directive', 'confidential-clearance', 'security-operations'])}",
            }
        },
        "CreateUser": {
            "requestParameters": {
                "userName": random.choice([
                    "intern.smith",
                    "contractor.johnson", 
                    "manager.williams",
                    "director.brown"
                ]),
                "tags": [
                    {"Key": "Office", "Value": random.choice(["NewYork", "LosAngeles", "Chicago", "Atlanta"])},
                    {"Key": "Department", "Value": random.choice(["Engineering", "Science", "Medical", "Management"])},
                ]
            }
        },
        "AssumeRole": {
            "requestParameters": {
                "roleArn": f"arn:aws:iam::{random.choice(['123456789012', '987654321098'])}:role/{random.choice(['corporate-admin', 'security-analyst', 'compliance-auditor'])}",
                "roleSessionName": f"{random.choice(['analysis', 'monitoring', 'audit'])}-session-{uuid.uuid4().hex[:8]}",
                "durationSeconds": random.choice([900, 1800, 3600]),
            }
        }
    }
    
    return extras.get(api_name, {})

TLS_VERS   = ["TLSv1.2", "TLSv1.3"]
CIPHERS    = ["ECDHE-RSA-AES128-GCM-SHA256", "ECDHE-RSA-AES256-GCM-SHA384"]

# ───────────────────── base template ───────────────────────
def _template() -> dict:
    now = _NOW()

    # Decide whether this event is malicious
    malicious = random.random() < _MALICIOUS_PCT
    api_pool = _MALICIOUS_APIS if malicious else _NORMAL_APIS

    svc, api = random.choice(api_pool)
    
    # Select a user - suspicious account for malicious, random corporate user for normal
    if malicious:
        user_info = {
            "name": "suspicious.user",
            "role": "external-contractor", 
            "department": "unknown",
            "clearance": "unauthorized",
            "account": "666666666666"  # Suspicious account ID
        }
    else:
        user_info = random.choice(_CORPORATE_USERS)

    record = {
        # Top-level searchable keys
        "eventCategory": "Management",
        "eventName": api,
        "eventSource": svc,
        "eventTime": _ISO(now),
        "eventVersion": "1.09",
        "eventID": str(uuid.uuid4()),
        "eventType": "AwsApiCall",
        "awsRegion": random.choice(_REGIONS),
        "readOnly": random.choice([True, False]),
        "managementEvent": True,
        "recipientAccountId": user_info["account"],
        "sourceIPAddress": _IP(),
        "userAgent": random.choice([
            "aws-cli/2.15.9 Python/3.11.4 Linux/5.10",
            "Corporate-Console/1.0 WebUI/2.4.7",
            "Business-SDK/3.2.1 CloudAPI/4.0",
            "aws-sdk-java/2.20.0 Linux/5.15 OpenJDK/17.0.6"
        ]),
        "tlsDetails": {
            "tlsVersion": random.choice(TLS_VERS),
            "cipherSuite": random.choice(CIPHERS),
            "clientProvidedHostHeader": f"{svc}",
        },

        # User identity block (needed for predicate)
        "userIdentity": {
            "type": "IAMUser",
            "principalId": f"AIDA{user_info['department'].upper().replace('-', '')}{random.randint(1000, 9999)}",
            "arn": f"arn:aws:iam::{user_info['account']}:user/{user_info['name']}",
            "accountId": user_info["account"],
            "accessKeyId": "AKIA" + uuid.uuid4().hex[:16].upper(),
            "userName": user_info["name"],
            "sessionContext": {
                "sessionIssuer": {
                    "type": "Role",
                    "principalId": f"AROA{user_info['role'].upper().replace('-', '')[:8]}",
                    "arn": f"arn:aws:iam::{user_info['account']}:role/{user_info['role']}",
                    "userName": user_info["role"],
                    "accountId": user_info["account"],
                },
                "attributes": {
                    "creationDate": _ISO(now - timedelta(minutes=random.randint(5, 60))),
                    "mfaAuthenticated": "false" if malicious else random.choice(["true", "false"]),
                },
            },
        },

        # Request / response
        "requestID": str(uuid.uuid4()),
        "requestParameters": {
            "durationSeconds": 900,
            "roleArn": f"arn:aws:iam::{user_info['account']}:role/{user_info['role']}",
            "roleSessionName": f"{user_info['department']}-session",
            "externalId": str(uuid.uuid4()),
        },
        "responseElements": {
            "assumedRoleUser": {
                "assumedRoleId": f"AROA{user_info['role'].upper().replace('-', '')[:8]}:{user_info['department']}-session",
                "arn": f"arn:aws:sts::{user_info['account']}:assumed-role/{user_info['role']}/{user_info['department']}-session",
            },
            "credentials": {
                "accessKeyId": "ASIA" + uuid.uuid4().hex[:16].upper(),
                "sessionToken": "IQoJb3JpZ2luX2VjEJ7//////////wEaCXVzLWVhc3QtMSJHMEUCIQD" + uuid.uuid4().hex,
                "expiration": _ISO(now + timedelta(hours=1)),
            },
            "sourceIdentity": user_info["name"],
        },

        # Extra structures referenced by the parser
        "sharedEventID": str(uuid.uuid4()),
        "vpcEndpointId": f"vpce-{user_info['department'].replace('-', '')[:8]}-{uuid.uuid4().hex[:9]}",

        "resources": [
            {
                "accountId": user_info["account"],
                "type": "AWS::S3::Bucket",
                "ARN": f"arn:aws:s3:::{random.choice(_CORPORATE_BUCKETS)}",
            }
        ],

        "additionalEventData": {
            "SignatureVersion": "SigV4",
            "CipherSuite": random.choice(CIPHERS),
            "bytesTransferredIn": 0,
            "bytesTransferredOut": random.randint(512, 10240),
            "AuthenticationMethod": "AuthHeader",
            "x-amz-id-2": uuid.uuid4().hex,
        },

        # A human-readable message
        "message": f"{user_info['name']} from {user_info['department']} executed {api} on {svc}",
    }

    # ────────── inject API-specific extras for better parser coverage ──────────
    extra = _get_api_extra(api, _CORPORATE_BUCKETS)
    if extra:
        if "requestParameters" in extra:
            record["requestParameters"].update(extra["requestParameters"])
        if "additionalEventData" in extra:
            record["additionalEventData"].update(extra["additionalEventData"])

    # Randomly surface errors to exercise errorCode/errorMessage paths
    if random.random() < 0.10:  # 10 % of events
        if malicious:
            record["errorCode"] = random.choice([
                "UnauthorizedAccess",
                "AccessDenied", 
                "TokenRefreshRequired",
                "InvalidUserID.NotFound"
            ])
            record["errorMessage"] = random.choice([
                "User suspicious.user is not authorized to perform this action - security alert triggered",
                "Access denied: Suspicious activity detected",
                "Security policy violation detected",
                "Administrative authorization required"
            ])
        else:
            record["errorCode"] = "AccessDenied"
            record["errorMessage"] = f"Insufficient clearance level: {user_info['clearance']} required for this operation"

    # Vary the eventCategory field
    if malicious:
        record["eventCategory"] = "Insight"  # Higher risk category for malicious events
    else:
        record["eventCategory"] = random.choice(["Management", "Data", "Insight"])

    return record

# ───────────────────── public factory ──────────────────────
def cloudtrail_log(overrides: dict | None = None) -> str:
    """
    Return a single CloudTrail event JSON string.

    Pass `overrides` to force any field to a specific value:
        cloudtrail_log({"eventName": "PutObject"})
    """
    record = _template()
    if overrides:
        record.update(overrides)
    return record  # Return as dict for hec_sender.py

# ─────────────────── standalone sanity run ─────────────────
if __name__ == "__main__":
    print(json.dumps(cloudtrail_log(), indent=2))