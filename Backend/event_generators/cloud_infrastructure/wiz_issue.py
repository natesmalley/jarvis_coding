#!/usr/bin/env python3
"""Wiz issue event generator.

Generates Wiz cloud security posture management issues with weighted
distribution. Supports multiple issue types including baseline issues,
critical vulnerabilities, open security groups, exposed secrets,
IAM misconfigurations, container vulnerabilities, and Kubernetes misconfigurations.
"""

from __future__ import annotations

import json
import os
import random
import sys
from datetime import timedelta
from typing import Any

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'shared'))
from generator_utils import (
    generate_uuid,
    now_utc,
    random_iso_timestamp,
)

# Issue type weights
# 40% baseline, 20% critical vuln, 15% open SG, 10% exposed secret, 8% IAM, 5% container, 2% k8s
ISSUE_WEIGHTS: dict[str, float] = {
    "issue": 0.40,
    "critical_vulnerability": 0.20,
    "open_security_group": 0.15,
    "exposed_secret": 0.10,
    "iam_misconfiguration": 0.08,
    "container_vulnerability": 0.05,
    "k8s_misconfiguration": 0.02,
}

SAMPLE_ISSUE: dict[str, Any] = {
    "id": "wiz-issue-baseline-001",
    "targetExternalId": "arn:aws:s3:::company-public-assets",
    "deleted": False,
    "targetObjectProviderUniqueId": "arn:aws:s3:::company-public-assets",
    "firstSeenAt": "2024-11-15T10:00:00Z",
    "result": "FAIL",
    "status": "OPEN",
    "severity": "MEDIUM",
    "remediation": "Update bucket ACL to remove public access",
    "resource": {
        "id": "resource-s3-baseline-001",
        "providerId": "aws-account-123456789012",
        "name": "company-public-assets",
        "nativeType": "S3 Bucket",
        "type": "BUCKET",
        "region": "us-east-1",
        "subscription": {
            "id": "sub-aws-prod-001",
            "name": "AWS Production Account",
            "externalId": "123456789012",
            "cloudProvider": "AWS",
        },
        "projects": [
            {"id": "project-marketing-001", "name": "Marketing Assets", "riskProfile": {"businessImpact": "MBI"}}
        ],
        "tags": [{"key": "Environment", "value": "Production"}, {"key": "Department", "value": "Marketing"}],
    },
    "rule": {
        "id": "rule-s3-public-001",
        "graphId": "graph-rule-001",
        "name": "S3 bucket is publicly accessible",
        "description": "S3 bucket allows public read access",
        "remediationInstructions": "Remove public ACL grants from bucket policy",
        "functionAsControl": False,
    },
    "securitySubCategories": [
        {
            "id": "cat-data-exposure-001",
            "title": "Data Exposure",
            "category": {
                "id": "cat-parent-001",
                "name": "Data Protection",
                "framework": {"id": "framework-cis-001", "name": "CIS AWS Foundations Benchmark"},
            },
        }
    ],
    "ignoreRules": None,
}

SAMPLE_CRITICAL_VULNERABILITY: dict[str, Any] = {
    "id": "beef-cafe-1337-wiz-cve-01",
    "targetExternalId": "arn:aws:ec2:us-east-1:987654321098:instance/i-0a1b2c3d4e5f67890",
    "deleted": False,
    "targetObjectProviderUniqueId": "i-0a1b2c3d4e5f67890",
    "firstSeenAt": "2024-12-01T08:00:00Z",
    "result": "FAIL",
    "status": "OPEN",
    "severity": "CRITICAL",
    "remediation": "Update Log4j library to version 2.17.1 or later",
    "resource": {
        "id": "resource-ec2-web-server-001",
        "providerId": "aws-987654321098",
        "name": "web-server-prod-01",
        "nativeType": "EC2 Instance",
        "type": "VIRTUAL_MACHINE",
        "region": "us-east-1",
        "subscription": {
            "id": "sub-aws-prod-002",
            "name": "AWS Production - Web Services",
            "externalId": "987654321098",
            "cloudProvider": "AWS",
        },
        "projects": [
            {"id": "project-ecommerce-001", "name": "E-commerce Platform", "riskProfile": {"businessImpact": "HBI"}}
        ],
        "tags": [
            {"key": "Environment", "value": "Production"},
            {"key": "Application", "value": "Webshop"},
            {"key": "Exposure", "value": "Internet-Facing"},
        ],
    },
    "rule": {
        "id": "rule-cve-2021-44228",
        "graphId": "graph-cve-log4j",
        "name": "CVE-2021-44228 - Log4Shell RCE vulnerability detected",
        "description": "Apache Log4j2 Remote Code Execution vulnerability (CVSS 10.0).",
        "remediationInstructions": "Immediately update Log4j to 2.17.1+.",
        "functionAsControl": False,
    },
    "securitySubCategories": [
        {
            "id": "cat-vuln-rce-001",
            "title": "Remote Code Execution",
            "category": {
                "id": "cat-vulnerabilities-001",
                "name": "Vulnerabilities",
                "framework": {"id": "framework-cve-001", "name": "CVE Database"},
            },
        }
    ],
    "ignoreRules": None,
    "cve_id": "CVE-2021-44228",
    "cvss_score": "10.0",
    "epss_score": "0.975",
    "exploit_available": "true",
    "internet_facing": "true",
}

SAMPLE_OPEN_SECURITY_GROUP: dict[str, Any] = {
    "id": "beef-cafe-1337-wiz-sg-01",
    "targetExternalId": "arn:aws:ec2:ap-southeast-1:555566667777:security-group/sg-0abc123def456789",
    "deleted": False,
    "targetObjectProviderUniqueId": "sg-0abc123def456789",
    "firstSeenAt": "2024-11-20T14:30:00Z",
    "result": "FAIL",
    "status": "OPEN",
    "severity": "HIGH",
    "remediation": "Restrict SSH access to known IP ranges or bastion hosts",
    "resource": {
        "id": "resource-sg-database-001",
        "providerId": "aws-555566667777",
        "name": "database-tier-sg",
        "nativeType": "Security Group",
        "type": "FIREWALL",
        "region": "ap-southeast-1",
        "subscription": {
            "id": "sub-aws-staging-001",
            "name": "AWS Staging Environment",
            "externalId": "555566667777",
            "cloudProvider": "AWS",
        },
        "projects": [
            {"id": "project-database-001", "name": "Database Infrastructure", "riskProfile": {"businessImpact": "HBI"}}
        ],
        "tags": [{"key": "Environment", "value": "Staging"}, {"key": "Tier", "value": "Database"}],
    },
    "rule": {
        "id": "rule-sg-ssh-open-001",
        "graphId": "graph-sg-ssh-world",
        "name": "Security group allows SSH (port 22) from 0.0.0.0/0",
        "description": "Security group has inbound rule allowing SSH access from any IP address",
        "remediationInstructions": "Limit SSH access to specific IP ranges.",
        "functionAsControl": True,
    },
    "securitySubCategories": [
        {
            "id": "cat-network-exposure-001",
            "title": "Network Exposure",
            "category": {
                "id": "cat-network-security-001",
                "name": "Network Security",
                "framework": {"id": "framework-cis-aws-001", "name": "CIS AWS Foundations"},
            },
        }
    ],
    "ignoreRules": None,
    "exposed_ports": "22",
    "cidr_blocks": "0.0.0.0/0",
    "attached_resources": "3 EC2 instances, 1 RDS database",
}

SAMPLE_EXPOSED_SECRET: dict[str, Any] = {
    "id": "beef-cafe-1337-wiz-secret-01",
    "targetExternalId": "arn:aws:ec2:us-west-2:111122223333:instance/i-secret-exposed-001",
    "deleted": False,
    "targetObjectProviderUniqueId": "i-secret-exposed-001",
    "firstSeenAt": "2024-12-02T09:15:00Z",
    "result": "FAIL",
    "status": "OPEN",
    "severity": "CRITICAL",
    "remediation": "Rotate exposed credentials immediately and remove from code",
    "resource": {
        "id": "resource-ec2-dev-001",
        "providerId": "aws-111122223333",
        "name": "dev-server-01",
        "nativeType": "EC2 Instance",
        "type": "VIRTUAL_MACHINE",
        "region": "us-west-2",
        "subscription": {
            "id": "sub-aws-dev-001",
            "name": "AWS Development",
            "externalId": "111122223333",
            "cloudProvider": "AWS",
        },
        "projects": [
            {"id": "project-dev-001", "name": "Development", "riskProfile": {"businessImpact": "LBI"}}
        ],
        "tags": [{"key": "Environment", "value": "Development"}],
    },
    "rule": {
        "id": "rule-secret-exposed-001",
        "graphId": "graph-secret-scan",
        "name": "Hardcoded AWS credentials detected in code",
        "description": "AWS access keys found in application code or configuration files",
        "remediationInstructions": "Remove hardcoded credentials and use IAM roles or secrets manager.",
        "functionAsControl": False,
    },
    "securitySubCategories": [
        {
            "id": "cat-secrets-001",
            "title": "Exposed Secrets",
            "category": {
                "id": "cat-secrets-mgmt-001",
                "name": "Secrets Management",
                "framework": {"id": "framework-owasp-001", "name": "OWASP Top 10"},
            },
        }
    ],
    "ignoreRules": None,
}

SAMPLE_IAM_MISCONFIGURATION: dict[str, Any] = {
    "id": "beef-cafe-1337-wiz-iam-01",
    "targetExternalId": "arn:aws:iam::444455556666:role/overly-permissive-role",
    "deleted": False,
    "targetObjectProviderUniqueId": "overly-permissive-role",
    "firstSeenAt": "2024-11-25T16:00:00Z",
    "result": "FAIL",
    "status": "OPEN",
    "severity": "HIGH",
    "remediation": "Apply principle of least privilege to IAM role",
    "resource": {
        "id": "resource-iam-role-001",
        "providerId": "aws-444455556666",
        "name": "overly-permissive-role",
        "nativeType": "IAM Role",
        "type": "IDENTITY",
        "region": "global",
        "subscription": {
            "id": "sub-aws-prod-003",
            "name": "AWS Production - Core",
            "externalId": "444455556666",
            "cloudProvider": "AWS",
        },
        "projects": [
            {"id": "project-core-001", "name": "Core Infrastructure", "riskProfile": {"businessImpact": "HBI"}}
        ],
        "tags": [{"key": "Environment", "value": "Production"}],
    },
    "rule": {
        "id": "rule-iam-admin-001",
        "graphId": "graph-iam-overperm",
        "name": "IAM role has AdministratorAccess policy attached",
        "description": "IAM role grants full administrative access to all AWS services",
        "remediationInstructions": "Replace AdministratorAccess with specific required permissions.",
        "functionAsControl": True,
    },
    "securitySubCategories": [
        {
            "id": "cat-iam-001",
            "title": "Excessive Permissions",
            "category": {
                "id": "cat-iam-security-001",
                "name": "Identity and Access Management",
                "framework": {"id": "framework-cis-aws-001", "name": "CIS AWS Foundations"},
            },
        }
    ],
    "ignoreRules": None,
}

SAMPLE_CONTAINER_VULNERABILITY: dict[str, Any] = {
    "id": "beef-cafe-1337-wiz-container-01",
    "targetExternalId": "arn:aws:ecr:us-east-1:777788889999:repository/app-image:latest",
    "deleted": False,
    "targetObjectProviderUniqueId": "app-image:latest",
    "firstSeenAt": "2024-12-03T12:00:00Z",
    "result": "FAIL",
    "status": "OPEN",
    "severity": "HIGH",
    "remediation": "Update base image and rebuild container",
    "resource": {
        "id": "resource-container-001",
        "providerId": "aws-777788889999",
        "name": "app-image:latest",
        "nativeType": "Container Image",
        "type": "CONTAINER_IMAGE",
        "region": "us-east-1",
        "subscription": {
            "id": "sub-aws-prod-004",
            "name": "AWS Production - Containers",
            "externalId": "777788889999",
            "cloudProvider": "AWS",
        },
        "projects": [
            {"id": "project-containers-001", "name": "Container Platform", "riskProfile": {"businessImpact": "HBI"}}
        ],
        "tags": [{"key": "Environment", "value": "Production"}],
    },
    "rule": {
        "id": "rule-container-vuln-001",
        "graphId": "graph-container-scan",
        "name": "Container image has critical vulnerabilities",
        "description": "Container image contains packages with known critical CVEs",
        "remediationInstructions": "Update vulnerable packages and rebuild image.",
        "functionAsControl": False,
    },
    "securitySubCategories": [
        {
            "id": "cat-container-vuln-001",
            "title": "Container Vulnerabilities",
            "category": {
                "id": "cat-container-security-001",
                "name": "Container Security",
                "framework": {"id": "framework-cis-docker-001", "name": "CIS Docker Benchmark"},
            },
        }
    ],
    "ignoreRules": None,
}

SAMPLE_K8S_MISCONFIGURATION: dict[str, Any] = {
    "id": "beef-cafe-1337-wiz-k8s-01",
    "targetExternalId": "arn:aws:eks:us-west-2:888899990000:cluster/prod-cluster/namespace/default/pod/privileged-pod",
    "deleted": False,
    "targetObjectProviderUniqueId": "privileged-pod",
    "firstSeenAt": "2024-12-04T08:30:00Z",
    "result": "FAIL",
    "status": "OPEN",
    "severity": "CRITICAL",
    "remediation": "Remove privileged mode from pod security context",
    "resource": {
        "id": "resource-k8s-pod-001",
        "providerId": "aws-888899990000",
        "name": "privileged-pod",
        "nativeType": "Kubernetes Pod",
        "type": "WORKLOAD",
        "region": "us-west-2",
        "subscription": {
            "id": "sub-aws-prod-005",
            "name": "AWS Production - EKS",
            "externalId": "888899990000",
            "cloudProvider": "AWS",
        },
        "projects": [
            {"id": "project-k8s-001", "name": "Kubernetes Platform", "riskProfile": {"businessImpact": "HBI"}}
        ],
        "tags": [{"key": "Environment", "value": "Production"}, {"key": "Cluster", "value": "prod-cluster"}],
    },
    "rule": {
        "id": "rule-k8s-privileged-001",
        "graphId": "graph-k8s-security",
        "name": "Pod running in privileged mode",
        "description": "Kubernetes pod is configured to run with privileged security context",
        "remediationInstructions": "Set securityContext.privileged to false.",
        "functionAsControl": True,
    },
    "securitySubCategories": [
        {
            "id": "cat-k8s-001",
            "title": "Kubernetes Misconfiguration",
            "category": {
                "id": "cat-k8s-security-001",
                "name": "Kubernetes Security",
                "framework": {"id": "framework-cis-k8s-001", "name": "CIS Kubernetes Benchmark"},
            },
        }
    ],
    "ignoreRules": None,
}

ALL_SAMPLE_ISSUES: dict[str, dict[str, Any]] = {
    "issue": SAMPLE_ISSUE,
    "critical_vulnerability": SAMPLE_CRITICAL_VULNERABILITY,
    "open_security_group": SAMPLE_OPEN_SECURITY_GROUP,
    "exposed_secret": SAMPLE_EXPOSED_SECRET,
    "iam_misconfiguration": SAMPLE_IAM_MISCONFIGURATION,
    "container_vulnerability": SAMPLE_CONTAINER_VULNERABILITY,
    "k8s_misconfiguration": SAMPLE_K8S_MISCONFIGURATION,
}

SEVERITIES = ["INFORMATIONAL", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
STATUSES = ["OPEN", "IN_PROGRESS", "RESOLVED", "REJECTED"]
REGIONS = ["us-east-1", "us-west-2", "eu-west-1", "ap-southeast-1", "ap-northeast-1"]


def generate_issue() -> dict[str, Any]:
    """Generate a single Wiz issue with weighted template selection and dynamic fields."""
    # Select template based on weights
    keys = list(ISSUE_WEIGHTS.keys())
    weights = [ISSUE_WEIGHTS[k] for k in keys]
    selected_key = random.choices(keys, weights=weights, k=1)[0]
    template = ALL_SAMPLE_ISSUES[selected_key]

    now = now_utc()
    start_time = now - timedelta(days=random.randint(1, 30))

    issue = {**template}
    issue["id"] = f"wiz-issue-{generate_uuid()}"
    issue["firstSeenAt"] = random_iso_timestamp(start_time, now)
    issue["status"] = random.choice(STATUSES)

    # Update resource with dynamic fields
    issue["resource"] = {**template["resource"]}
    issue["resource"]["id"] = f"resource-{generate_uuid()}"
    issue["resource"]["region"] = random.choice(REGIONS)

    return issue


def generate_issues(count: int = 100) -> list[dict[str, Any]]:
    """Generate multiple Wiz issues.

    Args:
        count: Number of issues to generate.

    Returns:
        List of generated issues.
    """
    return [generate_issue() for _ in range(count)]


def wiz_issue_log() -> str:
    """Return a single synthetic Wiz issue in JSON format.

    This is the main entry point for the generator, matching the pattern
    used by other generators in the repository.
    """
    return json.dumps(generate_issue())


if __name__ == "__main__":  # pragma: no cover
    for _ in range(3):
        print(wiz_issue_log())
