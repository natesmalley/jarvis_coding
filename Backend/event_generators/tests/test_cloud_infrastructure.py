"""
Comprehensive tests for cloud infrastructure event generators
"""
import pytest
import json
import sys
import os
from datetime import datetime, timedelta
from unittest.mock import patch, MagicMock, mock_open

# Add the parent directory to the path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    from cloud_infrastructure.wiz_issue import (
        generate_wiz_events,
        generate_security_issue,
        generate_vulnerability_alert,
        generate_cloud_misconfiguration,
        generate_iam_risk,
        generate_data_exposure_risk,
        get_severity_levels,
        get_issue_categories,
        get_cloud_providers
    )
except ImportError as e:
    pytest.skip(f"Cannot import wiz_issue: {e}", allow_module_level=True)

try:
    from shared.generator_utils import (
        generate_timestamp,
        generate_ip_address,
        generate_uuid,
        random_choice,
        random_int,
        random_float
    )
except ImportError as e:
    pytest.skip(f"Cannot import generator_utils: {e}", allow_module_level=True)


class TestWizIssueGenerator:
    """Test Wiz issue event generator"""
    
    def test_generate_security_issue(self):
        """Test generating security issue events"""
        event = generate_security_issue()
        
        # Verify required fields
        assert "issueId" in event
        assert "timestamp" in event
        assert "issueType" in event
        assert "severity" in event
        assert "status" in event
        assert "resource" in event
        assert "description" in event
        assert "recommendation" in event
        
        # Verify field values
        assert isinstance(event["issueId"], str)
        assert len(event["issueId"]) > 10
        assert isinstance(event["severity"], str)
        assert isinstance(event["status"], str)
        assert isinstance(event["resource"], dict)
        assert isinstance(event["description"], str)
        assert isinstance(event["recommendation"], str)
        
        # Verify resource information
        resource = event["resource"]
        assert "id" in resource
        assert "type" in resource
        assert "name" in resource
        assert "provider" in resource
        assert "region" in resource
        
        # Verify provider is a known cloud provider
        providers = ["AWS", "Azure", "GCP", "OCI"]
        assert resource["provider"] in providers
    
    def test_generate_vulnerability_alert(self):
        """Test generating vulnerability alert events"""
        event = generate_vulnerability_alert()
        
        # Verify vulnerability-specific fields
        assert "vulnerability" in event
        
        vuln = event["vulnerability"]
        assert "cveId" in vuln
        assert "cvssScore" in vuln
        assert "cvssVector" in vuln
        assert "package" in vuln
        assert "version" in vuln
        assert "fixedVersion" in vuln
        
        # Verify CVE format
        assert vuln["cveId"].startswith("CVE-")
        assert isinstance(vuln["cvssScore"], (int, float))
        assert 0.0 <= vuln["cvssScore"] <= 10.0
        assert isinstance(vuln["cvssVector"], str)
        assert vuln["cvssVector"].startswith("CVSS:")
        
        # Verify package information
        assert isinstance(vuln["package"], str)
        assert len(vuln["package"]) > 0
        assert isinstance(vuln["version"], str)
        assert isinstance(vuln["fixedVersion"], str)
    
    def test_generate_cloud_misconfiguration(self):
        """Test generating cloud misconfiguration events"""
        event = generate_cloud_misconfiguration()
        
        # Verify misconfiguration-specific fields
        assert "misconfiguration" in event
        
        misconfig = event["misconfiguration"]
        assert "configType" in misconfig
        assert "currentValue" in misconfig
        assert "recommendedValue" in misconfig
        assert "riskLevel" in misconfig
        assert "compliance" in misconfig
        
        # Verify misconfiguration details
        config_types = [
            "storage_bucket_public",
            "security_group_open",
            "iam_role_over_privileged",
            "encryption_disabled",
            "logging_disabled",
            "backup_disabled"
        ]
        assert misconfig["configType"] in config_types
        
        # Verify risk level
        risk_levels = ["critical", "high", "medium", "low"]
        assert misconfig["riskLevel"] in risk_levels
        
        # Verify compliance information
        if misconfig["compliance"]:
            compliance = misconfig["compliance"]
            assert "framework" in compliance
            assert "control" in compliance
            
            frameworks = ["CIS", "NIST", "ISO27001", "SOC2", "PCI-DSS", "HIPAA", "GDPR"]
            assert compliance["framework"] in frameworks
    
    def test_generate_iam_risk(self):
        """Test generating IAM risk events"""
        event = generate_iam_risk()
        
        # Verify IAM-specific fields
        assert "iamRisk" in event
        
        iam = event["iamRisk"]
        assert "riskType" in iam
        assert "principal" in iam
        assert "permissions" in iam
        assert "resources" in iam
        assert "exposure" in iam
        
        # Verify IAM risk types
        risk_types = [
            "over_privileged_role",
            "unused_credentials",
            "shared_credentials",
            "external_access",
            "privilege_escalation",
            "data_access"
        ]
        assert iam["riskType"] in risk_types
        
        # Verify principal information
        principal = iam["principal"]
        assert "type" in principal
        assert "name" in principal
        assert principal["type"] in ["User", "Role", "Service", "Group"]
        
        # Verify permissions
        assert isinstance(iam["permissions"], list)
        assert len(iam["permissions"]) > 0
        for permission in iam["permissions"]:
            assert isinstance(permission, str)
            assert len(permission) > 0
    
    def test_generate_data_exposure_risk(self):
        """Test generating data exposure risk events"""
        event = generate_data_exposure_risk()
        
        # Verify data exposure-specific fields
        assert "dataExposure" in event
        
        exposure = event["dataExposure"]
        assert "dataType" in exposure
        assert "exposureType" in exposure
        assert "location" in exposure
        assert "accessLevel" in exposure
        assert "sensitivity" in exposure
        
        # Verify data types
        data_types = [
            "pii",
            "phi",
            "financial",
            "credentials",
            "api_keys",
            "source_code",
            "logs"
        ]
        assert exposure["dataType"] in data_types
        
        # Verify exposure types
        exposure_types = [
            "public_bucket",
            "shared_link",
            "database_exposed",
            "api_endpoint",
            "backup_unencrypted",
            "log_public"
        ]
        assert exposure["exposureType"] in exposure_types
        
        # Verify sensitivity level
        sensitivity_levels = ["high", "medium", "low"]
        assert exposure["sensitivity"] in sensitivity_levels
    
    def test_get_severity_levels(self):
        """Test severity levels retrieval"""
        severities = get_severity_levels()
        
        assert isinstance(severities, list)
        assert len(severities) > 0
        
        expected_severities = ["critical", "high", "medium", "low", "info"]
        for severity in expected_severities:
            assert severity in severities
    
    def test_get_issue_categories(self):
        """Test issue categories retrieval"""
        categories = get_issue_categories()
        
        assert isinstance(categories, list)
        assert len(categories) > 0
        
        expected_categories = [
            "vulnerability",
            "misconfiguration",
            "iam_risk",
            "data_exposure",
            "compliance",
            "network_security"
        ]
        for category in expected_categories:
            assert category in categories
    
    def test_get_cloud_providers(self):
        """Test cloud providers retrieval"""
        providers = get_cloud_providers()
        
        assert isinstance(providers, list)
        assert len(providers) > 0
        
        expected_providers = ["AWS", "Azure", "GCP", "OCI"]
        for provider in expected_providers:
            assert provider in providers
    
    def test_generate_wiz_events_batch(self):
        """Test generating batch of Wiz events"""
        events = generate_wiz_events(count=50)
        
        assert isinstance(events, list)
        assert len(events) == 50
        
        # Verify each event has required structure
        for event in events:
            assert "issueId" in event
            assert "timestamp" in event
            assert "issueType" in event
            assert "severity" in event
            assert "status" in event
            assert "resource" in event
        
        # Verify event distribution
        issue_types = {}
        for event in events:
            issue_type = event["issueType"]
            issue_types[issue_type] = issue_types.get(issue_type, 0) + 1
        
        # Should have variety of issue types
        assert len(issue_types) >= 2


class TestWizEventValidation:
    """Test Wiz event validation and schema compliance"""
    
    def test_event_schema_compliance(self):
        """Test events comply with expected schema"""
        event_generators = [
            generate_security_issue,
            generate_vulnerability_alert,
            generate_cloud_misconfiguration,
            generate_iam_risk,
            generate_data_exposure_risk
        ]
        
        for generator in event_generators:
            event = generator()
            
            # Required base fields
            required_fields = ["issueId", "timestamp", "issueType", "severity", "status", "resource", "description"]
            for field in required_fields:
                assert field in event, f"Missing required field '{field}' in {generator.__name__}"
            
            # Issue ID format
            assert isinstance(event["issueId"], str)
            assert len(event["issueId"]) > 10
            
            # Timestamp format
            assert isinstance(event["timestamp"], str)
            datetime.fromisoformat(event["timestamp"].replace("Z", "+00:00"))
            
            # Severity validation
            valid_severities = ["critical", "high", "medium", "low", "info"]
            assert event["severity"] in valid_severities
            
            # Status validation
            valid_statuses = ["open", "resolved", "suppressed", "in_progress", "false_positive"]
            assert event["status"] in valid_statuses
            
            # Resource validation
            resource = event["resource"]
            assert "id" in resource
            assert "type" in resource
            assert "provider" in resource
            assert resource["provider"] in ["AWS", "Azure", "GCP", "OCI"]
    
    def test_vulnerability_validation(self):
        """Test vulnerability event validation"""
        event = generate_vulnerability_alert()
        
        vuln = event["vulnerability"]
        
        # CVE ID format
        assert vuln["cveId"].startswith("CVE-")
        cve_parts = vuln["cveId"].split("-")
        assert len(cve_parts) == 3
        assert cve_parts[1].isdigit()
        assert cve_parts[2].isdigit()
        
        # CVSS score validation
        assert 0.0 <= vuln["cvssScore"] <= 10.0
        
        # CVSS vector validation
        assert vuln["cvssVector"].startswith("CVSS:")
        assert len(vuln["cvssVector"]) > 10
    
    def test_misconfiguration_validation(self):
        """Test misconfiguration event validation"""
        event = generate_cloud_misconfiguration()
        
        misconfig = event["misconfiguration"]
        
        # Verify configuration types
        valid_types = [
            "storage_bucket_public",
            "security_group_open",
            "iam_role_over_privileged",
            "encryption_disabled",
            "logging_disabled",
            "backup_disabled"
        ]
        assert misconfig["configType"] in valid_types
        
        # Verify risk level
        valid_risks = ["critical", "high", "medium", "low"]
        assert misconfig["riskLevel"] in valid_risks
    
    def test_iam_risk_validation(self):
        """Test IAM risk event validation"""
        event = generate_iam_risk()
        
        iam = event["iamRisk"]
        
        # Verify risk types
        valid_types = [
            "over_privileged_role",
            "unused_credentials",
            "shared_credentials",
            "external_access",
            "privilege_escalation",
            "data_access"
        ]
        assert iam["riskType"] in valid_types
        
        # Verify principal
        principal = iam["principal"]
        assert principal["type"] in ["User", "Role", "Service", "Group"]
        
        # Verify permissions
        assert isinstance(iam["permissions"], list)
        assert len(iam["permissions"]) > 0


class TestWizPerformance:
    """Test Wiz generator performance"""
    
    def test_large_batch_generation(self):
        """Test generating large batches of events"""
        import time
        
        start_time = time.time()
        events = generate_wiz_events(count=500)
        end_time = time.time()
        
        assert len(events) == 500
        generation_time = end_time - start_time
        
        # Should generate 500 events in reasonable time
        assert generation_time < 3.0
    
    def test_memory_usage(self):
        """Test memory usage during event generation"""
        import sys
        
        # Get initial memory usage
        initial_size = sys.getsizeof([])
        
        # Generate events
        events = generate_wiz_events(count=100)
        
        # Check memory usage is reasonable
        final_size = sys.getsizeof(events)
        assert final_size > initial_size
        
        # Each event should be roughly the same size
        avg_event_size = final_size / len(events)
        assert 1000 < avg_event_size < 15000  # Reasonable range for event objects


class TestWizIntegration:
    """Integration tests for Wiz generator"""
    
    def test_cloud_provider_distribution(self):
        """Test cloud provider distribution in events"""
        events = generate_wiz_events(count=100)
        
        # Analyze provider distribution
        provider_counts = {}
        for event in events:
            provider = event["resource"]["provider"]
            provider_counts[provider] = provider_counts.get(provider, 0) + 1
        
        # Verify we have multiple providers
        assert len(provider_counts) >= 2
        
        # Verify all providers are valid
        valid_providers = ["AWS", "Azure", "GCP", "OCI"]
        for provider in provider_counts:
            assert provider in valid_providers
    
    def test_severity_distribution(self):
        """Test severity distribution in events"""
        events = generate_wiz_events(count=100)
        
        # Analyze severity distribution
        severity_counts = {}
        for event in events:
            severity = event["severity"]
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        # Verify we have variety of severities
        assert len(severity_counts) >= 2
        
        # Verify all severities are valid
        valid_severities = ["critical", "high", "medium", "low", "info"]
        for severity in severity_counts:
            assert severity in valid_severities
    
    def test_issue_type_correlation(self):
        """Test correlation between issue types and severities"""
        events = generate_wiz_events(count=50)
        
        # Analyze correlations
        correlations = {}
        for event in events:
            issue_type = event["issueType"]
            severity = event["severity"]
            
            if issue_type not in correlations:
                correlations[issue_type] = {}
            correlations[issue_type][severity] = correlations[issue_type].get(severity, 0) + 1
        
        # Verify correlations exist
        assert len(correlations) > 0
        
        # Verify each issue type has severity information
        for issue_type, severities in correlations.items():
            assert len(severities) > 0
    
    def test_resource_type_analysis(self):
        """Test resource type analysis"""
        events = generate_wiz_events(count=50)
        
        # Analyze resource types
        resource_types = {}
        for event in events:
            resource_type = event["resource"]["type"]
            resource_types[resource_type] = resource_types.get(resource_type, 0) + 1
        
        # Verify we have variety of resource types
        assert len(resource_types) >= 2
        
        # Verify common resource types
        common_types = ["EC2", "S3", "RDS", "Lambda", "VPC", "IAM", "Storage", "VM"]
        found_common = any(r_type in common_types for r_type in resource_types)
        assert found_common


class TestWizAdvancedScenarios:
    """Advanced scenario tests for Wiz generator"""
    
    def test_critical_vulnerability_simulation(self):
        """Test critical vulnerability simulation"""
        events = []
        
        # Generate critical vulnerabilities
        for _ in range(5):
            event = generate_vulnerability_alert()
            event["severity"] = "critical"
            event["vulnerability"]["cvssScore"] = random_float(8.0, 10.0)
            events.append(event)
        
        # Verify critical vulnerabilities
        critical_events = [e for e in events if e["severity"] == "critical"]
        assert len(critical_events) == 5
        
        # Verify high CVSS scores
        for event in critical_events:
            assert event["vulnerability"]["cvssScore"] >= 8.0
    
    def test_compliance_assessment_simulation(self):
        """Test compliance assessment simulation"""
        events = generate_wiz_events(count=30)
        
        # Filter compliance-related events
        compliance_events = []
        for event in events:
            if "misconfiguration" in event and "compliance" in event["misconfiguration"]:
                compliance_events.append(event)
        
        # Analyze compliance frameworks
        frameworks = {}
        for event in compliance_events:
            framework = event["misconfiguration"]["compliance"]["framework"]
            frameworks[framework] = frameworks.get(framework, 0) + 1
        
        # Verify compliance analysis
        assert len(compliance_events) >= 0
        if frameworks:
            valid_frameworks = ["CIS", "NIST", "ISO27001", "SOC2", "PCI-DSS", "HIPAA", "GDPR"]
            for framework in frameworks:
                assert framework in valid_frameworks
    
    def test_multi_cloud_security_posture(self):
        """Test multi-cloud security posture assessment"""
        events = generate_wiz_events(count=100)
        
        # Analyze multi-cloud distribution
        cloud_analysis = {}
        for event in events:
            provider = event["resource"]["provider"]
            severity = event["severity"]
            
            if provider not in cloud_analysis:
                cloud_analysis[provider] = {"total": 0, "critical": 0, "high": 0}
            
            cloud_analysis[provider]["total"] += 1
            if severity == "critical":
                cloud_analysis[provider]["critical"] += 1
            elif severity == "high":
                cloud_analysis[provider]["high"] += 1
        
        # Verify multi-cloud analysis
        assert len(cloud_analysis) >= 2
        
        # Verify each cloud has issues
        for provider, stats in cloud_analysis.items():
            assert stats["total"] > 0
    
    def test_attack_path_simulation(self):
        """Test attack path simulation"""
        events = []
        
        # Initial access (public resource)
        event = generate_cloud_misconfiguration()
        event["misconfiguration"]["configType"] = "storage_bucket_public"
        events.append(event)
        
        # Privilege escalation
        event = generate_iam_risk()
        event["iamRisk"]["riskType"] = "over_privileged_role"
        events.append(event)
        
        # Data exfiltration
        event = generate_data_exposure_risk()
        event["dataExposure"]["exposureType"] = "public_bucket"
        events.append(event)
        
        # Verify attack path
        assert len(events) == 3
        
        # Verify progression
        assert events[0]["issueType"] == "misconfiguration"
        assert events[1]["issueType"] == "iam_risk"
        assert events[2]["issueType"] == "data_exposure"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
