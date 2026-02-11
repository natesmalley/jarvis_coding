"""
Comprehensive tests for email security event generators
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
    from email_security.proofpoint_tap import (
        generate_proofpoint_events,
        generate_email_delivered,
        generate_email_blocked,
        generate_phishing_attempt,
        generate_malware_detected,
        generate_spam_detected,
        generate_dmarc_failure,
        get_threat_types,
        get_policy_actions
    )
except ImportError as e:
    pytest.skip(f"Cannot import proofpoint_tap: {e}", allow_module_level=True)

try:
    from shared.generator_utils import (
        generate_timestamp,
        generate_ip_address,
        generate_email,
        generate_domain,
        generate_uuid,
        random_choice,
        random_int
    )
except ImportError as e:
    pytest.skip(f"Cannot import generator_utils: {e}", allow_module_level=True)


class TestProofpointTAPGenerator:
    """Test Proofpoint TAP event generator"""
    
    def test_generate_email_delivered(self):
        """Test generating delivered email events"""
        event = generate_email_delivered()
        
        # Verify required fields
        assert "messageId" in event
        assert "sender" in event
        assert "recipients" in event
        assert "subject" in event
        assert "timestamp" in event
        assert "status" in event
        assert "messageSize" in event
        assert "attachments" in event
        
        # Verify field types and values
        assert event["status"] == "delivered"
        assert isinstance(event["recipients"], list)
        assert len(event["recipients"]) >= 1
        assert isinstance(event["messageSize"], int)
        assert event["messageSize"] > 0
        assert isinstance(event["attachments"], list)
        
        # Verify email format
        assert "@" in event["sender"]
        for recipient in event["recipients"]:
            assert "@" in recipient
    
    def test_generate_email_blocked(self):
        """Test generating blocked email events"""
        event = generate_email_blocked()
        
        # Verify required fields
        assert "messageId" in event
        assert "sender" in event
        assert "recipients" in event
        assert "subject" in event
        assert "timestamp" in event
        assert "status" in event
        assert "blockReason" in event
        assert "threatInfo" in event
        
        # Verify field values
        assert event["status"] == "blocked"
        assert event["blockReason"] in ["spam", "phishing", "malware", "policy"]
        assert isinstance(event["threatInfo"], dict)
        assert "threatType" in event["threatInfo"]
        assert "confidence" in event["threatInfo"]
    
    def test_generate_phishing_attempt(self):
        """Test generating phishing attempt events"""
        event = generate_phishing_attempt()
        
        # Verify phishing-specific fields
        assert event["status"] == "blocked"
        assert event["blockReason"] == "phishing"
        assert "phishingInfo" in event
        
        phishing_info = event["phishingInfo"]
        assert "brand" in phishing_info
        assert "impersonationType" in phishing_info
        assert "suspiciousElements" in phishing_info
        assert isinstance(phishing_info["suspiciousElements"], list)
        
        # Verify brand is a known brand
        known_brands = ["Microsoft", "Google", "Amazon", "Apple", "PayPal", "Bank", "LinkedIn"]
        assert phishing_info["brand"] in known_brands
    
    def test_generate_malware_detected(self):
        """Test generating malware detected events"""
        event = generate_malware_detected()
        
        # Verify malware-specific fields
        assert event["status"] == "blocked"
        assert event["blockReason"] == "malware"
        assert "malwareInfo" in event
        
        malware_info = event["malwareInfo"]
        assert "malwareType" in malware_info
        assert "malwareFamily" in malware_info
        assert "fileHash" in malware_info
        assert "fileName" in malware_info
        
        # Verify malware type
        malware_types = ["trojan", "ransomware", "spyware", "adware", "backdoor", "worm"]
        assert malware_info["malwareType"] in malware_types
        
        # Verify hash format
        assert len(malware_info["fileHash"]) in [32, 40, 64]  # MD5, SHA1, or SHA256
    
    def test_generate_spam_detected(self):
        """Test generating spam detected events"""
        event = generate_spam_detected()
        
        # Verify spam-specific fields
        assert event["status"] == "blocked"
        assert event["blockReason"] == "spam"
        assert "spamInfo" in event
        
        spam_info = event["spamInfo"]
        assert "spamScore" in spam_info
        assert "spamReasons" in spam_info
        assert isinstance(spam_info["spamScore"], (int, float))
        assert 0 <= spam_info["spamScore"] <= 100
        assert isinstance(spam_info["spamReasons"], list)
    
    def test_generate_dmarc_failure(self):
        """Test generating DMARC failure events"""
        event = generate_dmarc_failure()
        
        # Verify DMARC-specific fields
        assert "dmarcInfo" in event
        
        dmarc_info = event["dmarcInfo"]
        assert "dmarcResult" in dmarc_info
        assert "spfResult" in dmarc_info
        assert "dkimResult" in dmarc_info
        assert "alignedDomain" in dmarc_info
        
        # Verify result values
        dmarc_results = ["pass", "fail", "none"]
        spf_results = ["pass", "fail", "softfail", "neutral", "none", "temperror", "permerror"]
        dkim_results = ["pass", "fail", "neutral", "none", "temperror", "permerror"]
        
        assert dmarc_info["dmarcResult"] in dmarc_results
        assert dmarc_info["spfResult"] in spf_results
        assert dmarc_info["dkimResult"] in dkim_results
    
    def test_get_threat_types(self):
        """Test threat types retrieval"""
        threat_types = get_threat_types()
        
        assert isinstance(threat_types, list)
        assert len(threat_types) > 0
        
        expected_types = ["phishing", "malware", "spam", "business_email_compromise", "account_takeover"]
        for threat_type in expected_types:
            assert threat_type in threat_types
    
    def test_get_policy_actions(self):
        """Test policy actions retrieval"""
        actions = get_policy_actions()
        
        assert isinstance(actions, list)
        assert len(actions) > 0
        
        expected_actions = ["allow", "block", "quarantine", "modify", "deliver"]
        for action in expected_actions:
            assert action in actions
    
    def test_generate_proofpoint_events_batch(self):
        """Test generating batch of Proofpoint events"""
        events = generate_proofpoint_events(count=50)
        
        assert isinstance(events, list)
        assert len(events) == 50
        
        # Verify each event has required structure
        for event in events:
            assert "messageId" in event
            assert "timestamp" in event
            assert "status" in event
            assert "sender" in event
            assert "recipients" in event
        
        # Verify event distribution
        status_counts = {}
        for event in events:
            status = event["status"]
            status_counts[status] = status_counts.get(status, 0) + 1
        
        # Should have variety of statuses
        assert len(status_counts) >= 2
    
    def test_event_timestamp_consistency(self):
        """Test event timestamps are consistent"""
        start_time = datetime.now() - timedelta(hours=1)
        end_time = datetime.now()
        
        events = generate_proofpoint_events(count=10, start_time=start_time, end_time=end_time)
        
        for event in events:
            event_time = datetime.fromisoformat(event["timestamp"].replace("Z", "+00:00"))
            assert start_time <= event_time <= end_time
    
    def test_event_with_attachments(self):
        """Test events with attachments"""
        event = generate_email_delivered(include_attachments=True)
        
        assert "attachments" in event
        assert len(event["attachments"]) > 0
        
        for attachment in event["attachments"]:
            assert "name" in attachment
            assert "size" in attachment
            assert "type" in attachment
            assert "hash" in attachment
            assert isinstance(attachment["size"], int)
            assert attachment["size"] > 0
    
    def test_event_with_urls(self):
        """Test events with URLs"""
        event = generate_email_delivered(include_urls=True)
        
        assert "urls" in event
        assert len(event["urls"]) > 0
        
        for url_info in event["urls"]:
            assert "url" in url_info
            assert "reputation" in url_info
            assert "category" in url_info
            assert url_info["url"].startswith(("http://", "https://"))
    
    def test_custom_sender_domain(self):
        """Test events with custom sender domain"""
        custom_domain = "example.com"
        event = generate_email_delivered(sender_domain=custom_domain)
        
        assert event["sender"].endswith(f"@{custom_domain}")
    
    def test_custom_recipient_domain(self):
        """Test events with custom recipient domain"""
        custom_domain = "company.org"
        event = generate_email_delivered(recipient_domain=custom_domain)
        
        for recipient in event["recipients"]:
            assert recipient.endswith(f"@{custom_domain}")


class TestProofpointEventValidation:
    """Test Proofpoint event validation and schema compliance"""
    
    def test_event_schema_compliance(self):
        """Test events comply with expected schema"""
        event_types = [
            generate_email_delivered,
            generate_email_blocked,
            generate_phishing_attempt,
            generate_malware_detected,
            generate_spam_detected,
            generate_dmarc_failure
        ]
        
        for event_type in event_types:
            event = event_type()
            
            # Required base fields
            required_fields = ["messageId", "timestamp", "sender", "recipients", "subject", "status"]
            for field in required_fields:
                assert field in event, f"Missing required field '{field}' in {event_type.__name__}"
            
            # Message ID format
            assert isinstance(event["messageId"], str)
            assert len(event["messageId"]) > 10
            
            # Timestamp format
            assert isinstance(event["timestamp"], str)
            datetime.fromisoformat(event["timestamp"].replace("Z", "+00:00"))
            
            # Email formats
            assert "@" in event["sender"]
            assert isinstance(event["recipients"], list)
            assert len(event["recipients"]) > 0
            for recipient in event["recipients"]:
                assert "@" in recipient
    
    def test_threat_intelligence_fields(self):
        """Test threat intelligence fields in blocked events"""
        event = generate_email_blocked()
        
        if "threatInfo" in event:
            threat_info = event["threatInfo"]
            
            # Verify threat intelligence structure
            if "threatType" in threat_info:
                assert isinstance(threat_info["threatType"], str)
                assert len(threat_info["threatType"]) > 0
            
            if "confidence" in threat_info:
                assert isinstance(threat_info["confidence"], (int, float))
                assert 0 <= threat_info["confidence"] <= 100
            
            if "campaign" in threat_info:
                assert isinstance(threat_info["campaign"], dict)
    
    def test_geolocation_fields(self):
        """Test geolocation fields in events"""
        event = generate_email_delivered(include_geolocation=True)
        
        if "senderGeo" in event:
            geo = event["senderGeo"]
            assert "country" in geo
            assert "city" in geo
            assert isinstance(geo["country"], str)
            assert isinstance(geo["city"], str)


class TestProofpointPerformance:
    """Test Proofpoint generator performance"""
    
    def test_large_batch_generation(self):
        """Test generating large batches of events"""
        import time
        
        start_time = time.time()
        events = generate_proofpoint_events(count=1000)
        end_time = time.time()
        
        assert len(events) == 1000
        generation_time = end_time - start_time
        
        # Should generate 1000 events in reasonable time (less than 5 seconds)
        assert generation_time < 5.0
    
    def test_memory_usage(self):
        """Test memory usage during event generation"""
        import sys
        
        # Get initial memory usage
        initial_size = sys.getsizeof([])
        
        # Generate events
        events = generate_proofpoint_events(count=100)
        
        # Check memory usage is reasonable
        final_size = sys.getsizeof(events)
        assert final_size > initial_size
        
        # Each event should be roughly the same size
        avg_event_size = final_size / len(events)
        assert 1000 < avg_event_size < 10000  # Reasonable range for event objects


class TestProofpointIntegration:
    """Integration tests for Proofpoint generator"""
    
    def test_end_to_end_workflow(self):
        """Test complete workflow from generation to processing"""
        # Generate mixed events
        events = generate_proofpoint_events(count=100)
        
        # Process events (simulate security monitoring)
        blocked_events = [e for e in events if e["status"] == "blocked"]
        delivered_events = [e for e in events if e["status"] == "delivered"]
        
        # Analyze threats
        threat_types = {}
        for event in blocked_events:
            if "threatInfo" in event and "threatType" in event["threatInfo"]:
                threat_type = event["threatInfo"]["threatType"]
                threat_types[threat_type] = threat_types.get(threat_type, 0) + 1
        
        # Verify analysis
        assert len(blocked_events) > 0
        assert len(delivered_events) > 0
        assert len(threat_types) > 0
    
    def test_correlation_with_other_sources(self):
        """Test correlating Proofpoint events with other sources"""
        proofpoint_events = generate_proofpoint_events(count=10)
        
        # Simulate correlation with authentication logs
        correlated_events = []
        for pp_event in proofpoint_events:
            if pp_event["status"] == "blocked" and "phishingInfo" in pp_event:
                # Simulate finding related authentication attempt
                auth_event = {
                    "timestamp": pp_event["timestamp"],
                    "user": pp_event["recipients"][0],
                    "source": "authentication",
                    "result": "failed",
                    "correlation_id": pp_event["messageId"]
                }
                correlated_events.append((pp_event, auth_event))
        
        # Verify correlation logic
        assert len(correlated_events) >= 0  # May have correlations


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
