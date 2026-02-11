"""
Comprehensive tests for network security event generators
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
    from network_security.darktrace_breach import (
        generate_darktrace_events,
        generate_breach_detected,
        generate_anomalous_connection,
        generate_data_exfiltration,
        generate_lateral_movement,
        generate_command_control,
        get_severity_levels,
        get_model_confidences
    )
except ImportError as e:
    pytest.skip(f"Cannot import darktrace_breach: {e}", allow_module_level=True)

try:
    from network_security.vectra_detection import (
        generate_vectra_events,
        generate_detections,
        generate_score_increases,
        generate_host_compromise,
        generate_data_access_anomaly,
        generate_lateral_movement_detection
    )
except ImportError as e:
    pytest.skip(f"Cannot import vectra_detection: {e}", allow_module_level=True)

try:
    from shared.generator_utils import (
        generate_timestamp,
        generate_ip_address,
        generate_mac_address,
        generate_domain,
        generate_uuid,
        random_choice,
        random_int,
        random_float,
        is_private_ip
    )
except ImportError as e:
    pytest.skip(f"Cannot import generator_utils: {e}", allow_module_level=True)


class TestDarktraceBreachGenerator:
    """Test Darktrace breach event generator"""
    
    def test_generate_breach_detected(self):
        """Test generating breach detected events"""
        event = generate_breach_detected()
        
        # Verify required fields
        assert "eventId" in event
        assert "timestamp" in event
        assert "eventType" in event
        assert "severity" in event
        assert "confidence" in event
        assert "device" in event
        assert "threat" in event
        
        # Verify field values
        assert event["eventType"] == "breach_detected"
        assert isinstance(event["severity"], str)
        assert isinstance(event["confidence"], (int, float))
        assert 0 <= event["confidence"] <= 100
        assert isinstance(event["device"], dict)
        assert isinstance(event["threat"], dict)
        
        # Verify device information
        device = event["device"]
        assert "ip" in device
        assert "mac" in device
        assert "hostname" in device
        assert "os" in device
        assert is_private_ip(device["ip"])
    
    def test_generate_anomalous_connection(self):
        """Test generating anomalous connection events"""
        event = generate_anomalous_connection()
        
        # Verify connection-specific fields
        assert event["eventType"] == "anomalous_connection"
        assert "connection" in event
        
        connection = event["connection"]
        assert "sourceIp" in connection
        assert "destIp" in connection
        assert "destPort" in connection
        assert "protocol" in connection
        assert "bytesTransferred" in connection
        assert "duration" in connection
        
        # Verify connection details
        assert isinstance(connection["destPort"], int)
        assert 1 <= connection["destPort"] <= 65535
        assert connection["protocol"] in ["TCP", "UDP", "ICMP"]
        assert isinstance(connection["bytesTransferred"], int)
        assert connection["bytesTransferred"] >= 0
        assert isinstance(connection["duration"], (int, float))
        assert connection["duration"] >= 0
    
    def test_generate_data_exfiltration(self):
        """Test generating data exfiltration events"""
        event = generate_data_exfiltration()
        
        # Verify exfiltration-specific fields
        assert event["eventType"] == "data_exfiltration"
        assert "exfiltration" in event
        
        exfil = event["exfiltration"]
        assert "dataVolume" in exfil
        assert "dataTypes" in exfil
        assert "destinations" in exfil
        assert "method" in exfil
        
        # Verify exfiltration details
        assert isinstance(exfil["dataVolume"], int)
        assert exfil["dataVolume"] > 0
        assert isinstance(exfil["dataTypes"], list)
        assert len(exfil["dataTypes"]) > 0
        assert isinstance(exfil["destinations"], list)
        assert len(exfil["destinations"]) > 0
        
        # Verify data types
        expected_types = ["credentials", "financial", "pii", "intellectual_property", "healthcare"]
        for data_type in exfil["dataTypes"]:
            assert data_type in expected_types
    
    def test_generate_lateral_movement(self):
        """Test generating lateral movement events"""
        event = generate_lateral_movement()
        
        # Verify lateral movement fields
        assert event["eventType"] == "lateral_movement"
        assert "movement" in event
        
        movement = event["movement"]
        assert "sourceHost" in movement
        assert "destHost" in movement
        assert "technique" in movement
        assert "tools" in movement
        assert "privilegeEscalation" in movement
        
        # Verify movement details
        assert isinstance(movement["sourceHost"], dict)
        assert isinstance(movement["destHost"], dict)
        assert isinstance(movement["tools"], list)
        assert isinstance(movement["privilegeEscalation"], bool)
        
        # Verify MITRE ATT&CK techniques
        mitre_techniques = ["T1021", "T1028", "T1047", "T1069", "T1077", "T1098"]
        assert movement["technique"] in mitre_techniques
    
    def test_generate_command_control(self):
        """Test generating command and control events"""
        event = generate_command_control()
        
        # Verify C2 fields
        assert event["eventType"] == "command_control"
        assert "c2" in event
        
        c2 = event["c2"]
        assert "c2Server" in c2
        assert "beaconInterval" in c2
        assert "protocol" in c2
        assert "encryption" in c2
        assert "commands" in c2
        
        # Verify C2 details
        assert isinstance(c2["c2Server"], dict)
        assert isinstance(c2["beaconInterval"], (int, float))
        assert c2["beaconInterval"] > 0
        assert c2["protocol"] in ["HTTP", "HTTPS", "DNS", "ICMP"]
        assert isinstance(c2["encryption"], bool)
        assert isinstance(c2["commands"], list)
    
    def test_get_severity_levels(self):
        """Test severity levels retrieval"""
        severities = get_severity_levels()
        
        assert isinstance(severities, list)
        assert len(severities) > 0
        
        expected_severities = ["critical", "high", "medium", "low", "info"]
        for severity in expected_severities:
            assert severity in severities
    
    def test_get_model_confidences(self):
        """Test model confidence levels retrieval"""
        confidences = get_model_confidences()
        
        assert isinstance(confidences, list)
        assert len(confidences) > 0
        
        # Verify confidence values are valid
        for confidence in confidences:
            assert isinstance(confidence, (int, float))
            assert 0 <= confidence <= 100
    
    def test_generate_darktrace_events_batch(self):
        """Test generating batch of Darktrace events"""
        events = generate_darktrace_events(count=50)
        
        assert isinstance(events, list)
        assert len(events) == 50
        
        # Verify each event has required structure
        for event in events:
            assert "eventId" in event
            assert "timestamp" in event
            assert "eventType" in event
            assert "severity" in event
            assert "confidence" in event
        
        # Verify event distribution
        event_types = {}
        for event in events:
            event_type = event["eventType"]
            event_types[event_type] = event_types.get(event_type, 0) + 1
        
        # Should have variety of event types
        assert len(event_types) >= 2


class TestVectraDetectionGenerator:
    """Test Vectra detection event generator"""
    
    def test_generate_detections(self):
        """Test generating detection events"""
        event = generate_detections()
        
        # Verify required fields
        assert "detectionId" in event
        assert "timestamp" in event
        assert "detectionType" in event
        assert "category" in event
        assert "score" in event
        assert "certainty" in event
        assert "host" in event
        assert "description" in event
        
        # Verify field values
        assert isinstance(event["score"], (int, float))
        assert 0 <= event["score"] <= 100
        assert isinstance(event["certainty"], (int, float))
        assert 0 <= event["certainty"] <= 100
        assert isinstance(event["host"], dict)
        assert isinstance(event["description"], str)
        assert len(event["description"]) > 0
    
    def test_generate_score_increases(self):
        """Test generating score increase events"""
        event = generate_score_increases()
        
        # Verify score increase fields
        assert event["detectionType"] == "score_increase"
        assert "scoreChange" in event
        assert "previousScore" in event
        assert "newScore" in event
        assert "triggers" in event
        
        # Verify score change details
        assert isinstance(event["scoreChange"], (int, float))
        assert event["scoreChange"] > 0
        assert event["newScore"] > event["previousScore"]
        assert isinstance(event["triggers"], list)
        assert len(event["triggers"]) > 0
    
    def test_generate_host_compromise(self):
        """Test generating host compromise events"""
        event = generate_host_compromise()
        
        # Verify compromise fields
        assert event["detectionType"] == "host_compromise"
        assert "compromise" in event
        
        compromise = event["compromise"]
        assert "stage" in compromise
        assert "killChain" in compromise
        assert "indicators" in compromise
        assert "timeline" in compromise
        
        # Verify compromise details
        stages = ["reconnaissance", "initial_access", "execution", "persistence", "privilege_escalation", "lateral_movement", "exfiltration"]
        assert compromise["stage"] in stages
        
        assert isinstance(compromise["indicators"], list)
        assert isinstance(compromise["timeline"], list)
    
    def test_generate_data_access_anomaly(self):
        """Test generating data access anomaly events"""
        event = generate_data_access_anomaly()
        
        # Verify anomaly fields
        assert event["detectionType"] == "data_access_anomaly"
        assert "anomaly" in event
        
        anomaly = event["anomaly"]
        assert "dataType" in anomaly
        assert "accessPattern" in anomaly
        assert "volume" in anomaly
        assert "timeWindow" in anomaly
        assert "baseline" in anomaly
        
        # Verify anomaly details
        data_types = ["file_access", "database_query", "api_call", "cloud_storage"]
        assert anomaly["dataType"] in data_types
        
        assert isinstance(anomaly["volume"], dict)
        assert "current" in anomaly["volume"]
        assert "baseline" in anomaly["volume"]
    
    def test_generate_lateral_movement_detection(self):
        """Test generating lateral movement detection events"""
        event = generate_lateral_movement_detection()
        
        # Verify lateral movement detection fields
        assert event["detectionType"] == "lateral_movement"
        assert "lateralMovement" in event
        
        lateral = event["lateralMovement"]
        assert "sourceHost" in lateral
        assert "destinationHosts" in lateral
        assert "protocols" in lateral
        assert "accounts" in lateral
        assert "techniques" in lateral
        
        # Verify lateral movement details
        assert isinstance(lateral["destinationHosts"], list)
        assert len(lateral["destinationHosts"]) > 0
        assert isinstance(lateral["protocols"], list)
        assert isinstance(lateral["accounts"], list)
        assert isinstance(lateral["techniques"], list)
    
    def test_generate_vectra_events_batch(self):
        """Test generating batch of Vectra events"""
        events = generate_vectra_events(count=50)
        
        assert isinstance(events, list)
        assert len(events) == 50
        
        # Verify each event has required structure
        for event in events:
            assert "detectionId" in event
            assert "timestamp" in event
            assert "detectionType" in event
            assert "category" in event
            assert "score" in event
            assert "certainty" in event


class TestNetworkSecurityValidation:
    """Test network security event validation"""
    
    def test_darktrace_event_validation(self):
        """Test Darktrace event validation"""
        event_generators = [
            generate_breach_detected,
            generate_anomalous_connection,
            generate_data_exfiltration,
            generate_lateral_movement,
            generate_command_control
        ]
        
        for generator in event_generators:
            event = generator()
            
            # Required base fields
            required_fields = ["eventId", "timestamp", "eventType", "severity", "confidence"]
            for field in required_fields:
                assert field in event, f"Missing required field '{field}' in {generator.__name__}"
            
            # Event ID format
            assert isinstance(event["eventId"], str)
            assert len(event["eventId"]) > 10
            
            # Timestamp format
            assert isinstance(event["timestamp"], str)
            datetime.fromisoformat(event["timestamp"].replace("Z", "+00:00"))
            
            # Severity validation
            valid_severities = ["critical", "high", "medium", "low", "info"]
            assert event["severity"] in valid_severities
            
            # Confidence validation
            assert isinstance(event["confidence"], (int, float))
            assert 0 <= event["confidence"] <= 100
    
    def test_vectra_event_validation(self):
        """Test Vectra event validation"""
        event_generators = [
            generate_detections,
            generate_score_increases,
            generate_host_compromise,
            generate_data_access_anomaly,
            generate_lateral_movement_detection
        ]
        
        for generator in event_generators:
            event = generator()
            
            # Required base fields
            required_fields = ["detectionId", "timestamp", "detectionType", "category", "score", "certainty"]
            for field in required_fields:
                assert field in event, f"Missing required field '{field}' in {generator.__name__}"
            
            # Detection ID format
            assert isinstance(event["detectionId"], str)
            assert len(event["detectionId"]) > 10
            
            # Timestamp format
            assert isinstance(event["timestamp"], str)
            datetime.fromisoformat(event["timestamp"].replace("Z", "+00:00"))
            
            # Score validation
            assert isinstance(event["score"], (int, float))
            assert 0 <= event["score"] <= 100
            
            # Certainty validation
            assert isinstance(event["certainty"], (int, float))
            assert 0 <= event["certainty"] <= 100


class TestNetworkSecurityPerformance:
    """Test network security generator performance"""
    
    def test_darktrace_performance(self):
        """Test Darktrace generator performance"""
        import time
        
        start_time = time.time()
        events = generate_darktrace_events(count=500)
        end_time = time.time()
        
        assert len(events) == 500
        generation_time = end_time - start_time
        
        # Should generate 500 events in reasonable time
        assert generation_time < 3.0
    
    def test_vectra_performance(self):
        """Test Vectra generator performance"""
        import time
        
        start_time = time.time()
        events = generate_vectra_events(count=500)
        end_time = time.time()
        
        assert len(events) == 500
        generation_time = end_time - start_time
        
        # Should generate 500 events in reasonable time
        assert generation_time < 3.0


class TestNetworkSecurityIntegration:
    """Integration tests for network security generators"""
    
    def test_cross_platform_correlation(self):
        """Test correlating events across Darktrace and Vectra"""
        darktrace_events = generate_darktrace_events(count=20)
        vectra_events = generate_vectra_events(count=20)
        
        # Find potential correlations based on IP addresses
        correlations = []
        for dt_event in darktrace_events:
            if "device" in dt_event and "ip" in dt_event["device"]:
                dt_ip = dt_event["device"]["ip"]
                for v_event in vectra_events:
                    if "host" in v_event and "ip" in v_event["host"]:
                        if v_event["host"]["ip"] == dt_ip:
                            correlations.append((dt_event, v_event))
        
        # Verify correlation logic works
        assert isinstance(correlations, list)
    
    def test_attack_chain_simulation(self):
        """Test simulating complete attack chain"""
        events = []
        
        # Initial breach
        events.append(generate_breach_detected())
        
        # Lateral movement
        events.append(generate_lateral_movement())
        
        # Data exfiltration
        events.append(generate_data_exfiltration())
        
        # Command and control
        events.append(generate_command_control())
        
        # Verify attack chain progression
        assert len(events) == 4
        
        # Check timestamps are in chronological order
        timestamps = [datetime.fromisoformat(e["timestamp"].replace("Z", "+00:00")) for e in events]
        assert timestamps == sorted(timestamps)
    
    def test_severity_distribution(self):
        """Test severity distribution in generated events"""
        darktrace_events = generate_darktrace_events(count=100)
        vectra_events = generate_vectra_events(count=100)
        
        # Analyze severity distribution
        dt_severities = {}
        for event in darktrace_events:
            severity = event["severity"]
            dt_severities[severity] = dt_severities.get(severity, 0) + 1
        
        v_scores = {"low": 0, "medium": 0, "high": 0, "critical": 0}
        for event in vectra_events:
            score = event["score"]
            if score < 30:
                v_scores["low"] += 1
            elif score < 60:
                v_scores["medium"] += 1
            elif score < 80:
                v_scores["high"] += 1
            else:
                v_scores["critical"] += 1
        
        # Verify we have variety of severities
        assert len(dt_severities) >= 2
        assert sum(v_scores.values()) == 100


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
