"""
Comprehensive tests for generator utilities
"""
import pytest
import json
import sys
import os
from datetime import datetime, timedelta
from unittest.mock import patch, MagicMock, mock_open

# Add the parent directory to the path to import generator_utils
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    from shared.generator_utils import (
        generate_timestamp,
        generate_ip_address,
        generate_mac_address,
        generate_user_agent,
        generate_file_hash,
        generate_uuid,
        random_choice,
        random_int,
        random_float,
        weighted_choice,
        generate_email,
        generate_domain,
        generate_url,
        format_bytes,
        parse_timestamp,
        validate_json_schema,
        load_config,
        save_events,
        batch_events,
        retry_with_backoff,
        calculate_entropy,
        is_private_ip,
        normalize_domain,
        extract_iocs,
        generate_geolocation,
        calculate_risk_score,
        mask_sensitive_data
    )
except ImportError as e:
    pytest.skip(f"Cannot import generator_utils: {e}", allow_module_level=True)


class TestTimestampGeneration:
    """Test timestamp generation utilities"""
    
    def test_generate_timestamp_default(self):
        """Test default timestamp generation"""
        ts = generate_timestamp()
        assert isinstance(ts, str)
        # Should be ISO format
        assert "T" in ts
        assert "Z" in ts or "+" in ts
        # Should be parseable
        datetime.fromisoformat(ts.replace("Z", "+00:00"))
    
    def test_generate_timestamp_with_range(self):
        """Test timestamp generation with time range"""
        start = datetime.now() - timedelta(days=7)
        end = datetime.now()
        ts = generate_timestamp(start_time=start, end_time=end)
        
        parsed = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        assert start <= parsed <= end
    
    def test_generate_timestamp_with_format(self):
        """Test timestamp generation with custom format"""
        ts = generate_timestamp(format="%Y-%m-%d %H:%M:%S")
        assert isinstance(ts, str)
        assert "T" not in ts  # Should not have ISO format
        assert ":" in ts  # Should have time separator
    
    @patch('shared.generator_utils.datetime')
    def test_generate_timestamp_mocked(self, mock_datetime):
        """Test timestamp generation with mocked datetime"""
        mock_now = datetime(2024, 1, 15, 10, 30, 45)
        mock_datetime.now.return_value = mock_now
        mock_datetime.side_effect = lambda *args, **kw: datetime
        
        ts = generate_timestamp()
        assert "2024-01-15" in ts


class TestNetworkGeneration:
    """Test network-related generation utilities"""
    
    def test_generate_ip_address_v4(self):
        """Test IPv4 address generation"""
        ip = generate_ip_address(version=4)
        assert isinstance(ip, str)
        parts = ip.split('.')
        assert len(parts) == 4
        for part in parts:
            assert 0 <= int(part) <= 255
    
    def test_generate_ip_address_v6(self):
        """Test IPv6 address generation"""
        ip = generate_ip_address(version=6)
        assert isinstance(ip, str)
        assert ":" in ip
    
    def test_generate_ip_address_private(self):
        """Test private IP address generation"""
        ip = generate_ip_address(private=True)
        assert is_private_ip(ip)
    
    def test_generate_mac_address(self):
        """Test MAC address generation"""
        mac = generate_mac_address()
        assert isinstance(mac, str)
        assert len(mac) == 17  # XX:XX:XX:XX:XX:XX format
        parts = mac.split(':')
        assert len(parts) == 6
        for part in parts:
            assert len(part) == 2
            assert all(c in '0123456789ABCDEF' for c in part.upper())
    
    def test_is_private_ip(self):
        """Test private IP detection"""
        # Private IPs
        assert is_private_ip("192.168.1.1")
        assert is_private_ip("10.0.0.1")
        assert is_private_ip("172.16.0.1")
        assert is_private_ip("127.0.0.1")
        
        # Public IPs
        assert not is_private_ip("8.8.8.8")
        assert not is_private_ip("1.1.1.1")
        assert not is_private_ip("208.67.222.222")


class TestDataGeneration:
    """Test data generation utilities"""
    
    def test_generate_uuid(self):
        """Test UUID generation"""
        uuid_str = generate_uuid()
        assert isinstance(uuid_str, str)
        assert len(uuid_str) == 36
        assert uuid_str.count('-') == 4
    
    def test_generate_email(self):
        """Test email generation"""
        email = generate_email()
        assert isinstance(email, str)
        assert "@" in email
        assert "." in email.split('@')[1]
    
    def test_generate_domain(self):
        """Test domain generation"""
        domain = generate_domain()
        assert isinstance(domain, str)
        assert "." in domain
        assert not domain.startswith(".")
        assert not domain.endswith(".")
    
    def test_generate_url(self):
        """Test URL generation"""
        url = generate_url()
        assert isinstance(url, str)
        assert url.startswith(("http://", "https://"))
        assert "." in url
    
    def test_generate_file_hash(self):
        """Test file hash generation"""
        hash_md5 = generate_file_hash(algorithm="md5")
        assert isinstance(hash_md5, str)
        assert len(hash_md5) == 32
        
        hash_sha256 = generate_file_hash(algorithm="sha256")
        assert isinstance(hash_sha256, str)
        assert len(hash_sha256) == 64
    
    def test_generate_user_agent(self):
        """Test user agent generation"""
        ua = generate_user_agent()
        assert isinstance(ua, str)
        assert any(browser in ua for browser in ["Mozilla", "Chrome", "Safari", "Firefox"])
    
    def test_random_choice(self):
        """Test random choice from list"""
        choices = ["a", "b", "c", "d"]
        result = random_choice(choices)
        assert result in choices
        
        # Test with weights
        weighted_choices = [("a", 0.1), ("b", 0.8), ("c", 0.1)]
        results = [random_choice(weighted_choices) for _ in range(100)]
        # 'b' should appear more frequently
        assert results.count("b") > results.count("a")
        assert results.count("b") > results.count("c")
    
    def test_random_int(self):
        """Test random integer generation"""
        for _ in range(100):
            val = random_int(1, 10)
            assert 1 <= val <= 10
            assert isinstance(val, int)
    
    def test_random_float(self):
        """Test random float generation"""
        for _ in range(100):
            val = random_float(1.0, 10.0)
            assert 1.0 <= val <= 10.0
            assert isinstance(val, float)


class TestDataProcessing:
    """Test data processing utilities"""
    
    def test_format_bytes(self):
        """Test byte formatting"""
        assert format_bytes(1024) == "1.0 KB"
        assert format_bytes(1048576) == "1.0 MB"
        assert format_bytes(1073741824) == "1.0 GB"
        assert format_bytes(500) == "500.0 B"
    
    def test_parse_timestamp(self):
        """Test timestamp parsing"""
        # ISO format
        ts = "2024-01-15T10:30:45Z"
        parsed = parse_timestamp(ts)
        assert isinstance(parsed, datetime)
        
        # Custom format
        ts = "2024-01-15 10:30:45"
        parsed = parse_timestamp(ts, format="%Y-%m-%d %H:%M:%S")
        assert isinstance(parsed, datetime)
    
    def test_validate_json_schema(self):
        """Test JSON schema validation"""
        schema = {
            "type": "object",
            "properties": {
                "name": {"type": "string"},
                "age": {"type": "number"}
            },
            "required": ["name"]
        }
        
        # Valid data
        valid_data = {"name": "John", "age": 30}
        assert validate_json_schema(valid_data, schema)
        
        # Invalid data - missing required field
        invalid_data = {"age": 30}
        assert not validate_json_schema(invalid_data, schema)
        
        # Invalid data - wrong type
        invalid_data2 = {"name": 123, "age": 30}
        assert not validate_json_schema(invalid_data2, schema)
    
    def test_normalize_domain(self):
        """Test domain normalization"""
        assert normalize_domain("EXAMPLE.COM") == "example.com"
        assert normalize_domain("www.example.com") == "example.com"
        assert normalize_domain("sub.domain.example.com") == "example.com"
    
    def test_extract_iocs(self):
        """Test IOC extraction"""
        text = "Attack from 192.168.1.1 to https://evil.com/malware.exe with hash a1b2c3d4e5f6"
        iocs = extract_iocs(text)
        
        assert "192.168.1.1" in iocs.get("ips", [])
        assert "https://evil.com/malware.exe" in iocs.get("urls", [])
        assert "a1b2c3d4e5f6" in iocs.get("hashes", [])
    
    def test_mask_sensitive_data(self):
        """Test sensitive data masking"""
        data = {
            "username": "john.doe",
            "password": "secret123",
            "email": "john@example.com",
            "api_key": "sk-1234567890",
            "nested": {
                "token": "abc123",
                "public": "safe_data"
            }
        }
        
        masked = mask_sensitive_data(data)
        assert masked["username"] == "john.doe"
        assert masked["password"] == "***"
        assert masked["email"] == "j***@example.com"
        assert masked["api_key"] == "sk-********"
        assert masked["nested"]["token"] == "***"
        assert masked["nested"]["public"] == "safe_data"


class TestFileOperations:
    """Test file operation utilities"""
    
    def test_load_config(self):
        """Test configuration loading"""
        config_data = {"setting1": "value1", "setting2": 42}
        
        with patch("builtins.open", mock_open(read_data=json.dumps(config_data))):
            config = load_config("test_config.json")
            assert config == config_data
    
    def test_save_events(self):
        """Test event saving"""
        events = [
            {"timestamp": "2024-01-15T10:30:00Z", "event": "login"},
            {"timestamp": "2024-01-15T10:31:00Z", "event": "logout"}
        ]
        
        with patch("builtins.open", mock_open()) as mock_file:
            save_events(events, "test_events.json")
            mock_file.assert_called_once_with("test_events.json", "w")
    
    def test_batch_events(self):
        """Test event batching"""
        events = [{"id": i} for i in range(10)]
        batches = list(batch_events(events, batch_size=3))
        
        assert len(batches) == 4  # 3, 3, 3, 1
        assert len(batches[0]) == 3
        assert len(batches[3]) == 1


class TestAdvancedUtilities:
    """Test advanced utility functions"""
    
    def test_retry_with_backoff(self):
        """Test retry mechanism with backoff"""
        call_count = 0
        
        def failing_function():
            nonlocal call_count
            call_count += 1
            if call_count < 3:
                raise ValueError("Temporary failure")
            return "success"
        
        result = retry_with_backoff(failing_function, max_attempts=3, backoff_factor=0.1)
        assert result == "success"
        assert call_count == 3
    
    def test_retry_with_backoff_exhausted(self):
        """Test retry mechanism when attempts exhausted"""
        def always_failing():
            raise ValueError("Permanent failure")
        
        with pytest.raises(ValueError):
            retry_with_backoff(always_failing, max_attempts=2, backoff_factor=0.1)
    
    def test_calculate_entropy(self):
        """Test entropy calculation"""
        # High entropy (random)
        high_entropy = calculate_entropy("a1b2c3d4e5f6")
        assert high_entropy > 3.0
        
        # Low entropy (repetitive)
        low_entropy = calculate_entropy("aaaaaaaaaaaa")
        assert low_entropy < 1.0
    
    def test_generate_geolocation(self):
        """Test geolocation data generation"""
        geo = generate_geolocation()
        
        assert isinstance(geo, dict)
        assert "country" in geo
        assert "city" in geo
        assert "latitude" in geo
        assert "longitude" in geo
        assert -90 <= geo["latitude"] <= 90
        assert -180 <= geo["longitude"] <= 180
    
    def test_calculate_risk_score(self):
        """Test risk score calculation"""
        # High risk indicators
        high_risk_indicators = {
            "malicious_ip": True,
            "failed_logins": 10,
            "unusual_time": True,
            "privilege_escalation": True
        }
        score = calculate_risk_score(high_risk_indicators)
        assert score >= 70
        
        # Low risk indicators
        low_risk_indicators = {
            "malicious_ip": False,
            "failed_logins": 0,
            "unusual_time": False,
            "privilege_escalation": False
        }
        score = calculate_risk_score(low_risk_indicators)
        assert score <= 30


class TestIntegration:
    """Integration tests combining multiple utilities"""
    
    def test_complete_event_generation(self):
        """Test generating a complete security event"""
        event = {
            "timestamp": generate_timestamp(),
            "source_ip": generate_ip_address(private=True),
            "destination_ip": generate_ip_address(),
            "user": generate_email(),
            "event_id": generate_uuid(),
            "file_hash": generate_file_hash(),
            "user_agent": generate_user_agent(),
            "risk_score": calculate_risk_score({
                "malicious_ip": is_private_ip(generate_ip_address()),
                "failed_logins": random_int(0, 5)
            })
        }
        
        # Validate the event structure
        assert isinstance(event["timestamp"], str)
        assert isinstance(event["source_ip"], str)
        assert isinstance(event["destination_ip"], str)
        assert isinstance(event["user"], str)
        assert isinstance(event["event_id"], str)
        assert isinstance(event["file_hash"], str)
        assert isinstance(event["user_agent"], str)
        assert isinstance(event["risk_score"], (int, float))
        assert 0 <= event["risk_score"] <= 100
    
    def test_event_processing_pipeline(self):
        """Test complete event processing pipeline"""
        # Generate events
        events = []
        for _ in range(100):
            event = {
                "id": generate_uuid(),
                "timestamp": generate_timestamp(),
                "ip": generate_ip_address(),
                "data": f"Event with hash {generate_file_hash()}"
            }
            events.append(event)
        
        # Batch events
        batches = list(batch_events(events, batch_size=25))
        assert len(batches) == 4
        
        # Process each batch
        processed_batches = []
        for batch in batches:
            # Extract IOCs from batch
            all_text = " ".join([e["data"] for e in batch])
            iocs = extract_iocs(all_text)
            
            # Add IOCs to each event
            for event in batch:
                event["iocs"] = iocs
            
            processed_batches.append(batch)
        
        # Verify processing
        assert len(processed_batches) == 4
        for batch in processed_batches:
            for event in batch:
                assert "iocs" in event
                assert isinstance(event["iocs"], dict)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
