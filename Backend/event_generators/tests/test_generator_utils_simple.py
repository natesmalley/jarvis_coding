"""
Simple tests for generator utilities
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
    from shared.generator_utils import (
        generate_uuid,
        generate_uuid_hex,
        generate_ip,
        generate_private_ip,
        generate_email,
        generate_hostname,
        generate_country_code,
        generate_city,
        generate_user_agent,
        random_timestamp_between,
        random_timestamp_epoch,
        random_iso_timestamp,
        weighted_choice,
        weighted_choice_from_dict,
        generate_token,
        get_time_range,
        now_utc,
        now_iso,
        now_epoch,
        generate_md5,
        generate_sha256,
        generate_mac_address
    )
except ImportError as e:
    pytest.skip(f"Cannot import generator_utils: {e}", allow_module_level=True)


class TestGeneratorUtils:
    """Test generator utility functions"""
    
    def test_generate_uuid(self):
        """Test UUID generation"""
        uuid_str = generate_uuid()
        
        # Verify it's a string
        assert isinstance(uuid_str, str)
        
        # Verify UUID format (should have dashes)
        assert "-" in uuid_str
        assert len(uuid_str) == 36  # Standard UUID length with dashes
        
        # Generate another UUID and verify they're different
        uuid2 = generate_uuid()
        assert uuid_str != uuid2
    
    def test_generate_uuid_hex(self):
        """Test UUID hex generation"""
        uuid_hex = generate_uuid_hex()
        
        # Verify it's a string
        assert isinstance(uuid_hex, str)
        
        # Verify hex format (no dashes)
        assert "-" not in uuid_hex
        assert len(uuid_hex) == 32  # Standard UUID length without dashes
        
        # Verify it's all hex characters
        try:
            int(uuid_hex, 16)
        except ValueError:
            pytest.fail("UUID hex is not valid hexadecimal")
    
    def test_generate_ip(self):
        """Test IP address generation"""
        ip = generate_ip()
        
        # Verify it's a string
        assert isinstance(ip, str)
        
        # Verify IP format
        parts = ip.split(".")
        assert len(parts) == 4
        
        for part in parts:
            assert 0 <= int(part) <= 255
        
        # Verify first octet is not 0 or 255
        assert 1 <= int(parts[0]) <= 254
        # Verify last octet is not 0 or 255
        assert 1 <= int(parts[3]) <= 254
    
    def test_generate_private_ip(self):
        """Test private IP address generation"""
        ip = generate_private_ip()
        
        # Verify it's a string
        assert isinstance(ip, str)
        
        # Verify IP format
        parts = ip.split(".")
        assert len(parts) == 4
        
        # Verify it's in 10.x.x.x range
        assert parts[0] == "10"
        
        for part in parts:
            assert 0 <= int(part) <= 255
    
    def test_generate_email(self):
        """Test email generation"""
        email = generate_email()
        
        # Verify it's a string
        assert isinstance(email, str)
        
        # Verify email format
        assert "@" in email
        assert email.endswith("@example.com")  # Default domain
        
        # Verify username part
        username = email.split("@")[0]
        assert len(username) == 8
        assert username.islower()
        assert username.isalpha()
        
        # Test custom domain
        custom_email = generate_email(domain="custom.org")
        assert custom_email.endswith("@custom.org")
    
    def test_generate_hostname(self):
        """Test hostname generation"""
        hostname = generate_hostname()
        
        # Verify it's a string
        assert isinstance(hostname, str)
        
        # Verify hostname format
        assert "-" in hostname
        assert "." in hostname
        
        parts = hostname.split(".")
        assert len(parts) == 2
        
        prefix_parts = parts[0].split("-")
        assert len(prefix_parts) == 2
        
        # Verify prefix starts with known prefix
        valid_prefixes = ["web", "api", "app", "srv", "host", "node"]
        assert prefix_parts[0] in valid_prefixes
    
    def test_generate_country_code(self):
        """Test country code generation"""
        country = generate_country_code()
        
        # Verify it's a string
        assert isinstance(country, str)
        
        # Verify it's 2 characters
        assert len(country) == 2
        
        # Verify it's uppercase
        assert country.isupper()
        
        # Verify it's a known country code
        valid_countries = ["US", "GB", "DE", "FR", "JP", "AU", "CA", "IN", "BR", "CN", "RU", "KR"]
        assert country in valid_countries
    
    def test_generate_city(self):
        """Test city generation"""
        city = generate_city()
        
        # Verify it's a string
        assert isinstance(city, str)
        
        # Verify it's a known city
        valid_cities = [
            "New York", "San Francisco", "Chicago", "Austin", "Denver",
            "Seattle", "Boston", "Miami", "Los Angeles", "Portland"
        ]
        assert city in valid_cities
    
    def test_generate_user_agent(self):
        """Test user agent generation"""
        ua = generate_user_agent()
        
        # Verify it's a string
        assert isinstance(ua, str)
        
        # Verify it contains browser identifiers
        assert any(browser in ua for browser in ["Mozilla", "Chrome", "Safari", "Firefox"])
    
    def test_random_timestamp_between(self):
        """Test random timestamp generation between dates"""
        start = datetime(2024, 1, 1)
        end = datetime(2024, 1, 2)
        
        timestamp = random_timestamp_between(start, end)
        
        # Verify it's a datetime
        assert isinstance(timestamp, datetime)
        
        # Verify it's within range
        assert start <= timestamp <= end
    
    def test_random_timestamp_epoch(self):
        """Test random epoch timestamp generation"""
        start_epoch = 1704067200  # 2024-01-01 00:00:00 UTC
        end_epoch = 1704153600    # 2024-01-02 00:00:00 UTC
        
        epoch = random_timestamp_epoch(start_epoch, end_epoch)
        
        # Verify it's an integer
        assert isinstance(epoch, int)
        
        # Verify it's within range
        assert start_epoch <= epoch <= end_epoch
    
    def test_random_iso_timestamp(self):
        """Test random ISO timestamp generation"""
        start = datetime(2024, 1, 1)
        end = datetime(2024, 1, 2)
        
        iso_ts = random_iso_timestamp(start, end)
        
        # Verify it's a string
        assert isinstance(iso_ts, str)
        
        # Verify ISO format
        assert "T" in iso_ts
        assert iso_ts.endswith("000Z")
        
        # Verify it's parseable
        parsed = datetime.strptime(iso_ts, "%Y-%m-%dT%H:%M:%S.000Z")
        assert start <= parsed <= end
    
    def test_weighted_choice(self):
        """Test weighted choice selection"""
        items = {
            "a": ("value_a", 0.1),
            "b": ("value_b", 0.8),
            "c": ("value_c", 0.1)
        }
        
        result = weighted_choice(items)
        
        # Verify result is one of the values
        assert result in ["value_a", "value_b", "value_c"]
    
    def test_weighted_choice_from_dict(self):
        """Test weighted choice from dictionary"""
        templates = {
            "type1": {"field": "value1"},
            "type2": {"field": "value2"},
            "type3": {"field": "value3"}
        }
        weights = {
            "type1": 0.1,
            "type2": 0.8,
            "type3": 0.1
        }
        
        result = weighted_choice_from_dict(templates, weights)
        
        # Verify result is one of the templates
        assert result in templates.values()
    
    def test_generate_token(self):
        """Test token generation"""
        token = generate_token()
        
        # Verify it's a string
        assert isinstance(token, str)
        
        # Verify default length (32 chars = 16 bytes in hex)
        assert len(token) == 32
        
        # Verify it's hex characters
        try:
            int(token, 16)
        except ValueError:
            pytest.fail("Token is not valid hexadecimal")
        
        # Test custom length
        custom_token = generate_token(length=16)
        assert len(custom_token) == 16
    
    def test_get_time_range(self):
        """Test time range generation"""
        # Test with no parameters (default range)
        start, end = get_time_range()
        
        assert isinstance(start, datetime)
        assert isinstance(end, datetime)
        assert start < end
        
        # Test with custom range
        start, end = get_time_range(default_range_minutes=60)
        duration = end - start
        assert duration.total_seconds() == 3600  # 60 minutes
    
    def test_now_utc(self):
        """Test current UTC time"""
        now = now_utc()
        
        # Verify it's a datetime
        assert isinstance(now, datetime)
        
        # Verify it's recent (within 1 second)
        import time
        assert abs((datetime.now(timezone.utc) - now).total_seconds()) < 1.0
    
    def test_now_iso(self):
        """Test current ISO time"""
        iso = now_iso()
        
        # Verify it's a string
        assert isinstance(iso, str)
        
        # Verify ISO format
        assert "T" in iso
        assert iso.endswith("Z")
        
        # Verify it's parseable
        datetime.fromisoformat(iso.replace("Z", "+00:00"))
    
    def test_now_epoch(self):
        """Test current epoch time"""
        epoch = now_epoch()
        
        # Verify it's an integer
        assert isinstance(epoch, int)
        
        # Verify it's recent (within 1 second)
        import time
        assert abs(epoch - time.time()) < 1.0
    
    def test_generate_md5(self):
        """Test MD5 hash generation"""
        md5 = generate_md5()
        
        # Verify it's a string
        assert isinstance(md5, str)
        
        # Verify MD5 length (32 hex chars)
        assert len(md5) == 32
        
        # Verify it's hex characters
        try:
            int(md5, 16)
        except ValueError:
            pytest.fail("MD5 is not valid hexadecimal")
    
    def test_generate_sha256(self):
        """Test SHA256 hash generation"""
        sha256 = generate_sha256()
        
        # Verify it's a string
        assert isinstance(sha256, str)
        
        # Verify SHA256 length (64 hex chars)
        assert len(sha256) == 64
        
        # Verify it's hex characters
        try:
            int(sha256, 16)
        except ValueError:
            pytest.fail("SHA256 is not valid hexadecimal")
    
    def test_generate_mac_address(self):
        """Test MAC address generation"""
        mac = generate_mac_address()
        
        # Verify it's a string
        assert isinstance(mac, str)
        
        # Verify MAC format
        assert mac.count(":") == 5  # 6 parts separated by :
        parts = mac.split(":")
        
        for part in parts:
            # Verify each part is 2 hex characters
            assert len(part) == 2
            try:
                int(part, 16)
            except ValueError:
                pytest.fail(f"MAC part '{part}' is not valid hexadecimal")
            assert 0 <= int(part, 16) <= 255
    
    def test_uniqueness(self):
        """Test that generated values are unique"""
        # Generate multiple values
        uuids = [generate_uuid() for _ in range(10)]
        ips = [generate_ip() for _ in range(10)]
        emails = [generate_email() for _ in range(10)]
        
        # Verify uniqueness
        assert len(set(uuids)) == len(uuids)
        assert len(set(ips)) == len(ips)
        assert len(set(emails)) == len(emails)
    
    def test_performance_batch_generation(self):
        """Test performance of batch generation"""
        import time
        
        start_time = time.time()
        
        # Generate various types
        for _ in range(100):
            generate_uuid()
            generate_ip()
            generate_email()
            generate_mac_address()
        
        end_time = time.time()
        generation_time = end_time - start_time
        
        # Should generate 400 values in reasonable time
        assert generation_time < 1.0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
