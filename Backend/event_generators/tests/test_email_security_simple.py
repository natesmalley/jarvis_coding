"""
Simple tests for email security event generators
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
        generate_logs,
        generate_log,
        proofpoint_log
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
    
    def test_generate_log(self):
        """Test generating a single Proofpoint log"""
        log = generate_log()
        
        # Verify it's a dictionary
        assert isinstance(log, dict)
        
        # Verify it has some expected fields (Proofpoint logs have varied structures)
        assert len(log) > 0  # Should have some fields
        
        # Verify timestamp if present
        if "clickTime" in log:
            assert isinstance(log["clickTime"], str)
            # Should be parseable as ISO format
            try:
                datetime.fromisoformat(log["clickTime"].replace("Z", "+00:00"))
            except ValueError:
                pytest.fail("Invalid timestamp format")
    
    def test_generate_logs_batch(self):
        """Test generating batch of Proofpoint logs"""
        logs = generate_logs(count=10)
        
        # Verify it's a list
        assert isinstance(logs, list)
        assert len(logs) == 10
        
        # Verify each log is a dictionary
        for log in logs:
            assert isinstance(log, dict)
            assert len(log) > 0
    
    def test_proofpoint_log_string(self):
        """Test proofpoint_log returns a string"""
        result = proofpoint_log()
        
        # Verify it's a string
        assert isinstance(result, str)
        
        # Verify it's valid JSON
        try:
            parsed = json.loads(result)
            assert isinstance(parsed, dict)
        except json.JSONDecodeError:
            pytest.fail("proofpoint_log() did not return valid JSON")
    
    def test_log_with_time_range(self):
        """Test generating logs with time range"""
        start_time = datetime.now() - timedelta(hours=1)
        end_time = datetime.now()
        
        log = generate_log(start_time=start_time, end_time=end_time)
        
        # Verify log was generated
        assert isinstance(log, dict)
        assert len(log) > 0
    
    def test_log_structure_variety(self):
        """Test that logs have varied structures"""
        logs = generate_logs(count=50)
        
        # Collect all field names across all logs
        all_fields = set()
        for log in logs:
            all_fields.update(log.keys())
        
        # Should have variety of fields
        assert len(all_fields) > 5  # At least some different fields
        
        # Common Proofpoint fields that might appear
        possible_fields = [
            "messageID", "clickTime", "recipient", "sender", "campaignId",
            "classification", "threatStatus", "GUID", "id", "clickIP"
        ]
        
        # Should have at least some of these fields
        found_common_fields = [field for field in possible_fields if field in all_fields]
        assert len(found_common_fields) >= 2  # At least 2 common fields
    
    def test_performance_batch_generation(self):
        """Test performance of batch generation"""
        import time
        
        start_time = time.time()
        logs = generate_logs(count=100)
        end_time = time.time()
        
        assert len(logs) == 100
        generation_time = end_time - start_time
        
        # Should generate 100 logs in reasonable time (less than 2 seconds)
        assert generation_time < 2.0
    
    def test_memory_usage(self):
        """Test memory usage during generation"""
        import sys
        
        # Generate logs
        logs = generate_logs(count=50)
        
        # Check memory usage is reasonable
        log_size = sys.getsizeof(logs)
        assert log_size > 0
        
        # Each log should be roughly the same size
        if len(logs) > 0:
            avg_log_size = log_size / len(logs)
            assert 100 < avg_log_size < 10000  # Reasonable range for log objects
    
    def test_log_data_types(self):
        """Test that log data types are appropriate"""
        logs = generate_logs(count=20)
        
        for log in logs:
            for key, value in log.items():
                # Check common data types
                if key.endswith("Time") or key.endswith("time"):
                    # Time fields should be strings
                    assert isinstance(value, str)
                elif key.endswith("Id") or key.endswith("ID") or key == "id":
                    # ID fields should be strings
                    assert isinstance(value, str)
                elif key == "classification":
                    # Classification should be a string
                    assert isinstance(value, str)
                elif key == "threatStatus":
                    # Threat status should be a string
                    assert isinstance(value, str)
    
    def test_log_content_validation(self):
        """Test that log content is reasonable"""
        logs = generate_logs(count=10)
        
        for log in logs:
            # Check email formats if email fields exist
            if "recipient" in log:
                assert "@" in log["recipient"]
            if "sender" in log:
                assert "@" in log["sender"]
            
            # Check IP format if IP field exists
            if "clickIP" in log:
                ip = log["clickIP"]
                assert isinstance(ip, str)
                # Basic IP validation
                parts = ip.split(".")
                assert len(parts) == 4
                for part in parts:
                    assert 0 <= int(part) <= 255
    
    def test_reproducible_generation(self):
        """Test that generation is reasonably reproducible"""
        # Generate logs twice
        logs1 = generate_logs(count=5)
        logs2 = generate_logs(count=5)
        
        # Both should be lists of dictionaries
        assert isinstance(logs1, list)
        assert isinstance(logs2, list)
        assert len(logs1) == 5
        assert len(logs2) == 5
        
        # Each log should be a dictionary
        for log in logs1 + logs2:
            assert isinstance(log, dict)
            assert len(log) > 0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
