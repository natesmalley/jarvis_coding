"""
Pytest configuration and fixtures for event generator tests
"""
import pytest
import sys
import os
from datetime import datetime
from unittest.mock import MagicMock

# Add the parent directory to the path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


@pytest.fixture
def mock_timestamp():
    """Provide a consistent timestamp for testing"""
    return "2024-01-15T10:30:45Z"


@pytest.fixture
def mock_uuid():
    """Provide a consistent UUID for testing"""
    return "550e8400-e29b-41d4-a716-446655440000"


@pytest.fixture
def sample_ip():
    """Provide a sample IP address for testing"""
    return "192.168.1.100"


@pytest.fixture
def sample_email():
    """Provide a sample email for testing"""
    return "test.user@example.com"


@pytest.fixture
def sample_domain():
    """Provide a sample domain for testing"""
    return "example.com"


@pytest.fixture
def sample_mac():
    """Provide a sample MAC address for testing"""
    return "00:1A:2B:3C:4D:5E"


@pytest.fixture
def sample_user_agent():
    """Provide a sample user agent for testing"""
    return "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"


@pytest.fixture
def sample_file_hash():
    """Provide a sample file hash for testing"""
    return "a1b2c3d4e5f6789012345678901234567890abcd"


@pytest.fixture
def mock_datetime(monkeypatch):
    """Mock datetime for consistent testing"""
    mock_dt = MagicMock()
    mock_dt.now.return_value = datetime(2024, 1, 15, 10, 30, 45)
    mock_dt.side_effect = lambda *args, **kw: datetime
    
    monkeypatch.setattr("datetime.datetime", mock_dt)
    return mock_dt


@pytest.fixture
def mock_random(monkeypatch):
    """Mock random functions for predictable testing"""
    import random
    
    # Set a fixed seed for reproducible tests
    random.seed(42)
    
    # Mock specific random functions if needed
    mock_choice = MagicMock(side_effect=lambda x: x[0] if x else None)
    mock_randint = MagicMock(side_effect=lambda a, b: a)
    mock_uniform = MagicMock(side_effect=lambda a, b: a)
    
    monkeypatch.setattr("random.choice", mock_choice)
    monkeypatch.setattr("random.randint", mock_randint)
    monkeypatch.setattr("random.uniform", mock_uniform)
    
    return {
        "choice": mock_choice,
        "randint": mock_randint,
        "uniform": mock_uniform
    }


@pytest.fixture
def mock_crypto(monkeypatch):
    """Mock crypto functions for predictable UUID generation"""
    mock_uuid = MagicMock()
    mock_uuid.return_value = "550e8400-e29b-41d4-a716-446655440000"
    
    monkeypatch.setattr("uuid.uuid4", mock_uuid)
    return mock_uuid


@pytest.fixture
def sample_event_structure():
    """Provide a sample event structure for validation"""
    return {
        "id": "test-event-123",
        "timestamp": "2024-01-15T10:30:45Z",
        "source": "test-generator",
        "type": "test-event",
        "severity": "medium",
        "data": {
            "field1": "value1",
            "field2": "value2"
        }
    }


@pytest.fixture
def sample_network_event():
    """Provide a sample network event structure"""
    return {
        "eventId": "network-event-123",
        "timestamp": "2024-01-15T10:30:45Z",
        "eventType": "connection",
        "sourceIp": "192.168.1.100",
        "destIp": "10.0.0.50",
        "destPort": 443,
        "protocol": "TCP",
        "bytesTransferred": 1024,
        "duration": 5.5
    }


@pytest.fixture
def sample_auth_event():
    """Provide a sample authentication event structure"""
    return {
        "eventId": "auth-event-123",
        "timestamp": "2024-01-15T10:30:45Z",
        "eventType": "user.session.start",
        "actor": {
            "type": "User",
            "id": "user123",
            "alternateId": "test.user@example.com",
            "displayName": "Test User"
        },
        "target": {
            "type": "User",
            "id": "user123",
            "alternateId": "test.user@example.com"
        },
        "outcome": {
            "result": "SUCCESS"
        },
        "client": {
            "ip": "192.168.1.100",
            "userAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
        }
    }


@pytest.fixture
def sample_cloud_event():
    """Provide a sample cloud security event structure"""
    return {
        "issueId": "cloud-issue-123",
        "timestamp": "2024-01-15T10:30:45Z",
        "issueType": "misconfiguration",
        "severity": "high",
        "status": "open",
        "resource": {
            "id": "resource-123",
            "type": "EC2",
            "name": "test-instance",
            "provider": "AWS",
            "region": "us-east-1"
        },
        "description": "Test misconfiguration",
        "recommendation": "Fix the configuration"
    }


@pytest.fixture
def sample_email_event():
    """Provide a sample email security event structure"""
    return {
        "messageId": "email-msg-123",
        "timestamp": "2024-01-15T10:30:45Z",
        "sender": "attacker@evil.com",
        "recipients": ["victim@example.com"],
        "subject": "Test Phishing Email",
        "status": "blocked",
        "blockReason": "phishing",
        "threatInfo": {
            "threatType": "phishing",
            "confidence": 85
        }
    }


@pytest.fixture
def performance_threshold():
    """Performance threshold for tests (in seconds)"""
    return 5.0


@pytest.fixture
def batch_sizes():
    """Common batch sizes for testing"""
    return [1, 10, 50, 100, 500, 1000]


@pytest.fixture
def severity_levels():
    """Common severity levels for testing"""
    return ["critical", "high", "medium", "low", "info"]


@pytest.fixture
def event_types():
    """Common event types for testing"""
    return [
        "authentication",
        "authorization",
        "network",
        "malware",
        "phishing",
        "data_access",
        "privilege_escalation",
        "configuration_change"
    ]


@pytest.fixture
def cloud_providers():
    """Common cloud providers for testing"""
    return ["AWS", "Azure", "GCP", "OCI"]


@pytest.fixture
def protocols():
    """Common network protocols for testing"""
    return ["TCP", "UDP", "ICMP", "HTTP", "HTTPS", "DNS"]


@pytest.fixture
def auth_methods():
    """Common authentication methods for testing"""
    return [
        "password",
        "mfa_push",
        "mfa_totp",
        "mfa_sms",
        "saml",
        "oidc",
        "social"
    ]


@pytest.fixture
def compliance_frameworks():
    """Common compliance frameworks for testing"""
    return [
        "CIS",
        "NIST",
        "ISO27001",
        "SOC2",
        "PCI-DSS",
        "HIPAA",
        "GDPR"
    ]


@pytest.fixture
def mock_filesystem(tmp_path):
    """Provide a temporary filesystem for testing file operations"""
    return tmp_path


@pytest.fixture
def sample_json_data():
    """Sample JSON data for testing"""
    return {
        "events": [
            {
                "id": "1",
                "type": "login",
                "user": "alice",
                "timestamp": "2024-01-15T10:00:00Z"
            },
            {
                "id": "2",
                "type": "logout",
                "user": "alice",
                "timestamp": "2024-01-15T11:00:00Z"
            }
        ],
        "metadata": {
            "total": 2,
            "source": "test"
        }
    }


# Custom markers for categorizing tests
pytest_plugins = []

def pytest_configure(config):
    """Configure custom pytest markers"""
    config.addinivalue_line(
        "markers", "unit: Mark test as a unit test"
    )
    config.addinivalue_line(
        "markers", "integration: Mark test as an integration test"
    )
    config.addinivalue_line(
        "markers", "performance: Mark test as a performance test"
    )
    config.addinivalue_line(
        "markers", "slow: Mark test as slow running"
    )
    config.addinivalue_line(
        "markers", "network: Mark test as requiring network access"
    )


def pytest_collection_modifyitems(config, items):
    """Modify test collection to add markers automatically"""
    for item in items:
        # Add markers based on test names
        if "performance" in item.nodeid.lower():
            item.add_marker(pytest.mark.performance)
        if "integration" in item.nodeid.lower():
            item.add_marker(pytest.mark.integration)
        if "slow" in item.nodeid.lower():
            item.add_marker(pytest.mark.slow)
        if "network" in item.nodeid.lower():
            item.add_marker(pytest.mark.network)
