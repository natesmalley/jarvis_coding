# Event Generator Tests

This directory contains comprehensive test suites for the event generators in the HELIOS project.

## Test Structure

### Test Files

- **`test_generator_utils.py`** - Tests for shared utility functions used across all generators
- **`test_email_security.py`** - Tests for email security event generators (Proofpoint TAP)
- **`test_network_security.py`** - Tests for network security event generators (Darktrace, Vectra)
- **`test_identity_access.py`** - Tests for identity and access management generators (Okta)
- **`test_cloud_infrastructure.py`** - Tests for cloud infrastructure security generators (Wiz)
- **`conftest.py`** - Pytest configuration and shared fixtures

### Test Categories

#### Unit Tests
- Test individual functions and methods
- Validate data structures and formats
- Check edge cases and error conditions

#### Integration Tests
- Test complete workflows
- Validate event correlation
- Test cross-generator compatibility

#### Performance Tests
- Measure generation speed
- Test memory usage
- Validate batch processing

#### Validation Tests
- Schema compliance
- Data format validation
- Security context validation

## Running Tests

### Basic Test Execution

```bash
# Run all tests
cd Backend
python -m pytest event_generators/tests/ -v

# Run specific test file
python -m pytest event_generators/tests/test_generator_utils.py -v

# Run specific test function
python -m pytest event_generators/tests/test_generator_utils.py::TestTimestampGeneration::test_generate_timestamp_default -v
```

### With Coverage

```bash
# Run tests with coverage report
python -m pytest event_generators/tests/ --cov=event_generators --cov-report=term --cov-report=html

# Generate XML coverage report for CI
python -m pytest event_generators/tests/ --cov=event_generators --cov-report=xml:coverage.xml
```

### Performance Tests

```bash
# Run only performance tests
python -m pytest event_generators/tests/ -m performance -v

# Run with performance threshold
python -m pytest event_generators/tests/ -m performance --benchmark-only
```

### Integration Tests

```bash
# Run only integration tests
python -m pytest event_generators/tests/ -m integration -v
```

## Test Fixtures

The `conftest.py` file provides shared fixtures for consistent testing:

### Data Fixtures
- `mock_timestamp` - Consistent timestamp for testing
- `mock_uuid` - Predictable UUID generation
- `sample_ip` - Sample IP address
- `sample_email` - Sample email address
- `sample_domain` - Sample domain name

### Event Structure Fixtures
- `sample_event_structure` - Generic event template
- `sample_network_event` - Network security event template
- `sample_auth_event` - Authentication event template
- `sample_cloud_event` - Cloud security event template
- `sample_email_event` - Email security event template

### Configuration Fixtures
- `performance_threshold` - Performance timing threshold
- `batch_sizes` - Common batch sizes for testing
- `severity_levels` - Standard severity levels
- `cloud_providers` - Major cloud providers

## Test Coverage Areas

### Generator Utils
- Timestamp generation and parsing
- Network address generation (IP, MAC)
- Data generation (UUID, email, domain, hashes)
- Data processing and validation
- File operations
- Advanced utilities (retry, entropy, geolocation)

### Email Security
- Proofpoint TAP event generation
- Email delivery and blocking events
- Phishing and malware detection
- Spam filtering
- DMARC validation
- Threat intelligence fields

### Network Security
- Darktrace breach detection
- Vectra security analytics
- Anomalous connection detection
- Data exfiltration events
- Lateral movement detection
- Command and control communications

### Identity and Access
- Okta system log events
- Authentication and authorization
- MFA challenges
- Privilege escalation
- Account lockouts
- Security context validation

### Cloud Infrastructure
- Wiz security issue detection
- Vulnerability alerts
- Cloud misconfigurations
- IAM risk assessment
- Data exposure risks
- Multi-cloud security posture

## Test Data and Mocking

### Predictable Testing
- Fixed seeds for random generation
- Mocked datetime for consistent timestamps
- Predictable UUID generation
- Controlled random choices

### Realistic Data
- Valid IP addresses and network data
- Proper email formats and domains
- Realistic security event structures
- Compliance with actual product schemas

## Performance Benchmarks

### Generation Speed
- Small batches (1-10 events): < 0.1 seconds
- Medium batches (50-100 events): < 1 second
- Large batches (500-1000 events): < 5 seconds

### Memory Usage
- Average event size: 1-10 KB
- Batch processing efficiency
- No memory leaks in generation loops

## CI/CD Integration

### GitHub Actions
The tests are integrated with GitHub Actions workflow:

```yaml
- name: Run unit tests
  run: |
    cd Backend
    python -m pytest event_generators/tests/ -v --tb=short

- name: Run tests with coverage
  run: |
    cd Backend
    python -m pytest event_generators/tests/ \
      --cov=event_generators \
      --cov-report=term \
      --cov-report=xml:coverage.xml \
      -v
```

### Coverage Requirements
- Minimum coverage: 80%
- Critical functions: 95%
- Event generators: 85%

## Adding New Tests

### Test Naming Convention
- Test files: `test_<module_name>.py`
- Test classes: `Test<ClassName>`
- Test functions: `test_<function_description>`

### Test Structure
```python
class TestNewGenerator:
    """Test new event generator"""
    
    def test_generate_basic_event(self):
        """Test basic event generation"""
        event = generate_new_event()
        assert "required_field" in event
        assert event["type"] == "expected_type"
    
    def test_event_validation(self):
        """Test event schema validation"""
        event = generate_new_event()
        assert validate_schema(event)
```

### Fixtures Usage
```python
def test_with_fixtures(mock_timestamp, sample_ip):
    """Test using shared fixtures"""
    event = generate_event(timestamp=mock_timestamp, ip=sample_ip)
    assert event["timestamp"] == mock_timestamp
    assert event["ip"] == sample_ip
```

## Troubleshooting

### Common Issues

1. **Import Errors**
   - Ensure `shared.generator_utils` is accessible
   - Check Python path configuration
   - Verify module installation

2. **Test Failures**
   - Check for missing dependencies
   - Verify generator function signatures
   - Validate expected data formats

3. **Performance Issues**
   - Check test environment resources
   - Verify batch size parameters
   - Monitor memory usage

### Debug Mode
```bash
# Run with verbose output
python -m pytest event_generators/tests/ -v -s

# Run with debugging
python -m pytest event_generators/tests/ -v --pdb

# Stop on first failure
python -m pytest event_generators/tests/ -x -v
```

## Best Practices

### Test Design
- Write independent tests
- Use descriptive test names
- Test both success and failure cases
- Validate edge cases

### Data Management
- Use fixtures for consistent data
- Mock external dependencies
- Validate data formats and schemas

### Performance
- Set reasonable time limits
- Test with various batch sizes
- Monitor memory consumption

### Maintenance
- Keep tests up to date with generators
- Add tests for new features
- Regular review and refactoring
