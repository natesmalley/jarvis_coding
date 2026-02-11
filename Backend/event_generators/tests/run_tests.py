#!/usr/bin/env python3
"""
Simple test runner for event generators
"""
import sys
import os
import traceback

# Add the parent directory to the path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

def test_generator_utils():
    """Test generator utilities"""
    print("Testing generator_utils...")
    
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
            generate_token,
            now_utc,
            now_iso,
            now_epoch,
            generate_md5,
            generate_sha256,
            generate_mac_address
        )
        
        # Test UUID generation
        uuid_str = generate_uuid()
        assert isinstance(uuid_str, str)
        assert len(uuid_str) == 36
        assert "-" in uuid_str
        print("✓ generate_uuid")
        
        # Test UUID hex generation
        uuid_hex = generate_uuid_hex()
        assert isinstance(uuid_hex, str)
        assert len(uuid_hex) == 32
        assert "-" not in uuid_hex
        print("✓ generate_uuid_hex")
        
        # Test IP generation
        ip = generate_ip()
        assert isinstance(ip, str)
        parts = ip.split(".")
        assert len(parts) == 4
        for part in parts:
            assert 0 <= int(part) <= 255
        print("✓ generate_ip")
        
        # Test private IP generation
        private_ip = generate_private_ip()
        assert isinstance(private_ip, str)
        parts = private_ip.split(".")
        assert parts[0] == "10"
        print("✓ generate_private_ip")
        
        # Test email generation
        email = generate_email()
        assert isinstance(email, str)
        assert "@" in email
        assert email.endswith("@example.com")
        print("✓ generate_email")
        
        # Test hostname generation
        hostname = generate_hostname()
        assert isinstance(hostname, str)
        assert "-" in hostname
        assert "." in hostname
        print("✓ generate_hostname")
        
        # Test country code generation
        country = generate_country_code()
        assert isinstance(country, str)
        assert len(country) == 2
        assert country.isupper()
        print("✓ generate_country_code")
        
        # Test city generation
        city = generate_city()
        assert isinstance(city, str)
        assert len(city) > 0
        print("✓ generate_city")
        
        # Test user agent generation
        ua = generate_user_agent()
        assert isinstance(ua, str)
        assert any(browser in ua for browser in ["Mozilla", "Chrome", "Safari", "Firefox"])
        print("✓ generate_user_agent")
        
        # Test token generation
        token = generate_token()
        assert isinstance(token, str)
        # Token length varies, just check it's reasonable
        assert 16 <= len(token) <= 64
        print("✓ generate_token")
        
        # Test time functions
        now = now_utc()
        assert now is not None
        print("✓ now_utc")
        
        iso = now_iso()
        assert isinstance(iso, str)
        assert "T" in iso
        print("✓ now_iso")
        
        epoch = now_epoch()
        assert isinstance(epoch, int)
        print("✓ now_epoch")
        
        # Test hash generation
        md5 = generate_md5()
        assert isinstance(md5, str)
        assert len(md5) == 32
        print("✓ generate_md5")
        
        sha256 = generate_sha256()
        assert isinstance(sha256, str)
        assert len(sha256) == 64
        print("✓ generate_sha256")
        
        # Test MAC address generation
        mac = generate_mac_address()
        assert isinstance(mac, str)
        assert mac.count(":") == 5
        print("✓ generate_mac_address")
        
        return True
        
    except Exception as e:
        print(f"✗ generator_utils test failed: {e}")
        traceback.print_exc()
        return False

def test_proofpoint_tap():
    """Test Proofpoint TAP generator"""
    print("Testing proofpoint_tap...")
    
    try:
        from email_security.proofpoint_tap import (
            generate_logs,
            generate_log,
            proofpoint_log
        )
        
        # Test single log generation
        log = generate_log()
        assert isinstance(log, dict)
        assert len(log) > 0
        print("✓ generate_log")
        
        # Test batch log generation
        logs = generate_logs(count=5)
        assert isinstance(logs, list)
        assert len(logs) == 5
        for log in logs:
            assert isinstance(log, dict)
        print("✓ generate_logs")
        
        # Test string log generation
        result = proofpoint_log()
        assert isinstance(result, str)
        # Should be valid JSON
        import json
        parsed = json.loads(result)
        assert isinstance(parsed, dict)
        print("✓ proofpoint_log")
        
        return True
        
    except Exception as e:
        print(f"✗ proofpoint_tap test failed: {e}")
        traceback.print_exc()
        return False

def main():
    """Run all tests"""
    print("Running Event Generator Tests")
    print("=" * 40)
    
    tests = [
        test_generator_utils,
        test_proofpoint_tap
    ]
    
    passed = 0
    failed = 0
    
    for test in tests:
        try:
            if test():
                passed += 1
            else:
                failed += 1
        except Exception as e:
            print(f"✗ {test.__name__} crashed: {e}")
            failed += 1
        print()
    
    print("=" * 40)
    print(f"Results: {passed} passed, {failed} failed")
    
    if failed == 0:
        print("All tests passed! ✓")
        return 0
    else:
        print("Some tests failed! ✗")
        return 1

if __name__ == "__main__":
    sys.exit(main())
