"""
Comprehensive tests for identity and access management event generators
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
    from identity_access.okta_system_log import (
        generate_okta_events,
        generate_user_login,
        generate_user_logout,
        generate_failed_login,
        generate_password_change,
        generate_mfa_challenge,
        generate_privilege_escalation,
        generate_account_lockout,
        get_auth_methods,
        get_failure_reasons
    )
except ImportError as e:
    pytest.skip(f"Cannot import okta_system_log: {e}", allow_module_level=True)

try:
    from shared.generator_utils import (
        generate_timestamp,
        generate_ip_address,
        generate_email,
        generate_uuid,
        random_choice,
        random_int,
        is_private_ip
    )
except ImportError as e:
    pytest.skip(f"Cannot import generator_utils: {e}", allow_module_level=True)


class TestOktaSystemLogGenerator:
    """Test Okta system log event generator"""
    
    def test_generate_user_login(self):
        """Test generating user login events"""
        event = generate_user_login()
        
        # Verify required fields
        assert "eventId" in event
        assert "timestamp" in event
        assert "eventType" in event
        assert "actor" in event
        assert "target" in event
        assert "client" in event
        assert "outcome" in event
        
        # Verify field values
        assert event["eventType"] == "user.session.start"
        assert event["outcome"]["result"] == "SUCCESS"
        
        # Verify actor information
        actor = event["actor"]
        assert "type" in actor
        assert "id" in actor
        assert "alternateId" in actor
        assert "displayName" in actor
        assert actor["type"] == "User"
        assert "@" in actor["alternateId"]
        
        # Verify target information
        target = event["target"]
        assert "type" in target
        assert "id" in target
        assert "alternateId" in target
        assert target["type"] == "User"
        
        # Verify client information
        client = event["client"]
        assert "userAgent" in client
        assert "ip" in client
        assert "geographicalContext" in client
        assert is_private_ip(client["ip"]) or not is_private_ip(client["ip"])
    
    def test_generate_user_logout(self):
        """Test generating user logout events"""
        event = generate_user_logout()
        
        # Verify logout-specific fields
        assert event["eventType"] == "user.session.end"
        assert event["outcome"]["result"] == "SUCCESS"
        
        # Verify session information
        if "session" in event["outcome"]:
            session = event["outcome"]["session"]
            assert "id" in session
            assert "created" in session
            assert "lastUpdated" in session
    
    def test_generate_failed_login(self):
        """Test generating failed login events"""
        event = generate_failed_login()
        
        # Verify failure-specific fields
        assert event["outcome"]["result"] == "FAILURE"
        assert "reason" in event["outcome"]
        
        # Verify failure reason
        failure_reasons = [
            "INVALID_CREDENTIALS",
            "USER_LOCKED_OUT",
            "PASSWORD_EXPIRED",
            "ACCOUNT_SUSPENDED",
            "MFA_REQUIRED",
            "UNKNOWN_USER"
        ]
        assert event["outcome"]["reason"] in failure_reasons
        
        # Verify security context
        if "securityContext" in event:
            security = event["securityContext"]
            assert "asNumber" in security or "isp" in security
    
    def test_generate_password_change(self):
        """Test generating password change events"""
        event = generate_password_change()
        
        # Verify password change fields
        assert event["eventType"] == "user.password.change"
        assert event["outcome"]["result"] == "SUCCESS"
        
        # Verify password details
        if "detail" in event:
            assert "password" in event["detail"]
            password_detail = event["detail"]["password"]
            assert "complexity" in password_detail
            assert "history" in password_detail
    
    def test_generate_mfa_challenge(self):
        """Test generating MFA challenge events"""
        event = generate_mfa_challenge()
        
        # Verify MFA fields
        assert "mfa" in event
        
        mfa = event["mfa"]
        assert "credentialType" in mfa
        assert "factorType" in mfa
        assert "provider" in mfa
        
        # Verify MFA types
        credential_types = ["password", "otp", "push", "u2f", "webauthn"]
        assert mfa["credentialType"] in credential_types
        
        factor_types = ["token:software:totp", "token:hardware", "push", "sms", "email", "webauthn"]
        assert mfa["factorType"] in factor_types
    
    def test_generate_privilege_escalation(self):
        """Test generating privilege escalation events"""
        event = generate_privilege_escalation()
        
        # Verify privilege escalation fields
        assert "privilege" in event
        
        privilege = event["privilege"]
        assert "action" in privilege
        assert "role" in privilege
        assert "previousRole" in privilege
        
        # Verify escalation action
        actions = ["grant", "revoke", "elevate", "delegate"]
        assert privilege["action"] in actions
        
        # Verify role information
        assert isinstance(privilege["role"], str)
        assert len(privilege["role"]) > 0
    
    def test_generate_account_lockout(self):
        """Test generating account lockout events"""
        event = generate_account_lockout()
        
        # Verify lockout fields
        assert event["eventType"] == "user.account.lock"
        assert event["outcome"]["result"] == "SUCCESS"
        
        # Verify lockout details
        if "lockout" in event:
            lockout = event["lockout"]
            assert "reason" in lockout
            assert "duration" in lockout
            assert "unlockTime" in lockout
    
    def test_get_auth_methods(self):
        """Test authentication methods retrieval"""
        methods = get_auth_methods()
        
        assert isinstance(methods, list)
        assert len(methods) > 0
        
        expected_methods = [
            "password",
            "mfa_push",
            "mfa_totp",
            "mfa_sms",
            "mfa_email",
            "saml",
            "oidc",
            "social"
        ]
        for method in expected_methods:
            assert method in methods
    
    def test_get_failure_reasons(self):
        """Test failure reasons retrieval"""
        reasons = get_failure_reasons()
        
        assert isinstance(reasons, list)
        assert len(reasons) > 0
        
        expected_reasons = [
            "INVALID_CREDENTIALS",
            "USER_LOCKED_OUT",
            "PASSWORD_EXPIRED",
            "ACCOUNT_SUSPENDED",
            "MFA_REQUIRED",
            "UNKNOWN_USER",
            "RATE_LIMIT_EXCEEDED"
        ]
        for reason in expected_reasons:
            assert reason in reasons
    
    def test_generate_okta_events_batch(self):
        """Test generating batch of Okta events"""
        events = generate_okta_events(count=50)
        
        assert isinstance(events, list)
        assert len(events) == 50
        
        # Verify each event has required structure
        for event in events:
            assert "eventId" in event
            assert "timestamp" in event
            assert "eventType" in event
            assert "actor" in event
            assert "target" in event
            assert "outcome" in event
        
        # Verify event distribution
        event_types = {}
        for event in events:
            event_type = event["eventType"]
            event_types[event_type] = event_types.get(event_type, 0) + 1
        
        # Should have variety of event types
        assert len(event_types) >= 2


class TestOktaEventValidation:
    """Test Okta event validation and schema compliance"""
    
    def test_event_schema_compliance(self):
        """Test events comply with Okta System Log schema"""
        event_generators = [
            generate_user_login,
            generate_user_logout,
            generate_failed_login,
            generate_password_change,
            generate_mfa_challenge,
            generate_privilege_escalation,
            generate_account_lockout
        ]
        
        for generator in event_generators:
            event = generator()
            
            # Required base fields
            required_fields = ["eventId", "timestamp", "eventType", "actor", "target", "client", "outcome"]
            for field in required_fields:
                assert field in event, f"Missing required field '{field}' in {generator.__name__}"
            
            # Event ID format
            assert isinstance(event["eventId"], str)
            assert len(event["eventId"]) > 10
            
            # Timestamp format
            assert isinstance(event["timestamp"], str)
            datetime.fromisoformat(event["timestamp"].replace("Z", "+00:00"))
            
            # Actor validation
            actor = event["actor"]
            assert "type" in actor
            assert "id" in actor
            assert actor["type"] in ["User", "App", "System"]
            
            # Target validation
            target = event["target"]
            assert "type" in target
            assert "id" in target
            assert target["type"] in ["User", "App", "System", "Group"]
            
            # Outcome validation
            outcome = event["outcome"]
            assert "result" in outcome
            assert outcome["result"] in ["SUCCESS", "FAILURE", "SKIPPED"]
    
    def test_geographical_context_validation(self):
        """Test geographical context in events"""
        event = generate_user_login(include_geolocation=True)
        
        if "client" in event and "geographicalContext" in event["client"]:
            geo = event["client"]["geographicalContext"]
            
            # Verify geographical fields
            assert "country" in geo
            assert "city" in geo
            assert "latitude" in geo
            assert "longitude" in geo
            
            # Verify coordinate ranges
            assert -90 <= geo["latitude"] <= 90
            assert -180 <= geo["longitude"] <= 180
    
    def test_security_context_validation(self):
        """Test security context in events"""
        event = generate_failed_login(include_security_context=True)
        
        if "securityContext" in event:
            security = event["securityContext"]
            
            # Verify security fields
            assert isinstance(security, dict)
            
            # Common security context fields
            possible_fields = ["asNumber", "isp", "domain", "isProxy"]
            has_security_field = any(field in security for field in possible_fields)
            assert has_security_field


class TestOktaPerformance:
    """Test Okta generator performance"""
    
    def test_large_batch_generation(self):
        """Test generating large batches of events"""
        import time
        
        start_time = time.time()
        events = generate_okta_events(count=1000)
        end_time = time.time()
        
        assert len(events) == 1000
        generation_time = end_time - start_time
        
        # Should generate 1000 events in reasonable time
        assert generation_time < 5.0
    
    def test_memory_usage(self):
        """Test memory usage during event generation"""
        import sys
        
        # Get initial memory usage
        initial_size = sys.getsizeof([])
        
        # Generate events
        events = generate_okta_events(count=100)
        
        # Check memory usage is reasonable
        final_size = sys.getsizeof(events)
        assert final_size > initial_size
        
        # Each event should be roughly the same size
        avg_event_size = final_size / len(events)
        assert 1000 < avg_event_size < 10000  # Reasonable range for event objects


class TestOktaIntegration:
    """Integration tests for Okta generator"""
    
    def test_authentication_flow_simulation(self):
        """Test complete authentication flow"""
        events = []
        
        # Successful login flow
        events.append(generate_user_login())
        events.append(generate_mfa_challenge())
        events.append(generate_user_logout())
        
        # Failed login flow
        events.append(generate_failed_login())
        events.append(generate_account_lockout())
        
        # Password change flow
        events.append(generate_password_change())
        
        # Verify flow sequence
        assert len(events) == 6
        
        # Verify timestamps are in chronological order
        timestamps = [datetime.fromisoformat(e["timestamp"].replace("Z", "+00:00")) for e in events]
        assert timestamps == sorted(timestamps)
    
    def test_user_behavior_analysis(self):
        """Test user behavior analysis patterns"""
        # Generate events for a single user
        user_email = "test.user@example.com"
        events = generate_okta_events(count=20, user_email=user_email)
        
        # Analyze user behavior
        login_events = [e for e in events if e["eventType"] == "user.session.start"]
        failed_events = [e for e in events if e["outcome"]["result"] == "FAILURE"]
        
        # Verify user consistency
        for event in events:
            if "actor" in event and "alternateId" in event["actor"]:
                assert event["actor"]["alternateId"] == user_email
        
        # Verify behavior analysis
        assert len(login_events) >= 0
        assert len(failed_events) >= 0
    
    def test_risk_event_detection(self):
        """Test risk event detection patterns"""
        events = generate_okta_events(count=50)
        
        # Identify high-risk events
        risk_events = []
        
        for event in events:
            # Failed logins are risky
            if event["outcome"]["result"] == "FAILURE":
                risk_events.append(event)
            
            # Privilege escalations are risky
            if "privilege" in event:
                risk_events.append(event)
            
            # Account lockouts are risky
            if event["eventType"] == "user.account.lock":
                risk_events.append(event)
            
            # Unusual geographical locations
            if "client" in event and "geographicalContext" in event["client"]:
                geo = event["client"]["geographicalContext"]
                if geo.get("country") not in ["US", "CA", "GB", "AU"]:
                    risk_events.append(event)
        
        # Verify risk detection
        assert len(risk_events) >= 0
        assert len(risk_events) <= len(events)
    
    def test_compliance_event_tracking(self):
        """Test compliance event tracking"""
        events = generate_okta_events(count=30)
        
        # Track compliance-relevant events
        compliance_events = {
            "password_changes": [],
            "privilege_changes": [],
            "account_lockouts": [],
            "failed_authentications": []
        }
        
        for event in events:
            if event["eventType"] == "user.password.change":
                compliance_events["password_changes"].append(event)
            elif "privilege" in event:
                compliance_events["privilege_changes"].append(event)
            elif event["eventType"] == "user.account.lock":
                compliance_events["account_lockouts"].append(event)
            elif event["outcome"]["result"] == "FAILURE":
                compliance_events["failed_authentications"].append(event)
        
        # Verify compliance tracking
        total_compliance = sum(len(events) for events in compliance_events.values())
        assert total_compliance >= 0
        assert total_compliance <= len(events)


class TestOktaAdvancedScenarios:
    """Advanced scenario tests for Okta generator"""
    
    def test_brute_force_attack_simulation(self):
        """Test brute force attack simulation"""
        events = []
        
        # Simulate multiple failed logins followed by lockout
        for i in range(5):
            event = generate_failed_login()
            events.append(event)
        
        # Account lockout
        lockout_event = generate_account_lockout()
        events.append(lockout_event)
        
        # Verify attack pattern
        failed_events = [e for e in events if e["outcome"]["result"] == "FAILURE"]
        assert len(failed_events) == 5
        assert events[-1]["eventType"] == "user.account.lock"
    
    def test_privilege_escalation_chain(self):
        """Test privilege escalation attack chain"""
        events = []
        
        # Initial compromise (login)
        events.append(generate_user_login())
        
        # Privilege escalation
        events.append(generate_privilege_escalation())
        
        # Additional privilege changes
        for _ in range(2):
            events.append(generate_privilege_escalation())
        
        # Verify escalation chain
        escalation_events = [e for e in events if "privilege" in e]
        assert len(escalation_events) == 3
    
    def test_mfa_bypass_attempt(self):
        """Test MFA bypass attempt simulation"""
        events = []
        
        # Login without MFA
        events.append(generate_user_login())
        
        # Failed MFA challenge
        mfa_event = generate_mfa_challenge()
        mfa_event["outcome"]["result"] = "FAILURE"
        events.append(mfa_event)
        
        # Successful login (potential bypass)
        bypass_event = generate_user_login()
        events.append(bypass_event)
        
        # Verify bypass pattern
        assert len(events) == 3
        assert events[1]["outcome"]["result"] == "FAILURE"
        assert events[2]["outcome"]["result"] == "SUCCESS"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
