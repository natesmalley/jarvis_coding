#!/usr/bin/env python3
"""
RSA Adaptive Authentication event generator
Generates synthetic RSA Adaptive risk-based authentication events
"""
import random
from datetime import datetime, timezone, timedelta

USERS = ["carol@example.com", "dan@example.com", "eve@example.com", "admin@example.com"]
DEVICES = ["iOS", "Android", "Windows", "Web", "Mac"]
DECISIONS = ["APPROVE", "CHALLENGE", "DENY"]
FACTORS = ["password", "push", "sms", "token", "biometric"]

def get_random_ip():
    """Generate IP with some suspicious ranges."""
    suspicious_ranges = [f"203.0.113.{random.randint(100, 255)}", f"198.51.100.{random.randint(50, 100)}"]
    normal_ranges = [f"192.168.1.{random.randint(1, 100)}", f"10.0.0.{random.randint(1, 255)}"]
    
    return random.choice(suspicious_ranges + normal_ranges)

def generate_risk_score_and_decision():
    """Generate correlated risk score and decision."""
    risk_score = random.randint(0, 100)
    
    if risk_score <= 30:
        decision = "APPROVE"
    elif risk_score <= 70:
        decision = "CHALLENGE" 
    else:
        decision = "DENY"
    
    return risk_score, decision

def rsa_adaptive_log() -> dict:
    """Generate a single RSA Adaptive Authentication event log"""
    now = datetime.now(timezone.utc)
    event_time = now - timedelta(minutes=random.randint(0, 60))
    
    user = random.choice(USERS)
    ip = get_random_ip()
    device = random.choice(DEVICES)
    risk_score, decision = generate_risk_score_and_decision()
    factor = random.choice(FACTORS)
    
    # Determine result based on decision
    if decision == "APPROVE":
        result = "SUCCESS"
        message = "Login approved with low risk"
    elif decision == "CHALLENGE":
        result = "PENDING"
        message = f"High risk detected; {factor} challenge sent"
    else:  # DENY
        result = "FAILURE"
        message = "Login denied due to suspected fraud"
    
    timestamp = event_time.isoformat().replace('+00:00', 'Z')
    
    log_dict = {
        "timestamp": timestamp,
        "dataSource": "RSAAdaptiveAuth",
        "user": user,
        "ip": ip,
        "device": device,
        "riskScore": risk_score,
        "decision": decision,
        "factor": factor,
        "result": result,
        "message": message
    }
    
    return log_dict

if __name__ == "__main__":
    import json
    print("Sample RSA Adaptive Authentication Events:")
    print("=" * 50)
    for i in range(3):
        print(f"\nEvent {i+1}:")
        print(json.dumps(rsa_adaptive_log(), indent=2))