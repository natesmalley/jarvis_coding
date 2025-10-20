#!/usr/bin/env python3
"""
Microsoft Azure AD Sign-in logs generator (JSON format)
"""
from __future__ import annotations
import json
import random
import time
import uuid
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional

# Azure AD Applications
AZURE_APPLICATIONS = [
    ("00000003-0000-0000-c000-000000000000", "Microsoft Graph"),
    ("00000002-0000-0000-c000-000000000000", "Azure Active Directory Graph"),
    ("797f4846-ba00-4fd7-ba43-dac1f8f63013", "Windows Azure Service Management API"),
    ("00000005-0000-0000-c000-000000000000", "Microsoft Intune API"),
    ("a0c73c16-a7e3-4564-9a95-2bdf47383716", "Microsoft EMS"),
    ("c5393580-f805-4401-95e8-94b7a6ef2fc2", "Office 365 Management APIs"),
    ("89bee1f7-5e6e-4d8a-9f3d-ecd601259da7", "Office365 Shell WCSS-Client"),
    ("d326c1ce-6cc6-4de2-bebc-4591e5e13ef0", "SharePoint Online Client"),
    ("ab9b8c07-8f02-4f72-87fa-80105867a763", "OneDrive SyncEngine"),
    ("fb78d390-0c51-40cd-8e17-fdbfab77341b", "Microsoft Exchange REST API Based Powershell")
]

# Client applications
CLIENT_APPS = [
    "Browser", "Mobile Apps and Desktop clients", "Exchange ActiveSync", 
    "Other clients", "IMAP4", "POP3", "SMTP", "Legacy authentication protocols"
]

# Authentication methods
AUTH_METHODS = [
    "Password", "SMS", "Voice call", "Microsoft Authenticator app notification",
    "Microsoft Authenticator app code", "Hardware OATH token", "Software OATH token",
    "Windows Hello for Business", "FIDO2 security key", "Certificate-based authentication"
]

# Conditional Access statuses
CA_STATUSES = ["success", "failure", "notApplied", "unknownFutureValue"]

# Risk levels
RISK_LEVELS = ["none", "low", "medium", "high", "hidden", "unknownFutureValue"]
RISK_DETAILS = [
    "none", "adminGeneratedTemporaryPassword", "userPerformedSecuredPasswordChange",
    "userPerformedSecuredPasswordReset", "adminConfirmedSigninSafe", "aiConfirmedSigninSafe",
    "userPassedMFADrivenByRiskBasedPolicy", "adminDismissedAllRiskForUser", "adminConfirmedSigninCompromised",
    "hidden", "adminConfirmedUserCompromised", "unknownFutureValue"
]

# Result types (0 = success, others are various failure codes)
RESULT_TYPES = [
    0,    # Success
    50001, # InvalidRequestFormat
    50002, # InvalidRequest
    50003, # InvalidUserNameOrPassword
    50005, # DeviceAuthenticationRequired
    50011, # InvalidResourceServicePrincipalNotFound
    50020, # UserAccountNotInDirectory
    50034, # AccountDisabled
    50053, # IdsLocked
    50055, # InvalidPasswordExpiredPassword
    50057, # UserDisabled
    50058, # UserInformationNotProvided
    50074, # UserStrongAuthClientAuthNRequired
    50076, # UserStrongAuthClientAuthNRequiredInterrupt
    50079, # UserStrongAuthEnrollmentRequired
    50105, # EntitlementGrantsNotFound
    50126, # InvalidUserNameOrPassword
    50131, # DeviceAuthenticationFailed
    50133, # SsoArtifactRevoked
    50140, # KmsiInterrupt
    50144, # InvalidPasswordExpiredOnPremPassword
]

# Countries and cities for location
LOCATIONS = [
    ("United States", "US", "New York", "New York", 40.7128, -74.0060),
    ("United States", "US", "Los Angeles", "California", 34.0522, -118.2437),
    ("United States", "US", "Chicago", "Illinois", 41.8781, -87.6298),
    ("United Kingdom", "GB", "London", "England", 51.5074, -0.1278),
    ("Germany", "DE", "Berlin", "Berlin", 52.5200, 13.4050),
    ("France", "FR", "Paris", "Île-de-France", 48.8566, 2.3522),
    ("Japan", "JP", "Tokyo", "Tokyo", 35.6762, 139.6503),
    ("Australia", "AU", "Sydney", "New South Wales", -33.8688, 151.2093),
    ("Canada", "CA", "Toronto", "Ontario", 43.6532, -79.3832),
    ("Netherlands", "NL", "Amsterdam", "North Holland", 52.3676, 4.9041),
]

# Operating systems and browsers
OPERATING_SYSTEMS = [
    "Windows 10", "Windows 11", "macOS", "iOS", "Android", "Linux", "Unknown"
]

BROWSERS = [
    "Chrome", "Edge", "Firefox", "Safari", "Internet Explorer", "Mobile Browser", "Unknown"
]

# Users
USERS = [
    ("John Doe", "john.doe@company.com", "jdoe"),
    ("Jane Smith", "jane.smith@company.com", "jsmith"),
    ("Bob Johnson", "bob.johnson@company.com", "bjohnson"),
    ("Alice Williams", "alice.williams@company.com", "awilliams"),
    ("Charlie Brown", "charlie.brown@company.com", "cbrown"),
    ("Diana Prince", "diana.prince@company.com", "dprince"),
    ("Admin User", "admin@company.com", "admin"),
    ("Service Account", "service@company.com", "service")
]

def _generate_ip(internal=True):
    """Generate IP address"""
    if internal:
        return f"10.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"
    else:
        return f"{random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"

def _generate_device_info():
    """Generate device information"""
    os = random.choice(OPERATING_SYSTEMS)
    browser = random.choice(BROWSERS)
    
    device_id = str(uuid.uuid4()) if random.random() > 0.3 else None
    is_managed = random.choice([True, False]) if device_id else False
    is_compliant = is_managed and random.choice([True, False])
    
    return {
        "deviceId": device_id,
        "displayName": f"DEVICE-{random.randint(100, 999)}" if device_id else None,
        "operatingSystem": os,
        "browser": browser,
        "isManaged": is_managed,
        "isCompliant": is_compliant,
        "trustType": random.choice(["Hybrid Azure AD joined", "Azure AD joined", "Azure AD registered", "Unknown"]) if device_id else "Unknown"
    }

def _generate_location():
    """Generate location information"""
    country, country_code, city, state, lat, lon = random.choice(LOCATIONS)
    
    return {
        "city": city,
        "state": state,
        "countryOrRegion": country,
        "geoCoordinates": {
            "latitude": lat + random.uniform(-0.1, 0.1),  # Add some variance
            "longitude": lon + random.uniform(-0.1, 0.1)
        }
    }

def _generate_conditional_access_policies():
    """Generate conditional access policy results"""
    policies = []
    num_policies = random.randint(0, 5)
    
    policy_names = [
        "Require MFA for all users", "Block legacy authentication", 
        "Require compliant devices", "Require trusted locations",
        "Block high-risk sign-ins", "Require approved apps"
    ]
    
    for i in range(num_policies):
        policy_name = random.choice(policy_names)
        policies.append({
            "id": str(uuid.uuid4()),
            "displayName": policy_name,
            "enforcedGrantControls": random.choice([["mfa"], ["compliantDevice"], ["approvedApplication"], []]),
            "enforcedSessionControls": [],
            "result": random.choice(["success", "failure", "notApplied", "notEnabled", "unknown"])
        })
    
    return policies

def _generate_authentication_details():
    """Generate authentication step details"""
    details = []
    num_steps = random.randint(1, 3)
    
    for i in range(num_steps):
        method = random.choice(AUTH_METHODS)
        succeeded = random.choice([True, False]) if i == 0 else True  # First step can fail
        
        details.append({
            "authenticationStepDateTime": (datetime.now(timezone.utc) - timedelta(seconds=random.randint(1, 30))).strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
            "authenticationMethod": method,
            "authenticationMethodDetail": f"{method} via mobile app" if "app" in method.lower() else method,
            "succeeded": succeeded,
            "authenticationStepRequirement": "primaryAuthentication" if i == 0 else "multiFactorAuthentication",
            "authenticationStepResultDetail": "methodSucceeded" if succeeded else "methodFailed"
        })
    
    return details

def microsoft_azure_ad_signin_log(overrides: dict | None = None) -> Dict:
    """
    Return a single Microsoft Azure AD Sign-in event as JSON string.
    
    Pass `overrides` to force any field to a specific value:
        microsoft_azure_ad_signin_log({"resultType": 0})
    """
    # Generate timestamps
    now = datetime.now(timezone.utc)
    created_time = now - timedelta(seconds=random.randint(0, 300))
    
    # Select user and application (allow override of user)
    user_display_name, user_email, user_id = random.choice(USERS)
    app_id, app_name = random.choice(AZURE_APPLICATIONS)
    
    # Check for user overrides
    if overrides and "properties" in overrides:
        if "userPrincipalName" in overrides["properties"]:
            user_email = overrides["properties"]["userPrincipalName"]
        if "userDisplayName" in overrides["properties"]:
            user_display_name = overrides["properties"]["userDisplayName"]
    elif overrides and "userPrincipalName" in overrides:
        user_email = overrides["userPrincipalName"]
    
    # Generate result (success/failure)
    result_type = random.choice(RESULT_TYPES)
    is_success = result_type == 0
    
    # Generate location and IP
    location = _generate_location()
    caller_ip = _generate_ip(internal=random.random() > 0.7)  # 30% external IPs
    
    # Generate device info
    device_detail = _generate_device_info()
    
    # Generate risk information
    risk_level = random.choice(RISK_LEVELS)
    if risk_level in ["medium", "high"]:
        risk_detail = random.choice([d for d in RISK_DETAILS if d not in ["none", "hidden"]])
    else:
        risk_detail = "none"
    
    # Base event structure (Azure EventHub format)
    record = {
        "time": now.strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
        "resourceId": f"/tenants/{uuid.uuid4()}/providers/Microsoft.aadiam",
        "operationName": "Sign-in activity",
        "operationVersion": "1.0",
        "category": "SignInLogs",
        "tenantId": str(uuid.uuid4()),
        "resultType": str(result_type),
        "resultSignature": "None" if is_success else f"Error_{result_type}",
        "resultDescription": "Success" if is_success else f"Sign-in failure: {result_type}",
        "durationMs": random.randint(100, 5000),
        "callerIpAddress": caller_ip,
        "correlationId": str(uuid.uuid4()),
        "identity": user_email,
        "Level": 4 if is_success else 3,  # Informational vs Warning
        "location": location["countryOrRegion"],
        "properties": {
            "id": str(uuid.uuid4()),
            "createdDateTime": created_time.strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
            "userDisplayName": user_display_name,
            "userPrincipalName": user_email,
            "userId": str(uuid.uuid4()),
            "appId": app_id,
            "appDisplayName": app_name,
            "resourceDisplayName": app_name,
            "resourceId": app_id,
            "clientAppUsed": random.choice(CLIENT_APPS),
            "userAgent": random.choice([
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
                "Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Mobile/15E148 Safari/604.1",
                "Microsoft Office/16.0 (Windows NT 10.0; 16.0.14326; Pro)",
                "BAV2ROPC"  # Basic Auth
            ]),
            "conditionalAccessStatus": random.choice(CA_STATUSES),
            "originalRequestId": str(uuid.uuid4()),
            "isInteractive": random.choice([True, False]),
            "tokenIssuerName": random.choice(["Azure AD", "ADFS", "External IdP"]),
            "tokenIssuerType": random.choice(["AzureAD", "ADFederationServices", "External"]),
            "processingTimeInMilliseconds": random.randint(50, 2000),
            "networkLocationDetails": [],
            "signInEventTypes": ["interactiveUser"] if random.random() > 0.5 else ["nonInteractiveUser"],
            "servicePrincipalId": None,
            "servicePrincipalName": None,
            "statusCode": result_type,
            "statusMessage": "Success" if is_success else f"Sign-in error {result_type}",
            "uniqueTokenIdentifier": str(uuid.uuid4()),
            "requestId": str(uuid.uuid4()),
            "authenticationProtocol": random.choice(["oAuth2", "saml", "wsFed", "unknownFutureValue"]),
            "incomingTokenType": random.choice(["none", "primaryRefreshToken", "saml11", "saml20", "unknownFutureValue"]),
            "flaggedForReview": False,
            "isTenantRestricted": False,
            "autonomousSystemNumber": random.randint(1000, 99999),
            "crossTenantAccessType": random.choice(["none", "b2bCollaboration", "b2bDirectConnect", "microsoftSupport", "serviceProvider", "unknownFutureValue"]),
            "homeTenantId": str(uuid.uuid4()),
            "uniqueTokenIdentifier": str(uuid.uuid4()),
            "riskDetail": risk_detail,
            "riskLevelAggregated": risk_level,
            "riskLevelDuringSignIn": risk_level,
            "riskState": random.choice(["none", "confirmedSafe", "remediated", "dismissed", "atRisk", "confirmedCompromised", "unknownFutureValue"]),
            "authenticationContextClassReferences": [],
            "authenticationDetails": _generate_authentication_details(),
            "authenticationRequirementPolicies": [],
            "authenticationStrengths": {
                "id": str(uuid.uuid4()),
                "displayName": "Built-in Multi-factor authentication",
                "allowedCombinations": ["password,sms", "password,voice", "password,microsoftAuthenticatorPush"]
            } if random.random() > 0.5 else None
        }
    }
    
    # Add device details
    record["properties"]["deviceDetail"] = device_detail
    
    # Add location details  
    record["properties"]["location"] = location
    
    # Add IP address details
    record["properties"]["ipAddress"] = caller_ip
    record["properties"]["ipAddressFromResourceProvider"] = caller_ip
    
    # Add conditional access policies
    record["properties"]["appliedConditionalAccessPolicies"] = _generate_conditional_access_policies()
    
    # Add status information
    record["properties"]["status"] = {
        "errorCode": result_type,
        "failureReason": "Other" if not is_success else None,
        "additionalDetails": f"Sign-in error code: {result_type}" if not is_success else None
    }
    
    # Add MFA details for successful MFA scenarios
    if is_success and random.random() > 0.5:
        record["properties"]["mfaDetail"] = {
            "authMethod": random.choice(AUTH_METHODS),
            "authDetail": "User successfully completed MFA",
            "authApplication": "Microsoft Authenticator"
        }
    
    # Add risk event types for risky sign-ins
    if risk_level in ["medium", "high"]:
        record["properties"]["riskEventTypes"] = random.sample([
            "unlikelyTravel", "anonymizedIPAddress", "maliciousIPAddress", 
            "unfamiliarFeatures", "malwareInfectedIPAddress", "suspiciousIPAddress",
            "leakedCredentials", "investigationsThreatIntelligence", "generic"
        ], random.randint(1, 3))
        record["properties"]["riskEventTypes_v2"] = record["properties"]["riskEventTypes"]
    
    # Wrap in EventHub records format
    event = {
        "records": [record]
    }
    
    # Apply any overrides at the record level
    if overrides:
        record.update(overrides)
    
    return event

if __name__ == "__main__":
    # Generate sample logs
    #print("Sample Microsoft Azure AD Sign-in events:")
    for i in range(50):
        for result in [0, 50126, 50074]:  # Success, invalid password, MFA required
            #print(f"\nResult Type {result}:")
            event = json.dumps(microsoft_azure_ad_signin_log({"resultType": str(result)}))
            print(event)
            #print()