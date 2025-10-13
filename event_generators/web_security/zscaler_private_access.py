#!/usr/bin/env python3
"""
Zscaler Private Access Event Generator
Generates synthetic ZPA zero-trust network access events for testing
"""

import random
import time
import json
from datetime import datetime, timezone, timedelta

# SentinelOne AI-SIEM specific field attributes
def zscaler_private_access_log():
    """Generate a synthetic Zscaler Private Access log event in JSON format."""
    
    # Generate timestamp
    now = datetime.now(timezone.utc)
    
    # ZPA event types
    event_types = ["UserActivity", "AppConnectorStatus", "UserStatus", "PolicyViolation", "Authentication"]
    event_type = random.choice(event_types)
    
    # Generate common fields
    user_email = f"user{random.randint(1000,9999)}@company.com"
    client_ip = f"{random.randint(1,223)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
    
    # Build the JSON log entry matching marketplace parser expectations
    zpa_event = {
        "LogTimestamp": now.isoformat().replace("+00:00", "Z"),"Customer": "company.com","SessionID": f"{random.randint(10000000, 99999999)}", \
        "ConnectionID": f"conn_{random.randint(1000000, 9999999)}", \
        "InternalReason": "", \
        "ConnectionStatus": random.choice(["active", "closed", "timeout"]), \
        "IPProtocol": random.randint(1, 255), \
        "DoubleEncryption": random.randint(0, 1), \
        "Username": user_email, \
        "ServicePort": random.choice([443, 8443, 3389, 22, 445]), \
        "ClientPublicIP": client_ip, \
        "ClientPrivateIP": f"10.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}", \
        "ClientLatitude": round(random.uniform(-90, 90), 6), \
        "ClientLongitude": round(random.uniform(-180, 180), 6), \
        "ClientCountryCode": random.choice(["US", "GB", "DE", "FR", "JP", "AU"]), \
        "ClientZEN": f"zen{random.randint(1,10)}.zscaler.net", \
        "Policy": f"Policy_{random.randint(1,50)}", \
        "Connector": f"zpa-connector-{random.randint(10,99)}", \
        "ConnectorZEN": f"zen{random.randint(1,10)}.zscaler.net", \
        "ConnectorIP": f"172.16.{random.randint(0,255)}.{random.randint(1,254)}", \
        "ConnectorPort": random.randint(49152, 65535), \
        "Host": f"app{random.randint(1,20)}.internal.company.com", \
        "Application": random.choice(["Internal-CRM", "HR-Portal", "Dev-Environment", "Finance-DB", "Manufacturing-SCADA"]), \
        "AppGroup": random.choice(["Business_Apps", "Developer_Tools", "Admin_Tools"]), \
        "Server": f"server{random.randint(1,50)}.company.local", \
        "ServerIP": f"10.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}", \
        "ServerPort": random.choice([443, 8080, 3000, 5000]), \
        "ServerProtocol": random.choice(["HTTPS", "HTTP", "TCP", "UDP"]), \
        "Type": event_type, \
        "ZENLatitude": round(random.uniform(-90, 90), 6), \
        "ZENLongitude": round(random.uniform(-180, 180), 6), \
        "ZENCountryCode": random.choice(["US", "GB", "DE", "FR", "JP", "AU"]), \
        "TimestampRequestReceiveStart": now.isoformat(), \
        "TimestampRequestReceiveHeaderFinish": (now + timedelta(milliseconds=random.randint(1, 10))).isoformat(), \
        "TimestampRequestReceiveFinish": (now + timedelta(milliseconds=random.randint(10, 50))).isoformat(), \
        "TimestampRequestTransmitStart": (now + timedelta(milliseconds=random.randint(50, 100))).isoformat(), \
        "TimestampRequestTransmitFinish": (now + timedelta(milliseconds=random.randint(100, 200))).isoformat(), \
        "TimestampResponseReceiveStart": (now + timedelta(milliseconds=random.randint(200, 500))).isoformat(), \
        "TimestampResponseReceiveFinish": (now + timedelta(milliseconds=random.randint(500, 1000))).isoformat(), \
        "TimestampResponseTransmitStart": (now + timedelta(milliseconds=random.randint(1000, 1100))).isoformat(), \
        "TimestampResponseTransmitFinish": (now + timedelta(milliseconds=random.randint(1100, 1500))).isoformat(), \
        "TimestampCARx": (now + timedelta(milliseconds=random.randint(0, 5))).isoformat(), \
        "TimestampCATx": (now + timedelta(milliseconds=random.randint(1500, 2000))).isoformat(), \
        "TimestampAppLearnStart": "", \
        "TimestampZENFirstRxClient": (now + timedelta(milliseconds=random.randint(0, 10))).isoformat(), \
        "TimestampZENFirstTxClient": (now + timedelta(milliseconds=random.randint(10, 20))).isoformat(), \
        "TimestampZENLastRxClient": (now + timedelta(milliseconds=random.randint(1000, 1500))).isoformat(), \
        "TimestampZENLastTxClient": (now + timedelta(milliseconds=random.randint(1500, 2000))).isoformat(), \
        "TimestampConnectorZENSetupComplete": (now + timedelta(milliseconds=random.randint(0, 100))).isoformat(), \
        "TimestampZENFirstRxConnector": (now + timedelta(milliseconds=random.randint(100, 200))).isoformat(), \
        "TimestampZENFirstTxConnector": (now + timedelta(milliseconds=random.randint(200, 300))).isoformat(), \
        "TimestampZENLastRxConnector": (now + timedelta(milliseconds=random.randint(1000, 1500))).isoformat(), \
        "TimestampZENLastTxConnector": (now + timedelta(milliseconds=random.randint(1500, 2000))).isoformat(), \
        "ZENTotalBytesRxClient": random.randint(1024, 1048576), \
        "ZENBytesRxClient": random.randint(512, 524288), \
        "ZENTotalBytesTxClient": random.randint(1024, 1048576), \
        "ZENBytesTxClient": random.randint(512, 524288), \
        "ZENTotalBytesRxConnector": random.randint(1024, 1048576), \
        "ZENBytesRxConnector": random.randint(512, 524288), \
        "ZENTotalBytesTxConnector": random.randint(1024, 1048576), \
        "ZENBytesTxConnector": random.randint(512, 524288), \
        "Idp": random.choice(["Okta", "AzureAD", "Ping", "OneLogin"]), \
        "ClientToClient": "", \
        "ConnectionReason": "", \
        "TimestampUnAuthenticated": "", \
        "TotalTimeBlockedRequestTransmitFinish": 0, \
        "TotalTimeBlockedResponseReceiveFinish": 0, \
        "TotalTimeBlockedResponseTransmitFinish": 0, \
        "TotalTimeBlockedRequestReceiveFinish": 0, \
        "CPUUtilization": random.randint(1, 100), \
        "MemUtilization": random.randint(20, 95), \
        "ServicePortRange": "", \
        "ClientConnector": f"client-connector-{random.randint(1,5)}", \
        "ConnectorGroupID": f"GRP_{random.randint(100, 999)}", \
        "ConnectorGroup": "Default", \
        "PolicyProcessingTime": random.randint(1, 100), \
        "CAProcessingTime": random.randint(1, 50), \
        "AppLearnTime": 0, \
        "TimestampCAFirstRxApp": "", \
        "TimestampCAFirstTxApp": "", \
        "ServerSetupTime": random.randint(10, 500), \
        "TimestampCATxFirstReq": "", \
        "TimestampCAGapRxFirstReq": "", \
        "TimestampServerFirstRxCA": "", \
        "ClientCity": random.choice(["New York", "London", "Tokyo", "Sydney", "Frankfurt"]), \
        "ClientRegion": random.choice(["Americas", "EMEA", "APAC"]), \
        "ClientZENCity": random.choice(["San Jose", "London", "Tokyo", "Sydney", "Frankfurt"]), \
        "ZENCity": random.choice(["San Jose", "London", "Tokyo", "Sydney", "Frankfurt"]), \
        "ConnectorZENCity": random.choice(["San Jose", "London", "Tokyo", "Sydney", "Frankfurt"]), \
        "ConnectorCity": random.choice(["New York", "London", "Tokyo", "Sydney", "Frankfurt"]), \
        "ConnectorCountryCode": random.choice(["US", "GB", "DE", "FR", "JP", "AU"]), \
        "ConnectorLatitude": round(random.uniform(-90, 90), 6), \
        "ConnectorLongitude": round(random.uniform(-180, 180), 6), \
        "Method": random.choice(["GET", "POST", "PUT", "DELETE", "HEAD"]), \
        "URL": f"/api/v1/{random.choice(["users", "data", "reports", "config"])}/{random.randint(1,1000)}", \
        "HostHeader": f"app{random.randint(1,20)}.internal.company.com", \
        "UserAgent": random.choice([ \
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/91.0", \
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Safari/537.36", \
            "ZPA-Client/3.7.1.44" \
        ]), \
        "XFF": "", \
        "NameID": user_email, \
        "StatusCode": random.choice([200, 201, 204, 301, 302, 401, 403, 404, 500, 503]) if event_type != "PolicyViolation" else 403, \
        "RequestSize": random.randint(100, 10000), \
        "ResponseSize": random.randint(100, 100000), \
        "TotalBytesRx": random.randint(1000, 10000000), \
        "TotalBytesTx": random.randint(1000, 10000000), \
        "Exporter": "ZPA", \
        "TimestampRequestProxyConnSetupStart": "", \
        "TimestampRequestProxyConnSetupFinish": "", \
        "TotalTimeProxyConnSetup": 0, \
        "TotalTimeServerConnSetup": random.randint(10, 500), \
        "ServerConnSetupStartToFinish": random.randint(10, 500), \
        "Source": "USER", \
        "ClientCityGeoID": random.randint(1000000, 9999999), \
        "ClientStateOrProvince": random.choice(["NY", "CA", "TX", "FL", "IL", "WA"]), \
        "ClientPostalCode": f"{random.randint(10000, 99999)}", \
        "DeviceOwner": user_email, \
        "DeviceName": f"{user_email.split("@")[0]}-laptop", \
        "DeviceModel": random.choice(["MacBookPro", "ThinkPad", "Surface", "Dell Latitude"]), \
        "DeviceType": random.choice(["Laptop", "Desktop", "Mobile", "Tablet"]), \
        "DeviceOSType": random.choice(["Windows", "macOS", "Linux", "iOS", "Android"]), \
        "DeviceOSVersion": random.choice(["10.0", "11.0", "14.0", "22.04"]), \
        "DeviceHostName": f"device-{random.randint(1000, 9999)}.company.com", \
        "ConnectionCloseCode": random.choice(["0", "1", "2", "3"]) if event_type == "closed" else "", \
        "ConnectionCloseReason": "Normal closure" if event_type == "closed" else "", \
        "SAMLAttributes": json.dumps({"memberOf": ["group1", "group2"], "department": "Engineering"}), \
        "PostureUDID": f"UDID_{random.randint(100000, 999999)}", \
        "PostureTrustedNetwork": random.choice(["Corporate", "VPN", "Public"]), \
        "MicroTenantID": f"MT_{random.randint(100, 999)}", \
        "MicroTenantName": "Default"

    }
    
    return zpa_event

if __name__ == "__main__":
    # Generate and print sample events
    #print("Zscaler Private Access JSON Format Examples:")
    #print("=" * 60)
    
    for i in range(100):
        event = zscaler_private_access_log()
        json_string = json.dumps(event)
        print(json_string)
        #print(json.dumps(event, indent=2, default=str)[:500] + "...")