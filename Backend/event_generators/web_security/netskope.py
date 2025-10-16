#!/usr/bin/env python3
"""
Netskope cloud security event generator (JSON format)
"""
from __future__ import annotations
import json
import random
import time
import uuid
import hashlib
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional

# Event types and activities
EVENT_TYPES = [
    "page", "download", "upload", "login", "logout", "share", "delete", 
    "create", "edit", "move", "copy", "admin", "breach", "malware", "dlp"
]

ACTIVITIES = {
    "page": ["Page Visit", "Web Access", "Cloud App Access"],
    "download": ["File Download", "Data Download", "Document Download"],
    "upload": ["File Upload", "Data Upload", "Document Upload"],
    "login": ["User Login", "OAuth Login", "SSO Login"],
    "logout": ["User Logout", "Session Timeout", "Force Logout"],
    "share": ["File Share", "Link Share", "Permission Grant"],
    "delete": ["File Delete", "Data Delete", "Account Delete"],
    "create": ["File Create", "Folder Create", "Account Create"],
    "edit": ["File Edit", "Document Edit", "Config Change"],
    "move": ["File Move", "Data Transfer", "Account Migration"],
    "copy": ["File Copy", "Data Copy", "Backup"],
    "admin": ["Admin Activity", "Policy Change", "User Management"],
    "breach": ["Data Breach", "Policy Violation", "Security Incident"],
    "malware": ["Malware Detection", "Threat Detection", "Virus Scan"],
    "dlp": ["DLP Violation", "Data Loss Prevention", "Content Inspection"]
}

# Application categories and names
APP_CATEGORIES = [
    "Cloud Storage", "Collaboration", "Email", "Social Networking", 
    "Business Intelligence", "CRM", "Development Tools", "File Sharing",
    "HR", "IT Management", "Marketing", "Productivity", "Project Management",
    "Security", "Unknown", "Webmail", "Web Conferencing"
]

CLOUD_APPS = {
    "Cloud Storage": ["Google Drive", "Dropbox", "OneDrive", "Box", "iCloud"],
    "Collaboration": ["Microsoft Teams", "Slack", "Zoom", "Webex", "Google Workspace"],
    "Email": ["Gmail", "Outlook", "Yahoo Mail", "ProtonMail"],
    "Social Networking": ["Facebook", "LinkedIn", "Twitter", "Instagram"],
    "CRM": ["Salesforce", "HubSpot", "Dynamics 365", "Zoho CRM"],
    "Development Tools": ["GitHub", "GitLab", "Jira", "Confluence"],
    "File Sharing": ["WeTransfer", "ShareFile", "SendAnywhere"]
}

# Actions and policies
ACTIONS = ["allow", "block", "alert", "quarantine", "bypass", "encrypt", "decrypt"]
POLICY_TYPES = ["Real-time Protection", "DLP", "Threat Protection", "Cloud Firewall", "CASB"]

# DLP rules and categories
DLP_RULES = [
    "Credit Card Numbers", "Social Security Numbers", "Personal Health Information",
    "Financial Records", "Customer Data", "Employee Data", "Intellectual Property",
    "Source Code", "API Keys", "Passwords", "Corporate Confidential"
]

# Malware types and names
MALWARE_TYPES = ["trojan", "virus", "worm", "backdoor", "ransomware", "spyware", "adware"]
MALWARE_NAMES = [
    "Emotet", "TrickBot", "Dridex", "Ryuk", "Maze", "REvil", "Cobalt Strike",
    "Agent Tesla", "FormBook", "Lokibot", "NetWire", "AsyncRAT"
]

# Geographic locations
COUNTRIES = [
    "United States", "United Kingdom", "Germany", "France", "Japan", "Australia",
    "Canada", "Netherlands", "Singapore", "India", "Brazil", "Mexico", "Unknown"
]

REGIONS = {
    "United States": ["California", "New York", "Texas", "Florida", "Washington"],
    "United Kingdom": ["England", "Scotland", "Wales", "Northern Ireland"],
    "Germany": ["Bavaria", "Berlin", "Hamburg", "Hesse"],
    "France": ["Île-de-France", "Provence-Alpes-Côte d'Azur", "Occitanie"],
    "Japan": ["Tokyo", "Osaka", "Kyoto", "Yokohama"],
    "Unknown": ["Unknown"]
}

# Users and devices
USERS = [
    "jean.picard", "william.riker", "data.android", "geordi.laforge", "worf.security", 
    "deanna.troi", "beverly.crusher", "wesley.crusher", "tasha.yar", "guinan.bartender",
    "james.kirk", "spock.science", "leonard.mccoy", "montgomery.scott", "nyota.uhura",
    "pavel.chekov", "hikaru.sulu", "benjamin.sisko", "kira.nerys", "julian.bashir",
    "jadzia.dax", "miles.obrien", "odo.security", "kathryn.janeway", "chakotay.commander",
    "tuvok.security", "tom.paris", "belanna.torres", "harry.kim", "seven.of.nine"
]
DEVICE_TYPES = ["Windows", "Mac", "iOS", "Android", "Linux", "ChromeOS"]
BROWSERS = ["Chrome", "Firefox", "Safari", "Edge", "Internet Explorer"]

def _generate_hash(hash_type="md5"):
    """Generate a hash"""
    random_data = str(random.random()).encode()
    if hash_type == "md5":
        return hashlib.md5(random_data).hexdigest()
    elif hash_type == "sha256":
        return hashlib.sha256(random_data).hexdigest()
    else:
        return hashlib.sha1(random_data).hexdigest()

def _generate_ip(internal=False):
    """Generate IP address"""
    if internal:
        return f"10.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"
    else:
        return f"{random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"

def _generate_coordinates(country):
    """Generate approximate coordinates for a country"""
    coordinates = {
        "United States": (39.8283, -98.5795),
        "United Kingdom": (55.3781, -3.4360),
        "Germany": (51.1657, 10.4515),
        "France": (46.6034, 1.8883),
        "Japan": (36.2048, 138.2529),
        "Australia": (-25.2744, 133.7751),
        "Unknown": (0.0, 0.0)
    }
    base_lat, base_lon = coordinates.get(country, (0.0, 0.0))
    # Add some randomness
    lat = base_lat + random.uniform(-5, 5)
    lon = base_lon + random.uniform(-5, 5)
    return round(lat, 4), round(lon, 4)

def _generate_location_info():
    """Generate location information"""
    country = random.choice(COUNTRIES)
    region = random.choice(REGIONS.get(country, ["Unknown"]))
    lat, lon = _generate_coordinates(country)
    
    return {
        "country": country,
        "region": region, 
        "latitude": lat,
        "longitude": lon,
        "timezone": random.choice([
            "America/New_York", "America/Los_Angeles", "UTC", "Europe/London",
            "Europe/Berlin", "Asia/Tokyo", "Australia/Sydney"
        ]),
        "zipcode": str(random.randint(10000, 99999)) if country == "United States" else ""
    }

def netskope_log(overrides: dict | None = None) -> str:
    """
    Return a single Netskope event as JSON string.
    
    Pass `overrides` to force any field to a specific value:
        netskope_log({"event_type": "malware"})
    """
    # Select event type and activity
    event_type = random.choice(EVENT_TYPES)
    activity = random.choice(ACTIVITIES[event_type])
    
    # Select app category and name
    app_category = random.choice(APP_CATEGORIES)
    app_name = random.choice(CLOUD_APPS.get(app_category, ["Unknown App"]))
    
    # Generate user and device info
    user = random.choice(USERS)
    device_type = random.choice(DEVICE_TYPES)
    
    # Generate location info
    src_location = _generate_location_info()
    dst_location = _generate_location_info()
    
    # Generate timestamps
    now = datetime.now(timezone.utc)
    src_time = now - timedelta(seconds=random.randint(0, 300))
    
    # Base event structure
    event = {
        "_id": str(uuid.uuid4()),
        "_event_id": str(random.randint(1000000, 9999999)),
        "_category_id": random.randint(1000, 9999),
        "_category_tags": [event_type, app_category.lower().replace(" ", "_")],
        "_correlation_id": str(uuid.uuid4()),
        "_detection_name": f"Netskope {activity} Detection",
        "_nshostname": f"netskope-{random.randint(1, 10)}.company.com",
        "_resource_name": f"ns-resource-{random.randint(100, 999)}",
        "_service_identifier": f"netskope-service-{random.randint(1, 100)}",
        "timestamp": int(now.timestamp()),
        "src_time": int(src_time.timestamp()),
        "event_type": event_type,
        "activity": activity,
        "user": user,
        "user_id": str(uuid.uuid4()),
        "userkey": f"{user}_key_{random.randint(1000, 9999)}",
        "account_name": user.split('.')[0].title(),
        "app_name": app_name,
        "appcategory": app_category,
        "category": event_type.title(),
        "action": random.choice(ACTIONS),
        "device": f"{device_type}-{random.randint(100, 999)}",
        "hostname": f"{user.split('.')[0]}-{device_type.lower()}-{random.randint(100, 999)}",
        "os": device_type,
        "srcip": _generate_ip(internal=True),
        "userip": _generate_ip(internal=True),
        "dstip": _generate_ip(internal=False),
        "protocol": random.choice(["TCP", "UDP", "HTTPS", "HTTP"]),
        "src_country": src_location["country"],
        "src_region": src_location["region"],
        "src_latitude": src_location["latitude"],
        "src_longitude": src_location["longitude"],
        "src_timezone": src_location["timezone"],
        "src_zipcode": src_location["zipcode"],
        "dst_country": dst_location["country"],
        "dst_region": dst_location["region"],
        "dst_latitude": dst_location["latitude"],
        "dst_longitude": dst_location["longitude"],
        "dst_timezone": dst_location["timezone"],
        "dst_zipcode": dst_location["zipcode"],
        "request_id": str(uuid.uuid4()),
        "connection_id": str(random.randint(100000, 999999)),
        "transaction_id": str(uuid.uuid4()),
        "instance_id": str(uuid.uuid4()),
        "count": random.randint(1, 10),
        "severity": random.choice(["low", "medium", "high", "critical"]),
        "severity_id": random.randint(1, 4),
        "severity_level": random.choice(["Low", "Medium", "High", "Critical"]),
        "severity_level_id": random.randint(1, 4)
    }
    
    # Add URL if web-related activity
    if event_type in ["page", "download", "upload"]:
        event["url"] = f"https://{app_name.lower().replace(' ', '')}.com/{random.choice(['documents', 'files', 'drive', 'share'])}/{uuid.uuid4()}"
    
    # Add file information for file-related activities
    if event_type in ["download", "upload", "create", "edit", "delete", "copy", "move"]:
        file_extensions = [".pdf", ".docx", ".xlsx", ".pptx", ".txt", ".zip", ".jpg", ".png"]
        file_extension = random.choice(file_extensions)
        file_name = f"document_{random.randint(1000, 9999)}{file_extension}"
        
        event.update({
            "file_name": file_name,
            "file_type": file_extension[1:],  # Remove the dot
            "file_size": random.randint(1024, 50000000),  # 1KB to 50MB
            "local_md5": _generate_hash("md5"),
            "md5": _generate_hash("md5"),
            "local_sha256": _generate_hash("sha256")
        })
    
    # Add DLP information for DLP events
    if event_type == "dlp" or random.random() < 0.2:  # 20% chance for other events
        dlp_rule = random.choice(DLP_RULES)
        event.update({
            "dlp_file": event.get("file_name", f"sensitive_file_{random.randint(100, 999)}.txt"),
            "dlp_incident_id": str(uuid.uuid4()),
            "dlp_rule": dlp_rule,
            "dlp_rule_count": random.randint(1, 5),
            "matched_username": user if random.random() > 0.3 else random.choice(USERS)
        })
    
    # Add malware information for malware events
    if event_type == "malware" or random.random() < 0.1:  # 10% chance for other events
        malware_name = random.choice(MALWARE_NAMES)
        event.update({
            "malware_name": malware_name,
            "malware_type": random.choice(MALWARE_TYPES),
            "malware_severity": random.choice(["low", "medium", "high", "critical"]),
            "malsite_country": random.choice(COUNTRIES)
        })
    
    # Add breach information for breach events
    if event_type == "breach" or (event_type == "dlp" and random.random() > 0.5):
        event.update({
            "breach_id": str(uuid.uuid4()),
            "breach_score": random.randint(0, 100),
            "breach_date": (now - timedelta(days=random.randint(0, 30))).strftime("%Y-%m-%d"),
            "breach_description": f"Potential data breach detected: {random.choice(DLP_RULES)} exposure"
        })
    
    # Add alert information for high-severity events
    if event.get("severity") in ["high", "critical"] or event_type in ["breach", "malware", "dlp"]:
        alert_types = ["DLP Violation", "Malware Detection", "Policy Violation", "Anomalous Activity"]
        event.update({
            "alert_id": str(uuid.uuid4()),
            "alert_name": f"Netskope Alert: {random.choice(alert_types)}",
            "alert_type": random.choice(alert_types),
            "incident_id": str(uuid.uuid4())
        })
    
    # Add policy information
    event.update({
        "policy": random.choice(POLICY_TYPES),
        "policy_id": str(random.randint(1000, 9999)),
        "type": random.choice(["nspolicy", "dlp", "malware", "web"])
    })
    
    # Add additional context fields
    event.update({
        "true_obj_type": random.choice(["file", "folder", "email", "web_page", "application"]),
        "os10": f"{device_type} 10" if device_type == "Windows" else device_type,
        "os11": f"{device_type} 11" if device_type == "Windows" else device_type
    })
    
    # Apply any overrides
    if overrides:
        event.update(overrides)
    
    return json.dumps(event)

if __name__ == "__main__":
    # Generate sample logs for different event types
    print("Sample Netskope events:")
    for event_type in ["page", "download", "dlp", "malware", "breach"]:
        print(f"\n{event_type.upper()} event:")
        print(netskope_log({"event_type": event_type}))
        print()