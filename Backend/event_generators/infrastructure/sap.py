#!/usr/bin/env python3
"""
SAP application event generator
Generates synthetic SAP ERP, HANA, and security audit events
"""
import json
import random
import time
from datetime import datetime, timezone, timedelta
from typing import Dict

# SAP modules and transaction codes
SAP_MODULES = {
    "FI": ["FB01", "FB02", "FB03", "F-02", "F-03", "F-04", "F-05", "F-06", "F-07", "F-08"],
    "CO": ["KS01", "KS02", "KS03", "KB01", "KB02", "KB03", "KO01", "KO02", "KO03"],
    "MM": ["ME01", "ME02", "ME03", "ME21", "ME22", "ME23", "MIGO", "MIRO", "MB01", "MB02"],
    "SD": ["VA01", "VA02", "VA03", "VF01", "VF02", "VF03", "VL01", "VL02", "VL03"],
    "HR": ["PA01", "PA02", "PA03", "PA30", "PA40", "PA41", "PU01", "PU02", "PU03"],
    "PP": ["MD01", "MD02", "MD03", "MD04", "MD05", "CO01", "CO02", "CO03", "CO11", "CO12"],
    "BASIS": ["SM01", "SM02", "SM04", "SM12", "SM13", "SM21", "SM37", "SM50", "SM51", "SM66"]
}

# Event types
EVENT_TYPES = [
    {"type": "LOGON_SUCCESS", "severity": "INFO", "message": "User logon successful"},
    {"type": "LOGON_FAILED", "severity": "WARNING", "message": "User logon failed"},
    {"type": "TRANSACTION_START", "severity": "INFO", "message": "Transaction started"},
    {"type": "TRANSACTION_END", "severity": "INFO", "message": "Transaction completed"},
    {"type": "RFC_CALL", "severity": "INFO", "message": "RFC function called"},
    {"type": "TABLE_ACCESS", "severity": "INFO", "message": "Database table accessed"},
    {"type": "AUTHORIZATION_CHECK", "severity": "WARNING", "message": "Authorization check failed"},
    {"type": "CRITICAL_AUTH_OBJECT", "severity": "CRITICAL", "message": "Critical authorization object accessed"},
    {"type": "SENSITIVE_TRANSACTION", "severity": "HIGH", "message": "Sensitive transaction executed"},
    {"type": "SYSTEM_CHANGE", "severity": "WARNING", "message": "System configuration changed"},
    {"type": "USER_MASTER_CHANGE", "severity": "WARNING", "message": "User master data changed"},
    {"type": "ROLE_ASSIGNMENT", "severity": "INFO", "message": "Role assigned to user"},
    {"type": "DEBUG_SESSION", "severity": "WARNING", "message": "Debug session started"},
    {"type": "SPOOL_ACCESS", "severity": "INFO", "message": "Spool output accessed"}
]

# SAP clients (mandants)
SAP_CLIENTS = ["100", "200", "300", "400", "500", "800"]

# SAP systems
SAP_SYSTEMS = ["PRD", "QAS", "DEV", "TST", "SBX"]

# Authorization objects
AUTH_OBJECTS = [
    "S_TCODE", "S_TABU_NAM", "S_DATASET", "S_PROGRAM", "S_DEVELOP", 
    "S_USER_GRP", "S_USER_SAS", "S_RFC", "S_ADMI_FCD", "S_TRANSPRT",
    "F_BKPF_BUK", "F_BKPF_GSB", "M_MATE_WRK", "V_VBAK_VKO", "P_PERNR"
]

# Table names
TABLE_NAMES = [
    "BKPF", "BSEG", "MARA", "MARC", "VBAK", "VBAP", "EKKO", "EKPO",
    "PA0001", "PA0002", "T001", "T001W", "USR01", "USR02", "AGR_USERS"
]

# RFC functions
RFC_FUNCTIONS = [
    "RFC_READ_TABLE", "BAPI_USER_GET_DETAIL", "BAPI_USER_CHANGE", 
    "RFC_SYSTEM_INFO", "RFC_PING", "STFC_CONNECTION", "BAPI_MATERIAL_GET_DETAIL"
]

def generate_ip() -> str:
    """Generate SAP internal IP address"""
    return f"10.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"

def sap_log() -> Dict:
    """Generate a single SAP event log"""
    now = datetime.now(timezone.utc)
    event_time = now - timedelta(minutes=random.randint(0, 1440))
    
    event_info = random.choice(EVENT_TYPES)
    sap_client = random.choice(SAP_CLIENTS)
    sap_system = random.choice(SAP_SYSTEMS)
    
    event = {
        "timestamp": event_time.isoformat(),
        "date": event_time.strftime("%Y%m%d"),
        "time": event_time.strftime("%H%M%S"),
        "event_type": event_info["type"],
        "severity": event_info["severity"],
        "message": event_info["message"],
        "system_id": sap_system,
        "client": sap_client,
        "user": f"USER{random.randint(1, 999):03d}",
        "session_id": f"{random.randint(100000, 999999)}",
        "terminal": f"WS{random.randint(1000, 9999)}",
        "server": f"sap{sap_system.lower()}{random.randint(1, 10)}",
        "instance": f"{random.randint(0, 99):02d}",
        "ip_address": generate_ip(),
        "program": f"SAPL{random.choice(['RFBU', 'MMBE', 'RVAD', 'COSP'])}{random.randint(100, 999)}",
        "transaction_code": "",
        "language": random.choice(["EN", "DE", "FR", "ES", "PT", "JA", "ZH"])
    }
    
    # Add event-specific fields
    if "LOGON" in event_info["type"]:
        event.update({
            "logon_type": random.choice(["GUI", "RFC", "HTTP", "WEBDYNPRO", "MOBILE"]),
            "gui_version": f"{random.randint(740, 760)}.{random.randint(0, 9)}.{random.randint(0, 99)}",
            "codepage": random.choice(["4103", "4102", "4110", "4000"]),
            "user_group": random.choice(["SUPER", "PROFESSIONAL", "EMPLOYEE", "REFERENCE", "SERVICE"]),
            "user_type": random.choice(["A", "B", "C", "S"])  # Dialog, System, Comm, Service
        })
        
        if "FAILED" in event_info["type"]:
            event.update({
                "failure_reason": random.choice([
                    "Wrong password",
                    "User locked",
                    "Password expired",
                    "Too many failed attempts", 
                    "User does not exist",
                    "License exceeded"
                ]),
                "failed_attempts": random.randint(1, 5)
            })
    
    elif "TRANSACTION" in event_info["type"]:
        module = random.choice(list(SAP_MODULES.keys()))
        tcode = random.choice(SAP_MODULES[module])
        event.update({
            "transaction_code": tcode,
            "module": module,
            "screen": f"{random.randint(1000, 9999)}",
            "gui_mode": random.choice(["A", "E", "N"]),  # Display, Change, Create
            "response_time": random.randint(100, 5000),  # milliseconds
            "cpu_time": random.randint(10, 1000),  # milliseconds
            "db_requests": random.randint(1, 100),
            "roll_wait_time": random.randint(0, 100)
        })
        
        # Add sensitive transaction indicators
        sensitive_tcodes = ["SE80", "SM30", "SU01", "PFCG", "SE16", "SE11", "STMS"]
        if tcode in sensitive_tcodes:
            event["sensitive_transaction"] = True
            event["severity"] = "HIGH"
    
    elif event_info["type"] == "RFC_CALL":
        event.update({
            "rfc_function": random.choice(RFC_FUNCTIONS),
            "rfc_type": random.choice(["sRFC", "aRFC", "tRFC", "qRFC", "bgRFC"]),
            "calling_system": f"{random.choice(SAP_SYSTEMS)}_800",
            "destination": f"RFC_{random.choice(['DEST', 'CONN'])}_{random.randint(1, 99):02d}",
            "parameters": random.randint(1, 20),
            "execution_time": random.randint(10, 5000)  # milliseconds
        })
    
    elif event_info["type"] == "TABLE_ACCESS":
        table = random.choice(TABLE_NAMES)
        event.update({
            "table_name": table,
            "access_type": random.choice(["SELECT", "INSERT", "UPDATE", "DELETE", "MODIFY"]),
            "records_affected": random.randint(1, 10000),
            "where_condition": f"{random.choice(['BUKRS', 'MATNR', 'VBELN', 'PERNR'])} = '{random.randint(1000, 9999)}'",
            "client_dependent": random.choice([True, False]),
            "table_category": random.choice(["APPL", "CUST", "SYST", "USER"])
        })
        
        # Flag sensitive tables
        sensitive_tables = ["USR01", "USR02", "AGR_USERS", "PA0001", "PA0002"]
        if table in sensitive_tables:
            event["sensitive_table"] = True
            event["severity"] = "HIGH"
    
    elif event_info["type"] == "AUTHORIZATION_CHECK":
        auth_obj = random.choice(AUTH_OBJECTS)
        event.update({
            "authorization_object": auth_obj,
            "check_result": "FAILED",
            "activity": random.choice(["01", "02", "03", "06", "70"]),  # Display, Change, Create, Delete, Authorization
            "field_values": {
                f"field_{i}": f"value_{random.randint(1, 999)}" 
                for i in range(1, random.randint(2, 6))
            },
            "missing_authorization": f"Missing authorization for {auth_obj}",
            "role_required": f"Z_{random.choice(['FINANCE', 'SALES', 'MATERIAL', 'HR'])}_{random.randint(1, 99):02d}"
        })
    
    elif event_info["type"] == "CRITICAL_AUTH_OBJECT":
        critical_objects = ["S_DEVELOP", "S_ADMI_FCD", "S_TRANSPRT", "S_DATASET", "S_PROGRAM"]
        event.update({
            "authorization_object": random.choice(critical_objects), 
            "activity": random.choice(["01", "02", "03", "70"]),
            "risk_level": "CRITICAL",
            "business_impact": "High - System administration access",
            "compliance_relevant": True,
            "approval_required": True
        })
    
    elif event_info["type"] == "USER_MASTER_CHANGE":
        event.update({
            "changed_user": f"USER{random.randint(1, 999):03d}",
            "change_type": random.choice(["CREATE", "MODIFY", "DELETE", "LOCK", "UNLOCK"]),
            "changed_fields": random.sample([
                "Password", "Valid_from", "Valid_to", "User_group", "User_type", 
                "Reference_user", "Company", "Department", "E-mail"
            ], random.randint(1, 4)),
            "change_document": f"CHG_DOC_{random.randint(1000000, 9999999)}",
            "approval_workflow": f"WF_{random.randint(100000, 999999)}" if random.choice([True, False]) else ""
        })
    
    elif event_info["type"] == "ROLE_ASSIGNMENT":
        event.update({
            "assigned_role": f"Z_{random.choice(['SAP_', 'Z_'])}{''.join(random.choices('ABCDEFGHIJKLMNOPQRSTUVWXYZ', k=8))}",
            "role_type": random.choice(["Single", "Composite", "Derived"]),
            "assignment_type": random.choice(["DIRECT", "INHERITED", "TEMPORARY"]),
            "valid_from": event_time.strftime("%Y%m%d"),
            "valid_to": (event_time + timedelta(days=random.randint(30, 365))).strftime("%Y%m%d"),
            "org_levels": {
                "company_code": f"{random.randint(1000, 9999)}",
                "plant": f"{random.randint(1000, 9999)}",
                "sales_org": f"{random.randint(1000, 9999)}"
            }
        })
    
    elif event_info["type"] == "DEBUG_SESSION":
        event.update({
            "debug_type": random.choice(["ABAP Debugger", "JavaScript Debugger", "Web Debugger"]),
            "breakpoints": random.randint(1, 20),
            "session_duration": random.randint(300, 7200),  # seconds
            "debugged_user": f"USER{random.randint(1, 999):03d}",
            "production_system": sap_system == "PRD",
            "risk_assessment": "HIGH" if sap_system == "PRD" else "MEDIUM"
        })
    
    # Add audit and compliance fields
    event.update({
        "audit_class": random.choice(["SEC", "DAN", "RFE", "DTE", "CIN", "RUF"]),
        "audit_subclass": random.choice(["AU1", "AU2", "AU3", "RFE", "SEC"]),
        "retention_period": random.randint(7, 2555),  # days
        "gdpr_relevant": random.choice([True, False]),
        "sox_relevant": random.choice([True, False]) if random.choice(list(SAP_MODULES.keys())) == "FI" else False,
        "pci_relevant": random.choice([True, False]) if "payment" in event_info["message"].lower() else False
    })
    
    # Add system performance metrics
    event.update({
        "work_process": f"DIA_{random.randint(0, 20)}",
        "memory_usage": random.randint(1000, 50000),  # KB
        "database": random.choice(["HANA", "Oracle", "SQL Server", "DB2", "MaxDB"]),
        "database_time": random.randint(0, 1000),  # milliseconds
        "network_time": random.randint(0, 100),  # milliseconds
        "frontend_time": random.randint(0, 500)  # milliseconds
    })
    
    return event

if __name__ == "__main__":
    # Generate sample events
    print("Sample SAP Events:")
    print("=" * 50)
    for i in range(3):
        print(f"\nEvent {i+1}:")
        print(sap_log())