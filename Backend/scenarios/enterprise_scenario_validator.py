#!/usr/bin/env python3
"""
Enterprise Attack Scenario Validator
====================================
Validates event structure, attributes, and searchability for all 19 data sources
in the enterprise attack scenario.
"""

import os
import json
from datetime import datetime, timezone
from enterprise_attack_scenario import generate_enhanced_attack_scenario
from hec_sender import SOURCETYPE_MAP, JSON_PRODUCTS

def analyze_event_structure(event_data, source, phase):
    """Analyze the structure of a single event"""
    analysis = {
        "source": source,
        "phase": phase,
        "event_type": "JSON" if isinstance(event_data, dict) else "Raw",
        "has_timestamp": False,
        "key_fields": [],
        "searchable_values": [],
        "correlation_fields": []
    }
    
    if isinstance(event_data, dict):
        # JSON event analysis
        analysis["key_fields"] = list(event_data.keys())
        
        # Check for timestamp fields
        timestamp_fields = ['timestamp', 'time', 'TimeCreated', '@timestamp']
        for field in timestamp_fields:
            if field in event_data:
                analysis["has_timestamp"] = True
                break
        
        # Extract searchable values (IPs, usernames, domains, etc.)
        searchable_patterns = {
            "ip_addresses": [],
            "usernames": [], 
            "domains": [],
            "file_paths": [],
            "process_names": [],
            "event_codes": []
        }
        
        def extract_searchable(obj, prefix=""):
            """Recursively extract searchable values"""
            if isinstance(obj, dict):
                for key, value in obj.items():
                    field_path = f"{prefix}.{key}" if prefix else key
                    
                    # IP addresses
                    if any(ip_field in key.lower() for ip_field in ['ip', 'addr', 'host']):
                        if isinstance(value, str) and '.' in value:
                            searchable_patterns["ip_addresses"].append({"field": field_path, "value": value})
                    
                    # Usernames
                    if any(user_field in key.lower() for user_field in ['user', 'account', 'login', 'identity']):
                        if isinstance(value, str) and value:
                            searchable_patterns["usernames"].append({"field": field_path, "value": value})
                    
                    # Domains
                    if any(domain_field in key.lower() for domain_field in ['domain', 'hostname', 'fqdn']):
                        if isinstance(value, str) and '.' in value:
                            searchable_patterns["domains"].append({"field": field_path, "value": value})
                    
                    # Event codes
                    if any(code_field in key.lower() for code_field in ['event_id', 'code', 'id']):
                        if isinstance(value, (int, str)):
                            searchable_patterns["event_codes"].append({"field": field_path, "value": value})
                    
                    if isinstance(value, dict):
                        extract_searchable(value, field_path)
                    elif isinstance(value, list):
                        for i, item in enumerate(value):
                            if isinstance(item, dict):
                                extract_searchable(item, f"{field_path}[{i}]")
        
        extract_searchable(event_data)
        analysis["searchable_values"] = searchable_patterns
        
        # Correlation fields (common fields for joining events)
        correlation_candidates = []
        for field in event_data.keys():
            if any(corr_field in field.lower() for corr_field in 
                   ['user', 'ip', 'host', 'session', 'transaction', 'request_id']):
                correlation_candidates.append(field)
        analysis["correlation_fields"] = correlation_candidates
        
    else:
        # Raw event analysis
        analysis["raw_content"] = str(event_data)[:200] + "..." if len(str(event_data)) > 200 else str(event_data)
        
        # Extract basic patterns from raw text
        content = str(event_data).lower()
        if any(pattern in content for pattern in ['user', 'login', 'auth']):
            analysis["searchable_values"].append("authentication_related")
        if any(pattern in content for pattern in ['error', 'fail', 'deny']):
            analysis["searchable_values"].append("error_related")
        if any(pattern in content for pattern in ['allow', 'permit', 'success']):
            analysis["searchable_values"].append("success_related")
    
    return analysis

def validate_enterprise_scenario():
    """Comprehensive validation of the enterprise attack scenario"""
    print("🔍 ENTERPRISE ATTACK SCENARIO VALIDATION")
    print("=" * 80)
    
    # Generate scenario
    print("📝 Generating enterprise attack scenario...")
    scenario = generate_enhanced_attack_scenario()
    events = scenario["events"]
    
    print(f"✅ Generated {len(events)} events across {len(scenario['data_sources'])} sources")
    
    # Group events by source and phase
    source_analysis = {}
    phase_breakdown = {}
    
    for i, event_entry in enumerate(events):
        source = event_entry["source"]
        phase = event_entry["phase"]
        event_data = event_entry["event"]
        timestamp = event_entry["timestamp"]
        
        # Analyze event structure
        analysis = analyze_event_structure(event_data, source, phase)
        analysis["timestamp_wrapper"] = timestamp
        analysis["event_index"] = i
        
        # Group by source
        if source not in source_analysis:
            source_analysis[source] = {
                "count": 0,
                "phases": set(),
                "sample_events": [],
                "event_type": analysis["event_type"],
                "sourcetype": SOURCETYPE_MAP.get(source, f"unknown-{source}"),
                "is_json_product": source in JSON_PRODUCTS
            }
        
        source_analysis[source]["count"] += 1
        source_analysis[source]["phases"].add(phase)
        
        # Store first 2 events as samples
        if len(source_analysis[source]["sample_events"]) < 2:
            source_analysis[source]["sample_events"].append(analysis)
        
        # Group by phase
        if phase not in phase_breakdown:
            phase_breakdown[phase] = {"sources": set(), "count": 0}
        phase_breakdown[phase]["sources"].add(source)
        phase_breakdown[phase]["count"] += 1
    
    # Generate comprehensive report
    print(f"\n🏢 DATA SOURCE ANALYSIS:")
    print("-" * 60)
    
    for source, data in source_analysis.items():
        print(f"\n📊 {source.upper()}:")
        print(f"   Type: {data['event_type']}")
        print(f"   Sourcetype: {data['sourcetype']}")
        print(f"   JSON Product: {'✅' if data['is_json_product'] else '❌'}")
        print(f"   Event Count: {data['count']}")
        print(f"   Phases: {', '.join(sorted(data['phases']))}")
        
        # Show sample event structure
        if data["sample_events"]:
            sample = data["sample_events"][0]
            print(f"   Sample Event Structure:")
            
            if sample["event_type"] == "JSON":
                print(f"     🔑 Key Fields ({len(sample['key_fields'])}): {', '.join(sample['key_fields'][:10])}")
                if len(sample['key_fields']) > 10:
                    print(f"         ... and {len(sample['key_fields']) - 10} more")
                
                print(f"     ⏰ Has Timestamp: {'✅' if sample['has_timestamp'] else '❌'}")
                
                # Show searchable values
                for pattern_type, values in sample["searchable_values"].items():
                    if values:
                        print(f"     🔍 {pattern_type.title()}: {len(values)} found")
                        for value in values[:3]:  # Show first 3
                            print(f"         {value['field']} = {value['value']}")
                        if len(values) > 3:
                            print(f"         ... and {len(values) - 3} more")
            else:
                print(f"     📄 Raw Content Preview:")
                print(f"         {sample.get('raw_content', 'N/A')}")
    
    # Phase analysis
    print(f"\n🔥 ATTACK PHASE BREAKDOWN:")
    print("-" * 60)
    
    for phase, data in phase_breakdown.items():
        print(f"\n🎯 {phase.upper().replace('_', ' ')}:")
        print(f"   Event Count: {data['count']}")
        print(f"   Data Sources ({len(data['sources'])}): {', '.join(sorted(data['sources']))}")
    
    # Search guide generation
    print(f"\n🔍 SENTINELONE AI-SIEM SEARCH GUIDE:")
    print("=" * 80)
    
    search_guide = generate_search_guide(source_analysis, phase_breakdown)
    
    for phase, searches in search_guide.items():
        print(f"\n🎯 {phase.upper().replace('_', ' ')} PHASE:")
        print("-" * 40)
        
        for i, search in enumerate(searches, 1):
            print(f"{i}. {search['description']}")
            print(f"   Search: {search['query']}")
            print(f"   Expected Sources: {search['sources']}")
            if search.get('correlation_tip'):
                print(f"   💡 Correlation Tip: {search['correlation_tip']}")
            print()
    
    # Validation summary
    print(f"\n✅ VALIDATION SUMMARY:")
    print("=" * 40)
    
    json_sources = [s for s, d in source_analysis.items() if d['is_json_product']]
    raw_sources = [s for s, d in source_analysis.items() if not d['is_json_product']]
    
    print(f"📊 Total Events: {len(events)}")
    print(f"🏢 Total Sources: {len(source_analysis)}")
    print(f"🔥 Total Phases: {len(phase_breakdown)}")
    print(f"📋 JSON Sources: {len(json_sources)} - {', '.join(json_sources)}")
    print(f"📄 Raw Sources: {len(raw_sources)} - {', '.join(raw_sources)}")
    
    # Check for potential issues
    issues = []
    
    # Check timestamp coverage
    sources_without_timestamps = []
    for source, data in source_analysis.items():
        if data['sample_events'] and not data['sample_events'][0]['has_timestamp']:
            sources_without_timestamps.append(source)
    
    if sources_without_timestamps:
        issues.append(f"⚠️ Sources without internal timestamps: {', '.join(sources_without_timestamps)}")
    
    # Check sourcetype mapping
    unknown_sourcetypes = []
    for source, data in source_analysis.items():
        if data['sourcetype'].startswith('unknown-'):
            unknown_sourcetypes.append(source)
    
    if unknown_sourcetypes:
        issues.append(f"⚠️ Sources with unknown sourcetype: {', '.join(unknown_sourcetypes)}")
    
    if issues:
        print(f"\n⚠️ POTENTIAL ISSUES:")
        for issue in issues:
            print(f"   {issue}")
    else:
        print(f"\n✅ No validation issues found!")
    
    return {
        "source_analysis": source_analysis,
        "phase_breakdown": phase_breakdown,
        "search_guide": search_guide,
        "issues": issues
    }

def generate_search_guide(source_analysis, phase_breakdown):
    """Generate comprehensive search guide for each attack phase"""
    
    search_guide = {
        "reconnaissance": [
            {
                "description": "Network scanning detection (Fortigate firewall blocks)",
                "query": 'sourcetype="raw-fortinet-fortigate" AND (action=block OR action=deny) AND src_ip IN (185.220.101.45, 185.220.101.46, 185.220.101.47)',
                "sources": ["fortinet_fortigate"],
                "correlation_tip": "Look for repetitive scanning patterns from same source IPs"
            },
            {
                "description": "DNS reconnaissance queries (Cisco Umbrella)",
                "query": 'sourcetype="community-ciscoumbrella-latest" AND query_type=A AND (blocked=true OR threat_type=*)',
                "sources": ["cisco_umbrella"],
                "correlation_tip": "Correlate suspicious domains with subsequent web requests"
            },
            {
                "description": "Web application scanning (Imperva WAF)",
                "query": 'sourcetype="community-impervawaf-latest" AND (attack_type=* OR threat_level=high)',
                "sources": ["imperva_waf"],
                "correlation_tip": "Check for scanning patterns targeting specific applications"
            }
        ],
        
        "initial_compromise": [
            {
                "description": "Phishing email detection (Proofpoint)",
                "query": 'sourcetype="community-proofpoint-latest" AND (threat_type=phishing OR action=quarantine)',
                "sources": ["proofpoint"],
                "correlation_tip": "Link email timestamps with subsequent user activity"
            },
            {
                "description": "Malicious web traffic (Zscaler proxy)",
                "query": 'sourcetype="community-zscaler-latest" AND (action=blocked OR threat_name=* OR malware_category=*)',
                "sources": ["zscaler"],
                "correlation_tip": "Correlate blocked URLs with phishing email links"
            },
            {
                "description": "Payload execution detection (CrowdStrike)",
                "query": 'sourcetype="raw-crowdstrike-falcon" AND (ProcessRollup2 OR CommandLine) AND (powershell OR cmd OR rundll32)',
                "sources": ["crowdstrike_falcon"],
                "correlation_tip": "Look for process execution shortly after web visits"
            }
        ],
        
        "credential_access": [
            {
                "description": "Failed authentication attempts (Okta)",
                "query": 'sourcetype="community-oktaauthentication-latest" AND outcome.result=FAILURE AND eventType=user.authentication*',
                "sources": ["okta_authentication"],
                "correlation_tip": "Look for multiple failures followed by success from different locations"
            },
            {
                "description": "Suspicious Azure AD sign-ins",
                "query": 'sourcetype="community-microsoftazuread-latest" AND (riskLevelDuringSignIn=high OR status.errorCode!=0)',
                "sources": ["microsoft_azuread"],
                "correlation_tip": "Correlate with Okta failures and MFA bypass attempts"
            },
            {
                "description": "MFA bypass attempts (Cisco Duo)",
                "query": 'sourcetype="community-ciscoduo-latest" AND (result=FAILURE OR auth_device=*phone* OR factor_result=*)',
                "sources": ["cisco_duo"],
                "correlation_tip": "Check for approval of unexpected MFA requests"
            },
            {
                "description": "Windows credential dumping",
                "query": 'sourcetype="community-microsoftwindowseventlog-latest" AND (EventID=4624 OR EventID=4625 OR EventID=4648) AND LogonType IN (3,9,10)',
                "sources": ["microsoft_windows_eventlog"],
                "correlation_tip": "Look for LSASS access and unusual logon patterns"
            }
        ],
        
        "lateral_movement": [
            {
                "description": "Network lateral movement (Cisco ISE)",
                "query": 'sourcetype="community-ciscoise-latest" AND (FailureReason=* OR AuthenticationStatus=fail OR RadiusFlowType=*)',
                "sources": ["cisco_ise"],
                "correlation_tip": "Track device movement across network segments"
            },
            {
                "description": "Load balancer traffic anomalies (F5 Networks)",
                "query": 'sourcetype="community-f5networks-latest" AND (response_code>=400 OR connection_errors>0)',
                "sources": ["f5_networks"],
                "correlation_tip": "Unusual internal traffic patterns between systems"
            },
            {
                "description": "Remote desktop sessions (Windows)",
                "query": 'sourcetype="community-microsoftwindowseventlog-latest" AND EventID=4624 AND LogonType=10',
                "sources": ["microsoft_windows_eventlog"],
                "correlation_tip": "Chain RDP sessions across multiple hosts"
            }
        ],
        
        "privilege_escalation": [
            {
                "description": "AWS IAM privilege changes (CloudTrail)",
                "query": 'sourcetype="community-awscloudtrail-latest" AND eventName IN (AttachUserPolicy, CreateRole, AssumeRole) AND errorCode!=*',
                "sources": ["aws_cloudtrail"],
                "correlation_tip": "Look for rapid privilege elevation and resource access"
            },
            {
                "description": "HashiCorp Vault secret access",
                "query": 'sourcetype="community-hashicorpvault-latest" AND operation=read AND path=*secret*',
                "sources": ["hashicorp_vault"],
                "correlation_tip": "Unusual secret access patterns by compromised accounts"
            },
            {
                "description": "Windows admin privilege escalation",
                "query": 'sourcetype="community-microsoftwindowseventlog-latest" AND EventID=4672 AND SubjectUserName!=*SYSTEM*',
                "sources": ["microsoft_windows_eventlog"],
                "correlation_tip": "New admin privileges for previously standard users"
            }
        ],
        
        "data_discovery": [
            {
                "description": "Database queries (Imperva WAF)",
                "query": 'sourcetype="community-impervawaf-latest" AND sql_injection_attack=true OR database_activity=*',
                "sources": ["imperva_waf"],
                "correlation_tip": "Unusual database enumeration and large result sets"
            },
            {
                "description": "AWS S3 bucket enumeration",
                "query": 'sourcetype="community-awscloudtrail-latest" AND eventName IN (ListBuckets, GetObject, GetBucketLocation)',
                "sources": ["aws_cloudtrail"],
                "correlation_tip": "Systematic bucket discovery and data access patterns"
            },
            {
                "description": "GitHub repository access",
                "query": 'sourcetype="community-githubaudit-latest" AND action IN (git.clone, repo.access, org.member_team_add)',
                "sources": ["github_audit"],
                "correlation_tip": "Unusual repository access by compromised accounts"
            }
        ],
        
        "data_exfiltration": [
            {
                "description": "Large data transfers (Zscaler)",
                "query": 'sourcetype="community-zscaler-latest" AND bytes_out>10000000 AND urlcategory=*cloud*',
                "sources": ["zscaler"],
                "correlation_tip": "Abnormal upload volumes to cloud storage services"
            },
            {
                "description": "DNS tunneling (Cisco Umbrella)",
                "query": 'sourcetype="community-ciscoumbrella-latest" AND query_type=TXT AND response_size>100',
                "sources": ["cisco_umbrella"],
                "correlation_tip": "Unusual DNS query patterns with large responses"
            },
            {
                "description": "Cloud upload activity (Netskope)",
                "query": 'sourcetype="community-netskope-latest" AND activity=upload AND (app=*dropbox* OR app=*gdrive* OR app=*onedrive*)',
                "sources": ["netskope"],
                "correlation_tip": "Large file uploads to personal cloud storage"
            }
        ],
        
        "persistence": [
            {
                "description": "CI/CD pipeline modifications (Harness)",
                "query": 'sourcetype="raw-harness-ci" AND (pipeline_modified=true OR webhook_created=* OR secret_access=*)',
                "sources": ["harness_ci"],
                "correlation_tip": "Backdoors inserted into deployment pipelines"
            },
            {
                "description": "AWS persistent access (CloudTrail)",
                "query": 'sourcetype="community-awscloudtrail-latest" AND eventName IN (CreateAccessKey, CreateUser, CreateRole) AND errorCode!=*',
                "sources": ["aws_cloudtrail"],
                "correlation_tip": "Creation of persistent access mechanisms"
            },
            {
                "description": "Windows scheduled tasks",
                "query": 'sourcetype="community-microsoftwindowseventlog-latest" AND EventID=4698 AND TaskName!=*Microsoft*',
                "sources": ["microsoft_windows_eventlog"],
                "correlation_tip": "Suspicious scheduled tasks for persistence"
            }
        ],
        
        "detection": [
            {
                "description": "Fraud detection alerts (PingProtect)",
                "query": 'sourcetype="community-pingprotect-latest" AND risk_score>80 AND action=*block*',
                "sources": ["pingprotect"],
                "correlation_tip": "High-risk transactions flagged by fraud detection"
            },
            {
                "description": "EDR detection and response (CrowdStrike)",
                "query": 'sourcetype="raw-crowdstrike-falcon" AND (DetectName=* OR ThreatHuntingStatus=* OR FileName=*suspicious*)',
                "sources": ["crowdstrike_falcon"],
                "correlation_tip": "Endpoint detection of attack tools and techniques"
            }
        ]
    }
    
    return search_guide

if __name__ == "__main__":
    validation_results = validate_enterprise_scenario()
    
    print(f"\n💾 Saving validation results...")
    with open("enterprise_scenario_validation_report.json", "w") as f:
        # Convert sets to lists for JSON serialization
        serializable_results = {}
        for key, value in validation_results.items():
            if key == "source_analysis":
                serializable_results[key] = {}
                for source, data in value.items():
                    serializable_results[key][source] = {**data}
                    serializable_results[key][source]["phases"] = list(data["phases"])
            elif key == "phase_breakdown":
                serializable_results[key] = {}
                for phase, data in value.items():
                    serializable_results[key][phase] = {**data}
                    serializable_results[key][phase]["sources"] = list(data["sources"])
            else:
                serializable_results[key] = value
        
        json.dump(serializable_results, f, indent=2, default=str)
    
    print(f"✅ Validation complete! Report saved to enterprise_scenario_validation_report.json")