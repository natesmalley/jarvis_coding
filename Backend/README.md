# Security Event Generation and Parser Validation

Synthetic security event generators, parser metadata, and an API for sending events to SentinelOne AI SIEM via HEC. This repo helps you quickly validate field extraction and formatting across many vendor sources.

## Project Layout
- `api/`: FastAPI service (`app/` modules, `tests/`, `start_api.py`).
- `event_generators/`: Vendor generators and shared HEC sender.
- `parsers/`: Community/marketplace parser folders (`*-latest`).
- `scenarios/`: Example scenario configs for demos.
- `testing/`: Validation utilities and scripts.
- `docs/`: Extended docs (validation, guides).

## Quick Start

### Docker (Recommended)
1. **Create environment file** (first time only):
```bash
# From the repository root
cp ".env copy" .env
```

2. **Start services**:
```bash
docker-compose up --build
```
- API: http://localhost:8000
- API Docs: http://localhost:8000/docs
- Frontend UI: http://localhost:9001

**Note**: The default `.env` has `DISABLE_AUTH=true` for easy local development. No API keys needed!

### Local Python Development
```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r api/requirements.txt

# Run API
python api/start_api.py  # http://localhost:8000

# Send events to HEC (set env first)
export S1_HEC_TOKEN=...  # and optionally S1_HEC_URL
python event_generators/shared/hec_sender.py --product crowdstrike_falcon -n 3
```

## Configuration

### Environment Setup (.env)
The project uses a `.env` file for configuration. Copy the template to get started:
```bash
cp ".env copy" .env
```

### Authentication
By default, authentication is **disabled** for local development:
- `DISABLE_AUTH=true` - No API keys required (great for getting started!)
- `BACKEND_API_KEY` - Not needed when auth is disabled

For production environments, enable authentication:
```bash
DISABLE_AUTH=false
API_KEYS_ADMIN=your-secure-api-key-here
BACKEND_API_KEY=your-secure-api-key-here  # Used by frontend
```

Generate secure API keys using:
```bash
python -c "import secrets; print(secrets.token_urlsafe(32))"
```

After changing `.env`, restart services:
```bash
docker-compose down && docker-compose up -d
```

## Validation
- End‑to‑end validation workflow and troubleshooting are documented in `docs/VALIDATION.md`.
- The HEC sender now prefers dynamic sourcetype mappings by scanning `parsers/*/*-latest`, with explicit overrides where needed.

## Contributing
- See `AGENTS.md` for contributor guidelines (style, tests, PRs).
- `aws_cloudtrail`: AWS CloudTrail events
- `aws_elb`: AWS Elastic Load Balancer logs
- `aws_guardduty`: AWS GuardDuty findings
- `aws_elasticloadbalancer`: AWS Elastic Load Balancer logs
- `aws_route53`: AWS Route 53 DNS query logs
- `aws_vpc_dns`: AWS VPC DNS query logs
- `aws_vpcflow`: AWS VPC Flow Logs  
- `aws_vpcflowlogs`: AWS VPC Flow Logs
- `aws_waf`: AWS Web Application Firewall logs
- `google_cloud_dns`: Google Cloud DNS query and audit events
- `google_workspace`: Google Workspace admin and user activity events

### Network Security & Infrastructure
- `akamai_cdn`: Akamai CDN access and performance logs
- `akamai_dns`: Akamai DNS resolution and security logs
- `akamai_general`: Akamai general security and performance events
- `akamai_sitedefender`: Akamai SiteDefender WAF security events
- `cisco_asa`: Cisco ASA firewall logs
- `cisco_duo`: Cisco Duo multi-factor authentication events
- `cisco_fmc`: Cisco Firepower Management Center security events
- `cisco_ios`: Cisco IOS network device syslog events
- `cisco_ironport`: Cisco IronPort Email Security Appliance logs
- `cisco_isa3000`: Cisco ISA3000 industrial security appliance events
- `cisco_ise`: Cisco Identity Services Engine authentication events
- `cisco_firewall_threat_defense`: Cisco Firewall Threat Defense logs
- `cisco_meraki`: Cisco Meraki logs
- `cisco_meraki_flow`: Cisco Meraki Flow logs
- `cisco_networks`: Cisco network infrastructure events
- `cisco_umbrella`: Cisco Umbrella DNS logs
- `cloudflare_general`: Cloudflare security and performance events
- `corelight_conn`: Corelight network connection logs
- `corelight_http`: Corelight HTTP traffic logs
- `corelight_ssl`: Corelight SSL/TLS logs
- `corelight_tunnel`: Corelight tunnel traffic logs
- `extreme_networks`: Extreme Networks switch and access point events
- `f5_networks`: F5 BIG-IP load balancer and security events
- `f5_vpn`: F5 VPN access and session logs
- `fortinet_fortigate`: FortiGate firewall logs (multiple types)
- `isc_bind`: ISC BIND DNS server query and security logs
- `isc_dhcp`: ISC DHCP server lease and network logs
- `juniper_networks`: Juniper Networks device events
- `paloalto_prismasase`: Palo Alto Prisma SASE security and network events
- `ubiquiti_unifi`: Ubiquiti UniFi network equipment events
- `zscaler`: Zscaler proxy logs
- `zscaler_dns_firewall`: Zscaler DNS firewall security events
- `zscaler_firewall`: Zscaler firewall and security events

### Endpoint & Identity Security
- `abnormal_security`: Abnormal Security email security events
- `armis`: Armis IoT device discovery and security events
- `crowdstrike_falcon`: CrowdStrike Falcon endpoint events
- `hypr_auth`: HYPR passwordless authentication events
- `iis_w3c`: Microsoft IIS W3C web server logs
- `jamf_protect`: Jamf Protect macOS endpoint security events
- `linux_auth`: Linux authentication logs (/var/log/auth.log)
- `microsoft_365_collaboration`: Microsoft 365 SharePoint/OneDrive collaboration events
- `microsoft_365_defender`: Microsoft 365 Defender endpoint security events
- `microsoft_azure_ad_signin`: Microsoft Azure AD signin events
- `microsoft_azuread`: Azure AD audit logs
- `microsoft_defender_email`: Microsoft Defender for Office 365 events
- `microsoft_windows_eventlog`: Microsoft Windows Event Log events
- `okta_authentication`: Okta authentication events
- `pingfederate`: PingFederate SSO authentication and provisioning events
- `pingone_mfa`: PingOne multi-factor authentication events
- `pingprotect`: PingProtect fraud detection and authentication events
- `rsa_adaptive`: RSA Adaptive Authentication risk-based security events
- `sentinelone_endpoint`: SentinelOne XDR endpoint events (servers, workstations, Kubernetes)
- `sentinelone_identity`: SentinelOne Ranger AD identity/authentication events

### Email Security
- `mimecast`: Mimecast email security events
- `proofpoint`: Proofpoint email security events

### Web Application Security
- `imperva_sonar`: Imperva Sonar database security and compliance logs
- `imperva_waf`: Imperva Web Application Firewall security events
- `incapsula`: Imperva Incapsula WAF security events

### Privileged Access & Identity Management
- `beyondtrust_passwordsafe`: BeyondTrust Password Safe audit events
- `beyondtrust_privilegemgmtwindows`: BeyondTrust Privilege Management Windows logs
- `cyberark_conjur`: CyberArk Conjur secrets management audit events
- `cyberark_pas`: CyberArk Privileged Access Security events
- `hashicorp_vault`: HashiCorp Vault secrets management events
- `securelink`: SecureLink privileged remote access events

### SIEM & Analytics
- `darktrace`: Darktrace AI-powered threat detection events
- `darktrace_darktrace`: Darktrace AI-powered threat detection events
- `extrahop`: ExtraHop network detection and response events
- `manch_siem`: Manchester SIEM security events and alerts
- `vectra_ai`: Vectra AI network detection and response events

### IT Management & Data Protection
- `axway_sftp`: Axway SFTP file transfer and audit logs
- `cohesity_backup`: Cohesity data management and backup logs
- `github_audit`: GitHub repository and organization audit logs
- `manageengine_adauditplus`: ManageEngine AD Audit Plus events
- `manageengine_general`: ManageEngine IT management and security events
- `microsoft_365_mgmt_api`: Microsoft 365 Management API events
- `microsoft_azure_ad`: Microsoft Azure AD events
- `microsoft_eventhub_azure_signin`: Microsoft EventHub Azure Signin events
- `microsoft_eventhub_defender_email`: Microsoft EventHub Defender Email events
- `microsoft_eventhub_defender_emailforcloud`: Microsoft EventHub Defender Email for Cloud events
- `sap`: SAP ERP, HANA, and security audit events
- `veeam_backup`: Veeam backup and recovery operations logs
- `wiz_cloud`: Wiz cloud security posture and compliance events

### DevOps & CI/CD
- `buildkite`: Buildkite CI/CD audit and pipeline events
- `harness_ci`: Harness CI/CD pipeline and deployment logs
- `teleport`: Teleport access proxy events (SSH, database, Kubernetes)

### Network Access & VPN
- `apache_http`: Apache HTTP server access logs
- `netskope`: Netskope cloud security events
- `tailscale`: Tailscale zero-trust network access events

## Attack Scenario Generation

### Quick Scenarios
Generate focused attack scenarios for testing:
```bash
python event_python_writer/quick_scenario.py
```
Available scenarios: `phishing_attack`, `insider_threat`, `malware_outbreak`, `credential_stuffing`, `data_breach`

### Full APT Campaign Simulation
Generate comprehensive 14-day attack campaigns:
```bash
# Generate a complete attack campaign
python event_python_writer/attack_scenario_orchestrator.py

# Send generated scenario to HEC with timing control
python event_python_writer/scenario_hec_sender.py
```

### Scenario Features
- **Multi-platform correlation**: Events span email, identity, endpoint, network, cloud, and privileged access platforms
- **Realistic attack progression**: 5-phase attack chain (reconnaissance → initial access → persistence → escalation → exfiltration)
- **Temporal correlation**: Events follow realistic timing patterns
- **Threat intelligence**: Incorporates real attack techniques and IOCs

## Parser Testing & Validation

### End-to-End Testing Framework
The comprehensive testing framework validates parser effectiveness in production by:
1. **Generating test events** with unique tracking IDs
2. **Sending to HEC endpoint** via proven hec_sender.py
3. **Waiting for indexing** and parsing (configurable delay)
4. **Querying SDL API** to retrieve parsed events
5. **Analyzing field extraction** effectiveness vs expectations
6. **Generating detailed reports** with actionable insights

### Key Testing Tools

#### Complete Pipeline Testing
```bash
# Test all parsers with full HEC → SDL API validation
python event_python_writer/end_to_end_pipeline_tester.py

# Test specific parser subset
python event_python_writer/end_to_end_pipeline_tester.py --parsers aws_waf,cisco_duo
```

#### Comprehensive Analysis (Without API Dependency)
```bash
# Analyze all parsers for effectiveness without API calls
python event_python_writer/comprehensive_parser_effectiveness_tester.py
```

#### Field Mapping Analysis
```bash
# Analyze field matching between generators and parsers
python event_python_writer/comprehensive_field_matcher.py
```

### Testing Results Summary (Latest: September 2025)
- **Total Generators**: 100+ generators across all security categories
- **Working Generators**: 98+ generators functional (98% success rate)
- **Parser Coverage**: 100+ community and marketplace parsers available
- **Field Extraction**: Top performers extracting 240-294 fields
- **OCSF Compliance**: 100% compliance achieved by excellent parsers
- **AWS Compatibility**: Enhanced marketplace parser integration
- **Corporate Test Data**: Professional test data across all generators

## Architecture

### Event Generators
- Each generator is self-contained (<200 lines)
- Uses only Python standard library (except `hec_sender.py` which requires `requests`)
- Returns structured JSON events
- Includes AI-SIEM specific attributes for parser compatibility

### Parser Structure
Each parser directory contains:
- JSON configuration with parsing rules
- `metadata.yaml` with parser metadata
- Parser naming convention: `<vendor>_<product>_<description>-latest/`

### Key Patterns
1. Generators follow naming convention: `<vendor>_<product>.py`
2. Each generator exports a `<product>_log()` function returning a dictionary
3. `hec_sender.py` maps products to their respective generators
4. Parsers use JSON schema definitions for field mapping
5. Testing framework validates end-to-end pipeline effectiveness

## Environment Variables

### For Event Generation & HEC Sending
```bash
export S1_HEC_TOKEN="your-hec-token-here"
```

### For SDL API Querying (Parser Testing)
```bash
export S1_SDL_API_TOKEN="your-read-api-token-here"
```

## File Structure

```
├── README.md                                    # Project overview and setup guide
├── RELEASE_NOTES.md                            # Comprehensive release notes  
├── CHANGELOG.md                                 # Version history and changes
├── CLAUDE.md                                    # Development guidance for Claude Code
├── detections.conf                              # SentinelOne detection rules
├── event_generators/                           # Organized security event generators
│   ├── cloud_infrastructure/                   # AWS, Google Cloud, Azure (9 generators)
│   ├── network_security/                      # Firewalls, NDR, network devices (34 generators)
│   ├── endpoint_security/                     # EDR, endpoint protection (6 generators)
│   ├── identity_access/                       # IAM, authentication, PAM (20 generators)
│   ├── email_security/                        # Email security platforms (4 generators)
│   ├── web_security/                          # WAF, web proxies, CDN (13 generators)
│   ├── infrastructure/                        # IT management, backup, DevOps (20 generators)
│   └── shared/                                # Common utilities and HEC sender
├── parsers/community/                         # 100+ JSON-based parser configurations
├── scenarios/                                 # Attack simulation scenarios
├── testing/                                  # Comprehensive validation tools
│   ├── validation/                           # Parser effectiveness testing
│   ├── bulk_testing/                         # Bulk event sending and testing
│   └── utilities/                            # Testing utilities and fixes
├── utilities/                                # Supporting tools and scripts
│   ├── continuous_senders/                  # Continuous data streaming utilities
│   └── parsers/                             # Parser management tools
├── api/                                      # REST API implementation
├── docs/                                     # Comprehensive documentation
└── archive/                                  # Historical data and deprecated files
```

## Recent Major Improvements

### Repository Cleanup & Security (v2.2.0)
- **Security Enhancements**: Removed sensitive .coral files from version control
- **AWS Generator Fixes**: Updated CloudTrail, VPC Flow Logs, Route 53, GuardDuty, and WAF for better parser compatibility
- **Corporate Test Data**: Professional business-appropriate test data across all generators
- **Directory Organization**: Clean, organized structure with archived historical data
- **Continuous Data Senders**: New utilities for ongoing event streaming

### Parser Infrastructure (v2.0.0+)
- **100+ Generators**: Comprehensive coverage across all major security vendors
- **OCSF 1.1.0 Compliance**: All parsers follow Open Cybersecurity Schema Framework standards
- **Marketplace Integration**: 90+ SentinelOne marketplace parsers with enhanced field extraction
- **JSON-Based Configuration**: Modern parser format replacing legacy configurations
- **Enhanced Field Mapping**: Comprehensive OCSF schema mapping with observables extraction

### API Production Release (v2.1.0)
- **Complete REST API**: Production-ready API with 100+ generator endpoints
- **Authentication System**: Role-based access control with API key management
- **Interactive Documentation**: Swagger UI and comprehensive developer guides
- **Performance Optimization**: Sub-100ms response times with concurrent request handling
- **Monitoring & Metrics**: API usage tracking and performance monitoring

### Testing & Validation Framework
- **End-to-End Testing**: Real HEC ingestion and SDL API validation
- **Comprehensive Analysis**: Field extraction effectiveness measurement
- **Production Validation**: Actual parser performance in SentinelOne environment
- **Automated Testing**: Continuous validation across all generators and parsers
- **Performance Metrics**: Detailed reporting on extraction rates and compatibility

## Adding New Generators

1. **Create Generator File**: Follow naming convention `<vendor>_<product>.py` in appropriate category directory
2. **Implement Function**: Create `<product>_log()` function returning event dictionary
3. **Use Corporate Test Data**: Include professional business-appropriate test data
4. **Update HEC Sender**: Add to `PROD_MAP` and `SOURCETYPE_MAP` in `hec_sender.py`
5. **Test Compatibility**: Validate with corresponding parser using testing framework
6. **Update Documentation**: Add to README.md and create generator-specific docs
7. **Validate OCSF**: Ensure parser compatibility and field extraction

## Contributing

1. **Follow Patterns**: Use existing generator architecture and corporate test data standards
2. **Realistic Events**: Include appropriate field values matching actual vendor log formats
3. **Parser Compatibility**: Ensure events work with corresponding SentinelOne parsers
4. **Comprehensive Testing**: Use validation framework to test generators and parsers
5. **Documentation**: Update guides, README, and create usage examples
6. **Security Compliance**: Follow OCSF standards and security best practices
7. **Professional Data**: Use corporate business examples, not themed test data

## License

This project is designed for defensive security testing and research purposes. Use responsibly and in accordance with your organization's security policies.
