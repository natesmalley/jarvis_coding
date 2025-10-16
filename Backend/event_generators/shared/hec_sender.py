#!/usr/bin/env python3
"""Send logs from vendor_product generators to SentinelOne AI SIEM (Splunk‑HEC) one‑by‑one."""
import argparse, json, os, time, random, requests, importlib, sys
import gzip, io, threading
from typing import Callable, Tuple, Optional

# Add generator category paths to sys.path
import os
import sys
current_dir = os.path.dirname(os.path.abspath(__file__))
generator_root = os.path.dirname(current_dir)
for category in ['cloud_infrastructure', 'network_security', 'endpoint_security', 
                 'identity_access', 'email_security', 'web_security', 'infrastructure']:
    sys.path.insert(0, os.path.join(generator_root, category))
sys.path.insert(0, current_dir)  # for local imports like parser_map

try:
    # Prefer dynamic sourcetype discovery from the parsers directory
    from parser_map import load_sourcetypes  # type: ignore
    _REPO_ROOT = os.path.dirname(generator_root)
    _PARSERS_DIR = os.path.join(_REPO_ROOT, 'parsers')
    _LOADED_SOURCETYPE_MAP = load_sourcetypes(_PARSERS_DIR)
except Exception:
    _LOADED_SOURCETYPE_MAP = {}


# Marketplace parser mappings to generators
MARKETPLACE_PARSER_MAP = {
    # AWS parsers
    "marketplace-awscloudtrail-latest": "aws_cloudtrail",
    "marketplace-awscloudtrail-1.0.0": "aws_cloudtrail",
    "marketplace-awselasticloadbalancer-latest": "aws_elasticloadbalancer",
    "marketplace-awsguardduty-latest": "aws_guardduty",
    "marketplace-awsvpcflowlogs-latest": "aws_vpcflowlogs",
    "marketplace-awsvpcflowlogs-1.0.0": "aws_vpcflowlogs",
    
    # Check Point
    "marketplace-checkpointfirewall-latest": "checkpoint",
    "marketplace-checkpointfirewall-1.0.0": "checkpoint",
    "marketplace-checkpointfirewall-1.0.1": "checkpoint",
    
    # Cisco parsers
    "marketplace-ciscofirepowerthreatdefense-latest": "cisco_firewall_threat_defense",
    "marketplace-ciscofirepowerthreatdefense-1.0.0": "cisco_firewall_threat_defense",
    "marketplace-ciscofirepowerthreatdefense-2.0.0": "cisco_firewall_threat_defense",
    "marketplace-ciscofirewallthreatdefense-latest": "cisco_firewall_threat_defense",
    "marketplace-ciscofirewallthreatdefense-1.0.0": "cisco_firewall_threat_defense",
    "marketplace-ciscofirewallthreatdefense-1.0.1": "cisco_firewall_threat_defense",
    "marketplace-ciscofirewallthreatdefense-1.0.2": "cisco_firewall_threat_defense",
    "marketplace-ciscofirewallthreatdefense-1.0.3": "cisco_firewall_threat_defense",
    "marketplace-ciscoumbrella-latest": "cisco_umbrella",
    
    # Corelight parsers
    "marketplace-corelight-conn-latest": "corelight_conn",
    "marketplace-corelight-conn-1.0.0": "corelight_conn",
    "marketplace-corelight-conn-1.0.1": "corelight_conn",
    "marketplace-corelight-conn-2.0.0": "corelight_conn",
    "marketplace-corelight-http-latest": "corelight_http",
    "marketplace-corelight-http-1.0.0": "corelight_http",
    "marketplace-corelight-http-1.0.1": "corelight_http",
    "marketplace-corelight-http-2.0.0": "corelight_http",
    "marketplace-corelight-ssl-latest": "corelight_ssl",
    "marketplace-corelight-ssl-1.0.0": "corelight_ssl",
    "marketplace-corelight-ssl-1.0.1": "corelight_ssl",
    "marketplace-corelight-ssl-2.0.0": "corelight_ssl",
    "marketplace-corelight-tunnel-latest": "corelight_tunnel",
    "marketplace-corelight-tunnel-1.0.0": "corelight_tunnel",
    "marketplace-corelight-tunnel-2.0.0": "corelight_tunnel",
    
    # Fortinet parsers
    "marketplace-fortinetfortigate-latest": "fortinet_fortigate",
    "marketplace-fortinetfortigate-1.0.0": "fortinet_fortigate",
    "marketplace-fortinetfortigate-1.0.1": "fortinet_fortigate",
    "marketplace-fortinetfortigate-1.0.2": "fortinet_fortigate",
    "marketplace-fortinetfortigate-1.0.3": "fortinet_fortigate",
    "marketplace-fortinetfortigate-1.0.4": "fortinet_fortigate",
    "marketplace-fortinetfortigate-1.0.5": "fortinet_fortigate",
    "marketplace-fortinetfortigate-1.0.6": "fortinet_fortigate",
    "marketplace-fortinetfortimanager-latest": "fortimanager",
    "marketplace-fortinetfortimanager-1.0.0": "fortimanager",
    "marketplace-fortinetfortimanager-1.0.1": "fortimanager",
    "marketplace-fortinetfortimanager-2.0.0": "fortimanager",
    
    # Infoblox
    "marketplace-infobloxddi-latest": "infoblox_ddi",
    "marketplace-infobloxddi-1.0.0": "infoblox_ddi",
    "marketplace-infobloxddi-2.0.0": "infoblox_ddi",
    
    # Netskope
    "marketplace-netskopecloudlogshipper-latest": "netskope",
    "marketplace-netskopecloudlogshipper-1.0.0": "netskope",
    "marketplace-netskopecloudlogshipper-1.0.1": "netskope",
    "marketplace-netskopecloudlogshipper-1.0.2": "netskope",
    "marketplace-netskopecloudlogshipper-1.0.3": "netskope",
    "marketplace-netskopecloudlogshipperjson-latest": "netskope",
    "marketplace-netskopecloudlogshipperjson-1.0.0": "netskope",
    
    # Palo Alto Networks
    "marketplace-paloaltonetworksfirewall-latest": "paloalto_firewall",
    "marketplace-paloaltonetworksfirewall-1.0.0": "paloalto_firewall",
    "marketplace-paloaltonetworksfirewall-1.0.1": "paloalto_firewall",
    "marketplace-paloaltonetworksfirewall-1.0.2": "paloalto_firewall",
    "marketplace-paloaltonetworksfirewall-2.0.0": "paloalto_firewall",
    "marketplace-paloaltonetworksfirewall-2.0.1": "paloalto_firewall",
    "marketplace-paloaltonetworksfirewall-2.0.2": "paloalto_firewall",
    "marketplace-paloaltonetworksfirewall-2.0.3": "paloalto_firewall",
    "marketplace-paloaltonetworksfirewall-2.0.4": "paloalto_firewall",
    "marketplace-paloaltonetworksfirewall-2.0.5": "paloalto_firewall",
    "marketplace-paloaltonetworksfirewall-3.0.0": "paloalto_firewall",
    "marketplace-paloaltonetworksfirewall-3.0.1": "paloalto_firewall",
    "marketplace-paloaltonetworksfirewall-3.0.2": "paloalto_firewall",
    "marketplace-paloaltonetworksfirewall-3.0.3": "paloalto_firewall",
    "marketplace-paloaltonetworksprismaaccess-latest": "paloalto_prismasase",
    "marketplace-paloaltonetworksprismaaccess-1.0.0": "paloalto_prismasase",
    
    # Zscaler parsers
    "marketplace-zscalerinternetaccess-latest": "zscaler",
    "marketplace-zscalerinternetaccess-1.0.0": "zscaler",
    "marketplace-zscalerinternetaccess-1.0.1": "zscaler",
    "marketplace-zscalerinternetaccess-2.0.0": "zscaler",
    "marketplace-zscalerinternetaccess-3.0.0": "zscaler",
    "marketplace-zscalerprivateaccess-latest": "zscaler_private_access",
    "marketplace-zscalerprivateaccess-1.0.0": "zscaler_private_access",
    "marketplace-zscalerprivateaccess-2.0.0": "zscaler_private_access",
    "marketplace-zscalerprivateaccessjson-latest": "zscaler_private_access",
    "marketplace-zscalerprivateaccessjson-1.0.0": "zscaler_private_access",
}

# Map product → (module_name, generator function names)
PROD_MAP = {
    "fortinet_fortigate": (
        "fortinet_fortigate",
        ["local_log", "forward_log", "rest_api_log", "vpn_log", "virus_log"],
    ),
    "zscaler": (
        "zscaler",
        ["zscaler_log"],  # Use JSON format for gron parser compatibility
    ),
    "aws_cloudtrail": (
        "aws_cloudtrail",
        ["cloudtrail_log"],
    ),
    "aws_vpcflowlogs": (
        "aws_vpcflowlogs",
        ["vpcflow_log"],
    ),
    "aws_guardduty": (
        "aws_guardduty",
        ["guardduty_log"],
    ),
    "microsoft_azuread": (
        "microsoft_azuread",
        ["azuread_log"],
    ),
    "okta_authentication": (
        "okta_authentication",
        ["okta_authentication_log"],
    ),
    "cisco_asa": (
        "cisco_asa",
        ["asa_log"],
    ),
    "cisco_umbrella": (
        "cisco_umbrella",
        ["cisco_umbrella_log"],
    ),
    "cisco_meraki": (
        "cisco_meraki",
        ["cisco_meraki_log"],
    ),
    "crowdstrike_falcon": (
        "crowdstrike_falcon",
        ["crowdstrike_log"],
    ),
    "cyberark_pas": (
        "cyberark_pas",
        ["cyberark_pas_log"],
    ),
    "darktrace": (
        "darktrace",
        ["darktrace_log"],
    ),
    "proofpoint": (
        "proofpoint",
        ["proofpoint_log"],
    ),
    "microsoft_365_mgmt_api": (
        "microsoft_365_mgmt_api",
        ["microsoft_365_mgmt_api_log"],
    ),
    "netskope": (
        "netskope",
        ["netskope_log"],
    ),
    "mimecast": (
        "mimecast",
        ["mimecast_log"],
    ),
    "microsoft_azure_ad_signin": (
        "microsoft_azure_ad_signin",
        ["microsoft_azure_ad_signin_log"],
    ),
    "microsoft_defender_email": (
        "microsoft_defender_email",
        ["microsoft_defender_email_log"],
    ),
    "beyondtrust_passwordsafe": (
        "beyondtrust_passwordsafe",
        ["beyondtrust_passwordsafe_log"],
    ),
    "hashicorp_vault": (
        "hashicorp_vault",
        ["hashicorp_vault_log"],
    ),
    "corelight_conn": (
        "corelight_conn",
        ["corelight_conn_log"],
    ),
    "corelight_http": (
        "corelight_http",
        ["corelight_http_log"],
    ),
    "corelight_ssl": (
        "corelight_ssl",
        ["corelight_ssl_log"],
    ),
    "corelight_tunnel": (
        "corelight_tunnel",
        ["corelight_tunnel_log"],
    ),
    "vectra_ai": (
        "vectra_ai",
        ["vectra_ai_log"],
    ),
    "tailscale": (
        "tailscale",
        ["tailscale_log"],
    ),
    "extrahop": (
        "extrahop",
        ["extrahop_log"],
    ),
    "armis": (
        "armis",
        ["armis_log"],
    ),
    "sentinelone_endpoint": (
        "sentinelone_endpoint",
        ["sentinelone_endpoint_log"],
    ),
    "sentinelone_identity": (
        "sentinelone_identity",
        ["sentinelone_identity_log"],
    ),
    "apache_http": (
        "apache_http",
        ["apache_http_log"],
    ),
    "abnormal_security": (
        "abnormal_security",
        ["abnormal_security_log"],
    ),
    "buildkite": (
        "buildkite",
        ["buildkite_log"],
    ),
    "teleport": (
        "teleport",
        ["teleport_log"],
    ),
    "cisco_ise": (
        "cisco_ise",
        ["cisco_ise_log"],
    ),
    "google_workspace": (
        "google_workspace",
        ["google_workspace_log"],
    ),
    "aws_vpc_dns": (
        "aws_vpc_dns",
        ["aws_vpc_dns_log"],
    ),
    "cisco_networks": (
        "cisco_networks",
        ["cisco_networks_log"],
    ),
    "cloudflare_general": (
        "cloudflare_general",
        ["cloudflare_general_log"],
    ),
    "cloudflare_waf": (
        "cloudflare_waf",
        ["cloudflare_waf_log"],
    ),
    "extreme_networks": (
        "extreme_networks",
        ["extreme_networks_log"],
    ),
    "f5_networks": (
        "f5_networks",
        ["f5_networks_log"],
    ),
    "google_cloud_dns": (
        "google_cloud_dns",
        ["google_cloud_dns_log"],
    ),
    "imperva_waf": (
        "imperva_waf",
        ["imperva_waf_log"],
    ),
    "juniper_networks": (
        "juniper_networks",
        ["juniper_networks_log"],
    ),
    "ubiquiti_unifi": (
        "ubiquiti_unifi",
        ["ubiquiti_unifi_log"],
    ),
    "zscaler_firewall": (
        "zscaler_firewall",
        ["zscaler_firewall_log"],
    ),
    "cisco_fmc": (
        "cisco_fmc",
        ["cisco_fmc_log"],
    ),
    "cisco_ios": (
        "cisco_ios",
        ["cisco_ios_log"],
    ),
    "cisco_isa3000": (
        "cisco_isa3000",
        ["cisco_isa3000_log"],
    ),
    "incapsula": (
        "incapsula",
        ["incapsula_log"],
    ),
    "manageengine_general": (
        "manageengine_general",
        ["manageengine_general_log"],
    ),
    "manch_siem": (
        "manch_siem",
        ["manch_siem_log"],
    ),
    "microsoft_windows_eventlog": (
        "microsoft_windows_eventlog",
        ["microsoft_windows_eventlog_log"],
    ),
    "paloalto_prismasase": (
        "paloalto_prismasase",
        ["paloalto_prismasase_log"],
    ),
    "sap": (
        "sap",
        ["sap_log"],
    ),
    "securelink": (
        "securelink",
        ["securelink_log"],
    ),
    "aws_waf": (
        "aws_waf",
        ["aws_waf_log"],
    ),
    "aws_route53": (
        "aws_route53",
        ["aws_route53_log"],
    ),
    "cisco_ironport": (
        "cisco_ironport",
        ["cisco_ironport_log"],
    ),
    "cyberark_conjur": (
        "cyberark_conjur",
        ["cyberark_conjur_log"],
    ),
    "iis_w3c": (
        "iis_w3c",
        ["iis_w3c_log"],
    ),
    "linux_auth": (
        "linux_auth",
        ["linux_auth_log"],
    ),
    "microsoft_365_collaboration": (
        "microsoft_365_collaboration",
        ["microsoft_365_collaboration_log"],
    ),
    "microsoft_365_defender": (
        "microsoft_365_defender",
        ["microsoft_365_defender_log"],
    ),
    "pingfederate": (
        "pingfederate",
        ["pingfederate_log"],
    ),
    "zscaler_dns_firewall": (
        "zscaler_dns_firewall",
        ["zscaler_dns_firewall_log"],
    ),
    "akamai_cdn": (
        "akamai_cdn",
        ["akamai_cdn_log"],
    ),
    "akamai_dns": (
        "akamai_dns",
        ["akamai_dns_log"],
    ),
    "akamai_general": (
        "akamai_general",
        ["akamai_general_log"],
    ),
    "akamai_sitedefender": (
        "akamai_sitedefender",
        ["akamai_sitedefender_log"],
    ),
    "axway_sftp": (
        "axway_sftp",
        ["axway_sftp_log"],
    ),
    "cisco_duo": (
        "cisco_duo",
        ["cisco_duo_log"],
    ),
    "cohesity_backup": (
        "cohesity_backup",
        ["cohesity_backup_log"],
    ),
    "f5_vpn": (
        "f5_vpn",
        ["f5_vpn_log"],
    ),
    "github_audit": (
        "github_audit",
        ["github_audit_log"],
    ),
    "harness_ci": (
        "harness_ci",
        ["harness_ci_log"],
    ),
    "hypr_auth": (
        "hypr_auth",
        ["hypr_auth_log"],
    ),
    "imperva_sonar": (
        "imperva_sonar",
        ["imperva_sonar_log"],
    ),
    "isc_bind": (
        "isc_bind",
        ["isc_bind_log"],
    ),
    "isc_dhcp": (
        "isc_dhcp",
        ["isc_dhcp_log"],
    ),
    "jamf_protect": (
        "jamf_protect",
        ["jamf_protect_log"],
    ),
    "pingone_mfa": (
        "pingone_mfa",
        ["pingone_mfa_log"],
    ),
    "pingprotect": (
        "pingprotect",
        ["pingprotect_log"],
    ),
    "rsa_adaptive": (
        "rsa_adaptive",
        ["rsa_adaptive_log"],
    ),
    "veeam_backup": (
        "veeam_backup",
        ["veeam_backup_log"],
    ),
    "wiz_cloud": (
        "wiz_cloud",
        ["wiz_cloud_log"],
    ),
    # Newly created generators
    "aws_elasticloadbalancer": (
        "aws_elasticloadbalancer",
        ["aws_elasticloadbalancer_log"],
    ),
    "aws_vpcflow": (
        "aws_vpcflow", 
        ["aws_vpcflow_log"],
    ),
    "beyondtrust_privilegemgmt_windows": (
        "beyondtrust_privilegemgmt_windows",
        ["beyondtrust_privilegemgmt_windows_log"],
    ),
    "cisco_firewall_threat_defense": (
        "cisco_firewall_threat_defense",
        ["cisco_firewall_threat_defense_log"],
    ),
    "cisco_meraki_flow": (
        "cisco_meraki_flow",
        ["cisco_meraki_flow_log"],
    ),
    "manageengine_adauditplus": (
        "manageengine_adauditplus",
        ["manageengine_adauditplus_log"],
    ),
    "microsoft_azure_ad": (
        "microsoft_azure_ad",
        ["microsoft_azure_ad_log"],
    ),
    "microsoft_eventhub_azure_signin": (
        "microsoft_eventhub_azure_signin",
        ["microsoft_eventhub_azure_signin_log"],
    ),
    "microsoft_eventhub_defender_email": (
        "microsoft_eventhub_defender_email",
        ["microsoft_eventhub_defender_email_log"],
    ),
    "microsoft_eventhub_defender_emailforcloud": (
        "microsoft_eventhub_defender_emailforcloud", 
        ["microsoft_eventhub_defender_emailforcloud_log"],
    ),
    # Additional generators for marketplace parsers
    "checkpoint": (
        "checkpoint",
        ["checkpoint_log"],
    ),
    "fortimanager": (
        "fortimanager",
        ["fortimanager_log"],
    ),
    "infoblox_ddi": (
        "infoblox_ddi",
        ["infoblox_ddi_log"],
    ),
    "paloalto_firewall": (
        "paloalto_firewall",
        ["paloalto_firewall_log"],
    ),
    "zscaler_private_access": (
        "zscaler_private_access",
        ["zscaler_private_access_log"],
    ),
}
# I need to move this down below sourcetype_map so
#HEC_URL = os.getenv(
#    "S1_HEC_URL",
#   "https://ingest.us1.sentinelone.net/services/collector/raw?sourcetype=$sourcetype_map,
#)
HEC_TOKEN = os.getenv("S1_HEC_TOKEN")
if not HEC_TOKEN:
    raise RuntimeError("export S1_HEC_TOKEN=… first")

# Allow switching between Splunk and Bearer auth schemes
AUTH_SCHEME = os.getenv("S1_HEC_AUTH_SCHEME", "Splunk")
HEADERS = {"Authorization": f"{AUTH_SCHEME} {HEC_TOKEN}"}

def _make_poster(verify: bool, tls_low: bool) -> Callable:
    """Create a requests.post-like function with desired TLS settings."""
    session = requests.Session()
    if tls_low:
        try:
            from requests.adapters import HTTPAdapter
            from requests.packages.urllib3.util.ssl_ import create_urllib3_context

            class TLSAdapter(HTTPAdapter):
                def init_poolmanager(self, *args, **kwargs):
                    ctx = create_urllib3_context()
                    try:
                        ctx.set_ciphers('DEFAULT@SECLEVEL=1')
                    except Exception:
                        pass
                    if not verify:
                        try:
                            ctx.check_hostname = False
                        except Exception:
                            pass
                    kwargs['ssl_context'] = ctx
                    return super().init_poolmanager(*args, **kwargs)

            session.mount('https://', TLSAdapter())
        except Exception:
            # If TLS adapter cannot be created, proceed with default session
            pass

    session.verify = verify

    def _post(url, headers=None, data=None, json=None, timeout=10):
        return session.post(url, headers=headers, data=data, json=json, timeout=timeout)

    return _post

# TLS verification toggle (default True). Set S1_HEC_VERIFY=false to disable.
DEFAULT_VERIFY_TLS = os.getenv("S1_HEC_VERIFY", "true").lower() in ("true", "1", "yes")
# TLS compatibility (SECLEVEL=1) if requested
DEFAULT_TLS_LOW = bool(os.getenv("S1_HEC_TLS_LOW"))
# Allow insecure fallback automatically as last resort (off by default)
ALLOW_INSECURE_FALLBACK = os.getenv("S1_HEC_AUTO_INSECURE", "false").lower() in ("true", "1", "yes")
DEBUG = os.getenv("S1_HEC_DEBUG")

# Cache successful connection config to avoid retry loops
_CONNECTION_CACHE = {
    'configured': False,
    'event_base': None,
    'raw_base': None,
    'verify': DEFAULT_VERIFY_TLS,
    'tls_low': DEFAULT_TLS_LOW,
    'auth_scheme': None,
    'session': None
}

# Batch mode controls
_BATCH_ENABLED = os.getenv("S1_HEC_BATCH", "").lower() in ("1", "true", "yes")
_BATCH_MAX_BYTES = int(os.getenv("S1_HEC_BATCH_MAX_BYTES", str(5 * 1024 * 1024)))
_BATCH_FLUSH_MS = int(os.getenv("S1_HEC_BATCH_FLUSH_MS", "1000"))
_BATCH_LOCK = threading.Lock()
_BATCH_BUFFERS = {}  # key: (is_json:bool, product:str) -> {'lines': list[str], 'bytes': int, 'last': float}
_BATCH_THREAD_STARTED = False

def _batch_key(is_json: bool, product: str):
    return (is_json, product)

def _batch_enqueue(line_str: str, is_json: bool, product: str, attr_fields: dict):
    global _BATCH_THREAD_STARTED
    key = _batch_key(is_json, product)
    now = time.time()
    with _BATCH_LOCK:
        buf = _BATCH_BUFFERS.get(key)
        if not buf:
            buf = {'lines': [], 'bytes': 0, 'last': now}
            _BATCH_BUFFERS[key] = buf
        sz = len(line_str.encode('utf-8'))
        buf['lines'].append(line_str)
        buf['bytes'] += sz
        buf['last'] = now
        if buf['bytes'] >= _BATCH_MAX_BYTES:
            _flush_batch_locked(key)
        if not _BATCH_THREAD_STARTED:
            _start_batch_thread()

def _start_batch_thread():
    global _BATCH_THREAD_STARTED
    _BATCH_THREAD_STARTED = True
    t = threading.Thread(target=_batch_loop, daemon=True)
    t.start()

def _batch_loop():
    while True:
        time.sleep(0.2)
        now = time.time()
        to_flush = []
        with _BATCH_LOCK:
            for key, buf in list(_BATCH_BUFFERS.items()):
                if buf['lines'] and (now - buf['last']) * 1000 >= _BATCH_FLUSH_MS:
                    to_flush.append(key)
        for key in to_flush:
            with _BATCH_LOCK:
                _flush_batch_locked(key)

def _flush_batch_locked(key):
    buf = _BATCH_BUFFERS.get(key)
    if not buf or not buf['lines']:
        return
    is_json, product = key
    lines = buf['lines']
    _BATCH_BUFFERS[key] = {'lines': [], 'bytes': 0, 'last': time.time()}
    _send_batch(lines, is_json, product)

def _send_batch(lines: list, is_json: bool, product: str):
    if not lines:
        return
    # Ensure connection cache is established; if not, send first line via normal path
    if not _CONNECTION_CACHE['configured']:
        first = lines.pop(0)
        try:
            if is_json:
                payload = json.loads(first)
                send_one(payload, product, {})
            else:
                send_one(first, product, {})
        except Exception:
            pass
        if not lines:
            return
    if not _CONNECTION_CACHE['configured']:
        return
    if _CONNECTION_CACHE['session'] is None:
        _CONNECTION_CACHE['session'] = _make_poster(_CONNECTION_CACHE['verify'], _CONNECTION_CACHE['tls_low'])
    POST = _CONNECTION_CACHE['session']
    headers_auth = {**HEADERS}
    headers_auth["Authorization"] = f"{_CONNECTION_CACHE['auth_scheme']} {HEC_TOKEN}"
    if is_json:
        url = _CONNECTION_CACHE['event_base']
        headers = {**headers_auth, "Content-Type": "application/json", "Content-Encoding": "gzip"}
        body = "\n".join(lines).encode('utf-8')
    else:
        url = f"{_CONNECTION_CACHE['raw_base']}?{_build_qs(product)}"
        headers = {**headers_auth, "Content-Type": "text/plain", "Content-Encoding": "gzip"}
        body = ("\n".join(lines)).encode('utf-8')
    gz = gzip.compress(body)
    resp = POST(url, headers=headers, data=gz, timeout=30)
    resp.raise_for_status()

SOURCETYPE_MAP_OVERRIDES = {
    # ===== FIXED PARSER MAPPINGS (Based on actual parser directory names) =====
    # AWS parsers - use actual directory names
    "aws_cloudtrail": "aws_cloudtrail-latest",
    "aws_vpcflowlogs": "aws_vpcflowlogs-latest",
    "aws_guardduty": "aws_guardduty_logs-latest",
    "aws_elasticloadbalancer": "aws_elasticloadbalancer_logs-latest",
    "aws_waf": "aws_waf-latest",
    "aws_route53": "aws_route53-latest",
    "aws_vpc_dns": "aws_vpc_dns_logs-latest",
    "aws_vpcflow": "aws_vpcflow_logs-latest",
    
    # Network security - actual directory names
    "fortinet_fortigate": "fortinet_fortigate_candidate_logs-latest",
    "fortimanager": "fortinet_fortigate_fortimanager_logs-latest",
    "checkpoint": "checkpoint_checkpoint_logs-latest",
    "paloalto_firewall": "paloalto_firewall-latest",
    "paloalto_prismasase": "paloalto_prismasase_logs-latest",
    "cisco_firewall_threat_defense": "cisco_firewall_threat_defense-latest",
    "infoblox_ddi": "infoblox_ddi-latest",
    
    # Zscaler products
    "zscaler": "zscaler_logs-latest",
    "zscaler_private_access": "zscaler_private_access-latest",
    "zscaler_firewall": "zscaler_firewall_logs-latest",
    "zscaler_dns_firewall": "zscaler_dns_firewall-latest",
    
    # Netskope
    "netskope": "netskope_netskope_logs-latest",
    
    # Corelight
    "corelight_conn": "corelight_conn_logs-latest",
    "corelight_http": "corelight_http_logs-latest",
    "corelight_ssl": "corelight_ssl_logs-latest",
    "corelight_tunnel": "corelight_tunnel_logs-latest",
    
    # Identity and access management
    "okta_authentication": "okta_authentication-latest",
    "microsoft_azuread": "microsoft_azuread-latest",
    "microsoft_azure_ad": "microsoft_azure_ad_logs-latest",
    "microsoft_azure_ad_signin": "microsoft_azure_ad_signin-latest",
    "beyondtrust_passwordsafe": "beyondtrust_passwordsafe_logs-latest",
    "beyondtrust_privilegemgmt_windows": "beyondtrust_privilegemgmt_windows-latest",
    "hashicorp_vault": "hashicorp_vault-latest",
    "hypr_auth": "hypr_auth-latest",
    "pingfederate": "pingfederate-latest",
    "pingone_mfa": "pingone_mfa-latest",
    "pingprotect": "pingprotect-latest",
    "rsa_adaptive": "rsa_adaptive-latest",
    "cyberark_pas": "cyberark_pas_logs-latest",
    "cyberark_conjur": "cyberark_conjur-latest",
    
    # Microsoft products
    "microsoft_365_mgmt_api": "microsoft_365_mgmt_api_logs-latest",
    "microsoft_365_collaboration": "microsoft_365_collaboration-latest",
    "microsoft_365_defender": "microsoft_365_defender-latest",
    "microsoft_defender_email": "microsoft_defender_email-latest",
    "microsoft_windows_eventlog": "microsoft_windows_eventlog-latest",
    "microsoft_eventhub_azure_signin": "microsoft_eventhub_azure_signin_logs-latest",
    "microsoft_eventhub_defender_email": "microsoft_eventhub_defender_email_logs-latest",
    "microsoft_eventhub_defender_emailforcloud": "microsoft_eventhub_defender_emailforcloud_logs-latest",
    
    # Cisco products
    "cisco_asa": "cisco_asa-latest",
    "cisco_umbrella": "cisco_umbrella-latest",
    "cisco_meraki": "cisco_meraki-latest",
    "cisco_duo": "cisco_duo-latest",
    "cisco_ise": "cisco_ise_logs-latest",
    "cisco_fmc": "cisco_fmc_logs-latest",
    "cisco_ios": "cisco_ios_logs-latest",
    "cisco_ironport": "cisco_ironport-latest",
    "cisco_meraki_flow": "cisco_meraki_flow_logs-latest",
    "cisco_networks": "cisco_networks_logs-latest",
    
    # Endpoint security
    "crowdstrike_falcon": "crowdstrike_falcon-latest",
    "sentinelone_endpoint": "sentinelone_endpoint-latest",
    "sentinelone_identity": "sentinelone_identity-latest",
    "jamf_protect": "jamf_protect-latest",
    
    # Network detection
    "darktrace": "darktrace_darktrace_logs-latest",
    "extrahop": "extrahop_extrahop_logs-latest",
    "vectra_ai": "vectra_ai_logs-latest",
    "armis": "armis_armis_logs-latest",
    
    # Email security
    "proofpoint": "proofpoint_proofpoint_logs-latest",
    "mimecast": "mimecast_mimecast_logs-latest",
    "abnormal_security": "abnormal_security_logs-latest",
    
    # Web security and CDN
    "cloudflare_general": "cloudflare_general_logs-latest",
    "cloudflare_waf": "cloudflare_waf_logs-latest",
    "imperva_waf": "imperva_waf_logs-latest",
    "imperva_sonar": "imperva_sonar-latest",
    "incapsula": "incapsula_incapsula_logs-latest",
    "akamai_cdn": "akamai_cdn-latest",
    "akamai_dns": "akamai_dns-latest",
    "akamai_general": "akamai_general-latest",
    "akamai_sitedefender": "akamai_sitedefender-latest",
    
    # Cloud services
    "google_workspace": "google_workspace_logs-latest",
    "google_cloud_dns": "google_cloud_dns_logs-latest",
    "wiz_cloud": "wiz_cloud-latest",
    
    # Network infrastructure
    "apache_http": "apache_http_logs-latest",
    "f5_networks": "f5_networks_logs-latest",
    "f5_vpn": "f5_vpn-latest",
    "extreme_networks": "extreme_networks_logs-latest",
    "juniper_networks": "juniper_networks_logs-latest",
    "ubiquiti_unifi": "ubiquiti_unifi_logs-latest",
    "tailscale": "tailscale_tailscale_logs-latest",
    "isc_bind": "isc_bind-latest",
    "isc_dhcp": "isc_dhcp-latest",
    
    # IT management and DevOps
    "buildkite": "buildkite_ci_logs-latest",
    "github_audit": "github_audit-latest",
    "harness_ci": "harness_ci-latest",
    "teleport": "teleport_logs-latest",
    "linux_auth": "linux_auth-latest",
    "iis_w3c": "iis_w3c-latest",
    "veeam_backup": "veeam_backup-latest",
    "cohesity_backup": "cohesity_backup-latest",
    "axway_sftp": "axway_sftp-latest",
    "sap": "sap_logs-latest",
    "securelink": "securelink_logs-latest",
    "manageengine_general": "manageengine_general_logs-latest",
    "manageengine_adauditplus": "manageengine_adauditplus_logs-latest",
    "manch_siem": "manch_siem_logs-latest",
}

# Merge dynamically discovered sourcetypes with explicit overrides.
# Overrides win to preserve intentional non-standard mappings.
SOURCETYPE_MAP = {**_LOADED_SOURCETYPE_MAP, **SOURCETYPE_MAP_OVERRIDES}

# Optional envelope/query hints
ENV_SOURCE = os.getenv("S1_HEC_SOURCE")
ENV_HOST = os.getenv("S1_HEC_HOST")
ENV_INDEX = os.getenv("S1_HEC_INDEX")

def _build_qs(product: str) -> str:
    parts = [f"sourcetype={SOURCETYPE_MAP.get(product, product)}"]
    if ENV_SOURCE:
        parts.append(f"source={ENV_SOURCE}")
    if ENV_HOST:
        parts.append(f"host={ENV_HOST}")
    if ENV_INDEX:
        parts.append(f"index={ENV_INDEX}")
    return "&".join(parts)

# Generators that already emit structured JSON events; these must be sent to /event
JSON_PRODUCTS = {
    "aws_cloudtrail",
    "aws_guardduty",  # JSON format for marketplace parser
    "aws_waf",  # JSON format for marketplace parser
    "aws_route53",  # JSON format for marketplace parser
    "aws_vpc_dns",  # JSON format for marketplace parser
    "aws_vpcflowlogs",  # JSON format for marketplace parser
    "aws_elasticloadbalancer",  # JSON format for marketplace parser
    "zscaler",  # JSON format for gron parser
    "microsoft_azuread",
    "okta_authentication",
    # "crowdstrike_falcon",  # Returns CEF format, not JSON
    "cyberark_pas",
    "darktrace",
    "proofpoint",
    "microsoft_365_mgmt_api",
    "netskope",
    "microsoft_windows_eventlog",  # JSON wrapper to prevent line splitting
    "mimecast",
    "microsoft_azure_ad_signin",
    "microsoft_defender_email",
    # "beyondtrust_passwordsafe",  # Returns raw syslog, not JSON
    "hashicorp_vault",
    "corelight_conn",
    "corelight_http",
    "corelight_ssl",
    "corelight_tunnel",
    "tailscale",
    "github_audit",  # JSON format for direct field mapping
    "extrahop",
    "sentinelone_endpoint",
    "sentinelone_identity",
    "abnormal_security",
    "buildkite", 
    "teleport",
    "cisco_ise",
    "google_workspace",
    "aws_vpc_dns",
    "cisco_networks",
    "cloudflare_general",
    "cloudflare_waf",
    "extreme_networks",
    "f5_networks",
    "google_cloud_dns",
    "imperva_waf",
    "juniper_networks",
    "ubiquiti_unifi",
    "zscaler_firewall",
    "cisco_fmc",
    "cisco_ios",
    "cisco_isa3000",
    "incapsula",
    "manageengine_general",
    "manch_siem",
    "paloalto_prismasase",
    "sap",
    "securelink",
    "aws_waf",
    # "aws_route53",  # Returns raw log format, not JSON
    # "cisco_ironport",  # Returns raw syslog, not JSON
    "cyberark_conjur",
    "iis_w3c",
    "linux_auth",
    "microsoft_365_collaboration",
    "microsoft_365_defender",
    "pingfederate",
    "zscaler_dns_firewall",
    # "akamai_cdn",  # Returns raw log format, not JSON
    # "akamai_dns",  # Returns raw log format, not JSON
    # "akamai_general",  # Returns raw log format, not JSON
    "akamai_sitedefender",
    # "axway_sftp",  # Returns raw log format, not JSON
    "cisco_duo",
    # "cohesity_backup",  # Returns raw log format, not JSON
    # "f5_vpn",  # Returns raw log format, not JSON
    # "github_audit",  # Returns raw log format, not JSON
    # "harness_ci",  # Returns raw log format, not JSON
    # "hypr_auth",  # Returns raw log format, not JSON
    "imperva_sonar",
    "isc_bind",
    "isc_dhcp",
    # "jamf_protect",  # Returns raw log format, not JSON
    "pingone_mfa",
    "pingprotect",
    "rsa_adaptive",
    "veeam_backup",
    "wiz_cloud",
    # Newly created generators (JSON output)
    "aws_elasticloadbalancer",
    "beyondtrust_privilegemgmt_windows",
    "cisco_firewall_threat_defense",
    "cisco_meraki_flow",
    "manageengine_adauditplus",
    "microsoft_azure_ad",
    "microsoft_eventhub_azure_signin",
    "microsoft_eventhub_defender_email",
    "microsoft_eventhub_defender_emailforcloud",
    # Additional JSON products for marketplace parsers
    "checkpoint",
    "fortimanager",
    "infoblox_ddi",
    "zscaler_private_access",
    # Additional JSON products for enterprise attack scenario
    "cisco_duo",
    "pingone_mfa",
    "f5_networks",
    "imperva_waf",
    "pingprotect",
}

def _envelope(line, product: str, attr_fields: dict) -> dict:
    # Handle both JSON dict objects and string inputs
    if isinstance(line, dict):
        event_data = line  # Use dict directly for JSON products
    else:
        event_data = line  # Use string for raw products
    
    env = {"time": round(time.time()),
           "event": event_data,
           "sourcetype": SOURCETYPE_MAP.get(product, product),
           "fields": attr_fields}
    if ENV_SOURCE:
        env["source"] = ENV_SOURCE
    if ENV_HOST:
        env["host"] = ENV_HOST
    if ENV_INDEX:
        env["index"] = ENV_INDEX
    return env

def send_one(line, product: str, attr_fields: dict):
    """
    Route JSON‑structured products to the /event endpoint and all
    raw / CSV / syslog products to the /raw endpoint.
    Uses cached connection config after first successful send for performance.
    """
    # Build endpoint bases to try (env override → us1 → usea1 → global)
    env_event = os.getenv("S1_HEC_EVENT_URL_BASE")
    env_raw = os.getenv("S1_HEC_RAW_URL_BASE")
    # Backward-compat: single URL variable (may point to /raw or /event)
    single = os.getenv("S1_HEC_URL")
    if single and not (env_event and env_raw):
        if single.rstrip("/").endswith("/raw"):
            env_raw = single.rstrip("/")
            env_event = single.rstrip("/").rsplit("/", 1)[0] + "/event"
        elif single.rstrip("/").endswith("/event"):
            env_event = single.rstrip("/")
            env_raw = single.rstrip("/").rsplit("/", 1)[0] + "/raw"
        else:
            # Default to /event, derive /raw sibling
            base = single.rstrip("/")
            env_event = base + "/event"
            env_raw = base + "/raw"
    bases = []
    if env_event and env_raw:
        bases.append((env_event, env_raw))
    bases.extend([
        ("https://ingest.us1.sentinelone.net/services/collector/event",
         "https://ingest.us1.sentinelone.net/services/collector/raw"),
        ("https://ingest.usea1.sentinelone.net/services/collector/event",
         "https://ingest.usea1.sentinelone.net/services/collector/raw"),
        ("https://ingest.sentinelone.net/services/collector/event",
         "https://ingest.sentinelone.net/services/collector/raw"),
    ])

    # Try verification/TLS combinations (secure → low TLS → insecure as last resort)
    combos = [
        (DEFAULT_VERIFY_TLS, DEFAULT_TLS_LOW),
        (True, True),
    ]
    if ALLOW_INSECURE_FALLBACK:
        combos.append((False, True))

    # Attempt auth schemes: Splunk → Bearer
    auth_schemes = [os.getenv("S1_HEC_AUTH_SCHEME", "Splunk"), "Bearer"]

    last_error: Optional[Exception] = None

    # Batch mode: enqueue and return
    if _BATCH_ENABLED:
        if product in JSON_PRODUCTS:
            payload = _envelope(line, product, attr_fields)
            line_str = json.dumps(payload, separators=(",", ":"))
            _batch_enqueue(line_str, True, product, attr_fields)
        else:
            if isinstance(line, (dict, list)):
                line_str = json.dumps(line, separators=(",", ":"))
            else:
                line_str = str(line)
            _batch_enqueue(line_str, False, product, attr_fields)
        return {"status": "QUEUED"}

    # Try cached config first (fast path after first successful send)
    if _CONNECTION_CACHE['configured']:
        try:
            if _CONNECTION_CACHE['session'] is None:
                _CONNECTION_CACHE['session'] = _make_poster(
                    _CONNECTION_CACHE['verify'], 
                    _CONNECTION_CACHE['tls_low']
                )
            
            POST = _CONNECTION_CACHE['session']
            headers_auth = {**HEADERS}
            headers_auth["Authorization"] = f"{_CONNECTION_CACHE['auth_scheme']} {HEC_TOKEN}"
            
            if product in JSON_PRODUCTS:
                url = _CONNECTION_CACHE['event_base']
                payload = _envelope(line, product, attr_fields)
                headers = {**headers_auth, "Content-Type": "application/json"}
                resp = POST(url, headers=headers, json=payload, timeout=10)
            else:
                url = f"{_CONNECTION_CACHE['raw_base']}?{_build_qs(product)}"
                payload = line
                headers = {**headers_auth, "Content-Type": "text/plain"}
                resp = POST(url, headers=headers, data=payload, timeout=10)
            
            resp.raise_for_status()
            try:
                return resp.json()
            except ValueError:
                return {"status": "OK", "code": resp.status_code}
        except Exception as e:
            # Cache failed, fall through to full retry logic
            if DEBUG:
                print(f"[DEBUG] Cached config failed: {e}, trying full retry")
            _CONNECTION_CACHE['configured'] = False
            _CONNECTION_CACHE['session'] = None

    # Full retry logic (slow path for first send or after cache failure)
    for event_base, raw_base in bases:
        for verify, tls_low in combos:
            POST = _make_poster(verify=verify, tls_low=tls_low)

            for scheme in auth_schemes:
                headers_auth = {**HEADERS}
                headers_auth["Authorization"] = f"{scheme} {HEC_TOKEN}"

                try:
                    if product in JSON_PRODUCTS:
                        # JSON payload → /event
                        url = event_base
                        payload = _envelope(line, product, attr_fields)
                        headers = {**headers_auth, "Content-Type": "application/json"}
                        if DEBUG:
                            print(f"[DEBUG] Sending to {url}")
                            print(f"[DEBUG] Sourcetype: {payload.get('sourcetype')}")
                            print(f"[DEBUG] Payload: {payload}")
                        resp = POST(url, headers=headers, json=payload, timeout=10)
                    else:
                        # Raw payload → /raw
                        url = f"{raw_base}?{_build_qs(product)}"
                        payload = line
                        headers = {**headers_auth, "Content-Type": "text/plain"}
                        if DEBUG:
                            print(f"[DEBUG] Sending to {url}")
                            print(f"[DEBUG] Payload (first 200 chars): {str(payload)[:200]}")
                        resp = POST(url, headers=headers, data=payload, timeout=10)

                    # If unauthorized with Splunk, retry with Bearer (handled by loop)
                    if resp.status_code in (401, 403) and scheme == auth_schemes[0]:
                        continue

                    resp.raise_for_status()
                    
                    # Success! Cache this config for future sends
                    _CONNECTION_CACHE['configured'] = True
                    _CONNECTION_CACHE['event_base'] = event_base
                    _CONNECTION_CACHE['raw_base'] = raw_base
                    _CONNECTION_CACHE['verify'] = verify
                    _CONNECTION_CACHE['tls_low'] = tls_low
                    _CONNECTION_CACHE['auth_scheme'] = scheme
                    _CONNECTION_CACHE['session'] = POST
                    
                    try:
                        return resp.json()
                    except ValueError:
                        return {"status": "OK", "code": resp.status_code}
                except Exception as e:
                    last_error = e
                    # On SSL/connection errors, continue to next combo/base
                    continue

    # If all attempts failed, raise last error for visibility
    if last_error:
        raise last_error
    raise RuntimeError("HEC send failed with unknown error")
    resp.raise_for_status()
    try:
        return resp.json()
    except ValueError:
        return {"status": "OK", "code": resp.status_code}

def send_many_with_spacing(lines, product: str, attr_fields: dict,
                           min_delay=0.020, max_delay=60.0):
    """Send events individually with random delay between each."""
    results = []
    for idx, line in enumerate(lines, 1):
        results.append(send_one(line, product, attr_fields))
        if idx != len(lines):
            time.sleep(random.uniform(min_delay, max_delay))
    return results

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Generate & send security events from various vendors (one‑by‑one) to S1"
    )
    parser.add_argument("-n", "--count", type=int, default=1,
                        help="How many events to send (default 1)")
    parser.add_argument("--min-delay", type=float, default=0.020,
                        help="Minimum delay between events in seconds (default 0.02)")
    parser.add_argument("--max-delay", type=float, default=0.30,
                        help="Maximum delay between events in seconds (default 0.30)")
    parser.add_argument(
        "--product",
        choices=[
            "fortinet_fortigate",
            "zscaler",
            "aws_cloudtrail",
            "aws_vpcflowlogs",
            "aws_guardduty",
            "microsoft_azuread",
            "okta_authentication",
            "cisco_asa",
            "cisco_umbrella",
            "cisco_meraki",
            "crowdstrike_falcon",
            "cyberark_pas",
            "darktrace",
            "proofpoint",
            "microsoft_365_mgmt_api",
            "netskope",
            "mimecast",
            "microsoft_azure_ad_signin",
            "microsoft_defender_email",
            "beyondtrust_passwordsafe",
            "hashicorp_vault",
            "corelight_conn",
            "corelight_http",
            "corelight_ssl",
            "corelight_tunnel",
            "vectra_ai",
            "tailscale",
            "extrahop",
            "armis",
            "sentinelone_endpoint",
            "sentinelone_identity",
            "apache_http",
            "abnormal_security",
            "buildkite",
            "teleport",
            "cisco_ise",
            "google_workspace",
            "aws_vpc_dns",
            "cisco_networks",
            "cloudflare_general",
            "cloudflare_waf",
            "extreme_networks",
            "f5_networks",
            "google_cloud_dns",
            "imperva_waf",
            "juniper_networks",
            "ubiquiti_unifi",
            "zscaler_firewall",
            "cisco_fmc",
            "cisco_ios",
            "cisco_isa3000",
            "incapsula",
            "manageengine_general",
            "manch_siem",
            "microsoft_windows_eventlog",
            "paloalto_prismasase",
            "sap",
            "securelink",
            "aws_waf",
            "aws_route53",
            "cisco_ironport",
            "cyberark_conjur",
            "iis_w3c",
            "linux_auth",
            "microsoft_365_collaboration",
            "microsoft_365_defender",
            "pingfederate",
            "zscaler_dns_firewall",
            "akamai_cdn",
            "akamai_dns",
            "akamai_general",
            "akamai_sitedefender",
            "axway_sftp",
            "cisco_duo",
            "cohesity_backup",
            "f5_vpn",
            "github_audit",
            "harness_ci",
            "hypr_auth",
            "imperva_sonar",
            "isc_bind",
            "isc_dhcp",
            "jamf_protect",
            "pingone_mfa",
            "pingprotect",
            "rsa_adaptive",
            "veeam_backup",
            "wiz_cloud",
            # Newly created generators
            "aws_elasticloadbalancer",
                    "beyondtrust_privilegemgmt_windows",
            "cisco_firewall_threat_defense",
            "cisco_meraki_flow", 
            "manageengine_adauditplus",
            "microsoft_azure_ad",
            "microsoft_eventhub_azure_signin",
            "microsoft_eventhub_defender_email",
            "microsoft_eventhub_defender_emailforcloud",
            # Marketplace parser support
            "checkpoint",
            "fortimanager",
            "infoblox_ddi",
            "paloalto_firewall",
            "zscaler_private_access",
        ],
        default="fortinet_fortigate",
        help="Which log generator to use (default: fortinet_fortigate)",
    )
    parser.add_argument("--marketplace-parser", type=str,
                        help="Use a specific marketplace parser (e.g., marketplace-awscloudtrail-latest)")
    parser.add_argument("--print-responses", action="store_true",
                        help="Print all HEC responses instead of a concise summary")
    args = parser.parse_args()

    # Handle marketplace parser name
    if args.marketplace_parser:
        if args.marketplace_parser in MARKETPLACE_PARSER_MAP:
            product = MARKETPLACE_PARSER_MAP[args.marketplace_parser]
            # Override sourcetype with the specific marketplace parser
            SOURCETYPE_MAP[product] = args.marketplace_parser
        else:
            print(f"Error: Unknown marketplace parser: {args.marketplace_parser}")
            print(f"Available marketplace parsers:")
            for parser_name in sorted(MARKETPLACE_PARSER_MAP.keys()):
                print(f"  {parser_name}")
            sys.exit(1)
    else:
        product = args.product

    # Check if generator exists
    if product not in PROD_MAP:
        print(f"Error: Generator for product '{product}' not yet implemented")
        sys.exit(1)

    mod_name, func_names = PROD_MAP[product]
    gen_mod = importlib.import_module(mod_name)
    # ATTR_FIELDS removed - generators now produce realistic fields only
    attr_fields = {}  # Empty dict since we removed ATTR_FIELDS
    generators = [getattr(gen_mod, fn) for fn in func_names]

    events = [generators[i % len(generators)]() for i in range(args.count)]

    if args.count == 1:
        print("HEC response:", send_one(events[0], product, attr_fields))
    else:
        print(f"Sending {args.count} events one-by-one "
              f"(spacing {args.min_delay}s – {args.max_delay}s)…", flush=True)
        results = send_many_with_spacing(
            events, product, attr_fields, args.min_delay, args.max_delay
        )
        if args.print_responses:
            print("Responses:", results)
        else:
            # Concise summary
            total = len(results)
            ok = 0
            fail = 0
            samples = []
            for r in results:
                if isinstance(r, dict) and (r.get('code') == 0 or r.get('status') == 'OK'):
                    ok += 1
                else:
                    fail += 1
                    if len(samples) < 3:
                        samples.append(r)
            print(f"Done. Delivered {ok}/{total} successfully. Failures: {fail}.")
            if samples:
                print("Sample failure responses:")
                for s in samples:
                    print("  -", s)
