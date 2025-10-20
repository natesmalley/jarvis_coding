#!/usr/bin/env python3
"""
Simple Parser Downloader - No API Rate Limits
==============================================
Downloads parsers directly from raw GitHub content URLs.
Bypasses API rate limits by using direct file access.
"""

import json
import requests
from pathlib import Path
from datetime import datetime

# Known parsers that we need (based on our generators)
PARSER_CONFIGS = {
    "community": [
        "aws_waf-latest",
        "aws_route53-latest",
        "aws_guardduty_logs-latest",
        "aws_vpc_dns_logs-latest",
        "cisco_duo-latest",
        "cisco_fmc_logs-latest",
        "cisco_ironport-latest",
        "cisco_meraki_flow_logs-latest",
        "cisco_asa_logs-latest",
        "cisco_umbrella_logs-latest",
        "fortinet_fortigate_candidate_logs-latest",
        "microsoft_365_collaboration-latest",
        "microsoft_365_defender-latest",
        "microsoft_windows_eventlog-latest",
        "zscaler_logs-latest",
        "zscaler_dns_firewall-latest",
        "pingfederate-latest",
        "pingone_mfa-latest",
        "veeam_backup-latest",
        "cohesity_backup-latest",
        "github_audit-latest",
        "harness_ci-latest",
        "jamf_protect-latest",
        "abnormal_security_logs-latest",
        "cloudflare_waf_logs-latest",
        "google_workspace_logs-latest",
        "okta_logs-latest",
        "crowdstrike_logs-latest",
        "darktrace_darktrace_logs-latest",
        "cyberark_pas_logs-latest",
        "beyondtrust_passwordsafe_logs-latest",
        "proofpoint_logs-latest",
        "mimecast_mimecast_logs-latest",
        "netskope_netskope_logs-latest"
    ]
}

def download_parser_direct(parser_name, parser_type="community"):
    """Download parser files directly from raw GitHub URLs"""
    
    base_url = f"https://raw.githubusercontent.com/Sentinel-One/ai-siem/main/parsers/{parser_type}/{parser_name}"
    
    # Create output directory
    output_dir = Path("parsers") / parser_type / parser_name
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # Common parser files to try downloading
    files_to_try = [
        f"{parser_name.replace('-latest', '')}.json",  # Main parser file
        "metadata.yaml",  # Metadata file
        "metadata.yml",   # Alternative metadata
        "README.md",      # Documentation
        "parser.json",    # Alternative naming
        "config.json"     # Alternative naming
    ]
    
    downloaded = []
    
    for file_name in files_to_try:
        url = f"{base_url}/{file_name}"
        try:
            response = requests.get(url, timeout=10)
            if response.status_code == 200:
                file_path = output_dir / file_name
                with open(file_path, 'wb') as f:
                    f.write(response.content)
                downloaded.append(file_name)
                print(f"    ✅ {file_name}")
        except:
            pass  # File doesn't exist, skip
    
    return downloaded

def download_parsers_batch(parser_list=None):
    """Download multiple parsers without API rate limits"""
    
    print("=" * 70)
    print("🚀 Simple Parser Downloader (No Rate Limits)")
    print("=" * 70)
    print()
    print("📡 Using direct raw.githubusercontent.com URLs")
    print("   (Bypasses API rate limits)")
    print()
    
    if parser_list is None:
        parser_list = PARSER_CONFIGS["community"][:10]  # Start with first 10
    
    success_count = 0
    failed_parsers = []
    
    for parser_name in parser_list:
        print(f"📦 Downloading: {parser_name}")
        
        files = download_parser_direct(parser_name, "community")
        
        if files:
            success_count += 1
        else:
            print(f"    ⚠️  No files found")
            failed_parsers.append(parser_name)
        
        print()
    
    print("=" * 70)
    print("📊 Download Summary")
    print("=" * 70)
    print(f"✅ Successfully downloaded: {success_count}/{len(parser_list)} parsers")
    print(f"📁 Location: parsers/community/")
    
    if failed_parsers:
        print()
        print("⚠️  Failed parsers (may not exist on GitHub):")
        for parser in failed_parsers[:5]:  # Show first 5 failures
            print(f"   - {parser}")
    
    print()
    return success_count

def verify_existing_parsers():
    """Check which parsers we already have locally"""
    
    print("🔍 Checking existing parsers...")
    print()
    
    community_dir = Path("parsers/community")
    if not community_dir.exists():
        print("  ⚠️  No parsers/community directory found")
        return []
    
    existing = []
    for parser_dir in community_dir.iterdir():
        if parser_dir.is_dir():
            json_files = list(parser_dir.glob("*.json"))
            if json_files:
                existing.append(parser_dir.name)
    
    print(f"  ✅ Found {len(existing)} existing parsers")
    return existing

def main():
    """Main function"""
    import sys
    
    if len(sys.argv) > 1 and sys.argv[1] == "--verify":
        # Just verify what we have
        existing = verify_existing_parsers()
        if existing:
            print()
            print("📋 Existing parsers:")
            for parser in sorted(existing)[:20]:  # Show first 20
                print(f"   • {parser}")
            if len(existing) > 20:
                print(f"   ... and {len(existing) - 20} more")
    elif len(sys.argv) > 1 and sys.argv[1] == "--all":
        # Download all known parsers
        download_parsers_batch(PARSER_CONFIGS["community"])
    else:
        # Download a subset
        print("📝 Downloading essential parsers...")
        print()
        essential = [
            "aws_waf-latest",
            "cisco_duo-latest", 
            "fortinet_fortigate_candidate_logs-latest",
            "microsoft_365_defender-latest",
            "zscaler_logs-latest"
        ]
        download_parsers_batch(essential)
        
        print("💡 To download all parsers, run:")
        print("   python download_parsers_simple.py --all")

if __name__ == "__main__":
    main()