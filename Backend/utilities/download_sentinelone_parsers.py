#!/usr/bin/env python3
"""
Download SentinelOne Parser Definitions from GitHub
====================================================
Downloads parser configurations from the official SentinelOne AI SIEM repository.
Supports both community and sentinelone (marketplace) parsers.
"""

import json
import os
import re
import requests
import zipfile
import io
import time
from pathlib import Path
from datetime import datetime

# GitHub repository information
GITHUB_REPO = "Sentinel-One/ai-siem"
GITHUB_BRANCH = "main"  # or "master" depending on the default branch
BASE_URL = f"https://api.github.com/repos/{GITHUB_REPO}"
RAW_URL = f"https://raw.githubusercontent.com/{GITHUB_REPO}/{GITHUB_BRANCH}"

def download_with_retry(url, max_retries=5, delay=1):
    """Download with retry logic and exponential backoff"""
    for attempt in range(max_retries):
        try:
            response = requests.get(url)
            if response.status_code == 429:  # Rate limited
                wait_time = delay * (2 ** attempt)  # Exponential backoff
                print(f"    ⏳ Rate limited. Waiting {wait_time} seconds...")
                time.sleep(wait_time)
                continue
            response.raise_for_status()
            return response
        except requests.exceptions.RequestException as e:
            if attempt == max_retries - 1:
                raise e
            wait_time = delay * (2 ** attempt)
            print(f"    ⚠️  Request failed. Retrying in {wait_time} seconds...")
            time.sleep(wait_time)
    return None

def download_github_directory(path_in_repo, local_dir):
    """Download all files from a GitHub directory with rate limiting"""
    print(f"📥 Downloading from: {path_in_repo}")
    
    # Create local directory
    Path(local_dir).mkdir(parents=True, exist_ok=True)
    
    # Get directory contents from GitHub API
    api_url = f"{BASE_URL}/contents/{path_in_repo}"
    
    try:
        response = download_with_retry(api_url)
        if not response:
            print(f"  ❌ Failed to access: {path_in_repo}")
            return 0
        
        contents = response.json()
        downloaded_count = 0
        
        for idx, item in enumerate(contents):
            # Add a small delay between downloads to avoid rate limiting
            if idx > 0:
                time.sleep(0.5)  # 500ms delay between files
            
            if item['type'] == 'file':
                # Download file
                file_url = item['download_url']
                file_name = item['name']
                local_path = Path(local_dir) / file_name
                
                print(f"    📄 {file_name}")
                file_response = download_with_retry(file_url)
                if file_response:
                    with open(local_path, 'wb') as f:
                        f.write(file_response.content)
                    downloaded_count += 1
                else:
                    print(f"    ⚠️  Failed to download: {file_name}")
                
            elif item['type'] == 'dir':
                # Recursively download subdirectory
                subdir_name = item['name']
                subdir_path = f"{path_in_repo}/{subdir_name}"
                local_subdir = Path(local_dir) / subdir_name
                
                print(f"  📁 Entering directory: {subdir_name}")
                # Add delay before processing subdirectory
                time.sleep(1)
                sub_count = download_github_directory(subdir_path, local_subdir)
                downloaded_count += sub_count
        
        return downloaded_count
        
    except requests.exceptions.HTTPError as e:
        if e.response.status_code == 404:
            print(f"  ⚠️  Directory not found: {path_in_repo}")
        elif e.response.status_code == 429:
            print(f"  ❌ Rate limit exceeded. Please try again later.")
        else:
            print(f"  ❌ HTTP Error: {e}")
        return 0
    except Exception as e:
        print(f"  ❌ Error downloading: {e}")
        return 0

def download_parser_zip(parser_type="community"):
    """Download parser ZIP file from GitHub releases or repository"""
    print(f"🔍 Looking for {parser_type} parsers ZIP file...")
    
    # Try to find a releases/zip file
    # First check if there's a direct ZIP download available
    zip_urls = [
        f"{RAW_URL}/parsers/{parser_type}.zip",
        f"{RAW_URL}/parser/{parser_type}.zip",
        f"https://github.com/{GITHUB_REPO}/archive/refs/heads/{GITHUB_BRANCH}.zip"
    ]
    
    for url in zip_urls:
        try:
            print(f"  Trying: {url}")
            response = requests.get(url, stream=True)
            if response.status_code == 200:
                print(f"  ✅ Found ZIP file!")
                return response.content
        except:
            continue
    
    return None

def process_parser_directory(parser_dir, parser_type="community"):
    """Process a parser directory and extract parser configurations"""
    parsers = []
    
    for parser_path in Path(parser_dir).iterdir():
        if parser_path.is_dir():
            parser_name = parser_path.name
            
            # Look for JSON configuration files
            json_files = list(parser_path.glob("*.json"))
            yaml_files = list(parser_path.glob("*.yaml")) + list(parser_path.glob("*.yml"))
            
            if json_files or yaml_files:
                parser_info = {
                    "name": parser_name,
                    "type": parser_type,
                    "path": str(parser_path),
                    "files": {
                        "json": [str(f) for f in json_files],
                        "yaml": [str(f) for f in yaml_files]
                    }
                }
                parsers.append(parser_info)
                print(f"  ✅ Found parser: {parser_name}")
    
    return parsers

def download_sentinelone_parsers():
    """Main function to download and organize SentinelOne parsers"""
    print("=" * 70)
    print("🚀 SentinelOne Parser Downloader")
    print("=" * 70)
    print()
    
    # Create base directories
    base_dir = Path("parsers")
    community_dir = base_dir / "community_new"
    sentinelone_dir = base_dir / "sentinelone_new"
    
    all_parsers = []
    
    # Download community parsers
    print("📦 Downloading Community Parsers")
    print("-" * 40)
    
    # Download via API (more reliable for individual files)
    count = download_github_directory("parsers/community", community_dir)
    if count > 0:
        print(f"  ✅ Downloaded {count} files")
        community_parsers = process_parser_directory(community_dir, "community")
    else:
        community_parsers = []
    
    all_parsers.extend(community_parsers)
    
    print()
    print("📦 Downloading SentinelOne (Marketplace) Parsers")
    print("-" * 40)
    
    # Download via API (more reliable for individual files)
    count = download_github_directory("parsers/sentinelone", sentinelone_dir)
    if count > 0:
        print(f"  ✅ Downloaded {count} files")
        sentinelone_parsers = process_parser_directory(sentinelone_dir, "sentinelone")
    else:
        sentinelone_parsers = []
    
    all_parsers.extend(sentinelone_parsers)
    
    # Save parser inventory
    print()
    print("📋 Creating Parser Inventory")
    print("-" * 40)
    
    inventory = {
        "timestamp": datetime.now().isoformat(),
        "source": f"https://github.com/{GITHUB_REPO}",
        "branch": GITHUB_BRANCH,
        "community_count": len(community_parsers),
        "sentinelone_count": len(sentinelone_parsers),
        "total_count": len(all_parsers),
        "parsers": all_parsers
    }
    
    inventory_file = base_dir / "parser_inventory.json"
    with open(inventory_file, 'w') as f:
        json.dump(inventory, f, indent=2)
    
    print(f"  💾 Saved inventory to: {inventory_file}")
    
    # Print summary
    print()
    print("=" * 70)
    print("📊 Download Summary")
    print("=" * 70)
    print(f"  Community Parsers:    {len(community_parsers)}")
    print(f"  SentinelOne Parsers:  {len(sentinelone_parsers)}")
    print(f"  Total Parsers:        {len(all_parsers)}")
    print()
    
    if all_parsers:
        print("📂 Parser Locations:")
        print(f"  Community:   {community_dir}")
        print(f"  SentinelOne: {sentinelone_dir}")
        print(f"  Inventory:   {inventory_file}")
        print()
        print("✅ Parser download complete!")
        print()
        print("Next steps:")
        print("1. Review downloaded parsers in the directories above")
        print("2. Compare with existing parsers in parsers/community and parsers/sentinelone")
        print("3. Merge or update as needed")
        print("4. Update generator mappings in hec_sender.py")
    else:
        print("⚠️  No parsers were downloaded")
        print()
        print("Possible issues:")
        print("1. GitHub API rate limit (try again later)")
        print("2. Repository structure changed")
        print("3. Network connectivity issues")
    
    return len(all_parsers)

def list_github_parsers():
    """List available parsers without downloading"""
    print("🔍 Listing available parsers on GitHub...")
    print()
    
    parser_types = ["community", "sentinelone"]
    
    for parser_type in parser_types:
        print(f"📦 {parser_type.title()} Parsers:")
        print("-" * 40)
        
        api_url = f"{BASE_URL}/contents/parsers/{parser_type}"
        
        try:
            response = download_with_retry(api_url)
            if not response:
                print(f"  ❌ Failed to list {parser_type} parsers")
                continue
            
            contents = response.json()
            parsers = [item['name'] for item in contents if item['type'] == 'dir']
            
            for parser in sorted(parsers):
                print(f"  • {parser}")
            
            print(f"  Total: {len(parsers)} parsers")
            print()
            
            # Add delay between parser types to avoid rate limiting
            time.sleep(1)
            
        except Exception as e:
            print(f"  ❌ Error listing {parser_type} parsers: {e}")
            print()

if __name__ == "__main__":
    import sys
    
    if len(sys.argv) > 1 and sys.argv[1] == "--list":
        # Just list available parsers
        list_github_parsers()
    else:
        # Download all parsers
        parser_count = download_sentinelone_parsers()
        
        if parser_count == 0:
            print("\n💡 Tip: Run with --list flag to just list available parsers:")
            print("  python download_sentinelone_parsers.py --list")