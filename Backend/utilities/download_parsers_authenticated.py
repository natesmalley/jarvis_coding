#!/usr/bin/env python3
"""
Download SentinelOne Parser Definitions with GitHub Authentication
===================================================================
Downloads parser configurations from the official SentinelOne AI SIEM repository.
Uses GitHub authentication to avoid rate limiting issues.
"""

import json
import os
import requests
import time
from pathlib import Path
from datetime import datetime

# GitHub repository information
GITHUB_REPO = "Sentinel-One/ai-siem"
GITHUB_BRANCH = "main"
BASE_URL = f"https://api.github.com/repos/{GITHUB_REPO}"
RAW_URL = f"https://raw.githubusercontent.com/{GITHUB_REPO}/{GITHUB_BRANCH}"

def get_github_headers():
    """Get headers for GitHub API requests"""
    headers = {
        'Accept': 'application/vnd.github.v3+json',
        'User-Agent': 'SentinelOne-Parser-Downloader'
    }
    
    # Check for GitHub token in environment
    github_token = os.environ.get('GITHUB_TOKEN')
    if github_token:
        headers['Authorization'] = f'token {github_token}'
        print("✅ Using GitHub authentication (higher rate limits)")
    else:
        print("⚠️  No GitHub token found - using unauthenticated requests")
        print("   Set GITHUB_TOKEN environment variable for better rate limits")
        print("   Example: export GITHUB_TOKEN=your_github_personal_access_token")
    
    return headers

def download_with_retry(url, headers=None, max_retries=3, delay=2):
    """Download with retry logic and better error handling"""
    if headers is None:
        headers = get_github_headers()
    
    for attempt in range(max_retries):
        try:
            response = requests.get(url, headers=headers)
            
            if response.status_code == 200:
                return response
            elif response.status_code == 403:
                # Check rate limit headers
                remaining = response.headers.get('X-RateLimit-Remaining', 'unknown')
                reset_time = response.headers.get('X-RateLimit-Reset', 'unknown')
                
                if remaining == '0':
                    print(f"    ⏳ Rate limit exceeded. Resets at {reset_time}")
                    if attempt < max_retries - 1:
                        wait_time = delay * (2 ** attempt)
                        print(f"    Waiting {wait_time} seconds before retry...")
                        time.sleep(wait_time)
                        continue
                else:
                    print(f"    ❌ Access denied (403). Remaining requests: {remaining}")
                    return None
            elif response.status_code == 429:
                wait_time = delay * (2 ** attempt)
                print(f"    ⏳ Too many requests. Waiting {wait_time} seconds...")
                time.sleep(wait_time)
                continue
            elif response.status_code == 404:
                return None
            else:
                print(f"    ⚠️  HTTP {response.status_code}: {response.reason}")
                return None
                
        except requests.exceptions.RequestException as e:
            if attempt == max_retries - 1:
                print(f"    ❌ Failed after {max_retries} attempts: {e}")
                return None
            wait_time = delay * (2 ** attempt)
            print(f"    ⚠️  Request failed. Retrying in {wait_time} seconds...")
            time.sleep(wait_time)
    
    return None

def check_rate_limit(headers=None):
    """Check GitHub API rate limit status"""
    if headers is None:
        headers = get_github_headers()
    
    url = "https://api.github.com/rate_limit"
    response = requests.get(url, headers=headers)
    
    if response.status_code == 200:
        data = response.json()
        core = data['rate']
        print(f"📊 GitHub API Rate Limit Status:")
        print(f"   Limit: {core['limit']} requests/hour")
        print(f"   Remaining: {core['remaining']} requests")
        print(f"   Resets at: {datetime.fromtimestamp(core['reset']).strftime('%Y-%m-%d %H:%M:%S')}")
        return core['remaining'] > 10  # Need at least 10 requests
    return False

def download_parser_files(parser_name, parser_type="community", headers=None):
    """Download files for a specific parser"""
    if headers is None:
        headers = get_github_headers()
    
    base_dir = Path("parsers") / f"{parser_type}_downloaded"
    parser_dir = base_dir / parser_name
    parser_dir.mkdir(parents=True, exist_ok=True)
    
    # Get parser directory contents
    api_url = f"{BASE_URL}/contents/parsers/{parser_type}/{parser_name}"
    
    response = download_with_retry(api_url, headers)
    if not response:
        return 0
    
    contents = response.json()
    file_count = 0
    
    for item in contents:
        if item['type'] == 'file':
            file_url = item['download_url']
            file_name = item['name']
            
            print(f"    📄 {file_name}")
            
            # Small delay between files
            if file_count > 0:
                time.sleep(0.3)
            
            # Download file content directly (doesn't count against API rate limit)
            file_response = requests.get(file_url)
            if file_response.status_code == 200:
                local_path = parser_dir / file_name
                with open(local_path, 'wb') as f:
                    f.write(file_response.content)
                file_count += 1
    
    return file_count

def download_selected_parsers(parser_list=None, parser_type="community"):
    """Download specific parsers from the list"""
    headers = get_github_headers()
    
    print("=" * 70)
    print("🚀 SentinelOne Parser Downloader (Authenticated)")
    print("=" * 70)
    print()
    
    # Check rate limit first
    if not check_rate_limit(headers):
        print("❌ Insufficient GitHub API rate limit remaining")
        print("   Please wait for rate limit to reset or add GitHub token")
        return 0
    
    print()
    
    # Default to a small set of parsers if none specified
    if parser_list is None:
        parser_list = [
            "aws_waf-latest",
            "cisco_duo-latest",
            "fortinet_fortigate_candidate_logs-latest",
            "zscaler_logs-latest",
            "microsoft_365_defender-latest"
        ]
    
    success_count = 0
    
    for parser_name in parser_list:
        print(f"📦 Downloading: {parser_name}")
        print("-" * 40)
        
        file_count = download_parser_files(parser_name, parser_type, headers)
        
        if file_count > 0:
            print(f"  ✅ Downloaded {file_count} files")
            success_count += 1
        else:
            print(f"  ⚠️  Failed to download parser")
        
        print()
        
        # Small delay between parsers
        time.sleep(0.5)
    
    print("=" * 70)
    print("📊 Download Summary")
    print("=" * 70)
    print(f"  Successfully downloaded: {success_count}/{len(parser_list)} parsers")
    print(f"  Location: parsers/{parser_type}_downloaded/")
    print()
    
    return success_count

def main():
    """Main function"""
    import sys
    
    if len(sys.argv) > 1 and sys.argv[1] == "--check":
        # Just check rate limit
        get_github_headers()
        print()
        check_rate_limit()
    else:
        # Download parsers
        success = download_selected_parsers()
        
        if success == 0:
            print("💡 Tips:")
            print("1. Create a GitHub personal access token:")
            print("   https://github.com/settings/tokens")
            print("2. Set the token as environment variable:")
            print("   export GITHUB_TOKEN=your_token_here")
            print("3. Run the script again")

if __name__ == "__main__":
    main()