"""
Parser Sync Service - Check and upload parsers to destination AI SIEM

Uses the SentinelOne/Scalyr Configuration API:
- getFile: Check if a parser exists in the destination account
- putFile: Upload a parser to the destination account

API Documentation: https://app.scalyr.com/help/api#getFile
"""
import os
import json
import logging
from typing import Dict, List, Optional, Tuple
from pathlib import Path
import requests

from app.services.github_parser_service import get_github_parser_service

logger = logging.getLogger(__name__)

# Mapping from generator/source names to parser sourcetypes
# This maps scenario sources to their corresponding parser directory names
SCENARIO_SOURCE_TO_PARSER = {
    # Identity & Access
    "okta_authentication": "okta_authentication-latest",
    "microsoft_azuread": "microsoft_azuread-latest",
    "microsoft_azure_ad_signin": "microsoft_azure_ad_signin-latest",
    
    # Microsoft 365
    "microsoft_365_collaboration": "microsoft_365_collaboration-latest",
    "microsoft_365_mgmt_api": "microsoft_365_mgmt_api_logs-latest",
    "microsoft_365_defender": "microsoft_365_defender-latest",
    
    # Endpoint Security
    "crowdstrike_falcon": "crowdstrike_falcon-latest",
    "sentinelone_endpoint": "sentinelone_endpoint-latest",
    "sentinelone_identity": "sentinelone_identity-latest",
    "microsoft_windows_eventlog": "microsoft_windows_eventlog-latest",
    
    # Email Security
    "proofpoint": "proofpoint_proofpoint_logs-latest",
    "mimecast": "mimecast_mimecast_logs-latest",
    "microsoft_defender_email": "microsoft_defender_email-latest",
    
    # Cloud Infrastructure
    "aws_cloudtrail": "aws_cloudtrail-latest",
    "aws_guardduty": "aws_guardduty_logs-latest",
    "netskope": "netskope_netskope_logs-latest",
    
    # Network Security
    "darktrace": "darktrace_darktrace_logs-latest",
    "paloalto_firewall": "paloalto_firewall-latest",
    "fortinet_fortigate": "fortinet_fortigate_candidate_logs-latest",
    "zscaler": "zscaler_logs-latest",
    
    # Privileged Access
    "cyberark_pas": "cyberark_pas_logs-latest",
    "beyondtrust_passwordsafe": "beyondtrust_passwordsafe_logs-latest",
    "hashicorp_vault": "hashicorp_vault-latest",
    
    # Backup & Recovery
    "veeam_backup": "veeam_backup-latest",
    "cohesity_backup": "cohesity_backup-latest",
    
    # MFA & Identity (additional)
    "cisco_duo": "cisco_duo-latest",
    "pingone_mfa": "pingone_mfa-latest",
    "pingprotect": "pingprotect-latest",
    
    # Network & Infrastructure (additional)
    "cisco_umbrella": "cisco_umbrella-latest",
    # Note: cisco_ise, f5_networks, fortinet_fortigate, microsoft_windows_eventlog, zscaler
    # are excluded - parsers use incompatible syntax or don't have JSON definitions
    
    # DevOps & CI/CD
    "github_audit": "github_audit-latest",
    "harness_ci": "harness_ci-latest",
    
    # CDN & Web
    "akamai_cdn": "akamai_cdn-latest",
}


class ParserSyncService:
    """Service to check and upload parsers to destination AI SIEM"""
    
    def __init__(self, parsers_dir: Optional[str] = None, config_api_url: Optional[str] = None):
        """
        Initialize the parser sync service
        
        Args:
            parsers_dir: Path to the local parsers directory
            config_api_url: Config API URL for the destination (e.g., https://xdr.us1.sentinelone.net)
        """
        if parsers_dir:
            self.parsers_dir = Path(parsers_dir)
        else:
            # Default to Backend/parsers relative to this file
            self.parsers_dir = Path(__file__).parent.parent.parent.parent / "parsers"
        
        # API base URL - use provided URL, or fall back to environment variable
        if config_api_url:
            self.api_base_url = config_api_url.rstrip('/') + "/api"
        else:
            self.api_base_url = os.getenv("S1_CONFIG_API_URL", "https://app.scalyr.com/api")
    
    def get_parser_sourcetype(self, source: str) -> Optional[str]:
        """
        Get the parser sourcetype for a given scenario source
        
        Args:
            source: The scenario source name (e.g., 'okta_authentication')
            
        Returns:
            The parser sourcetype or None if not found
        """
        return SCENARIO_SOURCE_TO_PARSER.get(source)
    
    def get_parser_path_in_siem(self, sourcetype: str) -> str:
        """
        Get the parser file path in the SIEM configuration
        
        Args:
            sourcetype: The parser sourcetype (e.g., 'okta_authentication-latest')
            
        Returns:
            The parser path in SIEM (e.g., '/logParsers/okta_authentication-latest')
        """
        return f"/logParsers/{sourcetype}"
    
    def load_local_parser(self, sourcetype: str) -> Optional[str]:
        """
        Load parser content from local parsers directory
        
        Args:
            sourcetype: The parser sourcetype (e.g., 'okta_authentication-latest')
            
        Returns:
            The parser JSON content as string, or None if not found
        """
        # Try community directory first
        parser_dirs = [
            self.parsers_dir / "community" / sourcetype,
            self.parsers_dir / "community_new" / sourcetype,
            self.parsers_dir / "sentinelone" / sourcetype,
        ]
        
        for parser_dir in parser_dirs:
            if parser_dir.exists():
                # Look for parser.json or any .json file
                parser_file = parser_dir / "parser.json"
                if parser_file.exists():
                    try:
                        return parser_file.read_text()
                    except Exception as e:
                        logger.error(f"Error reading parser file {parser_file}: {e}")
                        continue
                
                # Try any .json file in the directory
                json_files = list(parser_dir.glob("*.json"))
                if json_files:
                    try:
                        return json_files[0].read_text()
                    except Exception as e:
                        logger.error(f"Error reading parser file {json_files[0]}: {e}")
                        continue
        
        logger.warning(f"Parser not found locally: {sourcetype}")
        return None
    
    def load_parser_from_github(
        self,
        sourcetype: str,
        repo_urls: List[str],
        selected_parser: Optional[Dict] = None,
        github_token: Optional[str] = None
    ) -> Optional[str]:
        """
        Load parser content from configured GitHub repositories
        
        Args:
            sourcetype: The parser sourcetype to find
            repo_urls: List of GitHub repository URLs to search
            selected_parser: Optional pre-selected parser info from user choice
            github_token: Optional GitHub personal access token
            
        Returns:
            Parser JSON content as string, or None if not found
        """
        if not repo_urls:
            return None
        
        github_service = get_github_parser_service()
        
        # If user already selected a specific parser, fetch that one
        if selected_parser:
            repo_url = selected_parser.get('repo_url')
            parser_path = selected_parser.get('path')
            if repo_url and parser_path:
                content = github_service.fetch_parser_content(
                    repo_url=repo_url,
                    parser_path=parser_path,
                    github_token=github_token
                )
                if content:
                    logger.info(f"Loaded parser from GitHub: {parser_path}")
                    return content
        
        # Otherwise, search for matching parser in all repos
        matches = github_service.search_parser_in_repos(
            parser_name=sourcetype,
            repo_urls=repo_urls,
            github_token=github_token
        )
        
        if not matches:
            logger.info(f"No matching parser found in GitHub repos for: {sourcetype}")
            return None
        
        # Use the best match (first one, sorted by similarity)
        best_match = matches[0]
        content = github_service.fetch_parser_content(
            repo_url=best_match.get('repo_url'),
            parser_path=best_match.get('path'),
            github_token=github_token
        )
        
        if content:
            logger.info(f"Loaded parser from GitHub: {best_match.get('path')} (similarity: {best_match.get('similarity', 0):.0%})")
        
        return content
    
    def check_parser_exists(
        self,
        config_token: str,
        parser_path: str,
        timeout: int = 30
    ) -> Tuple[bool, Optional[str]]:
        """
        Check if a parser exists in the destination SIEM using getFile API
        
        Args:
            config_token: The config API token (write token can also read)
            parser_path: The parser path in SIEM (e.g., '/parsers/okta_authentication-latest')
            timeout: Request timeout in seconds
            
        Returns:
            Tuple of (exists: bool, content: Optional[str])
        """
        try:
            url = f"{self.api_base_url}/getFile"
            payload = {
                "token": config_token,
                "path": parser_path
            }
            
            logger.info(f"Checking if parser exists: {parser_path}")
            
            response = requests.post(
                url,
                json=payload,
                timeout=timeout,
                headers={"Content-Type": "application/json"}
            )
            
            if response.status_code == 200:
                result = response.json()
                # Scalyr API returns status: "success" if file exists
                if result.get("status") == "success":
                    content = result.get("content")
                    logger.info(f"Parser exists: {parser_path}")
                    return True, content
                else:
                    # File doesn't exist
                    logger.info(f"Parser does not exist: {parser_path}")
                    return False, None
            elif response.status_code == 404:
                logger.info(f"Parser does not exist: {parser_path}")
                return False, None
            else:
                logger.warning(
                    f"Unexpected response checking parser {parser_path}: "
                    f"{response.status_code} - {response.text}"
                )
                return False, None
                
        except requests.exceptions.Timeout:
            logger.error(f"Timeout checking parser: {parser_path}")
            return False, None
        except Exception as e:
            logger.error(f"Error checking parser {parser_path}: {e}")
            return False, None
    
    def upload_parser(
        self,
        config_write_token: str,
        parser_path: str,
        content: str,
        timeout: int = 30
    ) -> bool:
        """
        Upload a parser to the destination SIEM using putFile API
        
        Args:
            config_write_token: The config write API token
            parser_path: The parser path in SIEM (e.g., '/parsers/okta_authentication-latest')
            content: The parser JSON content
            timeout: Request timeout in seconds
            
        Returns:
            True if upload succeeded, False otherwise
        """
        try:
            url = f"{self.api_base_url}/putFile"
            payload = {
                "token": config_write_token,
                "path": parser_path,
                "content": content
            }
            
            logger.info(f"Uploading parser: {parser_path}")
            
            response = requests.post(
                url,
                json=payload,
                timeout=timeout,
                headers={"Content-Type": "application/json"}
            )
            
            if response.status_code == 200:
                result = response.json()
                if result.get("status") == "success":
                    logger.info(f"Parser uploaded successfully: {parser_path}")
                    return True
                else:
                    logger.error(
                        f"Failed to upload parser {parser_path}: {result.get('message', 'Unknown error')}"
                    )
                    return False
            else:
                logger.error(
                    f"Failed to upload parser {parser_path}: "
                    f"{response.status_code} - {response.text}"
                )
                return False
                
        except requests.exceptions.Timeout:
            logger.error(f"Timeout uploading parser: {parser_path}")
            return False
        except Exception as e:
            logger.error(f"Error uploading parser {parser_path}: {e}")
            return False
    
    def ensure_parsers_for_sources(
        self,
        sources: List[str],
        config_write_token: str,
        github_repo_urls: Optional[List[str]] = None,
        github_token: Optional[str] = None,
        selected_parsers: Optional[Dict[str, Dict]] = None
    ) -> Dict[str, dict]:
        """
        Ensure all required parsers exist in the destination SIEM
        
        Args:
            sources: List of scenario sources (e.g., ['okta_authentication', 'microsoft_azuread'])
            config_write_token: The config API token (used for both reading and writing)
            github_repo_urls: Optional list of GitHub repository URLs to fetch parsers from
            github_token: Optional GitHub personal access token for private repos
            selected_parsers: Optional dict mapping sourcetype to user-selected parser info
            
        Returns:
            Dict with status for each source:
            {
                'okta_authentication': {
                    'status': 'exists' | 'uploaded' | 'uploaded_from_github' | 'failed' | 'no_parser',
                    'sourcetype': str,
                    'message': str
                }
            }
        """
        results = {}
        selected_parsers = selected_parsers or {}
        github_service = get_github_parser_service() if github_repo_urls else None
        
        for source in sources:
            sourcetype = self.get_parser_sourcetype(source)
            
            # If no local mapping, try to find parser in GitHub using source name directly
            if not sourcetype and github_repo_urls and github_service:
                logger.info(f"No local mapping for '{source}', searching GitHub repos...")
                matches = github_service.search_parser_in_repos(
                    parser_name=source,
                    repo_urls=github_repo_urls,
                    github_token=github_token
                )
                if matches:
                    # Use the best match's name as sourcetype
                    best_match = matches[0]
                    sourcetype = best_match.get('name')
                    # Store the match for later use
                    selected_parsers[sourcetype] = best_match
                    logger.info(f"Found GitHub parser '{sourcetype}' for source '{source}' (similarity: {best_match.get('similarity', 0):.0%})")
            
            if not sourcetype:
                results[source] = {
                    "status": "no_parser",
                    "sourcetype": None,
                    "message": f"No parser mapping found for source: {source}"
                }
                continue
            
            parser_path = self.get_parser_path_in_siem(sourcetype)
            
            # Check if parser exists (write token can also read)
            exists, _ = self.check_parser_exists(config_write_token, parser_path)
            
            if exists:
                results[source] = {
                    "status": "exists",
                    "sourcetype": sourcetype,
                    "message": f"Parser already exists: {parser_path}"
                }
                continue
            
            # Parser doesn't exist, try to find it
            parser_content = None
            from_github = False
            actual_sourcetype = sourcetype  # Track what we actually upload
            
            # First, try local parser (preferred - known good quality)
            parser_content = self.load_local_parser(sourcetype)
            
            # Fall back to GitHub repositories if no local parser found
            if not parser_content and github_repo_urls:
                selected = selected_parsers.get(sourcetype)
                parser_content = self.load_parser_from_github(
                    sourcetype=sourcetype,
                    repo_urls=github_repo_urls,
                    selected_parser=selected,
                    github_token=github_token
                )
                if parser_content:
                    from_github = True
                    # If we found from selected parser, use its name for the path
                    if selected and selected.get('name'):
                        actual_sourcetype = selected.get('name')
                        parser_path = self.get_parser_path_in_siem(actual_sourcetype)
            
            if not parser_content:
                results[source] = {
                    "status": "failed",
                    "sourcetype": sourcetype,
                    "message": f"Parser not found locally or in GitHub repos: {sourcetype}"
                }
                continue
            
            # Upload the parser
            success = self.upload_parser(config_write_token, parser_path, parser_content)
            
            if success:
                status = "uploaded_from_github" if from_github else "uploaded"
                source_label = "GitHub" if from_github else "local"
                results[source] = {
                    "status": status,
                    "sourcetype": actual_sourcetype,
                    "message": f"Parser uploaded successfully from {source_label}: {parser_path}"
                }
            else:
                results[source] = {
                    "status": "failed",
                    "sourcetype": actual_sourcetype,
                    "message": f"Failed to upload parser: {parser_path}"
                }
        
        return results
    
    def get_scenario_sources(self, scenario_id: str) -> List[str]:
        """
        Get the list of sources used by a scenario.
        
        Dynamically extracts generator names from scenario phases.
        
        Args:
            scenario_id: The scenario identifier
            
        Returns:
            List of unique source names used by the scenario
        """
        # Import here to avoid circular imports
        from app.services.scenario_service import ScenarioService
        
        scenario_service = ScenarioService()
        scenario = scenario_service.scenario_templates.get(scenario_id)
        
        if not scenario:
            logger.warning(f"Scenario not found: {scenario_id}")
            return []
        
        # Extract unique generators from all phases
        sources = set()
        for phase in scenario.get("phases", []):
            for generator in phase.get("generators", []):
                sources.add(generator)
        
        return list(sources)


# Singleton instance for use across the application
_parser_sync_service: Optional[ParserSyncService] = None


def get_parser_sync_service() -> ParserSyncService:
    """Get or create the parser sync service singleton"""
    global _parser_sync_service
    if _parser_sync_service is None:
        _parser_sync_service = ParserSyncService()
    return _parser_sync_service
