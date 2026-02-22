"""
Threat Intelligence service for sending IOCs to SentinelOne
=============================================================

Uses the S1 Management API to create IOCs in the private TI repository.
Endpoint: POST {s1_management_url}/web/api/v2.1/threat-intelligence/iocs
Auth: ApiToken <s1_api_token>
"""
import json
import logging
from datetime import datetime, timedelta, timezone
from typing import Dict, Any, List, Optional

import requests

logger = logging.getLogger(__name__)

# Supported IOC types
IOC_TYPES = [
    "DNS",
    "IPV4",
    "IPV6",
    "URL",
    "SHA256",
    "SHA1",
    "MD5",
    "Domain",
]

# Supported match methods
IOC_METHODS = ["EQUALS"]

# Supported threat actor types
THREAT_ACTOR_TYPES = [
    "Nation-state",
    "Criminal",
    "Hacktivist",
    "Insider",
    "APT",
    "Script kiddies",
]


class ThreatIntelService:
    """Service for managing Threat Intelligence IOCs via S1 Management API"""

    def list_ioc_types(self) -> Dict[str, Any]:
        """Return supported IOC types, methods, and threat actor types"""
        return {
            "types": IOC_TYPES,
            "methods": IOC_METHODS,
            "threat_actor_types": THREAT_ACTOR_TYPES,
        }

    def build_ioc(
        self,
        ioc_type: str,
        value: str,
        source: str = "HELIOS",
        creator: str = "HELIOS",
        method: str = "EQUALS",
        name: Optional[str] = None,
        description: Optional[str] = None,
        severity: Optional[int] = None,
        original_risk_score: Optional[int] = None,
        valid_until: Optional[str] = None,
        creation_time: Optional[str] = None,
        external_id: Optional[str] = None,
        pattern: Optional[str] = None,
        pattern_type: Optional[str] = None,
        metadata: Optional[str] = None,
        reference: Optional[List[str]] = None,
        intrusion_sets: Optional[List[str]] = None,
        campaign_names: Optional[List[str]] = None,
        malware_names: Optional[List[str]] = None,
        mitre_tactic: Optional[List[str]] = None,
        threat_actors: Optional[List[str]] = None,
        labels: Optional[List[str]] = None,
        category: Optional[List[str]] = None,
        threat_actor_types: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """
        Build a single IOC dict for the S1 TI API.

        Args:
            ioc_type: IOC type (DNS, IPV4, URL, SHA256, etc.)
            value: The IOC value (IP address, domain, hash, etc.)
            source: Source name
            creator: Creator name
            method: Match method (EQUALS)
            name: IOC display name
            description: IOC description
            severity: Severity score (0-100)
            original_risk_score: Original risk score
            valid_until: Expiry datetime ISO string
            creation_time: Creation datetime ISO string
            external_id: External reference ID
            pattern: Detection pattern
            pattern_type: Pattern language (e.g. STIX)
            metadata: Additional metadata string
            reference: External references
            intrusion_sets: Associated intrusion sets
            campaign_names: Associated campaigns
            malware_names: Associated malware
            mitre_tactic: MITRE ATT&CK tactics
            threat_actors: Threat actor names
            labels: Labels/tags
            category: IOC categories
            threat_actor_types: Threat actor type classifications

        Returns:
            IOC dict ready for the S1 TI API data array
        """
        now = datetime.now(timezone.utc)

        ioc = {
            "type": ioc_type,
            "value": value,
            "method": method,
            "source": source,
            "creator": creator,
            "creationTime": creation_time or now.strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
            "validUntil": valid_until or (now + timedelta(days=90)).strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
        }

        if name:
            ioc["name"] = name
        if description:
            ioc["description"] = description
        if severity is not None:
            ioc["severity"] = severity
        if original_risk_score is not None:
            ioc["originalRiskScore"] = original_risk_score
        if external_id:
            ioc["externalId"] = external_id
        if pattern:
            ioc["pattern"] = pattern
        if pattern_type:
            ioc["patternType"] = pattern_type
        if metadata:
            ioc["metadata"] = metadata
        if reference:
            ioc["reference"] = reference
        if intrusion_sets:
            ioc["intrusionSets"] = intrusion_sets
        if campaign_names:
            ioc["campaignNames"] = campaign_names
        if malware_names:
            ioc["malwareNames"] = malware_names
        if mitre_tactic:
            ioc["mitreTactic"] = mitre_tactic
        if threat_actors:
            ioc["threatActors"] = threat_actors
        if labels:
            ioc["labels"] = labels
        if category:
            ioc["category"] = category
        if threat_actor_types:
            ioc["threatActorTypes"] = threat_actor_types

        return ioc

    def send_iocs(
        self,
        s1_management_url: str,
        api_token: str,
        iocs: List[Dict[str, Any]],
        auth_type: str = "ApiToken",
        account_ids: Optional[str] = None,
        site_ids: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Send IOCs to the SentinelOne Threat Intelligence API.

        Args:
            s1_management_url: S1 management console URL
            api_token: Token for auth
            iocs: List of IOC dicts (from build_ioc or custom)
            auth_type: 'ApiToken' or 'Bearer'
            account_ids: Optional account ID for scoping
            site_ids: Optional site ID for scoping

        Returns:
            Dict with success status, response data, and details
        """
        url = f"{s1_management_url.rstrip('/')}/web/api/v2.1/threat-intelligence/iocs"

        # S1 API: if siteIds is passed, use site scope only (don't also pass accountIds)
        params = {}
        if site_ids:
            params["siteIds"] = site_ids
        elif account_ids:
            params["accountIds"] = account_ids

        headers = {
            "Authorization": f"{auth_type} {api_token}",
            "Content-Type": "application/json",
        }

        payload = {
            "filter": {},
            "data": iocs,
        }

        logger.info(
            "TI IOC send: url=%s ioc_count=%d account=%s site=%s",
            url, len(iocs), account_ids, site_ids,
        )

        try:
            response = requests.post(
                url,
                headers=headers,
                params=params,
                json=payload,
                timeout=30,
            )
            response.raise_for_status()

            resp_data = {}
            if response.content:
                try:
                    resp_data = response.json()
                except Exception:
                    resp_data = {"raw": response.text[:500]}

            logger.info(
                "TI IOC response: status=%s body=%s",
                response.status_code,
                json.dumps(resp_data)[:500],
            )

            return {
                "success": True,
                "status": response.status_code,
                "status_text": response.reason,
                "data": resp_data,
                "ioc_count": len(iocs),
            }
        except requests.exceptions.HTTPError as err:
            error_body = ""
            try:
                error_body = err.response.text
            except Exception:
                pass
            logger.error("TI IOC HTTP error: %s - %s", err, error_body)
            return {
                "success": False,
                "status": err.response.status_code if err.response is not None else 0,
                "error": str(err),
                "detail": error_body,
            }
        except requests.exceptions.RequestException as err:
            logger.error("TI IOC request error: %s", err)
            return {
                "success": False,
                "status": 0,
                "error": str(err),
            }


    def get_iocs(
        self,
        s1_management_url: str,
        api_token: str,
        auth_type: str = "ApiToken",
        account_ids: Optional[str] = None,
        site_ids: Optional[str] = None,
        ioc_type: Optional[str] = None,
        value: Optional[str] = None,
        source: Optional[str] = None,
        creator: Optional[str] = None,
        limit: int = 100,
        cursor: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Fetch IOCs from the SentinelOne Threat Intelligence API.

        Args:
            s1_management_url: S1 management console URL
            api_token: Token for auth
            auth_type: 'ApiToken' or 'Bearer'
            account_ids: Optional account ID for scoping
            site_ids: Optional site ID for scoping
            ioc_type: Filter by IOC type
            value: Filter by IOC value (contains)
            source: Filter by source
            creator: Filter by creator
            limit: Max results per page
            cursor: Pagination cursor

        Returns:
            Dict with success status, IOC data, and pagination info
        """
        url = f"{s1_management_url.rstrip('/')}/web/api/v2.1/threat-intelligence/iocs"

        # S1 TI GET endpoint returns 403 with scope params for multi-scope API tokens
        # Don't pass accountIds/siteIds — the API uses the token's inherent scope
        params = {"limit": limit}
        if ioc_type:
            params["type"] = ioc_type
        if value:
            params["value__contains"] = value
        if source:
            params["source__contains"] = source
        if creator:
            params["creator__contains"] = creator
        if cursor:
            params["cursor"] = cursor

        headers = {
            "Authorization": f"{auth_type} {api_token}",
            "Content-Type": "application/json",
        }

        logger.info(
            "TI IOC get: url=%s auth=%s type=%s limit=%d",
            url, auth_type, ioc_type, limit,
        )

        try:
            response = requests.get(
                url,
                headers=headers,
                params=params,
                timeout=30,
            )
            response.raise_for_status()

            resp_data = response.json() if response.content else {}

            return {
                "success": True,
                "status": response.status_code,
                "data": resp_data.get("data", []),
                "pagination": resp_data.get("pagination", {}),
            }
        except requests.exceptions.HTTPError as err:
            error_body = ""
            try:
                error_body = err.response.text
            except Exception:
                pass
            logger.error("TI IOC GET error: %s - %s", err, error_body)
            return {
                "success": False,
                "status": err.response.status_code if err.response is not None else 0,
                "error": str(err),
                "detail": error_body,
            }
        except requests.exceptions.RequestException as err:
            logger.error("TI IOC GET request error: %s", err)
            return {
                "success": False,
                "status": 0,
                "error": str(err),
            }


# Singleton instance
threat_intel_service = ThreatIntelService()
