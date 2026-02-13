"""
Alert service for sending UAM alerts to SentinelOne
====================================================

Uses the UAM ingest API (different from HEC). Requires:
- A Service Account token (separate from HEC token)
- S1-Scope header: {accountId} or {accountId}:{siteId}
- Gzip-compressed JSON payload
- POST to {uam_ingest_url}/v1/alerts
"""
import json
import gzip
import uuid
import time
import copy
import logging
from typing import Dict, Any, List, Optional
from pathlib import Path

import requests

logger = logging.getLogger(__name__)

# Directory containing alert template JSON files
TEMPLATES_DIR = Path(__file__).parent.parent / "alerts" / "templates"


class AlertService:
    def __init__(self):
        self.templates: Dict[str, Dict[str, Any]] = {}
        self._load_templates()

    def _load_templates(self):
        """Load all alert templates from the templates directory"""
        if not TEMPLATES_DIR.exists():
            logger.warning(f"Alert templates directory not found: {TEMPLATES_DIR}")
            return

        for json_file in TEMPLATES_DIR.glob("*.json"):
            try:
                with open(json_file, "r") as f:
                    template = json.load(f)
                template_id = json_file.stem
                self.templates[template_id] = template
                logger.info(f"Loaded alert template: {template_id}")
            except Exception as e:
                logger.error(f"Failed to load alert template {json_file}: {e}")

    def list_templates(self) -> List[Dict[str, Any]]:
        """List available alert templates with metadata"""
        result = []
        for template_id, template in self.templates.items():
            display_title = (
                template.get("title")
                or template.get("finding_info", {}).get("title")
                or template.get("class_name")
                or "Untitled"
            )
            result.append({
                "id": template_id,
                "title": display_title,
                "class_name": template.get("class_name", ""),
                "severity_id": template.get("severity_id", 0),
                "finding_title": template.get("finding_info", {}).get("title", ""),
            })
        return result

    def get_template(self, template_id: str) -> Optional[Dict[str, Any]]:
        """Get a specific alert template by ID"""
        return self.templates.get(template_id)

    def prepare_alert(
        self,
        template: Dict[str, Any],
        overrides: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Prepare an alert from a template by injecting fresh UID and timestamp.

        Args:
            template: The base alert template dict
            overrides: Optional dict of top-level field overrides
                       (e.g. title, severity_id, finding_info.title)

        Returns:
            A new alert dict ready for egress
        """
        alert = copy.deepcopy(template)

        # Inject fresh UID
        if "finding_info" not in alert:
            alert["finding_info"] = {}
        alert["finding_info"]["uid"] = str(uuid.uuid4())

        # Replace all "DYNAMIC" placeholders with current time (milliseconds since epoch)
        time_ms = int(time.time() * 1000)
        self._replace_dynamic(alert, time_ms)

        # Generate UIDs for related events
        if "related_events" in alert.get("finding_info", {}):
            for event in alert["finding_info"]["related_events"]:
                event["uid"] = str(uuid.uuid4())

        # Apply overrides
        if overrides:
            for key, value in overrides.items():
                if key == "finding_title" and "finding_info" in alert:
                    alert["finding_info"]["title"] = value
                else:
                    alert[key] = value

        return alert

    def _replace_dynamic(self, obj: Any, time_ms: int) -> None:
        """Recursively replace all 'DYNAMIC' string values with the given timestamp."""
        if isinstance(obj, dict):
            for key in obj:
                if obj[key] == "DYNAMIC":
                    obj[key] = time_ms
                elif isinstance(obj[key], (dict, list)):
                    self._replace_dynamic(obj[key], time_ms)
        elif isinstance(obj, list):
            for i, item in enumerate(obj):
                if item == "DYNAMIC":
                    obj[i] = time_ms
                elif isinstance(item, (dict, list)):
                    self._replace_dynamic(item, time_ms)

    def build_scope(self, account_id: str, site_id: Optional[str] = None) -> str:
        """Build the S1-Scope header value"""
        if site_id:
            return f"{account_id}:{site_id}"
        return account_id

    def egress_alert(
        self,
        alert: Dict[str, Any],
        scope: str,
        token: str,
        uam_ingest_url: str,
    ) -> Dict[str, Any]:
        """
        Send a single alert to the SentinelOne UAM ingest endpoint.

        Args:
            alert: The prepared alert dict
            scope: S1-Scope header value ({accountId} or {accountId}:{siteId})
            token: Service Account bearer token
            uam_ingest_url: Base URL (e.g. https://ingest.us1.sentinelone.net)

        Returns:
            Dict with status, statusText, and data on success; error info on failure
        """
        headers = {
            "Authorization": f"Bearer {token}",
            "S1-Scope": scope,
            "Content-Encoding": "gzip",
            "Content-Type": "application/json",
        }

        # UAM ingest API expects a single alert object (batch not supported for alerts)
        payload = json.dumps(alert).encode("utf-8")
        gzipped_alert = gzip.compress(payload)
        logger.info(f"Compressed alert payload: {len(payload)} bytes -> {len(gzipped_alert)} bytes (gzip)")

        url = uam_ingest_url.rstrip("/") + "/v1/alerts"

        try:
            logger.info(f"Sending POST request to {url}")
            response = requests.post(url, headers=headers, data=gzipped_alert, timeout=30)
            response.raise_for_status()
            resp_body = response.text if response.content else ""
            logger.info(
                "UAM alert response: status=%s body=%s headers=%s",
                response.status_code, resp_body[:500],
                dict(response.headers)
            )
            resp_data = {}
            if response.content:
                try:
                    resp_data = response.json()
                except Exception:
                    resp_data = {"raw": resp_body[:500]}
            return {
                "success": True,
                "status": response.status_code,
                "status_text": response.reason,
                "data": resp_data,
            }
        except requests.exceptions.HTTPError as err:
            error_body = ""
            try:
                error_body = err.response.text
            except Exception:
                pass
            logger.error("UAM alert HTTP error: %s - %s", err, error_body)
            return {
                "success": False,
                "status": err.response.status_code if err.response is not None else 0,
                "error": str(err),
                "detail": error_body,
            }
        except requests.exceptions.RequestException as err:
            logger.error("UAM alert request error: %s", err)
            return {
                "success": False,
                "status": 0,
                "error": str(err),
            }

    def send_alert(
        self,
        template_id: str,
        token: str,
        account_id: str,
        uam_ingest_url: str,
        site_id: Optional[str] = None,
        overrides: Optional[Dict[str, Any]] = None,
        count: int = 1,
    ) -> List[Dict[str, Any]]:
        """
        High-level method: prepare and send one or more alerts from a template.

        Args:
            template_id: ID of the alert template to use
            token: Service Account bearer token
            account_id: SentinelOne account ID
            uam_ingest_url: Base ingest URL
            site_id: Optional site ID
            overrides: Optional field overrides
            count: Number of alerts to send

        Returns:
            List of result dicts (one per alert sent)
        """
        template = self.get_template(template_id)
        if not template:
            return [{"success": False, "error": f"Template '{template_id}' not found"}]

        scope = self.build_scope(account_id, site_id)
        results = []

        for i in range(count):
            alert = self.prepare_alert(template, overrides)
            result = self.egress_alert(alert, scope, token, uam_ingest_url)
            result["alert_index"] = i
            result["alert_uid"] = alert.get("finding_info", {}).get("uid", "")
            results.append(result)

        return results

    def send_custom_alert(
        self,
        alert_json: Dict[str, Any],
        token: str,
        account_id: str,
        uam_ingest_url: str,
        site_id: Optional[str] = None,
        auto_generate_uid: bool = True,
    ) -> Dict[str, Any]:
        """
        Send a custom alert JSON (not from a template).

        Args:
            alert_json: Full alert dict provided by the user
            token: Service Account bearer token
            account_id: SentinelOne account ID
            uam_ingest_url: Base ingest URL
            site_id: Optional site ID
            auto_generate_uid: If True, inject fresh UID and timestamp

        Returns:
            Result dict
        """
        if auto_generate_uid:
            alert = self.prepare_alert(alert_json)
        else:
            alert = copy.deepcopy(alert_json)

        scope = self.build_scope(account_id, site_id)
        return self.egress_alert(alert, scope, token, uam_ingest_url)


# Singleton instance
alert_service = AlertService()
