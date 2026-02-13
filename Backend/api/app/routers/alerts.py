"""
Alert management and egress API endpoints
==========================================

Sends alerts to SentinelOne via the UAM ingest API.
This is a separate API from HEC and requires its own Service Account token.
"""
from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel, Field
from typing import Optional, Dict, Any, List
import logging

from app.core.simple_auth import require_read_access, require_write_access
from app.models.responses import BaseResponse
from app.services.alert_service import alert_service

logger = logging.getLogger(__name__)

router = APIRouter()


class AlertSendRequest(BaseModel):
    """Request model for sending an alert from a template"""
    template_id: str = Field(..., description="Alert template ID (e.g. 'default_alert')")
    token: str = Field(..., description="Service Account bearer token for UAM API")
    account_id: str = Field(..., description="SentinelOne account ID")
    uam_ingest_url: str = Field(
        default="https://ingest.us1.sentinelone.net",
        description="UAM ingest base URL"
    )
    site_id: Optional[str] = Field(None, description="Optional SentinelOne site ID")
    count: int = Field(1, ge=1, le=100, description="Number of alerts to send")
    overrides: Optional[Dict[str, Any]] = Field(
        None,
        description="Optional field overrides (e.g. title, severity_id, finding_title)"
    )


class CustomAlertSendRequest(BaseModel):
    """Request model for sending a custom alert JSON"""
    alert_json: Dict[str, Any] = Field(..., description="Full alert JSON payload")
    token: str = Field(..., description="Service Account bearer token for UAM API")
    account_id: str = Field(..., description="SentinelOne account ID")
    uam_ingest_url: str = Field(
        default="https://ingest.us1.sentinelone.net",
        description="UAM ingest base URL"
    )
    site_id: Optional[str] = Field(None, description="Optional SentinelOne site ID")
    auto_generate_uid: bool = Field(
        True,
        description="Auto-generate fresh UID and timestamp"
    )


@router.get("/templates", response_model=BaseResponse)
async def list_alert_templates(
    _: str = Depends(require_read_access)
):
    """List all available alert templates"""
    templates = alert_service.list_templates()
    return BaseResponse(
        success=True,
        data={
            "templates": templates,
            "total": len(templates)
        }
    )


@router.get("/templates/{template_id}", response_model=BaseResponse)
async def get_alert_template(
    template_id: str,
    _: str = Depends(require_read_access)
):
    """Get a specific alert template by ID"""
    template = alert_service.get_template(template_id)
    if not template:
        raise HTTPException(status_code=404, detail=f"Alert template '{template_id}' not found")

    return BaseResponse(
        success=True,
        data={
            "template_id": template_id,
            "template": template
        }
    )


@router.post("/send", response_model=BaseResponse)
async def send_alert(
    req: AlertSendRequest,
    _: str = Depends(require_write_access)
):
    """
    Send one or more alerts from a template to the UAM ingest API.

    Requires:
    - A Service Account token (different from HEC token)
    - Account ID (and optionally Site ID) for the S1-Scope header
    - UAM ingest URL (e.g. https://ingest.us1.sentinelone.net)
    """
    try:
        results = alert_service.send_alert(
            template_id=req.template_id,
            token=req.token,
            account_id=req.account_id,
            uam_ingest_url=req.uam_ingest_url,
            site_id=req.site_id,
            overrides=req.overrides,
            count=req.count,
        )

        successful = sum(1 for r in results if r.get("success"))
        failed = len(results) - successful

        return BaseResponse(
            success=failed == 0,
            data={
                "results": results,
                "summary": {
                    "total": len(results),
                    "successful": successful,
                    "failed": failed,
                }
            }
        )
    except Exception as e:
        logger.error(f"Failed to send alert: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/send-custom", response_model=BaseResponse)
async def send_custom_alert(
    req: CustomAlertSendRequest,
    _: str = Depends(require_write_access)
):
    """
    Send a custom alert JSON to the UAM ingest API.

    Provide the full alert payload. If auto_generate_uid is True (default),
    a fresh UID and timestamp will be injected automatically.
    """
    try:
        result = alert_service.send_custom_alert(
            alert_json=req.alert_json,
            token=req.token,
            account_id=req.account_id,
            uam_ingest_url=req.uam_ingest_url,
            site_id=req.site_id,
            auto_generate_uid=req.auto_generate_uid,
        )

        return BaseResponse(
            success=result.get("success", False),
            data=result
        )
    except Exception as e:
        logger.error(f"Failed to send custom alert: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))
