"""
Threat Intelligence API endpoints
===================================

Send IOCs to SentinelOne via the S1 Management API.
Uses ApiToken auth (same as XDR assets), not UAM ingest.
"""
from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel, Field
from typing import Optional, Dict, Any, List
import logging

from app.core.simple_auth import require_read_access, require_write_access
from app.models.responses import BaseResponse
from app.services.threat_intel_service import threat_intel_service

logger = logging.getLogger(__name__)

router = APIRouter()


class IOCItem(BaseModel):
    """A single IOC entry"""
    type: str = Field(..., description="IOC type (DNS, IPV4, IPV6, URL, SHA256, SHA1, MD5, Domain)")
    value: str = Field(..., description="The IOC value (IP, domain, hash, URL, etc.)")
    method: str = Field("EQUALS", description="Match method")
    source: str = Field("HELIOS", description="Source name")
    creator: str = Field("HELIOS", description="Creator name")
    name: Optional[str] = Field(None, description="IOC display name")
    description: Optional[str] = Field(None, description="IOC description")
    severity: Optional[int] = Field(None, ge=0, le=100, description="Severity (0-100)")
    original_risk_score: Optional[int] = Field(None, description="Original risk score")
    valid_until: Optional[str] = Field(None, description="Expiry datetime (ISO format)")
    creation_time: Optional[str] = Field(None, description="Creation datetime (ISO format)")
    external_id: Optional[str] = Field(None, description="External reference ID")
    pattern: Optional[str] = Field(None, description="Detection pattern")
    pattern_type: Optional[str] = Field(None, description="Pattern language (e.g. STIX)")
    metadata: Optional[str] = Field(None, description="Additional metadata string")
    reference: Optional[List[str]] = Field(None, description="External references")
    intrusion_sets: Optional[List[str]] = Field(None, description="Associated intrusion sets")
    campaign_names: Optional[List[str]] = Field(None, description="Associated campaigns")
    malware_names: Optional[List[str]] = Field(None, description="Associated malware names")
    mitre_tactic: Optional[List[str]] = Field(None, description="MITRE ATT&CK tactics")
    threat_actors: Optional[List[str]] = Field(None, description="Threat actor names")
    labels: Optional[List[str]] = Field(None, description="Labels/tags")
    category: Optional[List[str]] = Field(None, description="IOC categories")
    threat_actor_types: Optional[List[str]] = Field(None, description="Threat actor type classifications")


class ThreatIntelSendRequest(BaseModel):
    """Request model for sending IOCs"""
    s1_management_url: str = Field(..., description="S1 management console URL")
    api_token: str = Field(..., description="S1 API token")
    auth_type: str = Field("ApiToken", description="Auth type: 'ApiToken' or 'Bearer'")
    account_id: Optional[str] = Field(None, description="Account ID for scoping")
    site_id: Optional[str] = Field(None, description="Site ID for scoping")
    iocs: List[IOCItem] = Field(..., min_length=1, description="List of IOCs to send")


class ThreatIntelCustomRequest(BaseModel):
    """Request model for sending custom IOC JSON"""
    s1_management_url: str = Field(..., description="S1 management console URL")
    api_token: str = Field(..., description="S1 API token")
    auth_type: str = Field("ApiToken", description="Auth type: 'ApiToken' or 'Bearer'")
    account_id: Optional[str] = Field(None, description="Account ID for scoping")
    site_id: Optional[str] = Field(None, description="Site ID for scoping")
    iocs_json: List[Dict[str, Any]] = Field(..., description="Raw IOC dicts to send")


class ThreatIntelGetRequest(BaseModel):
    """Request model for fetching IOCs (POST body with creds)"""
    s1_management_url: str = Field(..., description="S1 management console URL")
    api_token: str = Field(..., description="S1 API token")
    auth_type: str = Field("ApiToken", description="Auth type: 'ApiToken' or 'Bearer'")
    account_id: Optional[str] = Field(None, description="Account ID for scoping")
    site_id: Optional[str] = Field(None, description="Site ID for scoping")
    ioc_type: Optional[str] = Field(None, description="Filter by IOC type")
    value: Optional[str] = Field(None, description="Filter by value (contains)")
    source: Optional[str] = Field(None, description="Filter by source (contains)")
    creator: Optional[str] = Field(None, description="Filter by creator (contains)")
    limit: int = Field(100, ge=1, le=1000, description="Max results per page")
    cursor: Optional[str] = Field(None, description="Pagination cursor")


@router.get("/types", response_model=BaseResponse)
async def get_ioc_types(
    _: str = Depends(require_read_access)
):
    """Get supported IOC types, methods, and threat actor types"""
    return BaseResponse(
        success=True,
        data=threat_intel_service.list_ioc_types()
    )


@router.post("/list", response_model=BaseResponse)
async def list_iocs(
    req: ThreatIntelGetRequest,
    _: str = Depends(require_read_access)
):
    """
    List IOCs from the SentinelOne Threat Intelligence API.

    Uses POST to securely pass API credentials in the body.
    Proxies GET /web/api/v2.1/threat-intelligence/iocs on S1.
    """
    try:
        result = threat_intel_service.get_iocs(
            s1_management_url=req.s1_management_url,
            api_token=req.api_token,
            auth_type=req.auth_type,
            account_ids=req.account_id,
            site_ids=req.site_id,
            ioc_type=req.ioc_type,
            value=req.value,
            source=req.source,
            creator=req.creator,
            limit=req.limit,
            cursor=req.cursor,
        )

        return BaseResponse(
            success=result.get("success", False),
            data=result,
        )
    except Exception as e:
        logger.error(f"Failed to list IOCs: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/send", response_model=BaseResponse)
async def send_iocs(
    req: ThreatIntelSendRequest,
    _: str = Depends(require_write_access)
):
    """
    Send IOCs to the SentinelOne Threat Intelligence API.

    Uses the S1 Management API with ApiToken authentication.
    IOCs are added to the private TI repository for third-party matching.
    """
    try:
        # Build IOC dicts from the structured request
        ioc_dicts = []
        for ioc in req.iocs:
            ioc_dict = threat_intel_service.build_ioc(
                ioc_type=ioc.type,
                value=ioc.value,
                method=ioc.method,
                source=ioc.source,
                creator=ioc.creator,
                name=ioc.name,
                description=ioc.description,
                severity=ioc.severity,
                original_risk_score=ioc.original_risk_score,
                valid_until=ioc.valid_until,
                creation_time=ioc.creation_time,
                external_id=ioc.external_id,
                pattern=ioc.pattern,
                pattern_type=ioc.pattern_type,
                metadata=ioc.metadata,
                reference=ioc.reference,
                intrusion_sets=ioc.intrusion_sets,
                campaign_names=ioc.campaign_names,
                malware_names=ioc.malware_names,
                mitre_tactic=ioc.mitre_tactic,
                threat_actors=ioc.threat_actors,
                labels=ioc.labels,
                category=ioc.category,
                threat_actor_types=ioc.threat_actor_types,
            )
            ioc_dicts.append(ioc_dict)

        result = threat_intel_service.send_iocs(
            s1_management_url=req.s1_management_url,
            api_token=req.api_token,
            iocs=ioc_dicts,
            auth_type=req.auth_type,
            account_ids=req.account_id,
            site_ids=req.site_id,
        )

        return BaseResponse(
            success=result.get("success", False),
            data=result,
        )
    except Exception as e:
        logger.error(f"Failed to send IOCs: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/send-custom", response_model=BaseResponse)
async def send_custom_iocs(
    req: ThreatIntelCustomRequest,
    _: str = Depends(require_write_access)
):
    """
    Send custom IOC JSON to the SentinelOne Threat Intelligence API.

    Accepts raw IOC dicts and sends them directly without building.
    """
    try:
        result = threat_intel_service.send_iocs(
            s1_management_url=req.s1_management_url,
            api_token=req.api_token,
            iocs=req.iocs_json,
            auth_type=req.auth_type,
            account_ids=req.account_id,
            site_ids=req.site_id,
        )

        return BaseResponse(
            success=result.get("success", False),
            data=result,
        )
    except Exception as e:
        logger.error(f"Failed to send custom IOCs: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))
