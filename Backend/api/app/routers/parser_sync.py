"""API endpoints for parser synchronization with destination SIEM"""
from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel, Field
from typing import Optional, Dict, List
import logging

from app.services.parser_sync_service import get_parser_sync_service, ParserSyncService
from app.services.github_parser_service import get_github_parser_service
from app.core.simple_auth import get_api_key

logger = logging.getLogger(__name__)

router = APIRouter()


class ParserSyncRequest(BaseModel):
    """Request model for parser sync"""
    scenario_id: str = Field(..., description="Scenario identifier")
    config_api_url: str = Field(..., description="Config API URL (e.g., https://xdr.us1.sentinelone.net)")
    config_write_token: str = Field(..., description="Config API token for reading and writing parsers")
    sources: Optional[List[str]] = Field(None, description="Optional list of sources to sync (overrides scenario defaults)")
    github_repo_urls: Optional[List[str]] = Field(None, description="Optional GitHub repository URLs to fetch parsers from")
    github_token: Optional[str] = Field(None, description="Optional GitHub token for private repositories")
    selected_parsers: Optional[Dict[str, Dict]] = Field(None, description="Optional user-selected parsers for similar name resolution")


class ParserSyncResponse(BaseModel):
    """Response model for parser sync"""
    scenario_id: str
    sources_checked: int
    parsers_uploaded: int
    parsers_existing: int
    parsers_failed: int
    results: Dict[str, dict]


@router.post("/sync", response_model=ParserSyncResponse)
async def sync_parsers(
    request: ParserSyncRequest,
    auth_info: tuple = Depends(get_api_key)
):
    """
    Synchronize parsers for a scenario with the destination SIEM
    
    This endpoint:
    1. Determines which parsers are needed for the scenario
    2. Checks if each parser exists in the destination SIEM (using getFile API)
    3. Uploads missing parsers (using putFile API)
    
    Returns detailed status for each parser.
    """
    # Create service with the destination's config API URL
    service = ParserSyncService(config_api_url=request.config_api_url)
    
    # Get sources for the scenario or use provided sources
    if request.sources:
        sources = request.sources
    else:
        sources = service.get_scenario_sources(request.scenario_id)
    
    if not sources:
        logger.warning(f"No sources found for scenario: {request.scenario_id}")
        return ParserSyncResponse(
            scenario_id=request.scenario_id,
            sources_checked=0,
            parsers_uploaded=0,
            parsers_existing=0,
            parsers_failed=0,
            results={}
        )
    
    logger.info(f"Syncing parsers for scenario {request.scenario_id}: {sources}")
    
    # Perform parser sync with optional GitHub repos
    results = service.ensure_parsers_for_sources(
        sources=sources,
        config_write_token=request.config_write_token,
        github_repo_urls=request.github_repo_urls,
        github_token=request.github_token,
        selected_parsers=request.selected_parsers
    )
    
    # Count results (include uploaded_from_github in uploaded count)
    uploaded = sum(1 for r in results.values() if r.get('status') in ('uploaded', 'uploaded_from_github'))
    existing = sum(1 for r in results.values() if r.get('status') == 'exists')
    failed = sum(1 for r in results.values() if r.get('status') in ('failed', 'no_parser'))
    
    logger.info(
        f"Parser sync complete for {request.scenario_id}: "
        f"{existing} existing, {uploaded} uploaded, {failed} failed"
    )
    
    return ParserSyncResponse(
        scenario_id=request.scenario_id,
        sources_checked=len(sources),
        parsers_uploaded=uploaded,
        parsers_existing=existing,
        parsers_failed=failed,
        results=results
    )


class SingleParserSyncRequest(BaseModel):
    """Request model for syncing a single parser by sourcetype"""
    sourcetype: str = Field(..., description="Sourcetype/parser name to sync")
    config_api_url: str = Field(..., description="Config API URL (e.g., https://xdr.us1.sentinelone.net)")
    config_write_token: str = Field(..., description="Config API token for reading and writing parsers")
    github_repo_urls: Optional[List[str]] = Field(None, description="Optional GitHub repository URLs to fetch parsers from")
    github_token: Optional[str] = Field(None, description="Optional GitHub token for private repositories")


class SingleParserSyncResponse(BaseModel):
    """Response model for single parser sync"""
    sourcetype: str
    status: str  # 'exists', 'uploaded', 'uploaded_from_github', 'failed', 'no_parser'
    message: str


@router.post("/sync-single", response_model=SingleParserSyncResponse)
async def sync_single_parser(
    request: SingleParserSyncRequest,
    auth_info: tuple = Depends(get_api_key)
):
    """
    Synchronize a single parser by sourcetype with the destination SIEM
    
    This endpoint is used by the Upload feature to ensure the parser exists
    before sending events. It:
    1. Checks if the parser exists in the destination SIEM
    2. If not, attempts to find and upload it from local parsers or GitHub repos
    
    Returns the sync status for the parser.
    """
    # Create service with the destination's config API URL
    service = ParserSyncService(config_api_url=request.config_api_url)
    
    logger.info(f"Syncing single parser for sourcetype: {request.sourcetype}")
    
    # Use the sourcetype as the source name for lookup
    results = service.ensure_parsers_for_sources(
        sources=[request.sourcetype],
        config_write_token=request.config_write_token,
        github_repo_urls=request.github_repo_urls,
        github_token=request.github_token
    )
    
    # Get result for the sourcetype
    result = results.get(request.sourcetype, {})
    status = result.get('status', 'no_parser')
    message = result.get('message', 'Unknown status')
    
    logger.info(f"Single parser sync for {request.sourcetype}: {status} - {message}")
    
    return SingleParserSyncResponse(
        sourcetype=request.sourcetype,
        status=status,
        message=message
    )


@router.get("/sources/{scenario_id}")
async def get_scenario_sources(
    scenario_id: str,
    auth_info: tuple = Depends(get_api_key)
):
    """
    Get the list of sources (and their parsers) required for a scenario
    """
    service = get_parser_sync_service()
    sources = service.get_scenario_sources(scenario_id)
    
    result = []
    for source in sources:
        sourcetype = service.get_parser_sourcetype(source)
        result.append({
            "source": source,
            "sourcetype": sourcetype,
            "parser_path": service.get_parser_path_in_siem(sourcetype) if sourcetype else None
        })
    
    return {
        "scenario_id": scenario_id,
        "sources": result
    }


@router.post("/check")
async def check_parser_exists(
    parser_path: str,
    config_token: str,
    auth_info: tuple = Depends(get_api_key)
):
    """
    Check if a specific parser exists in the destination SIEM
    """
    service = get_parser_sync_service()
    exists, content = service.check_parser_exists(config_token, parser_path)
    
    return {
        "parser_path": parser_path,
        "exists": exists,
        "has_content": content is not None
    }


class GitHubParserSearchRequest(BaseModel):
    """Request model for searching parsers in GitHub repos"""
    parser_name: str = Field(..., description="Parser name to search for")
    repo_urls: List[str] = Field(..., description="List of GitHub repository URLs to search")
    github_token: Optional[str] = Field(None, description="Optional GitHub token for private repos")


class GitHubParserMatch(BaseModel):
    """A parser match from GitHub"""
    name: str
    path: str
    repo_url: str
    similarity: float
    is_exact_normalized: bool


class GitHubParserSearchResponse(BaseModel):
    """Response model for GitHub parser search"""
    parser_name: str
    matches: List[Dict]
    has_similar_names: bool


@router.post("/github/search", response_model=GitHubParserSearchResponse)
async def search_github_parsers(
    request: GitHubParserSearchRequest,
    auth_info: tuple = Depends(get_api_key)
):
    """
    Search for a parser in configured GitHub repositories
    
    Returns matching parsers with similarity scores. If multiple similar
    parsers are found, the frontend should prompt the user to select one.
    """
    service = get_github_parser_service()
    
    matches = service.search_parser_in_repos(
        parser_name=request.parser_name,
        repo_urls=request.repo_urls,
        github_token=request.github_token
    )
    
    # Check if there are multiple similar matches that need user confirmation
    has_similar = len(matches) > 1 or (
        len(matches) == 1 and not matches[0].get('is_exact_normalized', False)
    )
    
    return GitHubParserSearchResponse(
        parser_name=request.parser_name,
        matches=matches,
        has_similar_names=has_similar
    )


class GitHubParserFetchRequest(BaseModel):
    """Request model for fetching a specific parser from GitHub"""
    repo_url: str = Field(..., description="GitHub repository URL")
    parser_path: str = Field(..., description="Path to the parser directory in the repo")
    github_token: Optional[str] = Field(None, description="Optional GitHub token for private repos")


@router.post("/github/fetch")
async def fetch_github_parser(
    request: GitHubParserFetchRequest,
    auth_info: tuple = Depends(get_api_key)
):
    """
    Fetch parser content from a specific GitHub repository path
    """
    service = get_github_parser_service()
    
    content = service.fetch_parser_content(
        repo_url=request.repo_url,
        parser_path=request.parser_path,
        github_token=request.github_token
    )
    
    if content is None:
        raise HTTPException(
            status_code=404,
            detail=f"Parser not found at {request.parser_path} in {request.repo_url}"
        )
    
    return {
        "repo_url": request.repo_url,
        "parser_path": request.parser_path,
        "content": content
    }


@router.get("/github/list")
async def list_github_repo_parsers(
    repo_url: str,
    github_token: Optional[str] = None,
    auth_info: tuple = Depends(get_api_key)
):
    """
    List all parsers available in a GitHub repository
    """
    service = get_github_parser_service()

    result = service.list_parsers_in_repo(
        repo_url=repo_url,
        github_token=github_token,
        return_meta=True
    )

    return {
        "repo_url": repo_url,
        "parsers": result.get("parsers", []),
        "count": result.get("count", 0),
        "rate_limited": result.get("rate_limited", False),
        "warning": result.get("warning"),
        "status_code": result.get("status_code"),
    }
