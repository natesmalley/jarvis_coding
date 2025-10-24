"""Utilities for HEC endpoint handling"""
from typing import Optional


def build_hec_url_from_destination(destination: dict) -> Optional[str]:
    """
    Build HEC URL from destination configuration.
    
    Args:
        destination: Dictionary containing destination configuration
        
    Returns:
        Complete HEC URL or None if invalid
    """
    if destination.get('type') != 'hec':
        return None
    
    endpoint_format = destination.get('endpoint_format', 'full_url')
    
    if endpoint_format == 'ip_port':
        # Build URL from host:port
        host = destination.get('host')
        port = destination.get('port')
        use_https = destination.get('use_https', True)
        
        if not host or not port:
            return None
        
        protocol = 'https' if use_https else 'http'
        base_url = f"{protocol}://{host}:{port}"
        
        # Add standard HEC path
        return f"{base_url}/services/collector"
    else:
        # Use full URL directly
        url = destination.get('url')
        if not url:
            return None
        
        # Normalize URL
        base_url = url.rstrip('/')
        if not (base_url.endswith('/event') or base_url.endswith('/raw') or '/services/collector' in base_url):
            base_url = base_url + '/services/collector'
        
        return base_url


def get_hec_endpoints(base_url: str) -> tuple[str, str]:
    """
    Get event and raw endpoints from base HEC URL.
    
    Args:
        base_url: Base HEC URL
        
    Returns:
        Tuple of (event_endpoint, raw_endpoint)
    """
    base = base_url.rstrip('/')
    
    # If URL already ends with /event or /raw, derive the other
    if base.endswith('/event'):
        event_url = base
        raw_url = base[:-6] + '/raw'
    elif base.endswith('/raw'):
        raw_url = base
        event_url = base[:-4] + '/event'
    else:
        # Assume base URL, add endpoints
        if not base.endswith('/services/collector'):
            base = base + '/services/collector'
        event_url = base + '/event'
        raw_url = base + '/raw'
    
    return event_url, raw_url