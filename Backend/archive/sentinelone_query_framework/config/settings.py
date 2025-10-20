"""
Configuration Settings for SentinelOne Query Framework
Centralized configuration management with environment variable support
"""

import os
from typing import Dict, List, Optional
from pathlib import Path

class SentinelOneConfig:
    """Configuration management for SentinelOne Query Framework"""
    
    # SentinelOne API Configuration
    DEFAULT_API_URL = "https://usea1-purple.sentinelone.net"
    DEFAULT_TIMEOUT = 30
    DEFAULT_RETRY_ATTEMPTS = 3
    
    # Query Configuration
    DEFAULT_TIME_WINDOW_MINUTES = 15
    DEFAULT_QUERY_LIMIT = 100
    DEFAULT_MAX_EVENTS_PER_QUERY = 1000
    
    # Paths Configuration
    PROJECT_ROOT = Path(__file__).parent.parent.parent
    DEFAULT_GENERATORS_PATH = PROJECT_ROOT / "event_generators"
    DEFAULT_PARSERS_PATH = PROJECT_ROOT / "parsers" / "community"
    DEFAULT_OUTPUT_DIR = PROJECT_ROOT / "reports"
    DEFAULT_LOGS_DIR = PROJECT_ROOT / "logs"
    
    # Framework Configuration
    DEFAULT_LOG_LEVEL = "INFO"
    DEFAULT_SESSION_TIMEOUT_HOURS = 24
    
    @classmethod
    def get_api_config(cls) -> Dict:
        """Get API configuration from environment or defaults"""
        return {
            'api_url': os.getenv('S1_API_URL', cls.DEFAULT_API_URL),
            'api_token': os.getenv('S1_SDL_API_TOKEN'),
            'hec_token': os.getenv('S1_HEC_TOKEN'),
            'timeout': int(os.getenv('S1_API_TIMEOUT', cls.DEFAULT_TIMEOUT)),
            'retry_attempts': int(os.getenv('S1_API_RETRY_ATTEMPTS', cls.DEFAULT_RETRY_ATTEMPTS))
        }
    
    @classmethod
    def get_query_config(cls) -> Dict:
        """Get query configuration"""
        return {
            'default_time_window_minutes': int(os.getenv('S1_DEFAULT_TIME_WINDOW', cls.DEFAULT_TIME_WINDOW_MINUTES)),
            'default_limit': int(os.getenv('S1_DEFAULT_LIMIT', cls.DEFAULT_QUERY_LIMIT)),
            'max_events_per_query': int(os.getenv('S1_MAX_EVENTS', cls.DEFAULT_MAX_EVENTS_PER_QUERY))
        }
    
    @classmethod
    def get_path_config(cls) -> Dict:
        """Get path configuration"""
        return {
            'generators_path': Path(os.getenv('GENERATORS_PATH', cls.DEFAULT_GENERATORS_PATH)),
            'parsers_path': Path(os.getenv('PARSERS_PATH', cls.DEFAULT_PARSERS_PATH)),
            'output_dir': Path(os.getenv('OUTPUT_DIR', cls.DEFAULT_OUTPUT_DIR)),
            'logs_dir': Path(os.getenv('LOGS_DIR', cls.DEFAULT_LOGS_DIR))
        }
    
    @classmethod
    def get_logging_config(cls) -> Dict:
        """Get logging configuration"""
        return {
            'log_level': os.getenv('LOG_LEVEL', cls.DEFAULT_LOG_LEVEL),
            'log_format': '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            'log_file': cls.get_path_config()['logs_dir'] / 'framework.log'
        }
    
    @classmethod
    def validate_configuration(cls) -> Dict:
        """Validate configuration and return status"""
        config_status = {
            'valid': True,
            'errors': [],
            'warnings': []
        }
        
        api_config = cls.get_api_config()
        path_config = cls.get_path_config()
        
        # Validate API token
        if not api_config['api_token']:
            config_status['errors'].append("S1_SDL_API_TOKEN environment variable not set")
            config_status['valid'] = False
        
        # Validate paths
        if not path_config['generators_path'].exists():
            config_status['errors'].append(f"Generators path not found: {path_config['generators_path']}")
            config_status['valid'] = False
        
        if not path_config['parsers_path'].exists():
            config_status['warnings'].append(f"Parsers path not found: {path_config['parsers_path']}")
        
        # Create output directories if they don't exist
        try:
            path_config['output_dir'].mkdir(exist_ok=True, parents=True)
            path_config['logs_dir'].mkdir(exist_ok=True, parents=True)
        except Exception as e:
            config_status['warnings'].append(f"Could not create output directories: {str(e)}")
        
        return config_status
    
    @classmethod
    def get_generator_categories(cls) -> List[str]:
        """Get list of generator categories"""
        generators_path = cls.get_path_config()['generators_path']
        categories = []
        
        if generators_path.exists():
            for item in generators_path.iterdir():
                if item.is_dir() and not item.name.startswith('.') and item.name != 'shared':
                    categories.append(item.name)
        
        return sorted(categories)
    
    @classmethod
    def get_marketplace_parsers(cls) -> List[str]:
        """Get list of available marketplace parsers"""
        # This would typically come from SentinelOne API or configuration
        # For now, return common marketplace parsers
        return [
            'marketplace-awscloudtrail-latest',
            'marketplace-awselasticloadbalancer-latest',
            'marketplace-awsguardduty-latest',
            'marketplace-awsvpcflowlogs-latest',
            'marketplace-checkpointfirewall-latest',
            'marketplace-ciscofirewallthreatdefense-latest',
            'marketplace-ciscofirepowerthreatdefense-latest',
            'marketplace-ciscoumbrella-latest',
            'marketplace-corelight-conn-latest',
            'marketplace-corelight-http-latest',
            'marketplace-corelight-ssl-latest',
            'marketplace-corelight-tunnel-latest',
            'marketplace-fortinetfortigate-latest',
            'marketplace-paloaltonetworksfirewall-latest',
            'marketplace-zscalerinternetaccess-latest',
            'marketplace-zscalerprivateaccess-latest'
        ]

# Global configuration instance
config = SentinelOneConfig()