"""
Parser service for handling parser operations
"""
import json
from pathlib import Path
from typing import List, Optional, Dict, Any

from app.core.config import settings


class ParserService:
    """Service for managing parsers"""
    
    def __init__(self):
        self.parsers_path = settings.PARSERS_PATH
        self.parser_cache = {}
        self._load_parser_metadata()
    
    def _load_parser_metadata(self):
        """Load metadata for all parsers"""
        self.parser_metadata = {}
        
        # Scan community parsers
        community_path = self.parsers_path / "community"
        if community_path.exists():
            for parser_dir in community_path.iterdir():
                if parser_dir.is_dir() and not parser_dir.name.startswith('_'):
                    self._load_parser_from_directory(parser_dir, "community")
    
    def _load_parser_from_directory(self, parser_dir: Path, parser_type: str):
        """Load parser metadata from a directory"""
        parser_id = parser_dir.name.replace('-latest', '')
        
        # Extract parser information first (before any potential errors)
        vendor, product = self._parse_parser_name(parser_id)
        
        # Look for JSON configuration files
        json_files = list(parser_dir.glob("*.json"))
        metadata_file = parser_dir / "metadata.yaml"
        
        if json_files:
            # Use the first JSON file as main config
            config_file = json_files[0]
            
            try:
                with open(config_file, 'r') as f:
                    config = json.load(f)
                
                # Determine parsing method
                parse_method = self._determine_parse_method(config)
                field_count = self._count_fields(config)
                
                self.parser_metadata[parser_id] = {
                    "id": parser_id,
                    "name": self._format_name(parser_id),
                    "type": parser_type,
                    "vendor": vendor,
                    "product": product,
                    "description": f"{vendor} {product} log parser",
                    "file_path": str(config_file),
                    "directory_path": str(parser_dir),
                    "parse_method": parse_method,
                    "field_count": field_count,
                    "config_valid": True,
                    "supported_formats": self._get_supported_formats(config),
                    "ocsf_compliant": "class_uid" in str(config) or "category_uid" in str(config),
                    "has_mappings": "mappings" in config or "rewrites" in str(config)
                }
                
            except json.JSONDecodeError as e:
                # Handle broken JSON
                self.parser_metadata[parser_id] = {
                    "id": parser_id,
                    "name": self._format_name(parser_id),
                    "type": parser_type,
                    "vendor": vendor,
                    "product": product,
                    "description": f"{vendor} {product} log parser (JSON syntax error)",
                    "file_path": str(config_file),
                    "directory_path": str(parser_dir),
                    "parse_method": "unknown",
                    "field_count": 0,
                    "config_valid": False,
                    "config_error": f"JSON Error: {str(e)}",
                    "supported_formats": [],
                    "ocsf_compliant": False,
                    "has_mappings": False
                }
            
            except Exception as e:
                # Handle other errors
                self.parser_metadata[parser_id] = {
                    "id": parser_id,
                    "name": self._format_name(parser_id),
                    "type": parser_type,
                    "vendor": vendor,
                    "product": product,
                    "description": f"{vendor} {product} log parser (configuration error)",
                    "file_path": str(config_file),
                    "directory_path": str(parser_dir),
                    "parse_method": "unknown",
                    "field_count": 0,
                    "config_valid": False,
                    "config_error": f"Config Error: {str(e)}",
                    "supported_formats": [],
                    "ocsf_compliant": False,
                    "has_mappings": False
                }
        else:
            # No JSON files found
            self.parser_metadata[parser_id] = {
                "id": parser_id,
                "name": self._format_name(parser_id),
                "type": parser_type,
                "vendor": vendor,
                "product": product,
                "description": f"{vendor} {product} log parser (no configuration found)",
                "file_path": "none",
                "directory_path": str(parser_dir),
                "parse_method": "unknown",
                "field_count": 0,
                "config_valid": False,
                "config_error": "No JSON configuration files found",
                "supported_formats": [],
                "ocsf_compliant": False,
                "has_mappings": False
            }
    
    def _parse_parser_name(self, parser_id: str) -> tuple:
        """Parse vendor and product from parser ID"""
        # Remove common suffixes
        clean_id = parser_id.replace('_logs', '').replace('_log', '')
        
        parts = clean_id.split('_')
        if len(parts) >= 2:
            vendor = parts[0].title()
            product = '_'.join(parts[1:]).replace('_', ' ').title()
        else:
            vendor = clean_id.title()
            product = clean_id.title()
        return vendor, product
    
    def _format_name(self, parser_id: str) -> str:
        """Format parser ID to readable name"""
        return parser_id.replace('_', ' ').replace(' logs', '').replace(' log', '').title()
    
    def _determine_parse_method(self, config: Dict[str, Any]) -> str:
        """Determine the parsing method from config"""
        config_str = str(config).lower()
        
        if 'parse=gron' in config_str:
            return "gron"
        elif 'logpattern' in config_str:
            return "regex"
        elif 'formats' in config and isinstance(config['formats'], list):
            return "format"
        elif 'mappings' in config:
            return "mappings"
        else:
            return "unknown"
    
    def _count_fields(self, config: Dict[str, Any]) -> int:
        """Count extractable fields from parser config"""
        field_count = 0
        
        # Count from rewrites
        if 'formats' in config:
            for format_config in config['formats']:
                if 'rewrites' in format_config:
                    field_count += len(format_config['rewrites'])
        
        # Count from mappings
        if 'mappings' in config and 'mappings' in config['mappings']:
            for mapping in config['mappings']['mappings']:
                if 'transformations' in mapping:
                    field_count += len(mapping['transformations'])
        
        # Default estimate for gron parsers
        if field_count == 0 and 'parse=gron' in str(config):
            field_count = 20  # Gron can extract many fields dynamically
        
        return field_count
    
    def _get_supported_formats(self, config: Dict[str, Any]) -> List[str]:
        """Get supported input formats for this parser"""
        formats = []
        
        config_str = str(config).lower()
        
        if 'parse=gron' in config_str:
            formats.append("json")
        if 'logpattern' in config_str or 'syslog' in config_str:
            formats.append("syslog")
        if 'csv' in config_str or 'delimiter' in config_str:
            formats.append("csv")
        if 'cef' in config_str:
            formats.append("cef")
        if 'key=value' in config_str or 'kv' in config_str:
            formats.append("key_value")
        
        # Default
        if not formats:
            formats.append("text")
        
        return formats
    
    async def list_parsers(
        self,
        type: Optional[str] = None,
        vendor: Optional[str] = None,
        search: Optional[str] = None,
        valid_only: bool = False
    ) -> List[Dict[str, Any]]:
        """List all parsers with optional filters"""
        parsers = []
        
        for parser_id, metadata in self.parser_metadata.items():
            # Apply filters
            if type and metadata["type"] != type:
                continue
            
            if vendor and vendor.lower() not in metadata["vendor"].lower():
                continue
            
            if search:
                search_lower = search.lower()
                if (search_lower not in parser_id.lower() and 
                    search_lower not in metadata["name"].lower() and
                    search_lower not in metadata["description"].lower()):
                    continue
            
            if valid_only and not metadata.get("config_valid", False):
                continue
            
            parsers.append(metadata)
        
        return parsers
    
    async def get_parser(self, parser_id: str) -> Optional[Dict[str, Any]]:
        """Get details for a specific parser"""
        if parser_id in self.parser_metadata:
            metadata = self.parser_metadata[parser_id].copy()
            
            # Add configuration details
            if metadata.get("config_valid", False):
                try:
                    with open(metadata["file_path"], 'r') as f:
                        config = json.load(f)
                    metadata["configuration"] = config
                except:
                    pass
            
            return metadata
        return None
    
    async def validate_parser(self, parser_id: str) -> Dict[str, Any]:
        """Validate parser configuration"""
        if parser_id not in self.parser_metadata:
            return {
                "valid": False,
                "parser_id": parser_id,
                "error": "Parser not found"
            }
        
        metadata = self.parser_metadata[parser_id]
        validation_results = {
            "valid": metadata.get("config_valid", False),
            "parser_id": parser_id,
            "checks": {
                "config_syntax_valid": metadata.get("config_valid", False),
                "has_field_mappings": metadata.get("has_mappings", False),
                "ocsf_compliant": metadata.get("ocsf_compliant", False),
                "supported_formats": len(metadata.get("supported_formats", [])) > 0
            },
            "issues": [],
            "warnings": []
        }
        
        # Add issues
        if not validation_results["checks"]["config_syntax_valid"]:
            validation_results["issues"].append("JSON configuration syntax error")
            if "config_error" in metadata:
                validation_results["issues"].append(f"Error: {metadata['config_error']}")
        
        if not validation_results["checks"]["has_field_mappings"]:
            validation_results["warnings"].append("No field mappings detected")
        
        if not validation_results["checks"]["ocsf_compliant"]:
            validation_results["warnings"].append("No OCSF class/category UIDs found")
        
        return validation_results
    
    async def get_parser_stats(self) -> Dict[str, Any]:
        """Get overall parser statistics"""
        total_parsers = len(self.parser_metadata)
        valid_parsers = sum(1 for p in self.parser_metadata.values() if p.get("config_valid", False))
        
        # Count by type
        type_counts = {}
        vendor_counts = {}
        method_counts = {}
        
        for metadata in self.parser_metadata.values():
            # Type counts
            parser_type = metadata.get("type", "unknown")
            type_counts[parser_type] = type_counts.get(parser_type, 0) + 1
            
            # Vendor counts
            vendor = metadata.get("vendor", "unknown")
            vendor_counts[vendor] = vendor_counts.get(vendor, 0) + 1
            
            # Method counts
            method = metadata.get("parse_method", "unknown")
            method_counts[method] = method_counts.get(method, 0) + 1
        
        return {
            "total": total_parsers,
            "valid": valid_parsers,
            "invalid": total_parsers - valid_parsers,
            "success_rate": (valid_parsers / total_parsers * 100) if total_parsers > 0 else 0,
            "by_type": type_counts,
            "by_vendor": dict(sorted(vendor_counts.items(), key=lambda x: x[1], reverse=True)[:10]),
            "by_method": method_counts
        }