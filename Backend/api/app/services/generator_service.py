"""
Generator service for handling generator operations
"""
import importlib.util
import sys
import json
import traceback
from pathlib import Path
from typing import List, Optional, Dict, Any
import re

from app.core.config import settings


class GeneratorService:
    """Service for managing generators"""
    
    def __init__(self):
        self.generators_path = settings.GENERATORS_PATH
        self.generator_cache = {}
        self._load_generator_metadata()
    
    def _load_generator_metadata(self):
        """Load metadata for all generators"""
        self.generator_metadata = {}
        
        # Define categories with their metadata
        categories_info = {
            "cloud_infrastructure": {
                "name": "Cloud Infrastructure",
                "description": "AWS, Google Cloud, Azure services",
                "icon": "☁️"
            },
            "network_security": {
                "name": "Network Security", 
                "description": "Firewalls, NDR, network devices",
                "icon": "🔒"
            },
            "endpoint_security": {
                "name": "Endpoint Security",
                "description": "EDR, endpoint protection platforms",
                "icon": "🖥️"
            },
            "identity_access": {
                "name": "Identity & Access",
                "description": "IAM, SSO, PAM solutions",
                "icon": "👤"
            },
            "email_security": {
                "name": "Email Security",
                "description": "Email protection platforms",
                "icon": "📧"
            },
            "web_security": {
                "name": "Web Security",
                "description": "WAF, web proxies, CDN security",
                "icon": "🌐"
            },
            "infrastructure": {
                "name": "Infrastructure",
                "description": "IT management, backup, DevOps",
                "icon": "🔧"
            }
        }
        
        # Scan for generators
        for category_dir in self.generators_path.iterdir():
            if category_dir.is_dir() and not category_dir.name.startswith('_'):
                category = category_dir.name
                
                for generator_file in category_dir.glob("*.py"):
                    if generator_file.name.startswith('_'):
                        continue
                    
                    generator_id = generator_file.stem
                    vendor, product = self._parse_generator_name(generator_id)
                    
                    self.generator_metadata[generator_id] = {
                        "id": generator_id,
                        "name": self._format_name(generator_id),
                        "category": category,
                        "vendor": vendor,
                        "product": product,
                        "description": f"{vendor} {product} event generator",
                        "file_path": str(generator_file),
                        "supported_formats": ["json"],  # Default, will be updated
                        "star_trek_enabled": True
                    }
    
    def _parse_generator_name(self, generator_id: str) -> tuple:
        """Parse vendor and product from generator ID"""
        parts = generator_id.split('_')
        if len(parts) >= 2:
            vendor = parts[0].title()
            product = '_'.join(parts[1:]).replace('_', ' ').title()
        else:
            vendor = generator_id.title()
            product = generator_id.title()
        return vendor, product
    
    def _format_name(self, generator_id: str) -> str:
        """Format generator ID to readable name"""
        return generator_id.replace('_', ' ').title()
    
    async def list_generators(
        self,
        category: Optional[str] = None,
        vendor: Optional[str] = None,
        search: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """List all generators with optional filters"""
        generators = []
        
        for gen_id, metadata in self.generator_metadata.items():
            # Apply filters
            if category and metadata["category"] != category:
                continue
            
            if vendor and vendor.lower() not in metadata["vendor"].lower():
                continue
            
            if search:
                search_lower = search.lower()
                if (search_lower not in gen_id.lower() and 
                    search_lower not in metadata["name"].lower() and
                    search_lower not in metadata["description"].lower()):
                    continue
            
            generators.append(metadata)
        
        return generators
    
    async def list_categories(self) -> List[Dict[str, Any]]:
        """List all generator categories"""
        categories = {}
        
        for metadata in self.generator_metadata.values():
            category = metadata["category"]
            if category not in categories:
                categories[category] = {
                    "id": category,
                    "name": category.replace('_', ' ').title(),
                    "generator_count": 0,
                    "top_generators": []
                }
            
            categories[category]["generator_count"] += 1
            if len(categories[category]["top_generators"]) < 3:
                categories[category]["top_generators"].append(metadata["id"])
        
        return list(categories.values())
    
    async def get_generator(self, generator_id: str) -> Optional[Dict[str, Any]]:
        """Get details for a specific generator"""
        if generator_id in self.generator_metadata:
            metadata = self.generator_metadata[generator_id].copy()
            
            # Try to get a sample output
            try:
                sample = await self.execute_generator(generator_id, count=1)
                if sample:
                    metadata["sample_output"] = sample[0]
            except:
                pass
            
            return metadata
        return None
    
    async def execute_generator(
        self,
        generator_id: str,
        count: int = 1,
        format: str = "json",
        star_trek_theme: bool = True,
        options: Dict[str, Any] = None
    ) -> List[Dict[str, Any]]:
        """Execute a generator and return events"""
        if generator_id not in self.generator_metadata:
            raise ValueError(f"Generator '{generator_id}' not found")
        
        metadata = self.generator_metadata[generator_id]
        file_path = metadata["file_path"]
        
        # Load and execute generator
        try:
            # Load the generator module
            spec = importlib.util.spec_from_file_location(generator_id, file_path)
            if not spec or not spec.loader:
                raise ImportError(f"Cannot load generator from {file_path}")
            
            module = importlib.util.module_from_spec(spec)
            
            # Add module to sys.modules temporarily
            sys.modules[generator_id] = module
            
            # Execute the module
            spec.loader.exec_module(module)
            
            # Find the generator function
            # Try common patterns: vendor_product_log, product_log, generate_event
            function_name = None
            for possible_name in [
                f"{generator_id}_log",
                generator_id.replace('_', '') + "_log",
                "generate_event",
                "generate_log"
            ]:
                if hasattr(module, possible_name):
                    function_name = possible_name
                    break
            
            if not function_name:
                # Try to find any function ending with _log
                for attr_name in dir(module):
                    if attr_name.endswith('_log') and not attr_name.startswith('_'):
                        function_name = attr_name
                        break
            
            if not function_name:
                raise AttributeError(f"No generator function found in {generator_id}")
            
            generator_func = getattr(module, function_name)
            
            # Generate events
            events = []
            for _ in range(count):
                event = generator_func()
                
                # Ensure event is a dict
                if isinstance(event, str):
                    try:
                        event = json.loads(event)
                    except:
                        event = {"raw": event}
                
                events.append(event)
            
            return events
            
        except Exception as e:
            raise RuntimeError(f"Failed to execute generator {generator_id}: {str(e)}")
        finally:
            # Clean up module from sys.modules
            if generator_id in sys.modules:
                del sys.modules[generator_id]
    
    async def validate_generator(
        self,
        generator_id: str,
        sample_size: int = 5
    ) -> Dict[str, Any]:
        """Validate generator output"""
        try:
            # Generate sample events
            events = await self.execute_generator(generator_id, count=sample_size)
            
            # Validation checks
            validation_results = {
                "valid": True,
                "generator_id": generator_id,
                "sample_size": sample_size,
                "checks": {
                    "events_generated": len(events) == sample_size,
                    "all_dict_format": all(isinstance(e, dict) for e in events),
                    "has_timestamp": all("timestamp" in e or "time" in e for e in events),
                    "star_trek_theme": any("starfleet" in str(e).lower() or "picard" in str(e).lower() for e in events),
                    "non_empty": all(e for e in events)
                },
                "issues": [],
                "warnings": []
            }
            
            # Check for issues
            if not validation_results["checks"]["events_generated"]:
                validation_results["issues"].append(f"Expected {sample_size} events, got {len(events)}")
                validation_results["valid"] = False
            
            if not validation_results["checks"]["all_dict_format"]:
                validation_results["issues"].append("Not all events are in dictionary format")
                validation_results["valid"] = False
            
            if not validation_results["checks"]["has_timestamp"]:
                validation_results["warnings"].append("Some events missing timestamp field")
            
            if not validation_results["checks"]["star_trek_theme"]:
                validation_results["warnings"].append("Star Trek theme not detected in events")
            
            return validation_results
            
        except Exception as e:
            return {
                "valid": False,
                "generator_id": generator_id,
                "error": str(e),
                "issues": [f"Validation failed: {str(e)}"]
            }
    
    async def get_generator_schema(self, generator_id: str) -> Dict[str, Any]:
        """Get the output schema for a generator"""
        try:
            # Generate a sample event
            events = await self.execute_generator(generator_id, count=1)
            if not events:
                return {}
            
            sample = events[0]
            
            # Build schema from sample
            schema = {
                "type": "object",
                "properties": {},
                "required": []
            }
            
            for key, value in sample.items():
                # Determine type
                if isinstance(value, str):
                    prop_type = "string"
                elif isinstance(value, (int, float)):
                    prop_type = "number"
                elif isinstance(value, bool):
                    prop_type = "boolean"
                elif isinstance(value, list):
                    prop_type = "array"
                elif isinstance(value, dict):
                    prop_type = "object"
                else:
                    prop_type = "string"
                
                schema["properties"][key] = {
                    "type": prop_type,
                    "example": value
                }
                
                # Mark common fields as required
                if key in ["timestamp", "time", "event_type", "user", "host"]:
                    schema["required"].append(key)
            
            return schema
            
        except Exception as e:
            raise RuntimeError(f"Failed to generate schema: {str(e)}")