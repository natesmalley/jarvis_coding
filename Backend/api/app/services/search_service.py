"""
Search service for finding generators, parsers, and scenarios
"""
import re
from typing import List, Dict, Any, Optional
import logging

from app.services.generator_service import GeneratorService

logger = logging.getLogger(__name__)


class SearchService:
    def __init__(self):
        self.generator_service = GeneratorService()
        self._cache = {}
    
    async def search_generators(
        self, 
        query: Optional[str] = None, 
        category: Optional[str] = None,
        vendor: Optional[str] = None,
        format: Optional[str] = None,
        star_trek: Optional[bool] = None
    ) -> List[Dict[str, Any]]:
        """Search generators using text matching and filters"""
        try:
            generators = await self.generator_service.list_generators(
                category=category,
                vendor=vendor
            )
            
            results = []
            
            for generator in generators:
                # Apply filters
                if format and format not in generator.get("supported_formats", []):
                    continue
                
                if star_trek is not None and generator.get("star_trek_enabled", True) != star_trek:
                    continue
                
                # Apply text search if provided
                if query:
                    query_lower = query.lower()
                    searchable_text = " ".join([
                        generator.get("name", ""),
                        generator.get("description", ""),
                        generator.get("vendor", ""),
                        generator.get("category", ""),
                        " ".join(generator.get("supported_formats", []))
                    ]).lower()
                    
                    # Calculate relevance score
                    score = 0
                    if query_lower in generator.get("name", "").lower():
                        score += 10
                    if query_lower in generator.get("vendor", "").lower():
                        score += 5
                    if query_lower in generator.get("category", "").lower():
                        score += 3
                    if query_lower in generator.get("description", "").lower():
                        score += 1
                    
                    if score > 0 or query_lower in searchable_text:
                        generator["search_score"] = score
                        results.append(generator)
                else:
                    # No query, include all matching filters
                    results.append(generator)
            
            # Sort by relevance score if query was provided
            if query:
                results.sort(key=lambda x: x.get("search_score", 0), reverse=True)
            
            return results
            
        except Exception as e:
            logger.error(f"Error searching generators: {e}")
            return []
    
    async def search_parsers(
        self, 
        query: Optional[str] = None, 
        parser_type: Optional[str] = None,
        vendor: Optional[str] = None,
        min_fields: Optional[int] = None
    ) -> List[Dict[str, Any]]:
        """Search parsers (placeholder - implement based on parser service)"""
        # This would integrate with a parser service when available
        results = []
        
        # Mock parser search for now
        mock_parsers = [
            {
                "id": "crowdstrike_endpoint",
                "name": "CrowdStrike Endpoint",
                "type": "community",
                "vendor": "CrowdStrike",
                "description": "CrowdStrike Falcon endpoint events",
                "fields_count": 150
            },
            {
                "id": "aws_cloudtrail",
                "name": "AWS CloudTrail",
                "type": "marketplace",
                "vendor": "AWS",
                "description": "AWS CloudTrail API audit events",
                "fields_count": 120
            },
            {
                "id": "fortinet_fortigate",
                "name": "FortiGate Firewall",
                "type": "marketplace",
                "vendor": "Fortinet",
                "description": "FortiGate firewall security events",
                "fields_count": 240
            }
        ]
        
        for parser in mock_parsers:
            # Apply filters
            if parser_type and parser["type"] != parser_type:
                continue
            
            if vendor and vendor.lower() != parser["vendor"].lower():
                continue
                
            if min_fields and parser["fields_count"] < min_fields:
                continue
            
            # Apply text search if provided
            if query:
                query_lower = query.lower()
                searchable = f"{parser['name']} {parser['vendor']} {parser['description']}".lower()
                if query_lower in searchable:
                    results.append(parser)
            else:
                results.append(parser)
        
        return results
    
    async def search_scenarios(
        self, 
        query: Optional[str] = None,
        category: Optional[str] = None,
        min_phases: Optional[int] = None
    ) -> List[Dict[str, Any]]:
        """Search scenarios (placeholder)"""
        # Mock scenario search
        mock_scenarios = [
            {
                "id": "phishing_campaign",
                "name": "Phishing Campaign",
                "description": "Multi-stage phishing attack",
                "category": "email_attack",
                "phases": 3
            },
            {
                "id": "ransomware_attack", 
                "name": "Ransomware Attack",
                "description": "Ransomware deployment and lateral movement",
                "category": "malware_attack",
                "phases": 5
            },
            {
                "id": "insider_threat",
                "name": "Insider Threat",
                "description": "Malicious insider data exfiltration",
                "category": "data_theft",
                "phases": 4
            }
        ]
        
        results = []
        for scenario in mock_scenarios:
            # Apply filters
            if category and scenario["category"] != category:
                continue
            
            if min_phases and scenario["phases"] < min_phases:
                continue
            
            # Apply text search if provided
            if query:
                query_lower = query.lower()
                searchable = f"{scenario['name']} {scenario['description']}".lower()
                if query_lower in searchable:
                    results.append(scenario)
            else:
                results.append(scenario)
        
        return results
    
    async def global_search(
        self,
        query: str,
        types: Optional[List[str]] = None
    ) -> Dict[str, List[Dict[str, Any]]]:
        """Search across all resource types"""
        if types is None:
            types = ["generators", "parsers", "scenarios"]
        
        results = {}
        
        if "generators" in types:
            results["generators"] = await self.search_generators(query)
        
        if "parsers" in types:
            results["parsers"] = await self.search_parsers(query)
        
        if "scenarios" in types:
            results["scenarios"] = await self.search_scenarios(query)
        
        return results
    
    async def get_compatibility_matches(
        self,
        generator_id: Optional[str] = None,
        parser_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """Find compatible generators and parsers"""
        if generator_id:
            generator = await self.generator_service.get_generator(generator_id)
            if not generator:
                return {"matches": [], "message": "Generator not found"}
            
            # Find compatible parsers
            compatible_parsers = await self.search_parsers()
            matches = []
            
            for parser in compatible_parsers:
                # Simple compatibility check based on vendor
                if parser["vendor"].lower() == generator.get("vendor", "").lower():
                    matches.append({
                        "parser": parser,
                        "compatibility_score": 0.9,
                        "reason": "Same vendor"
                    })
            
            return {
                "generator": generator,
                "compatible_parsers": matches,
                "total_matches": len(matches)
            }
        
        elif parser_id:
            parsers = await self.search_parsers()
            parser = next((p for p in parsers if p["id"] == parser_id), None)
            
            if not parser:
                return {"matches": [], "message": "Parser not found"}
            
            # Find compatible generators
            compatible_generators = await self.search_generators(vendor=parser["vendor"])
            matches = []
            
            for generator in compatible_generators:
                matches.append({
                    "generator": generator,
                    "compatibility_score": 0.8,
                    "reason": "Same vendor"
                })
            
            return {
                "parser": parser,
                "compatible_generators": matches,
                "total_matches": len(matches)
            }
        
        return {"matches": [], "message": "No ID provided"}
    
    async def get_statistics(self) -> Dict[str, Any]:
        """Get statistics about searchable resources"""
        generators = await self.search_generators()
        parsers = await self.search_parsers()
        scenarios = await self.search_scenarios()
        
        # Count by categories
        generator_categories = {}
        for gen in generators:
            cat = gen.get("category", "unknown")
            generator_categories[cat] = generator_categories.get(cat, 0) + 1
        
        parser_types = {}
        for parser in parsers:
            ptype = parser.get("type", "unknown")
            parser_types[ptype] = parser_types.get(ptype, 0) + 1
        
        return {
            "generators": {
                "total": len(generators),
                "categories": generator_categories,
                "avg_supported_formats": sum(
                    len(g.get("supported_formats", [])) for g in generators
                ) / len(generators) if generators else 0
            },
            "parsers": {
                "total": len(parsers),
                "types": parser_types,
                "avg_fields": sum(
                    p.get("fields_count", 0) for p in parsers
                ) / len(parsers) if parsers else 0
            },
            "scenarios": {
                "total": len(scenarios),
                "avg_phases": sum(
                    s.get("phases", 0) for s in scenarios
                ) / len(scenarios) if scenarios else 0
            }
        }
    
    async def get_recommendations(
        self,
        resource_type: str,
        based_on: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """Get recommendations based on similarity or usage"""
        recommendations = []
        
        if resource_type == "generator":
            if based_on:
                generator = await self.generator_service.get_generator(based_on)
                if generator:
                    # Find similar generators
                    similar = await self.search_generators(
                        category=generator.get("category"),
                        vendor=generator.get("vendor")
                    )
                    recommendations = [g for g in similar if g.get("id") != based_on][:5]
            else:
                # Popular generators
                all_generators = await self.search_generators()
                recommendations = all_generators[:5]
        
        elif resource_type == "parser":
            all_parsers = await self.search_parsers()
            # Recommend high field count parsers
            recommendations = sorted(
                all_parsers, 
                key=lambda x: x.get("fields_count", 0), 
                reverse=True
            )[:5]
        
        elif resource_type == "scenario":
            recommendations = await self.search_scenarios()
        
        return recommendations
    
    async def build_search_index(self):
        """Build search index for faster lookups"""
        if not self._cache:
            generators = await self.search_generators()
            parsers = await self.search_parsers()
            scenarios = await self.search_scenarios()
            
            self._cache = {
                "generators": {
                    "by_category": {},
                    "by_vendor": {},
                    "by_format": {}
                },
                "parsers": {
                    "by_type": {},
                    "by_vendor": {}
                },
                "scenarios": {
                    "by_category": {}
                }
            }
            
            # Index generators
            for gen in generators:
                cat = gen.get("category", "unknown")
                vendor = gen.get("vendor", "unknown")
                
                if cat not in self._cache["generators"]["by_category"]:
                    self._cache["generators"]["by_category"][cat] = []
                self._cache["generators"]["by_category"][cat].append(gen["id"])
                
                if vendor not in self._cache["generators"]["by_vendor"]:
                    self._cache["generators"]["by_vendor"][vendor] = []
                self._cache["generators"]["by_vendor"][vendor].append(gen["id"])
                
                for fmt in gen.get("supported_formats", []):
                    if fmt not in self._cache["generators"]["by_format"]:
                        self._cache["generators"]["by_format"][fmt] = []
                    self._cache["generators"]["by_format"][fmt].append(gen["id"])
            
            # Index parsers
            for parser in parsers:
                ptype = parser.get("type", "unknown")
                vendor = parser.get("vendor", "unknown")
                
                if ptype not in self._cache["parsers"]["by_type"]:
                    self._cache["parsers"]["by_type"][ptype] = []
                self._cache["parsers"]["by_type"][ptype].append(parser["id"])
                
                if vendor not in self._cache["parsers"]["by_vendor"]:
                    self._cache["parsers"]["by_vendor"][vendor] = []
                self._cache["parsers"]["by_vendor"][vendor].append(parser["id"])
            
            # Index scenarios
            for scenario in scenarios:
                cat = scenario.get("category", "unknown")
                if cat not in self._cache["scenarios"]["by_category"]:
                    self._cache["scenarios"]["by_category"][cat] = []
                self._cache["scenarios"]["by_category"][cat].append(scenario["id"])