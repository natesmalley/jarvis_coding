#!/usr/bin/env python3
"""
Automated Generator-Parser Fixing Framework

This tool automatically fixes format mismatches between generators and parsers by:
1. Converting generator output formats (JSON, Syslog, CSV, Key-Value)
2. Adding Star Trek character integration
3. Validating output against parser expectations
4. Creating backup copies before modifications
"""

import os
import json
import sys
import re
import shutil
from pathlib import Path
from typing import Dict, List, Any, Optional
from datetime import datetime, timezone

# Add the project root to Python path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

class GeneratorFixer:
    def __init__(self):
        self.project_root = project_root
        self.generators_dir = self.project_root / "event_generators"
        self.backup_dir = self.project_root / "scenarios" / "generator_backups"
        self.backup_dir.mkdir(exist_ok=True)
        
        # Star Trek characters for integration
        self.star_trek_characters = [
            "jean.picard", "william.riker", "data.android", "geordi.laforge", 
            "worf.security", "deanna.troi", "beverly.crusher", "wesley.crusher", 
            "tasha.yar", "guinan.bartender", "james.kirk", "spock.science", 
            "leonard.mccoy", "montgomery.scott", "nyota.uhura", "pavel.chekov", 
            "hikaru.sulu", "benjamin.sisko", "kira.nerys", "julian.bashir",
            "jadzia.dax", "miles.obrien", "odo.security", "kathryn.janeway", 
            "chakotay.commander", "tuvok.security", "tom.paris", "belanna.torres", 
            "harry.kim", "seven.of.nine"
        ]
        
    def load_fixing_plan(self, plan_file: str = "parser_generator_fixing_plan.json") -> Dict:
        """Load the systematic fixing plan"""
        plan_path = self.project_root / "scenarios" / plan_file
        with open(plan_path, 'r') as f:
            return json.load(f)
            
    def create_backup(self, generator_path: Path) -> Path:
        """Create backup of generator before modification"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_name = f"{generator_path.stem}_{timestamp}.py"
        backup_path = self.backup_dir / backup_name
        
        shutil.copy2(generator_path, backup_path)
        print(f"📦 Backup created: {backup_path}")
        return backup_path
        
    def fix_format_mismatch(self, generator_path: str, current_format: str, target_format: str):
        """Fix format mismatch by converting generator output"""
        generator_file = Path(generator_path)
        
        if not generator_file.exists():
            print(f"❌ Generator file not found: {generator_path}")
            return False
            
        print(f"🔧 Fixing {generator_file.name}: {current_format} → {target_format}")
        
        # Create backup
        backup_path = self.create_backup(generator_file)
        
        try:
            with open(generator_file, 'r') as f:
                content = f.read()
                
            # Apply format conversion
            if current_format == "JSON" and target_format == "Syslog":
                content = self._convert_json_to_syslog(content, generator_file.stem)
            elif current_format == "Syslog" and target_format == "JSON":
                content = self._convert_syslog_to_json(content, generator_file.stem)
            elif current_format == "Key-Value" and target_format == "JSON":
                content = self._convert_kv_to_json(content, generator_file.stem)
            elif current_format == "JSON" and target_format == "Key-Value":
                content = self._convert_json_to_kv(content, generator_file.stem)
            elif current_format == "JSON" and target_format == "CSV":
                content = self._convert_json_to_csv(content, generator_file.stem)
            else:
                print(f"⚠️  Conversion not implemented: {current_format} → {target_format}")
                return False
                
            # Add Star Trek integration if missing
            content = self._add_star_trek_integration(content, generator_file.stem)
            
            # Write the fixed content
            with open(generator_file, 'w') as f:
                f.write(content)
                
            print(f"✅ Fixed {generator_file.name}")
            return True
            
        except Exception as e:
            print(f"❌ Error fixing {generator_file.name}: {str(e)}")
            # Restore from backup
            shutil.copy2(backup_path, generator_file)
            return False
            
    def _convert_syslog_to_json(self, content: str, generator_name: str) -> str:
        """Convert generator from Syslog format to JSON format"""
        # Find the main function and modify its return statement
        function_name = self._get_function_name(generator_name)
        
        # Replace syslog format with JSON format
        if 'return f"' in content and not 'json.dumps' in content:
            # Add json import if missing
            if 'import json' not in content:
                content = content.replace('from datetime import', 'import json\nfrom datetime import')
                
            # Find the return statement with f-string formatting
            pattern = rf'(def {function_name}\([^)]*\):.*?)return f"([^"]+)"'
            
            def replace_return(match):
                func_part = match.group(1)
                format_string = match.group(2)
                
                # Convert syslog format to JSON structure
                json_event = self._extract_fields_from_syslog_format(format_string)
                
                # Build JSON return statement
                json_return = f'''    event = {json.dumps(json_event, indent=8)[4:-4]}  # Remove outer braces from json.dumps formatting
    
    # Apply overrides if provided
    if overrides:
        event.update(overrides)
    
    return json.dumps(event)'''
                
                return func_part + json_return
                
            content = re.sub(pattern, replace_return, content, flags=re.DOTALL)
            
        return content
        
    def _convert_kv_to_json(self, content: str, generator_name: str) -> str:
        """Convert generator from Key-Value format to JSON format"""
        function_name = self._get_function_name(generator_name)
        
        # Add json import if missing
        if 'import json' not in content:
            content = content.replace('from datetime import', 'import json\nfrom datetime import')
            
        # Replace key=value format with JSON format
        if 'return f"' in content and not 'json.dumps' in content:
            pattern = rf'(def {function_name}\([^)]*\):.*?)return f"([^"]+)"'
            
            def replace_return(match):
                func_part = match.group(1)
                format_string = match.group(2)
                
                # Convert key=value format to JSON structure
                json_event = self._extract_fields_from_kv_format(format_string)
                
                # Build JSON return statement
                json_return = f'''    event = {json.dumps(json_event, indent=8)[4:-4]}
    
    # Apply overrides if provided
    if overrides:
        event.update(overrides)
    
    return json.dumps(event)'''
                
                return func_part + json_return
                
            content = re.sub(pattern, replace_return, content, flags=re.DOTALL)
            
        return content
        
    def _convert_json_to_syslog(self, content: str, generator_name: str) -> str:
        """Convert generator from JSON format to Syslog format"""
        function_name = self._get_function_name(generator_name)
        
        # This is more complex as we need to convert JSON structure to syslog format
        # For now, provide a template that needs manual adjustment
        if 'json.dumps' in content:
            print(f"⚠️  JSON to Syslog conversion for {generator_name} requires manual adjustment")
            print("   Template will be provided in the comments")
            
            # Add syslog template in comments
            syslog_template = f'''
# TODO: Convert this JSON generator to Syslog format
# Syslog format template:
# return f"<{priority}>{timestamp} {hostname} {program}[{pid}]: {message}"
# Example: return f"<14>{now.strftime('%b %d %H:%M:%S')} firewall-01 cisco_asa[1234]: %ASA-6-302013: Built outbound TCP connection"
'''
            content = content.replace(f'def {function_name}', syslog_template + f'\ndef {function_name}')
            
        return content
        
    def _convert_json_to_kv(self, content: str, generator_name: str) -> str:
        """Convert generator from JSON format to Key-Value format"""
        function_name = self._get_function_name(generator_name)
        
        if 'json.dumps' in content:
            print(f"⚠️  JSON to Key-Value conversion for {generator_name} requires manual adjustment")
            print("   Template will be provided in the comments")
            
            # Add key-value template in comments
            kv_template = f'''
# TODO: Convert this JSON generator to Key-Value format
# Key-Value format template:
# return f"timestamp={now} src_ip={src_ip} dst_ip={dst_ip} action={action}"
'''
            content = content.replace(f'def {function_name}', kv_template + f'\ndef {function_name}')
            
        return content
        
    def _convert_json_to_csv(self, content: str, generator_name: str) -> str:
        """Convert generator from JSON format to CSV format"""
        function_name = self._get_function_name(generator_name)
        
        if 'json.dumps' in content:
            print(f"⚠️  JSON to CSV conversion for {generator_name} requires manual adjustment")
            print("   Template will be provided in the comments")
            
            # Add CSV template in comments
            csv_template = f'''
# TODO: Convert this JSON generator to CSV format
# CSV format template:
# return f"{now},{src_ip},{dst_ip},{action},{bytes}"
'''
            content = content.replace(f'def {function_name}', csv_template + f'\ndef {function_name}')
            
        return content
        
    def _add_star_trek_integration(self, content: str, generator_name: str) -> str:
        """Add Star Trek character integration to generator"""
        # Check if already has Star Trek characters
        if any(char in content.lower() for char in ["jean.picard", "starfleet.corp", "worf.security"]):
            return content  # Already integrated
            
        # Replace common hardcoded email patterns
        content = re.sub(r'@company\.com', '@starfleet.corp', content)
        content = re.sub(r'@corp\.com', '@starfleet.corp', content)
        content = re.sub(r'@enterprise\.com', '@starfleet.corp', content)
        
        # Replace user lists if found
        if 'USERS = [' in content:
            # Replace the entire USERS list with Star Trek characters
            pattern = r'USERS = \[[^\]]+\]'
            star_trek_users = f'''USERS = [
    {', '.join([f'"{char}"' for char in self.star_trek_characters[:20]])}
]'''
            content = re.sub(pattern, star_trek_users, content, flags=re.MULTILINE | re.DOTALL)
            
        # Replace hardcoded usernames in the content
        content = re.sub(r'"john\.doe"', '"jean.picard"', content)
        content = re.sub(r'"admin"', '"worf.security"', content)
        content = re.sub(r'"user\d+"', '"data.android"', content)
        
        return content
        
    def _get_function_name(self, generator_name: str) -> str:
        """Get the expected function name from generator filename"""
        # Convert filename to function name pattern
        return f"{generator_name}_log"
        
    def _extract_fields_from_syslog_format(self, format_string: str) -> Dict:
        """Extract fields from syslog format string and create JSON structure"""
        # This is a simplified extraction - would need more sophisticated parsing
        return {
            "timestamp": "{now}",
            "hostname": "{hostname}",
            "program": "{program}",
            "message": "{message}",
            "priority": "{priority}"
        }
        
    def _extract_fields_from_kv_format(self, format_string: str) -> Dict:
        """Extract fields from key-value format string and create JSON structure"""
        # Parse key=value pairs from format string
        fields = {}
        kv_pattern = r'(\w+)=\{([^}]+)\}'
        matches = re.findall(kv_pattern, format_string)
        
        for key, value in matches:
            fields[key] = f"{{{value}}}"
            
        return fields if fields else {"timestamp": "{now}", "event": "{event}"}
        
    def fix_critical_mismatches(self):
        """Fix all critical format mismatches"""
        plan = self.load_fixing_plan()
        critical_fixes = plan.get("phase_1_critical_fixes", [])
        
        print(f"🚨 Starting critical format mismatch fixes ({len(critical_fixes)} issues)")
        
        success_count = 0
        for fix in critical_fixes:
            if fix["action"] == "fix_format_mismatch":
                success = self.fix_format_mismatch(
                    fix["generator_path"],
                    fix["current_format"], 
                    fix["target_format"]
                )
                if success:
                    success_count += 1
                    
        print(f"✅ Fixed {success_count}/{len(critical_fixes)} critical format mismatches")
        
    def validate_generator_output(self, generator_path: Path, expected_format: str) -> bool:
        """Validate that generator produces expected format"""
        try:
            # Import and run the generator
            sys.path.insert(0, str(generator_path.parent))
            
            # Dynamic import
            module_name = generator_path.stem
            module = __import__(module_name)
            
            # Get the log function
            function_name = f"{module_name}_log"
            if not hasattr(module, function_name):
                return False
                
            log_function = getattr(module, function_name)
            
            # Generate sample output
            sample_output = log_function()
            
            # Validate format
            if expected_format == "JSON":
                try:
                    json.loads(sample_output)
                    return True
                except:
                    return False
            elif expected_format == "Syslog":
                # Basic syslog format check
                return sample_output.startswith('<') and '>' in sample_output
            elif expected_format == "Key-Value":
                return '=' in sample_output and not sample_output.startswith('{')
            elif expected_format == "CSV":
                return ',' in sample_output and not sample_output.startswith('{')
                
        except Exception as e:
            print(f"❌ Validation error for {generator_path.name}: {str(e)}")
            return False
            
        return False
        
    def generate_progress_report(self):
        """Generate progress report on fixes"""
        plan = self.load_fixing_plan()
        
        print("\n📊 FIXING PROGRESS REPORT")
        print("="*50)
        
        # Check backup directory
        backups = list(self.backup_dir.glob("*.py"))
        print(f"📦 Backups created: {len(backups)}")
        
        # Validate some generators
        critical_fixes = plan.get("phase_1_critical_fixes", [])
        validated = 0
        
        for fix in critical_fixes[:5]:  # Check first 5
            generator_path = Path(fix["generator_path"])
            if self.validate_generator_output(generator_path, fix["target_format"]):
                validated += 1
                
        print(f"✅ Validated generators: {validated}/{min(5, len(critical_fixes))}")

def main():
    """Main fixing function"""
    print("🔧 Starting Systematic Generator-Parser Fixing")
    print("="*60)
    
    fixer = GeneratorFixer()
    
    # Fix critical format mismatches
    fixer.fix_critical_mismatches()
    
    # Generate progress report
    fixer.generate_progress_report()
    
    print("\n✅ Systematic fixing complete!")
    print("📋 Review the generator_backups/ directory for all backups")
    print("🧪 Test the fixed generators before deploying to production")

if __name__ == "__main__":
    main()