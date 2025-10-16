#!/usr/bin/env python3
"""
Create SentinelOne Official Parsers
Extract parsers from sentinelone_parsers.json and create proper directory structure
"""

import json
import os
import re
from pathlib import Path
from datetime import datetime

def fix_json_syntax(content):
    """Fix common JSON syntax issues in the parser content"""
    # Remove trailing commas before closing braces/brackets
    content = re.sub(r',(\s*[}\]])', r'\1', content)
    
    # Fix missing commas between object properties
    content = re.sub(r'}\s*{', r'}, {', content)
    content = re.sub(r'}\s*"', r'}, "', content)
    
    # Fix unquoted keys (attributes, patterns, formats, etc.)
    content = re.sub(r'(\n\s*)(attributes|patterns|formats|rewrites)(\s*):', r'\1"\2"\3:', content)
    content = re.sub(r'(\n\s*)(format|repeat|input|output|match|replace|field)(\s*):', r'\1"\2"\3:', content)
    
    # Fix string concatenation with + operator
    content = re.sub(r'"\s*\+\s*"', '', content)
    
    # Fix missing quotes around values that should be strings
    content = re.sub(r':\s*([a-zA-Z][a-zA-Z0-9_]*)\s*([,}\]\n])', r': "\1"\2', content)
    
    # Fix true/false/null values (should not be quoted)
    content = re.sub(r': "(true|false|null)"', r': \1', content)
    
    # Fix numeric values (should not be quoted if they're actually numbers)
    content = re.sub(r': "(\d+)"([,}\]\n])', r': \1\2', content)
    
    return content

def extract_parser_section(content, start_line, parser_name):
    """Extract a single parser section from the content"""
    lines = content.split('\n')
    
    # Find the end of this parser section
    brace_count = 0
    end_line = start_line
    found_start = False
    
    for i in range(start_line, len(lines)):
        line = lines[i].strip()
        
        # Count braces to find where parser ends
        if '{' in line:
            brace_count += line.count('{')
            found_start = True
        if '}' in line:
            brace_count -= line.count('}')
            
        # If we've closed all braces and found another parser start, we're done
        if found_start and brace_count <= 0:
            end_line = i + 1
            break
            
        # Also check for next parser starting
        if i > start_line + 10 and '"dataSource.name":' in line and parser_name not in line:
            end_line = i - 1
            break
    
    # Extract the section
    parser_content = '\n'.join(lines[start_line-1:end_line])
    
    # Wrap in proper JSON structure if needed
    if not parser_content.strip().startswith('{'):
        parser_content = '{\n' + parser_content + '\n}'
    
    return parser_content

def create_metadata_yaml(parser_name, vendor, version="1.0.0"):
    """Create metadata.yaml content"""
    clean_name = parser_name.lower().replace(' ', '_').replace('-', '_')
    
    return f"""name: {clean_name}
version: {version}
vendor: {vendor}
product: {parser_name}
description: Official SentinelOne parser for {parser_name}
category: security
created: {datetime.now().isoformat()}
ocsf_compliant: true
source: official_sentinelone_parsers
"""

def create_sentinelone_parsers():
    """Create individual parser directories from official SentinelOne parsers"""
    print("🚀 Creating SentinelOne Official Parser Directories")
    print("=" * 60)
    
    # Try multiple file locations
    possible_files = [
        'sentinelone_parsers.json',
        'utilities/sentinelone_parsers.json',
        'sentinelone_parsers_example.json',
        'utilities/sentinelone_parsers_example.json'
    ]
    
    content = None
    used_file = None
    
    for file_path in possible_files:
        try:
            with open(file_path, 'r') as f:
                content = f.read()
                used_file = file_path
                print(f"✅ Found parser file: {file_path}")
                break
        except FileNotFoundError:
            continue
    
    if not content:
        print("❌ No parser file found! Looked for:")
        for f in possible_files:
            print(f"   - {f}")
        return 0
    
    print(f"📄 File size: {len(content):,} characters")
    
    # Try to parse as JSON first
    parsers_found = []
    
    try:
        data = json.loads(content)
        
        # Handle different JSON structures
        if isinstance(data, dict) and 'parsers' in data:
            # Structure: {"parsers": [...]}
            for parser in data['parsers']:
                if 'attributes' in parser and 'dataSource.name' in parser['attributes']:
                    parser_name = parser['attributes']['dataSource.name']
                    parsers_found.append((parser, parser_name))
        elif isinstance(data, list):
            # Structure: [...]
            for parser in data:
                if 'attributes' in parser and 'dataSource.name' in parser['attributes']:
                    parser_name = parser['attributes']['dataSource.name']
                    parsers_found.append((parser, parser_name))
        else:
            # Single parser
            if 'attributes' in data and 'dataSource.name' in data['attributes']:
                parser_name = data['attributes']['dataSource.name']
                parsers_found.append((data, parser_name))
                
    except json.JSONDecodeError:
        # Fall back to line-by-line parsing
        lines = content.split('\n')
        for i, line in enumerate(lines):
            if '"dataSource.name":' in line and 'field' not in line:
                # Extract parser name
                match = re.search(r'"dataSource.name":\s*"([^"]+)"', line)
                if match:
                    parser_name = match.group(1)
                    parsers_found.append((i + 1, parser_name))
    
    print(f"📊 Found {len(parsers_found)} parser definitions:")
    for item, parser_name in parsers_found:
        if isinstance(item, dict):
            print(f"  Parser: {parser_name}")
        else:
            print(f"  Line {item:4d}: {parser_name}")
    
    # Create directory for each parser
    parsers_created = 0
    
    for i, (line_num, parser_name) in enumerate(parsers_found):
        print(f"\n🔧 Processing: {parser_name}")
        
        # Create safe directory name
        safe_name = parser_name.lower().replace(' ', '_').replace('-', '_').replace('.', '_')
        parser_dir = Path(f"parsers/sentinelone/{safe_name}")
        
        try:
            # Create directory
            parser_dir.mkdir(parents=True, exist_ok=True)
            print(f"  📁 Created directory: {parser_dir}")
            
            # Extract parser content
            parser_content = extract_parser_section(content, line_num - 1, parser_name)
            
            # Fix JSON syntax
            fixed_content = fix_json_syntax(parser_content)
            
            # Try to parse as JSON to validate
            try:
                parser_json = json.loads(fixed_content)
                print(f"  ✅ Valid JSON structure")
            except json.JSONDecodeError as e:
                print(f"  ⚠️  JSON syntax issues, saving raw version")
                print(f"     Error: {str(e)[:100]}...")
                
                # Save raw version for manual review
                with open(parser_dir / f"{safe_name}_raw.txt", 'w') as f:
                    f.write(parser_content)
                
                # Create a simplified JSON structure
                parser_json = {
                    "attributes": {
                        "dataSource.vendor": parser_name.split()[0] if ' ' in parser_name else "Unknown",
                        "dataSource.name": parser_name,
                        "dataSource.category": "security"
                    },
                    "formats": [
                        {
                            "format": ".*${parse=json}$",
                            "attributes": {
                                "class_uid": 6003,
                                "category_uid": 6,
                                "activity_id": 99
                            }
                        }
                    ]
                }
            
            # Save JSON file
            json_file = parser_dir / f"{safe_name}.json"
            with open(json_file, 'w') as f:
                json.dump(parser_json, f, indent=2)
            print(f"  💾 Saved: {json_file}")
            
            # Create metadata.yaml
            vendor = parser_name.split()[0] if ' ' in parser_name else "SentinelOne"
            metadata_content = create_metadata_yaml(parser_name, vendor)
            
            metadata_file = parser_dir / "metadata.yaml"
            with open(metadata_file, 'w') as f:
                f.write(metadata_content)
            print(f"  📝 Created: {metadata_file}")
            
            parsers_created += 1
            
        except Exception as e:
            print(f"  ❌ Error creating parser {parser_name}: {e}")
    
    print(f"\n✅ Successfully created {parsers_created}/{len(parsers_found)} parsers")
    print(f"📁 All parsers saved to: parsers/sentinelone/")
    
    # List created directories
    print(f"\n📋 Created parser directories:")
    sentinelone_dir = Path("parsers/sentinelone")
    if sentinelone_dir.exists():
        for parser_dir in sorted(sentinelone_dir.iterdir()):
            if parser_dir.is_dir():
                files = list(parser_dir.glob("*"))
                print(f"  {parser_dir.name:30s} ({len(files)} files)")
    
    return parsers_created

if __name__ == "__main__":
    created_count = create_sentinelone_parsers()
    
    if created_count > 0:
        print(f"\n🎉 Parser creation complete!")
        print(f"\nNext steps:")
        print(f"1. Review created parsers in parsers/sentinelone/")
        print(f"2. Fix any JSON syntax issues in *_raw.txt files")
        print(f"3. Update hec_sender.py mappings to use official parsers")
        print(f"4. Test with SDL API validation")
    else:
        print(f"\n⚠️  No parsers were created successfully")