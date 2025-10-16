#!/usr/bin/env python3
"""
API Key Management Utility for Jarvis Coding API
Generates and manages API keys for different roles
"""
import sys
import argparse
import json
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Optional

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from app.core.simple_auth import generate_api_key, Role


class APIKeyManager:
    """Manage API keys for the Jarvis Coding platform"""
    
    def __init__(self, keys_file: str = "api_keys.json"):
        self.keys_file = Path(keys_file)
        self.keys = self._load_keys()
    
    def _load_keys(self) -> Dict:
        """Load existing keys from file"""
        if self.keys_file.exists():
            with open(self.keys_file, 'r') as f:
                return json.load(f)
        return {"keys": []}
    
    def _save_keys(self):
        """Save keys to file"""
        with open(self.keys_file, 'w') as f:
            json.dump(self.keys, f, indent=2)
    
    def create_key(self, name: str, role: str, rate_limit: Optional[int] = None) -> Dict:
        """Create a new API key"""
        if role not in Role.all_roles():
            raise ValueError(f"Invalid role. Must be one of: {Role.all_roles()}")
        
        api_key = generate_api_key()
        
        key_info = {
            "key": api_key,
            "name": name,
            "role": role,
            "created_at": datetime.now().isoformat(),
            "enabled": True,
            "rate_limit": rate_limit
        }
        
        self.keys["keys"].append(key_info)
        self._save_keys()
        
        return key_info
    
    def list_keys(self, role: Optional[str] = None, enabled_only: bool = False) -> List[Dict]:
        """List all API keys"""
        keys = self.keys.get("keys", [])
        
        if role:
            keys = [k for k in keys if k["role"] == role]
        
        if enabled_only:
            keys = [k for k in keys if k.get("enabled", True)]
        
        # Don't show full keys in list, just prefix
        safe_keys = []
        for key in keys:
            safe_key = key.copy()
            safe_key["key"] = key["key"][:8] + "..." if len(key["key"]) > 8 else key["key"]
            safe_keys.append(safe_key)
        
        return safe_keys
    
    def revoke_key(self, key_prefix: str) -> bool:
        """Revoke (disable) an API key by prefix"""
        for key in self.keys.get("keys", []):
            if key["key"].startswith(key_prefix):
                key["enabled"] = False
                key["revoked_at"] = datetime.now().isoformat()
                self._save_keys()
                return True
        return False
    
    def enable_key(self, key_prefix: str) -> bool:
        """Re-enable a revoked API key"""
        for key in self.keys.get("keys", []):
            if key["key"].startswith(key_prefix):
                key["enabled"] = True
                if "revoked_at" in key:
                    del key["revoked_at"]
                self._save_keys()
                return True
        return False
    
    def export_env_format(self, role: Optional[str] = None) -> str:
        """Export keys in environment variable format"""
        keys = self.keys.get("keys", [])
        
        if role:
            keys = [k for k in keys if k["role"] == role and k.get("enabled", True)]
        else:
            keys = [k for k in keys if k.get("enabled", True)]
        
        admin_keys = [k["key"] for k in keys if k["role"] == Role.ADMIN]
        write_keys = [k["key"] for k in keys if k["role"] == Role.WRITE]
        read_keys = [k["key"] for k in keys if k["role"] == Role.READ_ONLY]
        
        env_format = []
        if admin_keys:
            env_format.append(f'JARVIS_ADMIN_KEYS={",".join(admin_keys)}')
        if write_keys:
            env_format.append(f'JARVIS_WRITE_KEYS={",".join(write_keys)}')
        if read_keys:
            env_format.append(f'JARVIS_READ_KEYS={",".join(read_keys)}')
        
        return "\n".join(env_format)


def main():
    """CLI for API key management"""
    parser = argparse.ArgumentParser(description="Manage API keys for Jarvis Coding API")
    subparsers = parser.add_subparsers(dest="command", help="Commands")
    
    # Create command
    create_parser = subparsers.add_parser("create", help="Create a new API key")
    create_parser.add_argument("--name", required=True, help="Name for the API key")
    create_parser.add_argument("--role", required=True, choices=Role.all_roles(), 
                              help="Role for the API key")
    create_parser.add_argument("--rate-limit", type=int, help="Custom rate limit")
    
    # List command
    list_parser = subparsers.add_parser("list", help="List API keys")
    list_parser.add_argument("--role", choices=Role.all_roles(), help="Filter by role")
    list_parser.add_argument("--enabled-only", action="store_true", 
                            help="Show only enabled keys")
    
    # Revoke command
    revoke_parser = subparsers.add_parser("revoke", help="Revoke an API key")
    revoke_parser.add_argument("key_prefix", help="Key prefix to revoke")
    
    # Enable command
    enable_parser = subparsers.add_parser("enable", help="Re-enable a revoked key")
    enable_parser.add_argument("key_prefix", help="Key prefix to enable")
    
    # Export command
    export_parser = subparsers.add_parser("export", help="Export keys as environment variables")
    export_parser.add_argument("--role", choices=Role.all_roles(), help="Export specific role")
    
    # Generate command (quick key generation without saving)
    generate_parser = subparsers.add_parser("generate", help="Generate a new key without saving")
    generate_parser.add_argument("--length", type=int, default=40, help="Key length")
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return
    
    manager = APIKeyManager()
    
    if args.command == "create":
        try:
            key_info = manager.create_key(args.name, args.role, args.rate_limit)
            print(f"\n✅ API Key created successfully!")
            print(f"Name: {key_info['name']}")
            print(f"Role: {key_info['role']}")
            print(f"Key: {key_info['key']}")
            print(f"\n⚠️  Save this key securely - it won't be shown again!")
            print(f"\nEnvironment variable format:")
            
            if args.role == Role.ADMIN:
                print(f"JARVIS_ADMIN_KEYS={key_info['key']}")
            elif args.role == Role.WRITE:
                print(f"JARVIS_WRITE_KEYS={key_info['key']}")
            else:
                print(f"JARVIS_READ_KEYS={key_info['key']}")
                
        except Exception as e:
            print(f"❌ Error creating key: {e}")
            sys.exit(1)
    
    elif args.command == "list":
        keys = manager.list_keys(args.role, args.enabled_only)
        if not keys:
            print("No keys found")
        else:
            print(f"\n{'Name':<20} {'Role':<10} {'Key Prefix':<15} {'Status':<10} {'Created'}")
            print("-" * 80)
            for key in keys:
                status = "Enabled" if key.get("enabled", True) else "Revoked"
                created = key["created_at"][:10] if "created_at" in key else "Unknown"
                print(f"{key['name']:<20} {key['role']:<10} {key['key']:<15} {status:<10} {created}")
    
    elif args.command == "revoke":
        if manager.revoke_key(args.key_prefix):
            print(f"✅ Key starting with '{args.key_prefix}' has been revoked")
        else:
            print(f"❌ No key found starting with '{args.key_prefix}'")
            sys.exit(1)
    
    elif args.command == "enable":
        if manager.enable_key(args.key_prefix):
            print(f"✅ Key starting with '{args.key_prefix}' has been enabled")
        else:
            print(f"❌ No key found starting with '{args.key_prefix}'")
            sys.exit(1)
    
    elif args.command == "export":
        env_vars = manager.export_env_format(args.role)
        if env_vars:
            print("\n# Add these to your .env file or export them:")
            print(env_vars)
        else:
            print("No enabled keys to export")
    
    elif args.command == "generate":
        key = generate_api_key(args.length)
        print(f"Generated API key: {key}")


if __name__ == "__main__":
    main()