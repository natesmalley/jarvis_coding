"""Token encryption utilities using Fernet symmetric encryption"""
from cryptography.fernet import Fernet
import base64
import hashlib
import os
from typing import Optional
import logging

logger = logging.getLogger(__name__)


class TokenEncryption:
    """Handle encryption and decryption of sensitive tokens"""
    
    def __init__(self, secret_key: str):
        """
        Initialize encryption with a secret key
        
        Args:
            secret_key: Secret key from environment (e.g., SECRET_KEY)
        """
        # Derive a Fernet key from the secret key
        # Fernet requires a 32-byte base64-encoded key
        key_bytes = hashlib.sha256(secret_key.encode()).digest()
        self.fernet_key = base64.urlsafe_b64encode(key_bytes)
        self.cipher = Fernet(self.fernet_key)
    
    def encrypt(self, plaintext: str) -> str:
        """
        Encrypt a plaintext string
        
        Args:
            plaintext: The string to encrypt
            
        Returns:
            Base64-encoded encrypted string
        """
        try:
            encrypted_bytes = self.cipher.encrypt(plaintext.encode())
            return encrypted_bytes.decode('utf-8')
        except Exception as e:
            logger.error(f"Encryption failed: {e}")
            raise
    
    def decrypt(self, encrypted: str) -> str:
        """
        Decrypt an encrypted string
        
        Args:
            encrypted: Base64-encoded encrypted string
            
        Returns:
            Decrypted plaintext string
        """
        try:
            decrypted_bytes = self.cipher.decrypt(encrypted.encode())
            return decrypted_bytes.decode('utf-8')
        except Exception as e:
            logger.error(f"Decryption failed: {e}")
            raise


def get_encryption_instance(secret_key: Optional[str] = None) -> TokenEncryption:
    """
    Get a TokenEncryption instance
    
    Args:
        secret_key: Optional secret key; if not provided, uses SECRET_KEY from env
        
    Returns:
        TokenEncryption instance
    """
    if not secret_key:
        secret_key = os.getenv('SECRET_KEY', 'your-secret-key-change-in-production')
    
    return TokenEncryption(secret_key)
