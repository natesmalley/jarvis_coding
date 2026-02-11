"""Database models for destinations"""
from sqlalchemy import Column, String, Integer, DateTime, Text
from sqlalchemy.ext.declarative import declarative_base
from datetime import datetime

Base = declarative_base()


class Destination(Base):
    """Destination model for HEC and Syslog targets"""
    __tablename__ = "destinations"
    
    id = Column(String, primary_key=True)
    name = Column(String, nullable=False, unique=True)
    type = Column(String, nullable=False)  # 'hec' or 'syslog'
    
    # HEC fields
    url = Column(String, nullable=True)
    token_encrypted = Column(Text, nullable=True)  # Encrypted HEC token
    
    # Config API for parser management (SentinelOne/Scalyr API)
    config_api_url = Column(String, nullable=True)  # e.g., https://xdr.us1.sentinelone.net
    config_read_token_encrypted = Column(Text, nullable=True)  # For getFile API
    config_write_token_encrypted = Column(Text, nullable=True)  # For putFile API
    powerquery_read_token_encrypted = Column(Text, nullable=True)  # For PowerQuery Log Read Access
    
    # Syslog fields
    ip = Column(String, nullable=True)
    port = Column(Integer, nullable=True)
    protocol = Column(String, nullable=True)  # 'UDP' or 'TCP'
    
    # Metadata
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    def to_dict(self, include_token=False, encryption_service=None):
        """Convert to dictionary, optionally excluding sensitive data"""
        result = {
            'id': self.id,
            'name': self.name,
            'type': self.type,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None,
        }
        
        if self.type == 'hec':
            result['url'] = self.url
            if include_token:
                result['token_encrypted'] = self.token_encrypted
            
            # Check if destination has a real database token (not LOCAL_STORAGE placeholder)
            if self.token_encrypted and encryption_service:
                try:
                    decrypted = encryption_service.decrypt(self.token_encrypted)
                    result['has_database_token'] = (decrypted != 'LOCAL_STORAGE')
                except:
                    result['has_database_token'] = False
            else:
                result['has_database_token'] = bool(self.token_encrypted)
            
            # Config API settings for parser management
            result['config_api_url'] = self.config_api_url
            result['has_config_write_token'] = bool(self.config_write_token_encrypted)
            result['has_powerquery_read_token'] = bool(self.powerquery_read_token_encrypted)
        elif self.type == 'syslog':
            result['ip'] = self.ip
            result['port'] = self.port
            result['protocol'] = self.protocol
            result['has_database_token'] = None  # Not applicable for syslog
        
        return result
