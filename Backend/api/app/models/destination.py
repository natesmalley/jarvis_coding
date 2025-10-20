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
    
    # Syslog fields
    ip = Column(String, nullable=True)
    port = Column(Integer, nullable=True)
    protocol = Column(String, nullable=True)  # 'UDP' or 'TCP'
    
    # Metadata
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    def to_dict(self, include_token=False):
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
        elif self.type == 'syslog':
            result['ip'] = self.ip
            result['port'] = self.port
            result['protocol'] = self.protocol
        
        return result
