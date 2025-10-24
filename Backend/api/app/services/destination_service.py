"""Business logic for destination management"""
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy import select, delete
from typing import List, Optional
import logging
from datetime import datetime

from app.models.destination import Destination, Base
from app.utils.encryption import get_encryption_instance
from app.core.config import settings

logger = logging.getLogger(__name__)

# Create async engine and session
engine = create_async_engine(
    settings.DATABASE_URL,
    echo=False,
    future=True
)

async_session_maker = sessionmaker(
    engine, class_=AsyncSession, expire_on_commit=False
)


async def init_db():
    """Initialize database tables"""
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    logger.info("Destinations database initialized")


async def get_session() -> AsyncSession:
    """Get database session"""
    async with async_session_maker() as session:
        yield session


class DestinationService:
    """Service for managing destinations"""
    
    def __init__(self, session: AsyncSession, encryption_key: Optional[str] = None):
        self.session = session
        self.encryption = get_encryption_instance(encryption_key or settings.SECRET_KEY)
    
    async def create_destination(
        self,
        name: str,
        dest_type: str,
        url: Optional[str] = None,
        token: Optional[str] = None,
        ip: Optional[str] = None,
        port: Optional[int] = None,
        protocol: Optional[str] = None,
        endpoint_format: Optional[str] = 'full_url',
        host: Optional[str] = None,
        use_https: Optional[bool] = True
    ) -> Destination:
        """
        Create a new destination
        
        Args:
            name: Destination name (must be unique)
            dest_type: 'hec' or 'syslog'
            url: HEC URL (for HEC destinations with full_url format)
            token: HEC token (for HEC destinations, will be encrypted)
            ip: Syslog IP (for syslog destinations)
            port: Port number (for syslog or pipeline destinations)
            protocol: 'UDP' or 'TCP' (for syslog destinations)
            endpoint_format: 'full_url' or 'ip_port' (for HEC destinations)
            host: Host/IP for pipeline endpoints (when endpoint_format='ip_port')
            use_https: Whether to use HTTPS for pipeline endpoints
            
        Returns:
            Created Destination object
        """
        # Generate ID
        result = await self.session.execute(select(Destination))
        existing = result.scalars().all()
        dest_id = f"{dest_type}:{len(existing) + 1}"
        
        # Create destination
        destination = Destination(
            id=dest_id,
            name=name,
            type=dest_type
        )
        
        if dest_type == 'hec':
            destination.endpoint_format = endpoint_format
            if endpoint_format == 'ip_port':
                destination.host = host
                destination.port = port
                destination.use_https = use_https
            else:
                destination.url = url
            if token:
                destination.token_encrypted = self.encryption.encrypt(token)
        elif dest_type == 'syslog':
            destination.ip = ip
            destination.port = port
            destination.protocol = protocol
        
        self.session.add(destination)
        await self.session.commit()
        await self.session.refresh(destination)
        
        logger.info(f"Created destination: {dest_id} ({name})")
        return destination
    
    async def get_destination(self, dest_id: str) -> Optional[Destination]:
        """Get a destination by ID"""
        result = await self.session.execute(
            select(Destination).where(Destination.id == dest_id)
        )
        return result.scalar_one_or_none()
    
    async def get_destination_by_name(self, name: str) -> Optional[Destination]:
        """Get a destination by name"""
        result = await self.session.execute(
            select(Destination).where(Destination.name == name)
        )
        return result.scalar_one_or_none()
    
    async def list_destinations(self) -> List[Destination]:
        """List all destinations"""
        result = await self.session.execute(select(Destination))
        return result.scalars().all()
    
    async def update_destination(
        self,
        dest_id: str,
        name: Optional[str] = None,
        url: Optional[str] = None,
        token: Optional[str] = None,
        ip: Optional[str] = None,
        port: Optional[int] = None,
        protocol: Optional[str] = None
    ) -> Optional[Destination]:
        """Update a destination"""
        destination = await self.get_destination(dest_id)
        if not destination:
            return None
        
        if name:
            destination.name = name
        
        if destination.type == 'hec':
            if url:
                destination.url = url
            if token:
                destination.token_encrypted = self.encryption.encrypt(token)
        elif destination.type == 'syslog':
            if ip:
                destination.ip = ip
            if port:
                destination.port = port
            if protocol:
                destination.protocol = protocol
        
        destination.updated_at = datetime.utcnow()
        await self.session.commit()
        await self.session.refresh(destination)
        
        logger.info(f"Updated destination: {dest_id}")
        return destination
    
    async def delete_destination(self, dest_id: str) -> bool:
        """Delete a destination"""
        result = await self.session.execute(
            delete(Destination).where(Destination.id == dest_id)
        )
        await self.session.commit()
        
        deleted = result.rowcount > 0
        if deleted:
            logger.info(f"Deleted destination: {dest_id}")
        return deleted
    
    def get_hec_url(self, destination: Destination) -> Optional[str]:
        """
        Get the complete HEC URL for a destination.
        Handles both full_url and ip_port formats.
        """
        if destination.type != 'hec':
            return None
        
        if destination.endpoint_format == 'ip_port':
            # Build URL from components
            protocol = 'https' if destination.use_https else 'http'
            return f"{protocol}://{destination.host}:{destination.port}/services/collector"
        else:
            # Use the stored URL
            return destination.url
    
    def decrypt_token(self, encrypted_token: str) -> str:
        """Decrypt a token"""
        return self.encryption.decrypt(encrypted_token)
