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
        protocol: Optional[str] = None
    ) -> Destination:
        """
        Create a new destination
        
        Args:
            name: Destination name (must be unique)
            dest_type: 'hec' or 'syslog'
            url: HEC URL (for HEC destinations)
            token: HEC token (for HEC destinations, will be encrypted)
            ip: Syslog IP (for syslog destinations)
            port: Syslog port (for syslog destinations)
            protocol: 'UDP' or 'TCP' (for syslog destinations)
            
        Returns:
            Created Destination object
        """
        # Generate ID - find the next available number for this type
        result = await self.session.execute(
            select(Destination).where(Destination.type == dest_type)
        )
        existing = result.scalars().all()
        
        # Extract numbers from existing IDs and find max
        max_num = 0
        for dest in existing:
            try:
                num = int(dest.id.split(':')[1])
                if num > max_num:
                    max_num = num
            except (IndexError, ValueError):
                continue
        
        dest_id = f"{dest_type}:{max_num + 1}"
        
        # Create destination
        destination = Destination(
            id=dest_id,
            name=name,
            type=dest_type
        )
        
        if dest_type == 'hec':
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
    
    def decrypt_token(self, encrypted_token: str) -> str:
        """Decrypt a token"""
        return self.encryption.decrypt(encrypted_token)
