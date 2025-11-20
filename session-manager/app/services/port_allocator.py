"""Port allocation service for dynamic port assignment"""
import redis
import random
import logging
from typing import Optional
from ..core.config import settings

logger = logging.getLogger(__name__)


class PortAllocator:
    """Manages dynamic port allocation for containers"""
    
    def __init__(self, redis_client: Optional[redis.Redis] = None):
        """Initialize port allocator with Redis client"""
        if redis_client:
            self.redis = redis_client
        else:
            self.redis = redis.from_url(settings.redis_url, decode_responses=True)
        
        self.min_port = settings.port_range_start
        self.max_port = settings.port_range_end
        self.allocated_key = f"{settings.docker_network_prefix}:allocated_ports"
        
    def allocate_port(self) -> int:
        """
        Allocate an available port from the configured range
        
        Returns:
            Available port number
            
        Raises:
            RuntimeError: If no ports are available
        """
        max_attempts = 100
        
        for _ in range(max_attempts):
            port = random.randint(self.min_port, self.max_port)
            
            # Try to claim the port atomically
            if self.redis.sadd(self.allocated_key, port):
                # Set expiration on the entire set (refresh it)
                self.redis.expire(self.allocated_key, 86400 * 2)  # 2 days
                logger.info(f"Allocated port {port}")
                return port
                    
        # If we couldn't find a port, check how many are allocated
        allocated_count = self.redis.scard(self.allocated_key)
        total_available = self.max_port - self.min_port + 1
        
        raise RuntimeError(
            f"Could not allocate port after {max_attempts} attempts. "
            f"{allocated_count}/{total_available} ports are in use."
        )
        
    def release_port(self, port: int):
        """
        Release a port back to the pool
        
        Args:
            port: Port number to release
        """
        released = self.redis.srem(self.allocated_key, port)
        if released:
            logger.info(f"Released port {port}")
        else:
            logger.warning(f"Port {port} was not in allocated set")
            
    def release_multiple_ports(self, ports: list[int]):
        """
        Release multiple ports back to the pool
        
        Args:
            ports: List of port numbers to release
        """
        if ports:
            released = self.redis.srem(self.allocated_key, *ports)
            logger.info(f"Released {released} ports")
            
    def get_allocated_ports(self) -> set:
        """
        Get all currently allocated ports
        
        Returns:
            Set of allocated port numbers
        """
        return {int(p) for p in self.redis.smembers(self.allocated_key)}
        
    def get_available_count(self) -> int:
        """
        Get count of available ports
        
        Returns:
            Number of available ports
        """
        allocated = self.redis.scard(self.allocated_key)
        total = self.max_port - self.min_port + 1
        return total - allocated
        
    def cleanup_orphaned_ports(self):
        """
        Clean up ports that are allocated but not actually in use
        This should be called periodically to prevent port exhaustion
        """
        try:
            import docker
            client = docker.from_env()
            
            # Get all ports actually in use by containers
            used_ports = set()
            containers = client.containers.list(all=True)
            
            for container in containers:
                if container.attrs['HostConfig']['PortBindings']:
                    for port_bindings in container.attrs['HostConfig']['PortBindings'].values():
                        if port_bindings:
                            for binding in port_bindings:
                                if 'HostPort' in binding:
                                    try:
                                        port = int(binding['HostPort'])
                                        if self.min_port <= port <= self.max_port:
                                            used_ports.add(port)
                                    except (ValueError, TypeError):
                                        pass
            
            # Get allocated ports from Redis
            allocated_ports = self.get_allocated_ports()
            
            # Find orphaned ports (allocated but not in use)
            orphaned = allocated_ports - used_ports
            
            if orphaned:
                self.release_multiple_ports(list(orphaned))
                logger.info(f"Cleaned up {len(orphaned)} orphaned ports")
                
        except Exception as e:
            logger.error(f"Failed to cleanup orphaned ports: {e}")