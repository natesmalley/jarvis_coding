"""Docker container management service"""
import docker
from typing import Dict, Optional, List, Any
from datetime import datetime, timedelta
import logging
import secrets
from ..core.config import settings

logger = logging.getLogger(__name__)


class DockerManager:
    """Manages Docker containers for user sessions"""
    
    def __init__(self):
        """Initialize Docker client"""
        self.client = docker.from_env()
        self.network_prefix = settings.docker_network_prefix
        self.shared_network_name = f"{self.network_prefix}-shared"
        self._ensure_shared_network()
    
    def _ensure_shared_network(self):
        """Ensure the shared network exists"""
        try:
            # Check if network already exists
            try:
                network = self.client.networks.get(self.shared_network_name)
                logger.info(f"Using existing shared network: {self.shared_network_name}")
            except docker.errors.NotFound:
                # Create the shared network
                network = self.client.networks.create(
                    self.shared_network_name,
                    driver="bridge",
                    internal=False,
                    attachable=True,
                    options={
                        'com.docker.network.bridge.enable_icc': 'true',
                        'com.docker.network.bridge.enable_ip_masquerade': 'true'
                    }
                )
                logger.info(f"Created shared network: {self.shared_network_name}")
        except Exception as e:
            logger.error(f"Failed to ensure shared network: {e}")
            raise
        
    def create_session_containers(
        self, 
        session_id: str,
        user_id: str,
        backend_port: int,
        frontend_port: int,
        features: Dict[str, Any] = None
    ) -> Dict[str, str]:
        """
        Create frontend and backend containers for a session
        
        Args:
            session_id: Unique session identifier
            user_id: User ID requesting the session
            backend_port: Port for backend service
            frontend_port: Port for frontend service
            
        Returns:
            Dictionary with container information
        """
        try:
            # Use the shared network for all sessions
            network = self.client.networks.get(self.shared_network_name)
            logger.info(f"Using shared network for session {session_id}")
            
            # Generate session API key
            session_api_key = f"session_{secrets.token_urlsafe(32)}"
            
            # Environment variables for containers
            expires_at = (datetime.utcnow() + timedelta(hours=settings.session_ttl_hours)).isoformat()
            
            # Get features configuration
            if features is None:
                features = {
                    'generators': True,
                    'scenarios': True,
                    'destinations': True,
                    'uploads': True,
                    'export': True,
                    'continuous_mode': True
                }
            
            # Create backend container
            backend_env = {
                'SESSION_ID': session_id,
                'USER_ID': user_id,
                # Don't pass DATABASE_URL - let backend use its default SQLite
                'DISABLE_AUTH': 'true',  # Disable auth to avoid key mismatch issues
                'API_KEY': session_api_key,
                # Don't use SERVER_MODE - let it default to uvicorn
                'PORT': '8000',
                'LOG_LEVEL': 'info',
                # Feature flags
                'ENABLE_GENERATORS': str(features.get('generators', True)),
                'ENABLE_SCENARIOS': str(features.get('scenarios', True)),
                'ENABLE_DESTINATIONS': str(features.get('destinations', True)),
                'ENABLE_UPLOADS': str(features.get('uploads', True)),
                'ENABLE_EXPORT': str(features.get('export', True)),
                'ENABLE_CONTINUOUS': str(features.get('continuous_mode', True))
            }
            
            backend_labels = {
                'session_id': session_id,
                'user_id': user_id,
                'service': 'backend',
                'expires_at': expires_at,
                'managed_by': 'session_manager'
            }
            
            # Mount Backend directories for event generators and parsers
            import os
            # Use host path - session manager needs to specify paths accessible by Docker daemon
            # This should be configured via environment variable for portability
            workspace_path = os.environ.get('WORKSPACE_PATH', '/Users/nathanial.smalley/tech_summit_jarvis/jarvis_coding')
            backend_path = os.path.join(workspace_path, 'Backend')
            
            event_gen_path = os.path.join(backend_path, 'event_generators')
            parsers_path = os.path.join(backend_path, 'parsers')
            scenarios_path = os.path.join(backend_path, 'scenarios')
            
            # Build volumes dict
            volumes_dict = {
                event_gen_path: {'bind': '/event_generators', 'mode': 'ro'},
                parsers_path: {'bind': '/parsers', 'mode': 'ro'}
            }
            if os.path.exists(scenarios_path):
                volumes_dict[scenarios_path] = {'bind': '/scenarios', 'mode': 'ro'}
            
            # Add a named volume for persistent database storage per session
            # This ensures destinations persist across container restarts
            volumes_dict[f'jarvis-{session_id}-data'] = {'bind': '/app/data', 'mode': 'rw'}
                
            backend = self.client.containers.run(
                settings.backend_image,
                name=f"{self.network_prefix}-{session_id}-backend",
                detach=True,
                network=network.name,
                ports={'8000/tcp': backend_port},
                environment=backend_env,
                labels=backend_labels,
                volumes=volumes_dict,
                restart_policy={"Name": "unless-stopped"},
                mem_limit=settings.backend_memory_limit,
                cpu_quota=int(float(settings.backend_cpu_limit) * 100000),
                cpu_period=100000
            )
            logger.info(f"Created backend container for session {session_id}")
            
            # Create frontend container
            frontend_env = {
                'SESSION_ID': session_id,
                'API_BASE_URL': f'http://{self.network_prefix}-{session_id}-backend:8000',
                'BACKEND_API_KEY': session_api_key,
                # Don't use SERVER_MODE - let it default  
                'PORT': '8000',
                'LOG_LEVEL': 'info',
                # Feature flags (same as backend)
                'ENABLE_GENERATORS': str(features.get('generators', True)),
                'ENABLE_SCENARIOS': str(features.get('scenarios', True)),
                'ENABLE_DESTINATIONS': str(features.get('destinations', True)),
                'ENABLE_UPLOADS': str(features.get('uploads', True)),
                'ENABLE_EXPORT': str(features.get('export', True)),
                'ENABLE_CONTINUOUS': str(features.get('continuous_mode', True))
            }
            
            frontend_labels = {
                'session_id': session_id,
                'user_id': user_id,
                'service': 'frontend',
                'expires_at': expires_at,
                'managed_by': 'session_manager'
            }
            
            # Mount Backend directory for frontend to access event generators
            import os
            # Use host path - session manager needs to specify paths accessible by Docker daemon
            # This should be configured via environment variable for portability  
            workspace_path = os.environ.get('WORKSPACE_PATH', '/Users/nathanial.smalley/tech_summit_jarvis/jarvis_coding')
            backend_path = os.path.join(workspace_path, 'Backend')
            frontend_path = os.path.join(workspace_path, 'Frontend')
            
            # Share the same data volume between frontend and backend for persistence
            frontend_volumes = {
                backend_path: {'bind': '/app/Backend', 'mode': 'ro'},
                frontend_path: {'bind': '/app/Frontend', 'mode': 'ro'},
                f'jarvis-{session_id}-data': {'bind': '/app/shared-data', 'mode': 'rw'}
            }
            
            frontend = self.client.containers.run(
                settings.frontend_image,
                name=f"{self.network_prefix}-{session_id}-frontend",
                detach=True,
                network=network.name,
                ports={'8000/tcp': frontend_port},
                environment=frontend_env,
                labels=frontend_labels,
                volumes=frontend_volumes,
                restart_policy={"Name": "unless-stopped"},
                mem_limit=settings.frontend_memory_limit,
                cpu_quota=int(float(settings.frontend_cpu_limit) * 100000),
                cpu_period=100000
            )
            logger.info(f"Created frontend container for session {session_id}")
            
            return {
                'frontend_url': f'http://localhost:{frontend_port}',
                'backend_url': f'http://localhost:{backend_port}',
                'frontend_container_id': frontend.id,
                'backend_container_id': backend.id,
                'frontend_port': frontend_port,
                'backend_port': backend_port,
                'network': network.name,
                'api_key': session_api_key
            }
            
        except Exception as e:
            logger.error(f"Failed to create session containers: {e}")
            # Cleanup any partial resources
            self.cleanup_session(session_id)
            raise
    
    def stop_session(self, session_id: str, timeout: int = 30):
        """
        Stop and remove all containers for a session
        
        Args:
            session_id: Session identifier
            timeout: Seconds to wait for graceful shutdown
        """
        try:
            # Find all containers for this session
            containers = self.client.containers.list(
                all=True,
                filters={'label': f'session_id={session_id}'}
            )
            
            for container in containers:
                try:
                    logger.info(f"Stopping container {container.name}")
                    container.stop(timeout=timeout)
                    container.remove()
                except Exception as e:
                    logger.error(f"Error stopping container {container.name}: {e}")
            
            # No need to remove network since we're using a shared one
            logger.info(f"Session {session_id} containers removed")
                
        except Exception as e:
            logger.error(f"Failed to stop session {session_id}: {e}")
            raise
    
    def cleanup_session(self, session_id: str):
        """Emergency cleanup for a session"""
        try:
            self.stop_session(session_id, timeout=5)
        except:
            pass  # Best effort cleanup
    
    def get_session_health(self, session_id: str) -> Dict[str, bool]:
        """
        Check health of session containers
        
        Args:
            session_id: Session identifier
            
        Returns:
            Dictionary with health status
        """
        health = {
            'frontend_healthy': False,
            'backend_healthy': False
        }
        
        try:
            containers = self.client.containers.list(
                filters={'label': f'session_id={session_id}'}
            )
            
            for container in containers:
                service = container.labels.get('service')
                if service in ['frontend', 'backend']:
                    # Check if container is running
                    container.reload()
                    is_healthy = container.status == 'running'
                    health[f'{service}_healthy'] = is_healthy
                    
        except Exception as e:
            logger.error(f"Failed to check health for session {session_id}: {e}")
            
        return health
    
    def list_sessions(self) -> List[Dict[str, Any]]:
        """
        List all active sessions
        
        Returns:
            List of session information
        """
        sessions = {}
        
        try:
            containers = self.client.containers.list(
                all=True,
                filters={'label': 'managed_by=session_manager'}
            )
            
            for container in containers:
                session_id = container.labels.get('session_id')
                if session_id and session_id not in sessions:
                    sessions[session_id] = {
                        'session_id': session_id,
                        'user_id': container.labels.get('user_id'),
                        'expires_at': container.labels.get('expires_at'),
                        'containers': []
                    }
                
                if session_id:
                    sessions[session_id]['containers'].append({
                        'name': container.name,
                        'service': container.labels.get('service'),
                        'status': container.status,
                        'id': container.id
                    })
                    
        except Exception as e:
            logger.error(f"Failed to list sessions: {e}")
            
        return list(sessions.values())
    
    def cleanup_expired_sessions(self):
        """Clean up sessions that have expired
        
        Returns:
            int: Number of sessions cleaned up
        """
        cleaned_count = 0
        try:
            containers = self.client.containers.list(
                all=True,
                filters={'label': 'managed_by=session_manager'}
            )
            
            now = datetime.utcnow()
            
            for container in containers:
                expires_at_str = container.labels.get('expires_at')
                if expires_at_str:
                    try:
                        expires_at = datetime.fromisoformat(expires_at_str)
                        if expires_at < now:
                            session_id = container.labels.get('session_id')
                            logger.info(f"Cleaning up expired session {session_id}")
                            self.stop_session(session_id)
                            cleaned_count += 1
                    except Exception as e:
                        logger.error(f"Error processing expiration for container {container.name}: {e}")
                        
        except Exception as e:
            logger.error(f"Failed to cleanup expired sessions: {e}")
        
        return cleaned_count