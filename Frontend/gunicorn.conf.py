"""
Gunicorn configuration for Jarvis Frontend
Optimized for 150 concurrent users on a single system
Each user gets their own container, but within each container we optimize for that user's experience
"""
import os
import multiprocessing

# Server socket
bind = f"0.0.0.0:{os.getenv('PORT', '8000')}"
backlog = 2048

# Worker processes
# Since each user gets their own container, we optimize for single-user performance
# For the Tech Summit shared frontend (if needed), we use more workers
is_shared = os.getenv('SHARED_FRONTEND', 'false').lower() == 'true'

if is_shared:
    # Shared frontend serving multiple users (Tech Summit main UI)
    workers = min(multiprocessing.cpu_count() * 2, 16)  # More workers for shared instance
    threads = 4  # More threads per worker
else:
    # Per-user container (default for session isolation)
    workers = 2  # Minimal workers since it's single-user
    threads = 2  # Threads per worker

worker_class = 'gthread'  # Threaded worker for better Flask concurrency
worker_connections = 1000

# Worker timeout
timeout = 120  # 2 minutes for long operations
graceful_timeout = 30
keepalive = 5

# Restart workers periodically to prevent memory leaks
max_requests = 5000
max_requests_jitter = 500

# Logging
accesslog = '-'
errorlog = '-'
loglevel = os.getenv('LOG_LEVEL', 'info')
access_log_format = '%(h)s %(l)s %(u)s %(t)s "%(r)s" %(s)s %(b)s "%(f)s" "%(a)s" %(D)s'

# Process naming
proc_name = 'jarvis-frontend'

# Server mechanics
daemon = False
pidfile = None
user = None
group = None
tmp_upload_dir = None

# Performance tuning
worker_tmp_dir = '/dev/shm'  # Use RAM for worker heartbeat

# Preload app for better memory usage
preload_app = True

# Enable stats if configured
statsd_host = os.getenv('STATSD_HOST', None)
if statsd_host:
    statsd_prefix = 'jarvis.frontend'

def when_ready(server):
    """Called just after the master process is initialized."""
    server.log.info("Jarvis Frontend is ready. Listening at: %s", bind)
    server.log.info("Using %s workers with %s threads each", workers, threads)

def on_exit(server):
    """Called just before the master process exits."""
    server.log.info("Jarvis Frontend is shutting down")

def pre_fork(server, worker):
    """Called just before a worker is forked."""
    server.log.info("Forking worker %s", worker.pid)

def post_fork(server, worker):
    """Called just after a worker has been forked."""
    server.log.info("Worker spawned (pid: %s)", worker.pid)

def worker_exit(server, worker):
    """Called just after a worker has been exited."""
    server.log.info("Worker exited (pid: %s)", worker.pid)