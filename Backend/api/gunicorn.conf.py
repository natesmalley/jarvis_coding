"""
Gunicorn configuration for Jarvis Backend API
Optimized for 150 concurrent users on a single system
"""
import multiprocessing
import os

# Server socket
bind = f"0.0.0.0:{os.getenv('PORT', '8000')}"
backlog = 2048

# Worker processes
# For 150 concurrent users, we need adequate workers
# Formula: (2 * CPU cores) + 1 for I/O bound applications
workers = min(multiprocessing.cpu_count() * 2 + 1, 16)  # Cap at 16 for single system
worker_class = 'uvicorn.workers.UvicornWorker'  # Async worker for FastAPI
worker_connections = 1000  # Max simultaneous clients per worker

# Worker timeout (in seconds)
timeout = 120  # 2 minutes for long-running operations
graceful_timeout = 30  # Grace period for workers to finish serving requests
keepalive = 5  # Seconds to wait for requests on Keep-Alive connections

# Restart workers after this many requests (helps prevent memory leaks)
max_requests = 5000
max_requests_jitter = 500  # Randomize restart to avoid all workers restarting at once

# Logging
accesslog = '-'  # Log to stdout
errorlog = '-'   # Log to stderr
loglevel = os.getenv('LOG_LEVEL', 'info')
access_log_format = '%(h)s %(l)s %(u)s %(t)s "%(r)s" %(s)s %(b)s "%(f)s" "%(a)s" %(D)s'

# Process naming
proc_name = 'jarvis-backend'

# Server mechanics
daemon = False  # Don't daemonize (Docker handles this)
pidfile = None
user = None
group = None
tmp_upload_dir = None

# SSL (disabled by default, handled by reverse proxy)
keyfile = None
certfile = None

# Performance tuning for 150 users
# Each worker can handle ~10-20 concurrent connections effectively
# With 16 workers max, we can handle 160-320 concurrent connections
worker_tmp_dir = '/dev/shm'  # Use RAM for worker heartbeat (faster)

# Preload application for better memory usage (workers share memory)
preload_app = True

# Enable stats
statsd_host = os.getenv('STATSD_HOST', None)
if statsd_host:
    statsd_prefix = 'jarvis.backend'

def when_ready(server):
    """Called just after the master process is initialized."""
    server.log.info("Jarvis Backend API is ready. Listening at: %s", bind)
    server.log.info("Using %s workers with %s worker class", workers, worker_class)

def worker_int(worker):
    """Called just after a worker exited on SIGINT or SIGQUIT."""
    worker.log.info("Worker received INT or QUIT signal")

def on_exit(server):
    """Called just before the master process exits."""
    server.log.info("Jarvis Backend API is shutting down")

def pre_fork(server, worker):
    """Called just before a worker is forked."""
    server.log.info("Forking worker %s", worker.pid)

def post_fork(server, worker):
    """Called just after a worker has been forked."""
    server.log.info("Worker spawned (pid: %s)", worker.pid)

def worker_exit(server, worker):
    """Called just after a worker has been exited."""
    server.log.info("Worker exited (pid: %s)", worker.pid)