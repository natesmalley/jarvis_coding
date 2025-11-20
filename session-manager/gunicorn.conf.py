"""
Gunicorn configuration for Session Manager
Optimized for managing 150 concurrent user sessions
"""
import multiprocessing
import os

# Server socket
bind = f"0.0.0.0:{os.getenv('PORT', '9000')}"
backlog = 2048

# Worker processes
# Session Manager is lightweight, doesn't need as many workers as the main apps
workers = min(multiprocessing.cpu_count() + 1, 8)
worker_class = 'uvicorn.workers.UvicornWorker'
worker_connections = 1000

# Timeouts
timeout = 120
graceful_timeout = 30
keepalive = 5

# Restart workers periodically
max_requests = 10000
max_requests_jitter = 1000

# Logging
accesslog = '-'
errorlog = '-'
loglevel = os.getenv('LOG_LEVEL', 'info')
access_log_format = '%(h)s %(l)s %(u)s %(t)s "%(r)s" %(s)s %(b)s "%(f)s" "%(a)s" %(D)s'

# Process naming
proc_name = 'jarvis-session-manager'

# Server mechanics
daemon = False
pidfile = None
worker_tmp_dir = '/dev/shm'

# Preload app
preload_app = True

def when_ready(server):
    server.log.info("Session Manager is ready. Listening at: %s", bind)
    server.log.info("Using %s workers with %s worker class", workers, worker_class)

def on_exit(server):
    server.log.info("Session Manager is shutting down")