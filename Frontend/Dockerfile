# Dockerfile for Jarvis Frontend (Flask UI)
FROM python:3.11-slim

# Set working directory at repo root inside image to preserve Frontend/ <-> Backend/ relative paths
WORKDIR /app

# System deps (minimal)
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy only requirements first for better caching
COPY Frontend/requirements.txt Frontend/requirements.txt
RUN pip install --no-cache-dir -r Frontend/requirements.txt

# Copy source code (both Frontend and Backend to maintain expected relative paths)
COPY Frontend/ Frontend/
COPY Backend/ Backend/
 
 # Provide expected top-level path for event_generators used by the UI (CWD/event_generators)
 RUN ln -s Backend/event_generators event_generators

# Create non-root user
RUN useradd -m -u 1001 appuser && chown -R appuser:appuser /app
USER appuser

# Expose Flask port used by log_generator_ui.py
EXPOSE 8000

# Environment: allow overriding API base URL; default points to backend service name in compose
ENV API_BASE_URL=http://api:8000

# Start the Flask UI
CMD ["python", "Frontend/log_generator_ui.py"]
