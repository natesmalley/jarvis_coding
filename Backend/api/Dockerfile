# Multi-stage build for Jarvis Coding API
FROM python:3.11-slim as builder

# Set working directory
WORKDIR /app

# Install build dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements
COPY Backend/api/requirements.txt .

# Install Python dependencies into system site-packages
RUN pip install --no-cache-dir -r requirements.txt

# Production stage
FROM python:3.11-slim

# Install gosu for user switching in entrypoint
RUN apt-get update && apt-get install -y gosu && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy Python dependencies from builder
COPY --from=builder /usr/local /usr/local

# Copy application code
COPY Backend/api/app/ ./app/
COPY Backend/api/start_api.py .
COPY Backend/api/entrypoint.sh .

# Copy event generators and parsers from parent directory
COPY Backend/event_generators ./event_generators
COPY Backend/parsers ./parsers
COPY Backend/scenarios ./scenarios

# Ensure PATH is set (python, pip already in /usr/local/bin)
ENV PATH=/usr/local/bin:$PATH

# Provide absolute path compatibility for code expecting top-level dirs
RUN ln -s /app/event_generators /event_generators \
 && ln -s /app/parsers /parsers \
 && ln -s /app/scenarios /scenarios

# Create data directory for ephemeral database
RUN mkdir -p /app/data

# Fix Windows line endings for shell script
RUN apt-get update && apt-get install -y dos2unix && \
    dos2unix /app/entrypoint.sh && \
    apt-get remove -y dos2unix && \
    apt-get autoremove -y && \
    rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN useradd -m -u 1000 jarvis && \
    chown -R jarvis:jarvis /app && \
    chmod +x /app/entrypoint.sh

# Expose port
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD python -c "import requests; requests.get('http://localhost:8000/api/v1/health')" || exit 1

# Use entrypoint script to handle directory permissions
ENTRYPOINT ["/app/entrypoint.sh"]