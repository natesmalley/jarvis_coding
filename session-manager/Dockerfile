# Multi-stage build for Session Manager
FROM python:3.11-slim as builder

WORKDIR /app

# Install build dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Production stage
FROM python:3.11-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy Python dependencies from builder
COPY --from=builder /usr/local /usr/local

# Copy application code
COPY app/ ./app/
COPY gunicorn.conf.py .

# Create non-root user
RUN useradd -m -u 1000 session-manager && \
    chown -R session-manager:session-manager /app

# Note: Docker socket will be mounted as volume, so we don't switch user yet
# The container needs to run with appropriate permissions to access Docker socket

EXPOSE 9000

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD curl -f http://localhost:9000/api/health || exit 1

# Set environment variable for server mode
ENV SERVER_MODE=gunicorn

# Start with Gunicorn
CMD ["gunicorn", "app.main:app", "-c", "gunicorn.conf.py"]