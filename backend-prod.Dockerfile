FROM python:3.11-slim

WORKDIR /app

# Install system dependencies and gosu
RUN apt-get update && apt-get install -y \
    postgresql-client \
    gcc \
    python3-dev \
    libpq-dev \
    gosu \
    && rm -rf /var/lib/apt/lists/*

# Create jarvis user
RUN useradd -m -u 1000 jarvis && \
    mkdir -p /app/data && \
    chown -R jarvis:jarvis /app

# Copy backend code
COPY Backend/api/app /app/app
COPY Backend/api/entrypoint.sh /app/entrypoint.sh
COPY Backend/api/gunicorn.conf.py /app/gunicorn.conf.py
COPY Backend/api/requirements.txt /app/requirements.txt
COPY Backend/event_generators /event_generators
COPY Backend/parsers /parsers
RUN chmod +x /app/entrypoint.sh

# Install Python dependencies from requirements file
RUN pip install --no-cache-dir -r /app/requirements.txt

EXPOSE 8000

# Use the existing entrypoint script if SERVER_MODE is not gunicorn
# Otherwise use gunicorn
CMD if [ "$SERVER_MODE" = "gunicorn" ]; then \
        exec gunicorn app.main:app -w 4 -k uvicorn.workers.UvicornWorker -b 0.0.0.0:8000; \
    else \
        exec /app/entrypoint.sh; \
    fi