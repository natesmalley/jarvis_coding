#!/bin/bash
set -e

# Ensure data directory exists and has proper permissions
echo "Ensuring /app/data directory exists with proper permissions..."
mkdir -p /app/data

# Determine which server to use (default to gunicorn for production)
SERVER_MODE="${SERVER_MODE:-gunicorn}"

# Start the appropriate server
if [ "$SERVER_MODE" = "gunicorn" ]; then
    echo "Starting Jarvis Backend API with Gunicorn (production mode)..."
    START_CMD="gunicorn app.main:app -c /app/gunicorn.conf.py"
else
    echo "Starting Jarvis Backend API with Uvicorn (development mode)..."
    START_CMD="python start_api.py"
fi

# Fix ownership to jarvis user if running as root
if [ "$(id -u)" = "0" ]; then
    chown -R jarvis:jarvis /app/data
    echo "Fixed /app/data ownership for jarvis user"
    # Switch to jarvis user and start the application
    exec gosu jarvis $START_CMD
else
    # Already running as jarvis, just start the app
    exec $START_CMD
fi
