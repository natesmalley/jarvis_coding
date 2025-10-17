#!/bin/bash
set -e

# Ensure data directory exists and has proper permissions
echo "Ensuring /app/data directory exists with proper permissions..."
mkdir -p /app/data

# Fix ownership to jarvis user if running as root
if [ "$(id -u)" = "0" ]; then
    chown -R jarvis:jarvis /app/data
    echo "Fixed /app/data ownership for jarvis user"
    # Switch to jarvis user and start the application
    exec gosu jarvis python start_api.py
else
    # Already running as jarvis, just start the app
    exec python start_api.py
fi
