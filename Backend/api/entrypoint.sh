#!/bin/bash
set -e

# Ensure data directory exists
mkdir -p /app/data

# Start the application
exec python start_api.py
