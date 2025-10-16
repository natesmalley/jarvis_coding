#!/bin/bash

# --- Setup and Activation ---
echo "1. Creating and activating Python virtual environment (.venv)..."
# Create the virtual environment
python3 -m venv .venv

# Check if the environment was created successfully
if [ -d ".venv" ]; then
    # Activate the virtual environment
    source .venv/bin/activate
    echo "Virtual environment activated successfully."
else
    echo "Error: Failed to create the virtual environment. Exiting."
    exit 1
fi

python -m venv .venv && source .venv/bin/activate
#python /home/ubuntu/jarvis_coding/event_generators/web_security/zscaler_private_access.py --count 100 >> /home/ubuntu/sample-logs/zscaler-private-access.log
#python /home/ubuntu/jarvis_coding/event_generators/web_security/zscaler_dns_firewall.py --count 100 >> /home/ubuntu/sample-logs/zscaler-dns-firewall.log
#python /home/ubuntu/jarvis_coding/event_generators/web_security/zscaler_firewall.py --count 100 >> /home/ubuntu/sample-logs/zscaler-firewall.log
#python /home/ubuntu/jarvis_coding/event_generators/identity_access/microsoft_azure_ad_signin.py >> /home/ubuntu/sample-logs/azure_ad_signin.log
#python /home/ubuntu/jarvis_coding/event_generators/identity_access/microsoft_azure_ad.py >> /home/ubuntu/sample-logs/azure_ad.log
# --- Cleanup ---
# Deactivate the virtual environment (optional, but good practice)
deactivate
echo "Virtual environment deactivated."

echo "Log generation complete. Check files in $LOG_DIR"