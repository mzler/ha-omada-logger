#!/usr/bin/with-contenv bashio
# ==============================================================================
# Home Assistant Add-on: Omada Diagnostic Advisor
# Starts the async Python backend (FastAPI, Syslog UDP Server, Poller)
# ==============================================================================

bashio::log.info "Starting Omada Diagnostic Advisor..."

# Ensure data directory exists for SQLite storage
if [ ! -d "/data" ]; then
    bashio::log.info "Creating persistent storage directory /data..."
    mkdir -p /data
fi

# Run main application
bashio::log.info "Launching FastAPI / Syslog / Poller engine on port 8099 & 5514/udp..."
exec python3 -u /app/app.py
