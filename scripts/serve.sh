#!/bin/bash
# Periodically build and serve the status web page and json files.
set -euo pipefail

# Configurable update interval (seconds)
UPDATE_INTERVAL="${UPDATE_INTERVAL:-10}"

# Load IP2LOCATION_IO_KEY from file if specified
if [ -n "${IP2LOCATION_IO_KEY_FILE:-}" ] && [ -f "$IP2LOCATION_IO_KEY_FILE" ]; then
    IP2LOCATION_IO_KEY=$(cat "$IP2LOCATION_IO_KEY_FILE")
fi

port="${HTTP_PORT:-80}"

mini_httpd -r -d /vpn/web -p ${port} -D &
HTTPD_PID=$!

cleanup() {
    kill "$HTTPD_PID"
    exit
}
trap cleanup SIGINT SIGTERM


while true; do
    IPADDR=$(curl -fsSL https://ifconfig.co || echo "unknown")
    ORIGADDR=$(cat /tmp/orig.ip 2>/dev/null || echo "unknown")
    OLDIP=$(cat /tmp/old.ip 2>/dev/null || echo "unknown")

    # Fetch IP info JSON only if IP has changed or it's the first run
    if [ "$IPADDR" != "$OLDIP" ]; then
        if ! curl -fsSL -o /vpn/web/ipinfo.json https://api.ip2location.io/?key=${IP2LOCATION_IO_KEY} ; then
            echo "Failed to fetch ipinfo.json" >&2
        fi
        # Store the current IP for future comparison
        echo "$IPADDR" > /tmp/old.ip
    fi
    STATUS=$(cat /tmp/status.txt 2>/dev/null || echo "unknown")
    NOW=$(date)

    # Update index.html if changed
    INDEX_TMP=$(mktemp)
    sed -e "s/%IPADDR%/${IPADDR}/g" \
        -e "s/%ORIGADDR%/${ORIGADDR}/g" \
        -e "s/%STATUS%/${STATUS}/g" \
        -e "s/%NOW%/${NOW}/g" \
        /vpn/templates/index.html > "${INDEX_TMP}"
    if ! cmp -s "${INDEX_TMP}" /vpn/web/index.html 2>/dev/null; then
        mv "${INDEX_TMP}" /vpn/web/index.html
        chmod 644 /vpn/web/index.html
    else
        rm "${INDEX_TMP}"
    fi

    # Update status.json if changed
    STATUS_TMP=$(mktemp)
    sed -e "s/%IPADDR%/${IPADDR}/g" \
        -e "s/%ORIGADDR%/${ORIGADDR}/g" \
        -e "s/%STATUS%/${STATUS}/g" \
        -e "s/%NOW%/${NOW}/g" \
        /vpn/templates/status.json > "${STATUS_TMP}"
    if ! cmp -s "${STATUS_TMP}" /vpn/web/status.json 2>/dev/null; then
        mv "${STATUS_TMP}" /vpn/web/status.json
        chmod 644 /vpn/web/status.json
    else
        rm "${STATUS_TMP}"
    fi

    sleep "${UPDATE_INTERVAL}"
done
