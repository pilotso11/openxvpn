#!/bin/bash
# Periodically build and serve the status web page and json files.
set -euo pipefail

# Configurable update interval (seconds)
UPDATE_INTERVAL="${UPDATE_INTERVAL:-10}"

mini_httpd -r -d /vpn/web -p 80 -D &
HTTPD_PID=$!

cleanup() {
    kill "$HTTPD_PID"
    exit
}
trap cleanup SIGINT SIGTERM

while true; do
    # Fetch IP info JSON
    if ! curl -fsSL -o /vpn/web/ipinfo.json https://ipinfo.io/; then
        echo "Failed to fetch ipinfo.json" >&2
    fi

    IPADDR=$(curl -fsSL https://ifconfig.co || echo "unknown")
    ORIGADDR=$(cat /tmp/old.ip 2>/dev/null || echo "unknown")
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

    ls -l /vpn/web

    sleep "${UPDATE_INTERVAL}"
done
