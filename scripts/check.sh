#!/bin/bash
# Healthcheck script for OpenVPN container.

set -euo pipefail

NEW_IP_FILE="/tmp/new.ip"
OLD_IP_FILE="/tmp/orig.ip"
STATUS_FILE="/tmp/status.txt"

# Fetch new IP, handle curl failure
if ! curl -fsSL -o "$NEW_IP_FILE" https://ifconfig.co; then
    echo "ERROR: Failed to fetch new IP" | tee "$STATUS_FILE" >&2
    exit 1
fi

if [[ -f "$OLD_IP_FILE" && -s "$NEW_IP_FILE" ]]; then
    old_ip=$(<"$OLD_IP_FILE")
    new_ip=$(<"$NEW_IP_FILE")
    if [[ "$old_ip" != "$new_ip" ]]; then
        echo "IP address changed from $old_ip to $new_ip"
        echo "OK" > "$STATUS_FILE"
        exit 0
    else
        echo "IP address remains the same"
        echo "ERROR: unchanged" > "$STATUS_FILE"
        exit 1
    fi
elif [[ -s "$NEW_IP_FILE" ]]; then
    echo "New IP address could not be determined" | tee "$STATUS_FILE" >&2
    echo "ERROR: new ip" > "$STATUS_FILE"
    exit 1
else
    echo "Original IP address could not be determined" | tee "$STATUS_FILE" >&2
    echo "ERROR: old ip" > "$STATUS_FILE"
    exit 1
fi
