#!/bin/bash

# Mock OpenVPN script for e2e testing
# This script simulates OpenVPN behavior without actually establishing a VPN connection

# Parse command line arguments
CONFIG_FILE=""
AUTH_FILE=""
DAEMON_MODE=false
VERBOSE=false

while [[ $# -gt 0 ]]; do
    case $1 in
        --config)
            CONFIG_FILE="$2"
            shift 2
            ;;
        --auth-user-pass)
            AUTH_FILE="$2"
            shift 2
            ;;
        --daemon)
            DAEMON_MODE=true
            shift
            ;;
        --verb)
            VERBOSE=true
            shift 2
            ;;
        --script-security|--dhcp-option|--down-pre|--up|--down)
            # Skip these arguments and their values
            shift 2
            ;;
        *)
            # Skip unknown arguments
            shift
            ;;
    esac
done

# Log startup message
echo "Mock OpenVPN starting..."
echo "Config file: $CONFIG_FILE"
echo "Auth file: $AUTH_FILE"

# Validate required files exist
if [[ ! -f "$CONFIG_FILE" ]]; then
    echo "ERROR: Config file not found: $CONFIG_FILE" >&2
    exit 1
fi

if [[ ! -f "$AUTH_FILE" ]]; then
    echo "ERROR: Auth file not found: $AUTH_FILE" >&2
    exit 1
fi

# Read and validate auth file
if [[ $(wc -l < "$AUTH_FILE") -lt 2 ]]; then
    echo "ERROR: Auth file must contain at least 2 lines (username and password)" >&2
    exit 1
fi

# Simulate connection process
echo "Attempting connection..."
sleep 1
echo "Connected to mock VPN server"

# Check for mock failure mode (if config contains "MOCK_FAIL")
if grep -q "MOCK_FAIL" "$CONFIG_FILE" 2>/dev/null; then
    echo "ERROR: Mock failure mode activated" >&2
    exit 1
fi

# Check for mock timeout mode (if config contains "MOCK_TIMEOUT")
if grep -q "MOCK_TIMEOUT" "$CONFIG_FILE" 2>/dev/null; then
    echo "Simulating timeout..."
    sleep 30
    echo "Connection timed out" >&2
    exit 1
fi

# Simulate running state
echo "VPN connection established"
echo "Mock OpenVPN running in background..."

# If in daemon mode or running normally, keep the process alive
# In testing, this will be terminated by the test framework
if [[ "$DAEMON_MODE" == true ]]; then
    # Run in background, but for testing purposes, we'll simulate with a loop
    while true; do
        sleep 10
        # Check if we should exit (for graceful shutdown testing)
        if [[ -f "/tmp/mock_openvpn_stop" ]]; then
            echo "Received stop signal, shutting down..."
            rm -f "/tmp/mock_openvpn_stop"
            exit 0
        fi
    done
else
    # Run in foreground
    trap 'echo "Received interrupt signal, shutting down..."; exit 0' INT TERM
    while true; do
        sleep 1
    done
fi