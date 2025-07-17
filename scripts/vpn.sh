#!/bin/bash
# VPN Start script
set -euo pipefail

if [[ -z "${OPEN_VPN_USER_PASS_PATH:-}" ]]; then
    if [[ -z "${OPEN_VPN_USER:-}" ]] || [[ -z "${OPEN_VPN_PASSWORD:-}" ]]; then
        echo "OPEN_VPN_USER and OPEN_VPN_PASSWORD must be set" >&2
        exit 1
    fi
    USERPASSS=/tmp/user.txt
    # Create our user-pass file (permissions: owner read/write only)
    echo "${OPEN_VPN_USER}" > ${USERPASS}
    echo "${OPEN_VPN_PASSWORD}" >> ${USERPASS}
    chmod 700 ${USERPASS}
else
    if [[ ! -f "$OPEN_VPN_USER_PASS_PATH" ]]; then
        echo "OPEN_VPN_USER_PASS_PATH file not found" >&2
        exit 1
    fi
    USERPASS="${OPEN_VPN_USER_PASS_PATH}"
fi

# Save our current network interface
if ! curl -fsSL -o /tmp/old.ip https://ifconfig.co; then
    echo "Failed to fetch original IP address" >&2
    exit 1
fi

# Select config file
cfg=$(ls /vpn/config/*${SERVER:-}*.ovpn 2>/dev/null | shuf | head -n 1 || true)
if [[ -z "$cfg" ]]; then
    echo "No .ovpn config file found matching SERVER='${SERVER:-}'" >&2
    exit 1
fi

/bin/bash /vpn/serve.sh &  # webserver in background

# Ensure local network remains accessible
if [[ -z "${LAN:-}" ]]; then
    echo "LAN not set - unable to add route back to LAN, status web server may be unavailable"
else
    gateway=$(ip route | awk '/eth0/ && /default/ {print $3; exit}')
    if [[ -n "$gateway" ]]; then
        echo "lan route: route add ${LAN} via ${gateway}"
        ip route add "${LAN}" via "${gateway}"
    else
        echo "Could not determine gateway for eth0" >&2
    fi
fi

exec openvpn --config "${cfg}" --script-security 2 \
    --up /etc/openvpn/up.sh \
    --down /etc/openvpn/down.sh \
    --auth-user-pass "${USERPASS}" \
    --dhcp-option 'DOMAIN-ROUTE .' --down-pre
