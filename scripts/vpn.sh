#!/bin/bash
# VPN Start script
if [ -z "${OPEN_VPN_USER}" ] || [ -z "${OPEN_VPN_PASSWORD}" ]; then
    echo "OPEN_VPN_USER and OPEN_VPN_PASSWORD must be set"
    exit 1
fi

# Create our user-pass file
echo ${OPEN_VPN_USER} > /tmp/user.txt
echo ${OPEN_VPN_PASSWORD} >> /tmp/user.txt

# Save our current network interface
curl -s -o /tmp/old.ip https://ifconfig.co
cfg=`ls /vpn/config/*${SERVER}*.ovpn | shuf | head -n 1`
/bin/bash /vpn/serve.sh &  # webserver in background

# Ensure local network remains accessible
if [ -z "${LAN}" ]; then
    echo "LAN not set - unable to add route back to LAN, status web server will be unavailable"
else
    gateway=$(ip route | grep eth0 | grep default | cut -f3 -d' ')
    echo "lan route: route add ${LAN} via ${gateway}"
    ip route add ${LAN} via ${gateway}
fi

openvpn --config "${cfg}" --script-security 2 \
    --up /etc/openvpn/up.sh \
    --down /etc/openvpn/down.sh \
    --auth-user-pass /tmp/user.txt \
    --dhcp-option 'DOMAIN-ROUTE .' --down-pre
