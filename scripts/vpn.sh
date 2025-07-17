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
# todo: we need to get this from the container, not hardcode it.
ip route add $LAN via 172.19.0.1

openvpn --config "${cfg}" --script-security 2 \
    --up /etc/openvpn/up.sh \
    --down /etc/openvpn/down.sh \
    --auth-user-pass /tmp/user.txt \
    --dhcp-option 'DOMAIN-ROUTE .' --down-pre
