#!/bin/bash
# Healthcheck script for OpenVPN container.
rm -rf /tmp/new.ip
curl -s -o /tmp/new.ip https://ifconfig.co
if [ -f /tmp/old.ip ] && [ -f /tmp/new.ip ]; then
    old_ip=$(cat /tmp/old.ip)
    new_ip=$(cat /tmp/new.ip)
    if [ "$old_ip" != "$new_ip" ]; then
        echo "IP address changed from $old_ip to $new_ip"
        echo "OK" > /tmp/status.txt
        exit 0
    else
        echo "IP address remains the same"
        echo "ERROR: unchanged" > /tmp/status.txt
        exit 1
    fi
elif [ -f /tmp/new.ip ]; then
    echo "New IP address could not be determined"
    echo "ERROR: new ip" > /tmp/status.txt
    exit 1
else
    echo "Original IP address could not be determined"
    echo "ERROR: old ip" > /tmp/status.txt
    exit 1
fi
exit 1
