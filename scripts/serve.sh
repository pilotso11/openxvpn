#!/bin/bash
mini_httpd -r -d /vpn/web -p 80 -D &

# Update our status every 10 seconds.
while true;
do
    sleep 10
    # echo "Refresh IP Status"
    IP=`curl -s https://ifconfig.co`
    curl -s -o /vpn/web/ipinfo.json https://ipinfo.io/
    ORIG=$(cat /tmp/old.ip)
    STATUS=$(cat /tmp/status.txt)
    NOW=$(date)
    sed "s/%IPADDR%/$IP/g" /vpn/template.html | \
        sed "s/%ORIGADDR%/$ORIG/g" | \
        sed "s/%STATUS%/$STATUS/g" | \
        sed "s/%NOW%/$NOW/g" > /vpn/web/index.html
done
