#!/bin/bash
mini_httpd -r -d /vpn/web -p 80 -D &

# Update our status every 10 seconds.
while true;
do
    sleep 10
    # echo "Refresh IP Status"
    curl -s -o /vpn/web/ipinfo.json https://ipinfo.io/
    IP=`curl -s https://ifconfig.co`
    ORIG=$(cat /tmp/old.ip)
    STATUS=$(cat /tmp/status.txt)
    NOW=$(date)
    sed -e "s/%IPADDR%/$IP/g" \
        -e "s/%ORIGADDR%/$ORIG/g" \
        -e "s/%STATUS%/$STATUS/g" \
        -e "s/%NOW%/$NOW/g" \
        /vpn/templates/index.html > /vpn/web/index.html
    sed -e "s/%IPADDR%/$IP/g" \
        -e "s/%ORIGADDR%/$ORIG/g" \
        -e "s/%STATUS%/$STATUS/g" \
        -e "s/%NOW%/$NOW/g" \
        /vpn/templates/status.json > /vpn/web/status.json
done
