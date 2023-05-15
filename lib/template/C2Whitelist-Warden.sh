#!/bin/bash

printf "Content-type: text/plain\n\n"

printf "example error message\n" > /dev/stderr

if [ "POST" = "$REQUEST_METHOD" -a -n "$CONTENT_LENGTH" ]; then
  read -n "$CONTENT_LENGTH" POST_DATA
fi

# Create log file.
mkdir C2Whitelist-data > /dev/null 2>&1 && chmod 777 C2Whitelist-data > /dev/null 2>&1
list=('allow-ips.lst' 'deny-ips.lst' 'other-ips.lst')
for i in ${list[@]};
do
  touch C2Whitelist-data/$i > /dev/null 2>&1 && chmod 777 C2Whitelist-data/$i > /dev/null 2>&1;
done

# Dingtalk bot
export EVENT_ID=$(cat /proc/sys/kernel/random/uuid | awk -F '-' '{print $5}')
timeout 60 python3 C2Whitelist-Dingtalk.py -bot-token "REPLACE_WITH_BOT_TOKEN" -vps-ip "REPLACE_TO_VPS_IP" -c2-port "REPLACE_TO_IPTABLES_PORTS" -c2warden-port "REPLACE_TO_WARDEN_PORT"

# Check ip in allow/denly list? if not in these, that measn expired.
if grep -Fxq "$REMOTE_HOST" C2Whitelist-data/allow-ips.lst C2Whitelist-data/deny-ips.lst
then
    :
else
    iptables -D INPUT -s $REMOTE_HOST -p tcp --dport 6443 -j DROP > /dev/null 2>&1
    echo $REMOTE_HOST >> C2Whitelist-data/other-ips.lst
    python3 C2Whitelist-Dingtalk.py -bot-token "REPLACE_WITH_BOT_TOKEN" -expire-tips
fi

exit 0