#!/bin/bash

printf "Content-type: text/plain\n\n"

printf "example error message\n" > /dev/stderr

if [ "POST" = "$REQUEST_METHOD" -a -n "$CONTENT_LENGTH" ]; then
  read -n "$CONTENT_LENGTH" POST_DATA
fi

iptables -I INPUT -s $REMOTE_HOST -p tcp --dport REPLEACE_HERE -j ACCEPT
echo "[+] TeamServer Guard: Add IP: ${REMOTE_HOST} to whitelist"

exit 0
