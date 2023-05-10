rm -rf GeoLite2-Country.mmdb >/dev/null 2>&1
wget https://git.io/GeoLite2-Country.mmdb

rm -rf bad-user-agents.caddy >/dev/null 2>&1
wget https://raw.githubusercontent.com/mitchellkrogza/nginx-ultimate-bad-bot-blocker/master/_generator_lists/bad-user-agents.list -O bad-user-agents.list
for i in $(cat aaa); do echo "header User-Agent *$i*" >> bad-user-agents.caddy; done

rm -rf bad-user-agents.list >/dev/null 2>&1

# bad ips should update by yourself.
