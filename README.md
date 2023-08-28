# RedCaddy
C2 redirector base on caddy

## Table of content
* [Overview](#Overview)
* [Feature](#Feature)
* [Note](#Note)
* [Quick start](#Quick-start)
* [Step by step](#Step-by-step)
* [References](#References)

### Overview
Generate caddyfile with c2 malleable profiles

### Feature
- Block IP by GEOIP country
- Allow requests by header matcher
- User-agent & IP blacklist
- Support multiple redirection
- TeamServer port warden

### Note
- **The "redwarden_parser.py" under modules is from [RedWarden](https://github.com/mgeeky/RedWarden) by [mgeeky](https://github.com/mgeeky)**  
- Plenty of inspiration from this article: [🇬🇧 Carrying the Tortellini's golf sticks](https://aptw.tf/2021/11/25/c2-redirectors-using-caddy.html)  
- IP Blacklists from [RedGuard's IP Blacklists](https://github.com/wikiZ/RedGuard/blob/main/data/banned_ips.go)
- User-Agent Blacklists from [mitchellkrogza's UA blacklists](https://github.com/mitchellkrogza/nginx-ultimate-bad-bot-blocker/blob/master/_generator_lists/bad-user-agents.list)  
- self-signed-cert.py modified from [CarbonCopy](https://github.com/paranoidninja/CarbonCopy) 

### Quick start
- Generate self-signed certificate
- Build the custom caddy with specific modules (optional)
- **Make sure `set trust_x_forwarded_for "true";` already enabled in C2 malleable profile**
- Copy your C2 malleable profile into RedCaddy
- Add your redirect rules into files (E.g [chains.list](https://github.com/XiaoliChan/RedCaddy/blob/main/chains.list))
- Finally, generate Caddyfile with the ugly python script.

### Step by step
- **1. Generate self-signed certificates with "self-signed-cert.py"** :  
`python3 self-signed-cert.py -t [Https Server]`  
![image](https://github.com/XiaoliChan/RedCaddy/assets/30458572/72cec673-3df3-4779-9caa-737c88c76109)
As you can see, `localhost.*` are generated in `core/cert-out`   
![image](https://github.com/XiaoliChan/RedCaddy/assets/30458572/dd7944d5-f09a-4405-aae3-69479c7a2ffa)

- **2. Enable `set trust_x_forwarded_for "true";` in C2 malleable profile**  
![image](https://user-images.githubusercontent.com/30458572/196095882-c60f306c-b11d-4642-af0c-86779200b3d3.png)

- **3. Host & Referer headers needed to define in each client blocks of C2 malleable profile**  
:warning: Note: the fake sub-domain must exists in self-signed certificates SAN (subject alternative name) attribute  
![image](https://user-images.githubusercontent.com/30458572/210927201-d2403730-f731-45be-8d0f-1d3dbdc21be4.png)

- **4. Copy the C2 profile into RedCaddy**  
I use [threatexpress‘s jquery-c2.4.3.profile](https://github.com/threatexpress/malleable-c2/blob/master/jquery-c2.4.3.profile) as demonstrate  
![image](https://user-images.githubusercontent.com/30458572/195805856-bb7e5352-6227-42df-92da-7682511cc7c1.png)

- **5. Edit redirection rules in "chains.list"**  
`443:https:192.168.128.64:10001` means incomming from port *:443 redirect to localhost `https://192.168.128.64:10001` (C2 backend)  
  ![image](https://github.com/XiaoliChan/RedCaddy/assets/30458572/075839e8-22e2-4083-ba64-4b8c0f5969c8)

  **Q: What is "warden"?**  
  A: Warden is a whitelist function feature to protect your teamserver port, this will generate a random link with random secure strings. The user without ability connect to teamserver before trigged it ("warden" behind 443 means handling the link on port 443).

- **6. Pass arguments the generator.py needed, then hit enter.**  
`python3 generator.py -f geacon_jd_pro.profile -r forward-chains.list -c CN -vps-ip 1.1.1.1`
![image](https://github.com/XiaoliChan/RedCaddy/assets/30458572/cb573764-25f1-4962-8a43-ee365404ebba)

- **7. Finally, run caddy with caddyfile just generated :)**  
`sudo ./run.sh`
![image](https://github.com/XiaoliChan/RedCaddy/assets/30458572/2a04987f-957b-46b0-aaf5-725a2c4ea2bc)

- **8. Optional: Build the custom caddy with specific modules**  
```
git clone https://github.com/XiaoliChan/RedCaddy-core.git
cd cmd/caddy
go get github.com/aksdb/caddy-cgi/v2
go get github.com/XiaoliChan/caddy-maxmind-geolocation@self
CGO_ENABLED=0 go build
upx --best --lzma caddy
```

- **Q: Why not use json or yaml format?**  
A: Sorry, I don't know how to write caddyfile in json/yaml format.

- **Q: Can response 404 with unmatch routes?**  
A: Well, caddy can't do this ¯\\_(ツ)_/¯.

### Reference
- [Malleable C2 Profile parser](https://github.com/mgeeky/RedWarden/blob/master/plugins/malleable_redirector.py)  
- [🇬🇧 Carrying the Tortellini's golf sticks](https://aptw.tf/2021/11/25/c2-redirectors-using-caddy.html)  
- [Cobalt stagger](https://improsec.com/tech-blog/staging-cobalt-strike-with-mtls-using-caddy)  
- [How to create self-signed certificates](https://gist.github.com/cecilemuller/9492b848eb8fe46d462abeb26656c4f8)  
- [Caddy access control](https://blog.xm.mk/posts/da50/)  
