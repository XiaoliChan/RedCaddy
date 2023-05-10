import os
import sys
import argparse
import uuid
from colorama import Fore, Back, Style

from lib.modules.redwarden_parser import MalleableParser
from lib.modules.logger import logger

class caddy_Proxy:
    def __init__(self, profile, local, chains, geo_country, xf):
        self.__profile = profile
        # Redirect destination, only https
        self.__local = local
        self.__chains = chains
        self.__outfile = "Caddyfile"
        self.__country = geo_country
        self.__xf_switch = xf

    def wrapper(self):
        # Load module and profile
        test_Parser = MalleableParser(logger)
        loaded = test_Parser.parse(self.__profile)

        # UA
        user_agent = test_Parser.config['useragent']

        # Staging detection
        staging = test_Parser.config['host_stage']
        selection = ['http-get','http-post','http-stager']
        if staging == 'false':
            print("[+] Stageless")
            selection.remove('http-stager')

        # Grab headers & uri path & reuqest method
        full_Block = ""
        host_ListFinal = []
        host_List = []
        
        # Redirect chains
        with open(self.__chains,'r') as f:
            chains = f.readlines()
        for chain in chains:
            c2_backend = chain.strip("\n").split(":")[1] + "://" + chain.strip("\n").split(":")[2] + ":" + chain.strip("\n").split(":")[3]
            print(Fore.GREEN + "[+] Determine redirect chain, incomming from port: %s redirect to %s:%s"%(chain.strip("\n").split(":")[0], chain.strip("\n").split(":")[2], chain.strip("\n").split(":")[3]))

            # Generate reverse proxy blocks
            tmp_Block = ""
            for select in selection:
                for variant in test_Parser.config[select].keys():
                    try:
                        uri = ''
                        method = ''
                        if select == 'http-stager':
                            # Stager is only supported GET request
                            uri = test_Parser.config['http-stager'][variant]['uri_x86'] + test_Parser.config['http-stager'][variant]['uri_x64']
                            method = "GET"
                        else:
                            uri = test_Parser.config[select][variant]['uri']
                            method = test_Parser.config[select][variant]['verb']
                        headers = test_Parser.config[select][variant]['client']['header']
                        caddy_Block = self.generate_ReverseProxy(uri, user_agent, headers, method, select, variant, c2_backend)
                        tmp_Block = tmp_Block + "\r\n\r\n" + caddy_Block
                    except:
                        pass

            full_Block += self.generate_HanldeBlock(chain, tmp_Block)

        if self.__country != None:
            geoip_Block = r'''
(GEOFILTER) {
    @geofilter {
        not maxmind_geolocation {
                db_path "./lib/data/GeoLite2-Country.mmdb"
                allow_countries REPLEACE_ME
        }
        not remote_ip 10.0.0.0/8
        not remote_ip 172.16.0.0/12
        not remote_ip 192.168.0.0/16
    }
    route @geofilter
    {
        abort
    }
}
 
'''.replace("REPLEACE_ME",self.__country)
            full_Block = geoip_Block + full_Block
        
        self.generate_Caddyfile(full_Block)
        self.tips(chains)
        

    def generate_ReverseProxy(self, uri, user_agent, headers, method, select, variant, c2_backend):
        host_Header = ""
        matcher_Name = "@matcher_%s "%(select + "_" + variant + "_" + str(c2_backend.split(":")[2]))
        reverse_proxy_Partly = r''' {
        # Enable this when using serverless cloud function, like tencent scf, aliyun scf.
        #scf header_up X-Forwarded-For {http.request.header.X-Forwarded-For}

        # Enable this when using VPS directly.
        #noscf header_up X-Forwarded-For {remote_host}

        header_up Host {http.reverse_proxy.upstream.hostport}
            transport http {
                tls
                tls_insecure_skip_verify
            }
    }'''
        method = "method " + method
        format_URI = "path"

        # Add user agent first
        format_Headers = 'header \"user-agent\" \"%s\"'%user_agent + "\r\n\t"
        for i in uri:
            format_URI = format_URI + " " + i
        for i in headers:
            format_Headers = format_Headers + "header" + ' \"%s\"'%i[0] + ' \"%s\"'%i[1] + "\r\n\t"
        
        matcher_tmp = "{" + "\r\n\t" + format_URI + "\r\n\t" + method + "\r\n\t" + format_Headers.strip("\t") + "}"
        matcher_Full = matcher_Name + matcher_tmp

        if self.__xf_switch == True:
            print("[+] SCF feature: Selecting x-forwarded-for header ip as source ip addr")
            reverse_proxy_Partly = reverse_proxy_Partly.replace(r"#scf ",'')
        else:
            reverse_proxy_Partly = reverse_proxy_Partly.replace(r"#noscf ",'')

        reverse_proxy = "reverse_proxy " + matcher_Name + '\"%s\"'%c2_backend + reverse_proxy_Partly

        full = matcher_Full + "\r\n" + reverse_proxy + "\r\n"
        return full

    def generate_HanldeBlock(self, chain, proxyBlock):
        tag = "(caddy-guard-%s)"%str(chain.strip("\n").split(":")[3])
        template_Header = r''' {
	# For old windows version support, like: win7
	tls ./cert-out/localhost.crt ./cert-out/localhost.key {
		ciphers TLS_RSA_WITH_AES_128_CBC_SHA TLS_RSA_WITH_AES_256_CBC_SHA TLS_RSA_WITH_AES_128_GCM_SHA256 TLS_RSA_WITH_AES_256_GCM_SHA384 TLS_AES_128_GCM_SHA256 TLS_AES_256_GCM_SHA384 TLS_CHACHA20_POLY1305_SHA256 TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
    }
	import basic-security
	handle /* {
		import basic-blacklist
		# GEO_IMPORT
'''
        template_End = r'''
	}
}
'''
        if self.__country != None:
            template_Header = template_Header.replace(r"# GEO_IMPORT","import GEOFILTER")
        
        basic_Listen = ":%s "%chain.strip("\n").split(":")[0]
        
        handle_Block = basic_Listen + "{ import %s }\r\n"%tag.replace("(",'').replace(")",'')

        # For TeamServer port warden
        try:
            if chain.strip("\n").split(":")[4] == "warden":
                print(Fore.YELLOW + "[+] Teamserver warden handle on port %s"%chain.strip("\n").split(":")[0])
                warden_Path = uuid.uuid4().hex
                securityString = uuid.uuid4().hex
                teamserver_WardenBlock = r'''
@matcher_TeamserverGuard {
    path /REPLEACE_A
    method GET
    header "user-agent" "SecurityString"
    header "Accept-SecurityString" "REPLEACE_B"
}
cgi @matcher_TeamserverGuard ./lib/run/iptables.sh'''
                teamserver_WardenBlock = teamserver_WardenBlock.replace("REPLEACE_A",warden_Path).replace("REPLEACE_B",securityString)
                proxyBlock = proxyBlock + teamserver_WardenBlock
                
                # Generate new iptables.sh
                with open("./lib/template/iptables-template.sh",'r') as f: file = f.read()
                
                if os.path.exists('./lib/run') == False: os.makedirs('./lib/run', exist_ok=True)

                with open("./lib/run/iptables.sh",'w') as f2: f2.write(file.replace("REPLEACE_HERE",chain.strip("\n").split(":")[5]))
                
                # Teamserver warden tips

                if os.path.exists('teamserver-guard') == False: os.makedirs('teamserver-guard', exist_ok=True)

                with open('./lib/template/teamserver-guard-Win.ps1', 'r') as f: windows_CurlTips = f.read()

                with open('./teamserver-guard/teamserver-guard-Win.ps1', 'w') as f:
                    f.write(windows_CurlTips.replace("REPLEACE_A",chain.strip("\n").split(":")[0]).replace("REPLEACE_B",securityString).replace("REPLEACE_C",warden_Path))
                
                linux_Script = 'curl https://[REPLEACE_TO_YOUR_VPS_IP]:%s/%s -H "user-agent: SecurityString" -H "Accept-SecurityString: %s" -k'%(chain.strip("\n").split(":")[0], warden_Path, securityString)

                with open('./teamserver-guard/teamserver-guard-Linux.sh', 'w') as f: f.write(linux_Script)

                with open('run.sh', 'w') as run_Script: run_Script.write("chmod 777 ./lib/run/iptables.sh\nsudo iptables -I INPUT -p tcp --dport %s -j DROP"%chain.strip("\n").split(":")[5])
                #print(Fore.YELLOW + "sudo iptables -I INPUT -p tcp --dport %s -j DROP"%chain.strip("\n").split(":")[5])
                print(Fore.GREEN + "\r\n[+] Add whitelist ip into teamserver port warden scripts in: ./teamserver-guard")

        except:
            pass
        
        final = tag + template_Header + proxyBlock + template_End + handle_Block
        return final

    def generate_Caddyfile(self, full_Block):
        with open('./lib/template/caddyfile-header', 'r') as f: caddyguard_Header = f.read()
    
        with open(self.__outfile,'w+') as f: f.write(caddyguard_Header + full_Block)

    def tips(self, chains):
        print(Fore.GREEN + "[+] Formating caddyfile")
        os.system("cat %s | ./caddy fmt --overwrite"%self.__outfile)
        iptables = open("run.sh", 'a')
        for i in chains:
            iptables.write("\nsudo iptables -I INPUT -p tcp --dport %s -j DROP"%(i.strip("\n").split(":")[3]))
            iptables.write("\nsudo iptables -I INPUT -s %s -p tcp --dport %s -j ACCEPT"%(self.__local, i.strip("\n").split(":")[3]))
        iptables.write("\nsudo ./caddy run --config %s --adapter caddyfile"%self.__outfile)
        iptables.close()
        os.chmod('./run.sh', 0o0777)
        print(Fore.RED + "\r\n[!] Run redcaddy with: ./run.sh")

if __name__ == '__main__':
    parser = argparse.ArgumentParser(add_help = True, description = "Generate C2 redirection config file which is base on caddy.")
    parser.add_argument('-f','-profile', metavar="c2.profile" ,action='store', help='Specify C2 malleable profile')
    parser.add_argument('-l', '-local-ip', metavar="192.168.85.100" ,action='store', help='Specify machine local ip address')
    parser.add_argument('-r','-redir-chain', metavar="file" ,action='store', help='Redirect chain files, format: [caddy-port]:[https]:[C2 Host]:[C2 Port] '
                        'E.g.: "443:https:127.0.0.1:8443:warden:50050"')
    parser.add_argument('-c', '-allow-country', metavar="CN" ,action='store', help='Whitelist IP with country (detect with GEOIP database) '
                        'For multiple country please separated by a single space, Like: CN US')
    parser.add_argument('-xf', action='store_true', help='Using x-forwarded-for header ip address as remote ip'
                        ',the source request must include x-forwarded-for header')
    
    if len(sys.argv)==1:
        parser.print_help()
        sys.exit(1)

    options = parser.parse_args()

    if options.f == None:
        logger.err("[-] Please specify C2 malleable profile")
        sys.exit(1)
    if options.l == None:
        logger.err("[-] Please specify machine local ip address")
        sys.exit(1)
    if options.r == None:
        logger.err("[-] Please specify port")
        sys.exit(1)

    executer = caddy_Proxy(options.f, options.l, options.r, options.c, options.xf)
    executer.wrapper()