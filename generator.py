import os
import sys
import argparse

from lib.modules.warden import warden
from lib.modules.redwarden_parser import MalleableParser
from lib.modules.logger import logger
from colorama import Fore

class caddy_Proxy:
    def __init__(self, profile, chains, geo_country, xf, options):
        self.__profile = profile
        # Redirect destination, only https
        self.__chains = chains
        self.__outfile = "./core/Caddyfile"
        self.__country = geo_country
        self.__xf_switch = xf
        self.vps_ip = options.vps_ip
        self.whitelist_Mode = False
        self.invoke_Method = warden(self.vps_ip)

        if options.mode == "whitelist":
            self.bot_token = options.bot_token
            self.whitelist_Mode = True

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

        # Redirect chains
        full_Block = ""
        with open(self.__chains,'r') as f:
            chains = f.readlines()

        # for white list mode:
        for i in chains:
            if "warden" in i:
                if i.strip("\n").split(":").index("warden") == 4:
                    print("[+] Blacklist mode detection")
                    iptables_Ports = self.iptables_Ports(chains)
                elif i.strip("\n").split(":").index("warden") == 2:
                    print("[+] whitelist mode detection.")
                    iptables_Ports, iptables_Ports_ = self.iptables_Ports(chains, True)

        for chain in chains:
            # For whitelist mode
            warden_Block = ""
            if chain.strip("\n").split(":")[2] == "warden":
                #invoke_Method = warden(chain, proxyBlock, self.vps_ip)
                proxyBlock = self.invoke_Method.C2Whitelist_block(chain, iptables_Ports_, self.bot_token)
                proxyBlock_Warden = self.invoke_Method.teamserverPort_Warden(chain, proxyBlock, self.whitelist_Mode)
                warden_Block = self.generate_HanldeBlock(chain, proxyBlock_Warden)
            else:
                c2_backend = "{}://{}:{}".format(chain.strip("\n").split(":")[1], chain.strip("\n").split(":")[2], chain.strip("\n").split(":")[3])
                print(Fore.GREEN + "[+] Determine redirect chain, incomming from port: {} redirect to {}://{}:{}".format(chain.strip("\n").split(":")[0], chain.strip("\n").split(":")[1], chain.strip("\n").split(":")[2], chain.strip("\n").split(":")[3]))

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
            full_Block += warden_Block

        if self.__country != None:
            geoip_Block = r'''
(GEOFILTER) {
    @geofilter {
        not maxmind_geolocation {
                db_path "../lib/data/GeoLite2-Country.mmdb"
                allow_countries REPLACE_ME
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
 
'''.replace("REPLACE_ME",self.__country)
            full_Block = geoip_Block + full_Block
        self.generate_Caddyfile(full_Block)
        self.tips(chains, iptables_Ports)
        
    def generate_ReverseProxy(self, uri, user_agent, headers, method, select, variant, c2_backend):
        matcher_Name = "@matcher_%s "%(select + "_" + variant + "_" + str(c2_backend.split(":")[2]))
        reverse_proxy_Partly = r''' {
        # Enable this when using serverless cloud function, like tencent scf, aliyun scf.
        #cdn header_up X-Forwarded-For {http.request.header.X-Forwarded-For}

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
            reverse_proxy_Partly = reverse_proxy_Partly.replace(r"#cdn ",'')
        else:
            reverse_proxy_Partly = reverse_proxy_Partly.replace(r"#noscf ",'')

        reverse_proxy = "reverse_proxy " + matcher_Name + '\"%s\"'%c2_backend + reverse_proxy_Partly

        full = matcher_Full + "\r\n" + reverse_proxy + "\r\n"
        return full

    def generate_HanldeBlock(self, chain, proxyBlock):
        tag = "(caddy-guard-%s)"%str(chain.strip("\n").split(":")[0])
        template_Header = r''' {
	# For old windows version support, like: win7
	#SSL tls ./cert-out/localhost.crt ./cert-out/localhost.key {
	#SSL 	ciphers TLS_RSA_WITH_AES_128_CBC_SHA TLS_RSA_WITH_AES_256_CBC_SHA TLS_RSA_WITH_AES_128_GCM_SHA256 TLS_RSA_WITH_AES_256_GCM_SHA384 TLS_AES_128_GCM_SHA256 TLS_AES_256_GCM_SHA384 TLS_CHACHA20_POLY1305_SHA256 TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
    #SSL}
	import basic-security
	handle /* {
		import basic-blacklist
		# GEO_IMPORT
'''
        template_End = r'''
	}
}
'''
        if chain.strip("\n").split(":")[1] == "https":
            template_Header = template_Header.replace('#SSL', '')
        
        if self.__country != None:
            template_Header = template_Header.replace(r"# GEO_IMPORT","import GEOFILTER")
        
        basic_Listen = ":%s "%chain.strip("\n").split(":")[0]
        
        handle_Block = basic_Listen + "{ import %s }\r\n"%tag.replace("(",'').replace(")",'')

        # For TeamServer port warden
        # In whitelist mode, it should handle in a new port.
        if len(chain.strip("\n").split(":")) == 6 and "warden" in chain.strip("\n").split(":")[4]:
            proxyBlock = self.invoke_Method.teamserverPort_Warden(chain, proxyBlock)
        
        final = tag + template_Header + proxyBlock + template_End + handle_Block
        return final

    def generate_Caddyfile(self, full_Block):
        with open('./lib/template/caddyfile-header', 'r') as f: caddyguard_Header = f.read()
        with open(self.__outfile,'w+') as f: f.write(caddyguard_Header + full_Block)

    def iptables_Ports(self, chains, whitelist=False):
        iptables_Ports = ""
        iptables_Ports_ = ""
        if whitelist == False:
            for i in chains:
                iptables_Ports += (i.strip("\n").split(":")[3]) + ","
            iptables_Ports = iptables_Ports.rstrip(',')
            return iptables_Ports
        else:
            for i in chains:
                if i.strip("\n").split(":")[2] == "warden":
                    pass
                else:
                    iptables_Ports += (i.strip("\n").split(":")[3]) + ","
                    iptables_Ports += (i.strip("\n").split(":")[0]) + ","
                    # Without c2 backend port
                    iptables_Ports_ += (i.strip("\n").split(":")[0]) + ","
            iptables_Ports = iptables_Ports.rstrip(',')
            iptables_Ports_ = iptables_Ports_.rstrip(',')
            return iptables_Ports, iptables_Ports_

    def tips(self, chains, iptables_Ports):
        print(Fore.GREEN + "[+] Formating caddyfile")
        os.system("./core/caddy fmt --overwrite %s"%self.__outfile)
        iptables = open("run.sh", 'a')
        if self.whitelist_Mode == False:
            iptables.write("\nsudo iptables -I INPUT -p tcp -m multiport --dports %s -j DROP" %iptables_Ports)
            # for difference backen c2 hosts, like 192.168.1.1:443 forward to 192.168.1.2:10001
            for i in chains:
                iptables.write("\nsudo iptables -I INPUT -s %s -p tcp --dport %s -j ACCEPT"%(i.strip("\n").split(":")[2], i.strip("\n").split(":")[3]))
        else:
            iptables.write("\nsudo iptables -I INPUT -p tcp -m multiport --dports %s -j DROP" %iptables_Ports)
            for i in chains:
                if i.strip("\n").split(":")[2] == "warden":
                    pass
                else:
                    iptables.write("\nsudo iptables -I INPUT -s %s -p tcp --dport %s -j ACCEPT"%(i.strip("\n").split(":")[2], i.strip("\n").split(":")[3]))
        iptables.write("\nsudo ./caddy run --config Caddyfile --adapter caddyfile")
        iptables.close()
        os.chmod('./run.sh', 0o0777)
        print(Fore.RED + "\r\n[!] Run redcaddy with: ./run.sh")

if __name__ == '__main__':
    parser = argparse.ArgumentParser(add_help = True, description = "Generate C2 redirection config file which is base on caddy.")
    parser.add_argument('-f','-profile', metavar="c2.profile" ,action='store', help='Specify C2 malleable profile')
    parser.add_argument('-r','-redir-chain', metavar="file" ,action='store', help='Redirect chain files, format: [caddy-port]:[https]:[C2 Host]:[C2 Port] '
                        'E.g.: "443:https:127.0.0.1:8443:warden:50050"')
    parser.add_argument('-c', '-allow-country', metavar="CN" ,action='store', help='Whitelist IP with country (detect with GEOIP database) '
                        'For multiple country please separated by a single space, Like: CN US')
    parser.add_argument('-xf', action='store_true', help='Using x-forwarded-for header ip address as remote ip'
                        ',the source request must include x-forwarded-for header')
    parser.add_argument('-vps-ip', action='store', metavar="8.8.8.8", help='Specify VPS external IP addr.')

    subparsers = parser.add_subparsers(dest='mode', help='Experimental mode')

    whitelistMode_parser = subparsers.add_parser('whitelist', help='whitelist mode. (default is blacklist mode)')
    whitelistMode_parser.add_argument('-bot-token', action='store', help='DingTalk bot token')

    
    if len(sys.argv)==1:
        parser.print_help()
        sys.exit(1)

    options = parser.parse_args()

    if options.f == None:
        logger.err("[-] Please specify C2 malleable profile")
        sys.exit(1)
    if options.r == None:
        logger.err("[-] Please specify redirect chain file")
        sys.exit(1)
        
    executer = caddy_Proxy(options.f, options.r, options.c, options.xf, options)
    executer.wrapper()