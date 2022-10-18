import os
import sys
import argparse
import uuid
from colorama import Fore, Back, Style

from modules.redwarden_parser import MalleableParser
from modules.logger import logger

class caddy_Proxy:
    def __init__(self, profile, local, chains, filename, geo_country, xf):
        self.__profile = profile
        # Redirect destination, only https
        self.__local = local
        self.__chains = chains
        self.__outfile = filename
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
                db_path "./data/GeoLite2-Country.mmdb"
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
	tls ./localhost.crt ./localhost.key
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
cgi @matcher_TeamserverGuard REPLEACE_C/iptables.sh'''
                teamserver_WardenBlock = teamserver_WardenBlock.replace("REPLEACE_A",warden_Path).replace("REPLEACE_B",securityString).replace("REPLEACE_C",os.getcwd())
                proxyBlock = proxyBlock + teamserver_WardenBlock
                
                # Generate new iptables.sh
                print(Fore.YELLOW + "\r\n[+] Don't foget grant execute permission to iptables.sh")
                print(Fore.RED + "chmod 777 ./iptables.sh\r\n")
                with open("iptables-template.sh",'r') as f:
                    file = f.read()
                with open("iptables.sh",'w') as f2:
                    f2.write(file.replace("REPLEACE_HERE",chain.strip("\n").split(":")[5]))
                
                # Teamserver warden tips
                windows_CurlTips = r'''
add-type @"
    using System.Net;
    using System.Security.Cryptography.X509Certificates;
    public class TrustAllCertsPolicy : ICertificatePolicy {
        public bool CheckValidationResult(
            ServicePoint srvPoint, X509Certificate certificate,
            WebRequest request, int certificateProblem) {
            return true;
        }
    }
"@
[System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy

$headers = @{
    "user-agent" = 'SecurityString'
    "Accept-SecurityString"  = 'REPLEACE_B'      
}
Invoke-WebRequest https://[REPLEACE_TO_YOUR_VPS_IP]:REPLEACE_A/REPLEACE_C -Headers $headers            
'''
                print(Fore.RED + "[!] Execute this command on your vps server")
                print(Fore.YELLOW + "sudo iptables -I INPUT -p tcp --dport %s -j DROP"%chain.strip("\n").split(":")[5])
                print(Fore.GREEN + "\r\n[1] Add whitelist ip into teamserver port warden (for linux client -- bash)")
                print(Fore.YELLOW + 'curl https://[REPLEACE_TO_YOUR_VPS_IP]:%s/%s -H "user-agent: SecurityString" -H "Accept-SecurityString: %s" -k -vvv '%(chain.strip("\n").split(":")[0], warden_Path, securityString))
                print(Fore.GREEN + "\r\n[2] Add whitelist ip into teamserver port warden (for windows client -- powershell)")
                print("-"*120 + Fore.YELLOW + windows_CurlTips.replace("REPLEACE_A",chain.strip("\n").split(":")[0]).replace("REPLEACE_B",securityString).replace("REPLEACE_C",warden_Path) + Fore.GREEN + "-"*120 + Style.RESET_ALL)

        except:
            pass
        
        final = tag + template_Header + proxyBlock + template_End + handle_Block
        return final

    def generate_Caddyfile(self, full_Block):
        caddyguard_Header = r'''{
        debug
        log
        order tls last
        auto_https off
        order cgi last
    }

    (basic-security) {
        header {
		Server "Apache/2.4.50 (Unix) OpenSSL/1.1.1d"
		X-Robots-Tag "noindex, nofollow, nosnippet, noarchive"
		X-Content-Type-Options "nosniff"
		Permissions-Policy interest-cohort=()
		Strict-Transport-Security max-age=31536000;
		X-Content-Type-Options nosniff
		X-Frame-Options DENY
		Referrer-Policy no-referrer-when-downgrade
		Cache-Control no-cache
		X-Powered-By
		X-Page-Speed
		X-Varnish
        }
    }

    (basic-blacklist) {
        @ua_denylist {
            import ./data/bad-user-agents.caddy
        }

        @ip_denylist {
            import ./data/bad-ips.caddy
        }

        # UA blacklist
        route @ua_denylist {
            abort
        }

        # IP blacklist
        route @ip_denylist {
            abort
        }
    }

    '''
    
        with open(self.__outfile,'w+') as f:
            f.write(caddyguard_Header + full_Block)

    def tips(self,chains):
        print(Fore.GREEN + "[+] Formating caddyfile")
        os.system("cat %s | ./caddy fmt --overwrite"%self.__outfile)
        print(Fore.RED + "[!] Use iptables rules to drop C2 backend port traffic and make sure it only allow incomming traffic with upstream address")
        for i in chains:
            print(Fore.YELLOW + "sudo iptables -I INPUT -p tcp --dport %s -j DROP"%(i.strip("\n").split(":")[3]))
            print("sudo iptables -I INPUT -s %s  -p tcp --dport %s -j ACCEPT"%(self.__local, i.strip("\n").split(":")[3]))
        print(Fore.RED + "\r\n[!] Run caddy with profile")
        print(Fore.YELLOW + "sudo ./caddy run --config %s --adapter caddyfile"%self.__outfile)
        print("\r\n[!] Reload caddy with profile")
        print("sudo ./caddy reload --config %s --adapter caddyfile"%self.__outfile + Style.RESET_ALL)

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
    parser.add_argument('-o', '-out', metavar="filename" ,action='store', help='Filename you want to save as')
    
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
    if options.o == None:
        logger.err("[-] Please output output destination")
        sys.exit(1)

    executer = caddy_Proxy(options.f, options.l, options.r, options.o, options.c, options.xf)
    executer.wrapper()