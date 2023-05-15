import uuid
import os
from colorama import Fore, Back, Style

class warden():
    def __init__(self, vps_ip):
        self.vps_ip = vps_ip
    
    def C2Whitelist_block(self, chain, ipatbles_ports, bot_token):
        warden_Path = uuid.uuid4().hex
        securityString = uuid.uuid4().hex
        C2Whitelist_WardenBlock = r'''
@matcher_C2Whitelist_Warden {
path /REPLACE_A
method GET
header "user-agent" "SecurityString"
header "Accept-SecurityString" "REPLACE_B"
}
cgi @matcher_C2Whitelist_Warden ./C2Whitelist-Warden.sh'''
        C2Whitelist_WardenBlock = C2Whitelist_WardenBlock.replace("REPLACE_A",warden_Path).replace("REPLACE_B",securityString)
        with open('./lib/template/C2Whitelist-Warden.sh', 'r') as f : file = f.read()
        with open('./core/C2Whitelist-Warden.sh', 'w') as f2: f2.write(file.replace('REPLACE_WITH_BOT_TOKEN', bot_token).replace('REPLACE_TO_VPS_IP', self.vps_ip).replace('REPLACE_TO_IPTABLES_PORTS', ipatbles_ports).replace("REPLACE_TO_WARDEN_PORT", chain.strip("\n").split(":")[0]))

        return C2Whitelist_WardenBlock

    def teamserverPort_Warden(self, chain, proxyBlock, whitelist_Mode = False):
            print(Fore.YELLOW + "[+] Teamserver warden handle on port %s"%chain.strip("\n").split(":")[0])
            warden_Path = uuid.uuid4().hex
            securityString = uuid.uuid4().hex
            teamserver_WardenBlock = r'''
@matcher_teamserverPort_Warden {
    path /REPLACE_A
    method GET
    header "user-agent" "SecurityString"
    header "Accept-SecurityString" "REPLACE_B"
}
cgi @matcher_teamserverPort_Warden ./teamserverPort-Warden.sh'''
            teamserver_WardenBlock = teamserver_WardenBlock.replace("REPLACE_A",warden_Path).replace("REPLACE_B",securityString)
            proxyBlock = proxyBlock + teamserver_WardenBlock
            
            # Generate new teamserverPort-Warden.sh
            with open("./lib/template/teamserverPort-Warden-template.sh",'r') as f: file = f.read()

            if whitelist_Mode == False:
                with open("./core/teamserverPort-Warden.sh",'w') as f2: f2.write(file.replace("REPLACE_HERE", chain.strip("\n").split(":")[5]))
            else:
                with open("./core/teamserverPort-Warden.sh",'w') as f2: f2.write(file.replace("REPLACE_HERE", chain.strip("\n").split(":")[3]))
            
            # Teamserver warden tips

            # REPLACE_A = Warden port
            # REPLACE_B = Security path
            # REPLACE_C = Security strings

            if os.path.exists('teamserver-guard') == False: os.makedirs('teamserver-guard', exist_ok=True)

            with open('./lib/template/teamserver-guard-Win.ps1', 'r') as f: windows_CurlTips = f.read()

            with open('./teamserver-guard/teamserver-guard-Win.ps1', 'w') as f:
                f.write(windows_CurlTips.replace("REPLACE_TO_VPS_IP", self.vps_ip).replace("REPLACE_PORT",chain.strip("\n").split(":")[0]).replace("REPLACE_SECURITY_STRINGS",securityString).replace("REPLACE_WARDEN_PATH",warden_Path))
            
            with open('./lib/template/teamserver-guard-Linux.sh', 'r') as f: Linux_CurlTips = f.read()

            with open('./teamserver-guard/teamserver-guard-Linux.sh', 'w') as f:
                f.write(Linux_CurlTips.replace("REPLACE_TO_VPS_IP", self.vps_ip).replace("REPLACE_PORT",chain.strip("\n").split(":")[0]).replace("REPLACE_SECURITY_STRINGS",securityString).replace("REPLACE_WARDEN_PATH",warden_Path))
            
            with open('run.sh', 'w') as run_Script:
                if whitelist_Mode == False:
                    run_Script.write("cd ./core\nchmod 777 ./teamserverPort-Warden.sh\nsudo iptables -I INPUT -p tcp --dport %s -j DROP"%chain.strip("\n").split(":")[5])
                else:
                    run_Script.write("cd ./core\ncp ../lib/utils/C2Whitelist-Dingtalk.py .\nchmod 777 ./C2Whitelist-Warden.sh\nchmod 777 ./teamserverPort-Warden.sh\nsudo iptables -I INPUT -p tcp --dport %s -j DROP"%chain.strip("\n").split(":")[3])

            print(Fore.GREEN + "\r\n[+] Teamserver port warden scripts generated in: ./teamserver-guard")

            return proxyBlock
    
