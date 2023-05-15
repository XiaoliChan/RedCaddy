#! /usr/bin/python3

import requests
import os
import random
import json
import subprocess
import uuid
import argparse

from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry

from flask import Flask, request
from multiprocessing import Process

REMOTE_HOST = os.environ['REMOTE_HOST']
EVENT_ID = os.environ['EVENT_ID']
ROUTE_PATH = str(uuid.uuid4())
EXPIRE_CHECKR = "/tmp/%s"%EVENT_ID
TOKEN = ""
VPS_IP = ""
C2WARDEN_PORT = ""
C2_PORT = ""

requests.packages.urllib3.disable_warnings() 

class flask_Server:
    app = Flask(__name__)
    def __init__(self):
        self.action = ""

    @app.route("/{}".format(ROUTE_PATH), methods=['GET'])
    def index():
        action = request.args.get("action")
        if action == "ACCEPT":
            os.system("iptables -D INPUT -s {} -p tcp --dport {} -j {} > /dev/null 2>&1".format(REMOTE_HOST, C2WARDEN_PORT, 'DROP'))
            os.system("iptables -I INPUT -s {} -p tcp -m multiport --dports {} -j {} > /dev/null 2>&1".format(REMOTE_HOST, C2_PORT, 'ACCEPT'))
            with open("C2Whitelist-data/allow-ips.lst", 'a') as f: f.write("{}\n".format(REMOTE_HOST))
            dingtalk_MSG(2)
            os.kill(os.getpid(), 9)
        else:
            with open("C2Whitelist-data/deny-ips.lst", 'a') as f: f.write("{}\n".format(REMOTE_HOST))
            dingtalk_MSG(3)
            os.kill(os.getpid(), 9)

    def run(self, port):
        self.app.run(host='0.0.0.0', port=port)
        return self.action

def get_IptablesWhitelist():
    try:
        with open('C2Whitelist-data/allow-ips.lst') as f:
            whitelist = list(set(f.read().splitlines()))
    except:
        whitelist = ['']
    return(whitelist)

def dingtalk_MSG(msg_num):
    url = "https://oapi.dingtalk.com/robot/send?access_token=%s"%TOKEN
    flask_port = random.randint(50000, 65535)
    msg_type = {
        "1":"Beacon IP: **{}** attempt to connect to C2 (Link only vaild in one minutes).<br><br>Event id: **{}**<br><br>[allow](http://{}:{}/{}?action=ACCEPT)<br><br>[reject](http://{}:{}/{}?action=DROP)".format(REMOTE_HOST, EVENT_ID, VPS_IP, flask_port, ROUTE_PATH, VPS_IP, flask_port, ROUTE_PATH),
        "2":"Allow beacon IP: **{}** connect to C2.<br><br>Event id: **{}**".format(REMOTE_HOST, EVENT_ID),
        "3":"Refused beacon IP: **{}** to connect to C2.<br><br>Event id: **{}**".format(REMOTE_HOST, EVENT_ID),
        "4":"Beacon IP: **{}** alrealy in whitelist.<br><br>Event id: **{}**".format(REMOTE_HOST, EVENT_ID),
        "5":"Link for beacon IP: **{}** expired.<br><br>Event id: **{}**".format(REMOTE_HOST, EVENT_ID)
    }

    headers = {
        'Content-Type': 'application/json'
    }
    data = {
        "msgtype": "markdown",
        "markdown": {
            "title": "CS whitelist bot",
            "text": msg_type[str(msg_num)]
        }
    }

    s = requests.Session()

    retries = Retry(total=3,
                    backoff_factor=1,
                    status_forcelist=[ 500, 502, 503, 504 ])

    s.mount('https://', HTTPAdapter(max_retries=retries))
    s.mount('http://', HTTPAdapter(max_retries=retries))


    r = s.request('POST', url=url, headers=headers, data=json.dumps(data), verify=False, timeout=10)
    r.raise_for_status()

    #requests.post(url=url, headers=headers, data=json.dumps(data), verify=False, timeout=10)
    if msg_num == 1:
        flask = flask_Server()
        server = Process(target=flask.run(flask_port))
        server.start()

if __name__ == '__main__':
    parser = argparse.ArgumentParser(add_help = True, description = "Dingtalk bot")
    parser.add_argument('-vps-ip', metavar="8.8.8.8", action='store', help='Specify vbs externa; ip.')
    parser.add_argument('-c2-port', metavar="443 or 443,8443", action='store', help='Specifyg C2 port')
    parser.add_argument('-c2warden-port', action='store', help='Spcify the port which is warden handling.')
    parser.add_argument('-bot-token', action='store', help='Specify dingtalk bot token.')
    parser.add_argument('-expire-tips', action='store_true', help='Link expire tips.')

    options = parser.parse_args()

    TOKEN = options.bot_token
    C2_PORT  = options.c2_port
    C2WARDEN_PORT = options.c2warden_port

    if options.expire_tips == True:
        dingtalk_MSG(5)
    else:
        if all([options.vps_ip, options.bot_token]):
            whitelist = get_IptablesWhitelist()
            if REMOTE_HOST not in whitelist:
                # first connection will be drop
                os.system("iptables -I INPUT -s {} -p tcp --dport 6443 -j {} > /dev/null 2>&1".format(REMOTE_HOST, 'DROP'))
                VPS_IP = options.vps_ip
                dingtalk_MSG(1)
            else:
                dingtalk_MSG(4)