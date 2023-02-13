#!/usr/bin/python3
# Retrieving SSH host key and verifying SSH host key using Paramiko

import paramiko
import hashlib
import base64
import subprocess
import json
import sys
sys.path.append("/usr/local/src/security/lib/")
from db_functions import read_ip_open_port_v4,write_into_ip_service_ssh

class VerifyHostKeyPolicy(paramiko.client.MissingHostKeyPolicy):
    def __init__(self, hostkey):
        self.hostkey = hostkey
    def missing_host_key(self, client, hostname, key):
        if key.get_base64() != self.hostkey.getBase64Key():
            raise paramiko.ssh_exception.SSHException("Invalid Host Key Fingerprint")

def retrieveSSHInfo(host,destport):
    
    try:
        command = ['/usr/local/bin/ssh-audit', host, '-p', destport, '-j']
        result = subprocess.run(command, capture_output=True, universal_newlines=True).stdout
        jsonraw = json.loads(result)
        #print(jsonraw)
        banner = jsonraw['banner']
        raw = banner['raw']
    except:
        print("IP:"+host+"  Port:"+destport+" is nto a SSH service")
        raw = "false"
    #try:
    #    client.connect(host, port=destport)
    #except:
    #    pass
    #version = client.get_transport().get_security_options()
    #client.close()
    return(raw)

def connectWithHostKey(host, user, password, hostkey, destport):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(VerifyHostKeyPolicy(HostKeyInfo(hostkey)))
    client.connect(host, port=destport, username=user, password=password)
    return client

if __name__ == '__main__':
    open_ports = read_ip_open_port_v4()
    for x in open_ports:
        host = str(x['ip4'])
        port = str(x['port'])
        version = retrieveSSHInfo(host,port)
        if version != "false":
            write_into_ip_service_ssh(host,port,version)
