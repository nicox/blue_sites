#!/usr/bin/python3
import sys
sys.path.append("/usr/local/src/security/lib/")
from db_functions import read_ip_open_port_v4,write_into_ip_service_ftp
import time
from ftplib import FTP

#hostname = '194.232.72.14'
#ftpObject = FTP("")

def ftp_request(host,destport):
    ftpObject = FTP("")
    print(host+destport)
    try:
        ftpResponse = ftpObject.connect(host, int(destport), timeout=2)
        ftp_response = ftpResponse
    except:
        ftp_response = "false"
    try:
        ftpResponse = ftpObject.login(user="anonymous")
        ftp_message_login = ftpObject.getwelcome()
    except:
        ftp_message_login = "false"
    return(ftp_response,ftp_message_login)

if __name__ == '__main__':
    open_ports = read_ip_open_port_v4()
    for x in open_ports:
        host = str(x['ip4'])
        port = str(x['port'])
        #print(host+port)
        raw = ftp_request(host,port)
        #print(raw[0])
        if raw[0] != "false":
            #print(raw[0])
            #print(raw.content)
            #headers = str(raw.headers)
            #headers_bytes = headers.encode('ascii')
            #base64_headers_bytes = base64.b64encode(headers_bytes)
            #content = str(raw.content)
            #content_bytes = content.encode('ascii')
            #base64_content_bytes = base64.b64encode(content_bytes)
            #print(base64_headers_bytes)
            #b64content = str(base64_content_bytes)[1:]
            #b64headers = str(base64_content_bytes)[1:]
            #print(b64content)
            #get_screenshot(host,port)
            write_into_ip_service_ftp(host,port,raw[0],raw[1])
