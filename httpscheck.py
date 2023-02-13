#!/usr/bin/python3
# Retrieving SSH host key and verifying SSH host key using Paramiko

import paramiko
import hashlib
import base64
import subprocess
import json
import sys
sys.path.append("/usr/local/src/security/lib/")
from db_functions import read_ip_open_port_v4,write_into_ip_service_https
import requests
from selenium import webdriver
from selenium.webdriver import FirefoxOptions
import time

def get_screenshot(host,destport):
#driver = webdriver.PhantomJS()
  opts = FirefoxOptions()
  opts.add_argument("--headless")
  driver = webdriver.Firefox(options=opts)
  driver.set_window_size(1120, 550)
  driver.get("https://"+host+":"+destport+"/")
  time.sleep(3)
  driver.get_screenshot_as_file("/usr/local/src/security/display/static/https-screenshots/"+host+"-"+destport+".png")
  driver.quit()


def httpsgetrequest(host,destport):
    uri = "https://"+host+":"+destport
    print(uri)
    try:
        response = requests.get(uri, timeout=1, verify=False)
        print(response)
    except:
        print("false")
        response = "false"
    return(response)

if __name__ == '__main__':
    open_ports = read_ip_open_port_v4()
    for x in open_ports:
        host = str(x['ip4'])
        port = str(x['port'])
        raw = httpsgetrequest(host,port)
        if raw != "false":
            #print(raw.headers)
            #print(raw.content)
            headers = str(raw.headers)
            headers_bytes = headers.encode('ascii')
            base64_headers_bytes = base64.b64encode(headers_bytes)
            content = str(raw.content)
            content_bytes = content.encode('ascii')
            base64_content_bytes = base64.b64encode(content_bytes)
            #print(base64_headers_bytes)
            b64content = str(base64_content_bytes)[1:]
            b64headers = str(base64_headers_bytes)[1:]
            #print(b64content)
            try:
                get_screenshot(host,port)
            except:
                print("screenshot did not work")
            write_into_ip_service_https(host,port,b64headers,b64content)
