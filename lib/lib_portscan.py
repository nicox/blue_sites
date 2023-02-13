from socket import AF_INET
from socket import SOCK_STREAM
from socket import socket
import pyfiglet
import sys
sys.path.append("/usr/local/src/security/lib/")
from db_functions import write_into_ip_open_port_v4
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor

def test_port_number(host,port):
    #host = "192.168.1.1"
    # create and configure the socket
    with socket(AF_INET, SOCK_STREAM) as sock:
        # set a timeout of a few seconds
        sock.settimeout(1)
        # connecting may fail
        try:
            # attempt to connect
            #print(host+port)
            sock.connect((host, port))
            # a successful connection was made
            return True
        except:
            # ignore the failure
            return False


def fast_portscan(hosts, port):
    #print(ports)
    #host = "192.168.1.2"
    #ports = range(100)
    print(port)
    #print(f'Scanning {host}...')
    ports = []
    for x in range(len(hosts)):
        ports.append(port)
    #print(hosts)
    #print(ports)
    # create the thread pool
    with ThreadPoolExecutor(500) as executor:
        # dispatch all tasks
        results = executor.map(test_port_number, hosts, ports, timeout=1000)
        # report results in order
        #print(results)
        for host,is_open in zip(hosts,results):
            #print(portresult)
            #print(is_open)
            if is_open:
                #print(host)
                #print(is_open)
                #print(port)
                write_into_ip_open_port_v4(host,port)
                print(f'> {host}:{port} open')


def portscan(iplist):
  targets = []
  for ip in iplist:
      targets.append(ip['ip4'])
  #print(targets)
  try:
    for port in range(1,65535):
      #print(port)
      # returns an error indicator
      #for target in targets:
      fast_portscan(targets, port)
        #print(target)
        #s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        #socket.setdefaulttimeout(1)
        #s.settimeout(0.2)
        #result = s.connect_ex((target,port))
#        if result ==0:
          #write_into_ip_open_port_v4(target,port)
          #print("Port {} is open at {}".format(port,target))
#        s.close()
  except:
    print("something wrong")
		
