# SuperFastPython.com
# scan a range of port numbers on a host concurrently
from socket import AF_INET
from socket import SOCK_STREAM
from socket import socket
from concurrent.futures import ThreadPoolExecutor
 
# returns True if a connection can be made, False otherwise
def test_port_number(host, port):
    # create and configure the socket
    with socket(AF_INET, SOCK_STREAM) as sock:
        # set a timeout of a few seconds
        sock.settimeout(3)
        # connecting may fail
        try:
            # attempt to connect
            sock.connect((host, port))
            # a successful connection was made
            #print(host+port)
            return True
        except:
            # ignore the failure
            return False
 
# scan port numbers on a host
def port_scan(host, ports):
    print(ports)
    print(f'Scanning {host}...')
    # create the thread pool
    with ThreadPoolExecutor(len(ports)) as executor:
        # dispatch all tasks
        results = executor.map(test_port_number, [host]*len(ports), ports)
        # report results in order
        for port,is_open in zip(ports,results):
            if is_open:
                print(f'> {host}:{port} open')
 
# define host and port numbers to scan
HOST = '192.168.1.1'
PORTS = range(1024)
# test the ports
port_scan(HOST, PORTS)
