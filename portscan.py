#!/usr/bin/python3

import sys
sys.path.append("/usr/local/src/security/lib/")
from lib_portscan import portscan
from db_functions import read_ip_v4net

#iplist = ["192.168.1.2","192.168.1.1"]
#portscan(iplist)
iplist = read_ip_v4net()
portscan(iplist)
#for row in iplist:
    
#    print(row['ip4'])
