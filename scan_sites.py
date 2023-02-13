#!/usr/bin/python3

import sys
sys.path.append("/usr/local/src/security/lib/")
from ssllabs_handling import extractDomain
from lib_scan_sites import new_sites_check_scan,get_header
from db_functions import write_intossllabs_check,get_siteids,get_siteids_rowcount
from init_db_conn import get_db_connection



try:
    connection = get_db_connection()
    new_sites_check_scan()
    siteids = get_siteids()
    sql = ""
    rowcount = get_siteids_rowcount()
    i = 1
    for row in siteids:
        site_id = row['site_id']
        site = row['URI']
        sql = sql + "(SELECT site_id, timestamp_scan FROM scan_security_param WHERE site_id = '"+str(site_id)+"' ORDER BY sitescan_id  DESC LIMIT 1) " 
        if rowcount > i:
            sql = sql + " UNION "
        else:
            sql = sql + " ORDER BY timestamp_scan ASC LIMIT 1;"
        i=i+1
    #print(sql)
    with connection.cursor() as cursor:
        cursor.execute(sql)
        for row in cursor:
            site_id = row['site_id']
    
    get_header(site_id)
finally:
    exit
