#!/usr/bin/python3

import pymysql.cursors
import ssllabs
import ssllabsscanner
import json
import sys
sys.path.append("/usr/local/src/security/lib/")
from ssllabs_handling import get_ssllabs_from_siteid,extractDomain
from db_functions import write_intossllabs_check



def get_siteids():
    with connection.cursor() as cursor:
        sql = "SELECT site_id, URI from sites where active=1"
        cursor.execute(sql)
        return cursor

def get_siteids_rowcount():
    with connection.cursor() as cursor:
        sql = "SELECT site_id from sites WHERE active=1"
        cursor.execute(sql)
        return cursor.rowcount

def new_sites_check():
    with connection.cursor() as cursor:
        sql = "select sites.site_id, ssllabs_checks.timestamp_check  from sites left join ssllabs_checks ON (sites.site_id = ssllabs_checks.site_id) WHERE sites.active = 1 group by site_id order by site_id;"
        cursor.execute(sql)
        for row in cursor:
            #print(row['timestamp_check'])
            if row['timestamp_check'] == None:
                data = get_ssllabs_from_siteid(row['site_id'])
                write_intossllabs_check(row['site_id'],data)
        return 


#def check_new_site():

# Connect to the database.
connection = pymysql.connect(host='localhost',
    user='',
    password='',
    db='security',
    charset='utf8mb4',
    cursorclass=pymysql.cursors.DictCursor)

try:
    new_sites_check()
    siteids = get_siteids()
    sql = ""
    rowcount = get_siteids_rowcount()
    i = 1
    for row in siteids:
        site_id = row['site_id']
        site = row['URI']
        sql = sql + "(SELECT site_id, timestamp_check from ssllabs_checks where site_id = '"+str(site_id)+"' ORDER BY ssllabs_check_id  DESC LIMIT 1) " 
        if rowcount > i:
            sql = sql + " UNION "
        else:
            sql = sql + " ORDER BY timestamp_check ASC LIMIT 1;"
        i=i+1
    with connection.cursor() as cursor:
        cursor.execute(sql)
        for row in cursor:
            site_id = row['site_id']
    
    data = get_ssllabs_from_siteid(site_id)
    #print(data)
    #print(data['certs'][0])
    #print(data['endpoints'][0]['ipAddress'])
    #print(data['hasWarnings'])
    #print(data['endpoints'][0]['details']['cert']['notAfter'])

    write_intossllabs_check(site_id,data)
    #site = row['URI']
#                timestamp = row['timestamp_check']
            #data = ssllabsscanner.newScan(extractDomain(site))
            #print(data)  
#              print("id=" + str(site_id) + "site=" +str(site), "  timestamp:" + str(timestamp))
#                if str(timestamp) == "None":
#                    print("none timestamp")
#                    fqdn =  extractDomain(site)
#                #data = ssllabsscanner.newScan(extractDomain(site))
#                    data = ssllabsscanner.resultsFromCache(extractDomain(site)) 
#                #print(data['endpoints'][0]['grade'])
#                #print(data.items('host'))
#                #print(data.items())
#                # add new entry to ssllabs_checks
#                    add_entry = "INSERT INTO ssllabs_checks (site_id, grade) VALUES ("+str(site_id)+", '"+str(data['endpoints'][0]['grade'])+"');"
#                #print(resp['grade'])
#                    cursor.execute(add_entry)
#                    connection.commit()
#            #print(data['endpoints'][0]['grade'])

finally:
    connection.close()

