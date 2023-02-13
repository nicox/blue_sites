import json
import re
import cookies
import sys
import getopt
import requests

from init_db_conn import get_db_connection
connection = get_db_connection()

def new_sites_check_scan(): 
     with connection.cursor() as cursor:
        sql = "select sites.site_id, scan_security_param.timestamp_scan  from sites left join scan_security_param ON (sites.site_id = scan_security_param.site_id) group by site_id order by site_id"
        cursor.execute(sql)
        for row in cursor:
            #print(row['site_id'])
            if row['timestamp_scan'] == None:
                print(row['site_id'])
                print(get_header(row['site_id']))    
            #    data = get_ssllabs_from_siteid(row['site_id'])
            #    write_intossllabs_check(row['site_id'],data)
        return 
##### get the headers
def get_header(siteid):
    import MySQLdb
    fields = "(site_id"
    values = "("+str(siteid)
    from init_db_conn import get_db_connection
    interesting_headers = ['Server','Location','X-Powered-By','Strict-Transport-Security','X-XSS-Protection','X-Content-Type-Options','X-Frame-Options','Content-Security-Policy','X-Content-Security-Policy','X-WebKit-CSP','Referrer-Policy','Feature-Policy','Expect-CT','Set-Cookie']
    error = ''
    response = lambda: None
    response.headers = ' no response'  
    with connection.cursor() as cursor:
        sql = "SELECT URI FROM sites where site_id = "+str(siteid)+""
        cursor.execute(sql)
        for row in cursor:
            site = row['URI']
            waf_seen = req_waf(site,siteid)
            software_seen = get_software(site)
            #print("inside get_ssllabs_from_siteid site_id:"+str(site))
            try:
                response = requests.get(
                    site,verify=False,
                )
            except requests.exceptions.RequestException as e:
                error = e
                print (error  )
            headers_response = response.headers
            for header in interesting_headers:
             #   print(header)
                if header in headers_response:
                    headervalue = headers_response[header]
                    #print(headervalue)
                    headervalue_ = headervalue.replace("'","\\'")
                    fields = fields+", "+header
                    values = values+", '"+headervalue_+"'"

            fields = fields+", waf, software)"
            values = values+", '"+waf_seen+"', '"+software_seen+"')"
            values_ = str(MySQLdb.escape_string(values))
            fields_ = fields.replace('-','_')
            add_entry = "INSERT INTO scan_security_param "+fields_+" VALUES "+values
            print(site+"    "+add_entry)
            cursor.execute(add_entry)
            connection.commit()

        return 
  
def req_waf(site, site_id):
  waf = {"F5" : "Support ID"}
  error = ''
  url = site +"/'%20or%201=1'"
  try:
    response = requests.get(
      url,verify=False,
      )
  except requests.exceptions.RequestException as e:
    error = e
    print (str(error) + ' when connecting to '+ str(site) + ' for waf check')
    waf_seen = ""
  #print (response.content)
  if error is '':
    waf_response = str(response.content)
    for x in waf:
      result = re.search(waf[x],waf_response, flags=re.IGNORECASE)
      if result is not None:
        waf_seen = x
      else:
          waf_seen = ""
  return waf_seen

def get_software(site):
    software = { "Typo3" : "typo3", "Nextcloud" : "nextcloud", "Citrix Gateway" : "\/vpn\/login.js", \
      "Wordpress" : "wp-content", "Nextcloud/Owncloud": "\/core\/js\/oc.js", \
        "JQuery" : "jquery", "RMG Messtechnik" : "RMG - Webportal", "Check Point(VPN?)" : "Check Point Software Technologies Ltd. All rights reserved.", \
        "F5 APM Auth" : "apm.css", "RMData" : "rmdata", "Bootstrap" : "bootstrap.css", "Serv-U Fileserver" : "Serv-U" }
    try: 
        response = requests.get(
        site,verify=False,
        )
    except:
        response = ""
    software_seen = ""
    try: 
        body_response = str(response.content)
        for x in software:
            result = re.search(software[x],body_response, flags=re.IGNORECASE)
            if result is not None:
                software_seen = software_seen+","+x

    except:
        print("no body")
    #print (body_response)
    software_seen = software_seen[1:]
    print(software_seen)
    return software_seen
