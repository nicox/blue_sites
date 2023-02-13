import sys
sys.path.append("/usr/local/src/security/lib/")
from init_db_conn import get_db_connection
connection = get_db_connection()

def close_connections():
    cursor.close()
    connection.close()

def get_siteids():
    from init_db_conn import get_db_connection
    connection = get_db_connection()
    with connection.cursor() as cursor:
        sql = "SELECT site_id, URI from sites where active=1"
        cursor.execute(sql)
    cursor.close()
    connection.close()
    return cursor

def get_ips():
    from init_db_conn import get_db_connection
    connection = get_db_connection()
    with connection.cursor() as cursor:
        sql = "SELECT ip4 FROM ip where active=1" 
        cursor.execute(sql)
    cursor.close
    connection.close()
    return cursor

def get_siteids_group(gruppe):
    from init_db_conn import get_db_connection
    connection = get_db_connection()
    with connection.cursor() as cursor:
        sql = "SELECT site_id, URI from sites where gruppe = '"+gruppe+"' AND active=1"
        print(sql)
        cursor.execute(sql)
    cursor.close()
    connection.close()
    return cursor

def get_ip_group(gruppe):
    from init_db_conn import get_db_connection
    connection = get_db_connection()
    with connection.cursor() as cursor:
        sql = "SELECT ip4 from ip where gruppe = '"+gruppe+"' AND active=1"
        print(sql)
        cursor.execute(sql)
    cursor.close()
    connection.close()
    return cursor

def get_ip_scans():
    from init_db_conn import get_db_connection
    connection = get_db_connection()
    with connection.cursor() as cursor:
        sql = "SELECT ip4 from ip where active=1"
        print(sql)
        cursor.execute(sql)
    cursor.close()
    connection.close()
    return cursor

def get_groups():
    from init_db_conn import get_db_connection
    connection = get_db_connection()
    with connection.cursor() as cursor:
        sql = "SELECT gruppe from sites group by gruppe"
        cursor.execute(sql)
    cursor.close()
    connection.close()
    return cursor

def get_ipgroups():
    from init_db_conn import get_db_connection
    connection = get_db_connection()
    with connection.cursor() as cursor:
        sql = "SELECT gruppe from ip group by gruppe"
        cursor.execute(sql)
    cursor.close()
    connection.close()
    return cursor


def get_siteids_rowcount():
    from init_db_conn import get_db_connection
    connection = get_db_connection()
    with connection.cursor() as cursor:
        sql = "SELECT site_id from sites where active=1"
        cursor.execute(sql)
    cursor.close()
    connection.close()
    return cursor.rowcount

def get_ip_rowcount():
    from init_db_conn import get_db_connection
    connection = get_db_connection()
    with connection.cursor() as cursor:
        sql = "SELECT ip4 from ip where active=1"
        cursor.execute(sql)
    cursor.close()
    connection.close()
    return cursor.rowcount

def get_siteids_rowcount_group(group):
    from init_db_conn import get_db_connection
    connection = get_db_connection()
    with connection.cursor() as cursor:
        sql = "SELECT site_id from sites where gruppe = '"+group+"' and active=1"
        cursor.execute(sql)
    cursor.close()
    connection.close()
    return cursor.rowcount

def get_ip_rowcount_group(group):
    from init_db_conn import get_db_connection
    connection = get_db_connection()
    with connection.cursor() as cursor:
        sql = "SELECT ip4 from ip where gruppe = '"+group+"' and active=1"
        cursor.execute(sql)
    cursor.close()
    connection.close()
    return cursor.rowcount

def get_URI_from_siteid(site_id):
    from init_db_conn import get_db_connection
    connection = get_db_connection()
    with connection.cursor() as cursor:
        sql = "SELECT URI FROM sites where site_id = "+str(site_id)+""
        cursor.execute(sql)
        for row in cursor:
            URI = row['URI']
    cursor.close()
    connection.close()
    return URI

def get_latest_scandata(siteids,rowcount):
    from init_db_conn import get_db_connection
    connection = get_db_connection()
    sql = ""
    i = 1
    for row in siteids:
        site_id = row['site_id']
        sql = sql + "(SELECT * from ssllabs_checks where site_id = '"+str(site_id)+"' ORDER BY ssllabs_check_id  DESC LIMIT 1) " 
        if rowcount > i:
            sql = sql + " UNION "
        else:
            sql = sql + " ORDER BY site_id ;"
        i=i+1
    print(sql)
    with connection.cursor() as cursor:
        cursor.execute(sql)
    cursor.close()
    connection.close()
    return(cursor)

def get_open_port(siteids,rowcount):
    from init_db_conn import get_db_connection
    connection = get_db_connection()
    sql = ""
    i = 1
    for row in siteids:
        site_id = row['site_id']
        sql = sql + "(SELECT * from ssllabs_checks where site_id = '"+str(site_id)+"' ORDER BY ssllabs_check_id  DESC LIMIT 1) "
        if rowcount > i:
            sql = sql + " UNION "
        else:
            sql = sql + " ORDER BY site_id ;"
        i=i+1
    print(sql)
    with connection.cursor() as cursor:
        cursor.execute(sql)
    cursor.close()
    connection.close()
    return(cursor)


def write_intossllabs_check(site_id,data):
    from datetime import datetime
    tlsver = ""
    try:
        for row in data['endpoints'][0]['details']['protocols']:
            tlsver = tlsver+ row['name']+row['version'] + ", "
    except KeyError:
        tlsver = "not available"
        #print(row['name']+row['version'])
    tlsversion = tlsver[:-2]
    try:
        hasWarnings = data['endpoints'][0]['hasWarnings']
    except KeyError:
        hasWarnings = "???"
    
    try:
        notAfter = data['certs'][0]['notAfter']/1000
    except IndexError:
        notAfter = 1
    except KeyError:
        notAfter = 1

    altNames = ""
    try:
        for row in data['certs'][0]['altNames']:
            altNames = altNames+ row +", "    
    except IndexError:
        altNames = ""
    except KeyError:
        altNames = ""
    #print(altNames)
    try:
        grade = data['endpoints'][0]['grade']
    except KeyError:
        grade = "x"
    try:
        expiration = datetime.utcfromtimestamp(notAfter).strftime('%Y-%m-%d %H:%M:%S')
    except KeyError:
        expiration = ""

    try:
        ipaddress = data['endpoints'][0]['ipAddress']
    except KeyError:
        ipaddress = ""
    with connection.cursor() as cursor:
        add_entry = "INSERT INTO ssllabs_checks (site_id, grade, ipAddress, altNames, tlsversion, hasWarnings, expiration_date) \
            VALUES ("+str(site_id)+", \
                '"+str(grade)+"', \
                '"+str(ipaddress)+"', \
                '"+str(altNames)+"', \
                '"+str(tlsversion)+"', \
                '"+str(hasWarnings)+"', \
                '"+str(expiration)+"' );"
        #print(add_entry)
        cursor.execute(add_entry)
        connection.commit()
    cursor.close()
    connection.close()

def new_sites_check_scan(): 
    #from scan_sites import get_header
    with connection.cursor() as cursor:
        sql = "select sites.site_id, scan_security_param.timestamp_scan  from sites left join scan_security_param ON (sites.site_id = scan_security_param.site_id) group by site_id order by site_id limit 1"
        cursor.execute(sql)
        for row in cursor:
            #print(row['site_id'])
            if row['timestamp_scan'] == None:
                print(row['site_id'])
                print(get_header(row['site_id']))    
            #    data = get_ssllabs_from_siteid(row['site_id'])
            #    write_intossllabs_check(row['site_id'],data)
        cursor.close()
        connection.close()
        return 

def get_latest_headerdata(siteids,rowcount):
    from init_db_conn import get_db_connection
    connection = get_db_connection()
    sql = ""
    i = 1
    for row in siteids:
        site_id = row['site_id']
        sql = sql + "(SELECT * from scan_security_param where site_id = '"+str(site_id)+"' ORDER BY sitescan_id  DESC LIMIT 1) " 
        if rowcount > i:
            sql = sql + " UNION "
        else:
            sql = sql + " ORDER BY site_id ;"
        i=i+1
    with connection.cursor() as cursor:
        #print(sql)
        cursor.execute(sql)
        cursor.close()
        connection.close()
        return(cursor)


def write_into_sites(url,group):
    from init_db_conn import get_db_connection
    connection = get_db_connection()
    with connection.cursor() as cursor:
        add_entry = "INSERT INTO sites ( URI, gruppe, active) \
            VALUES ('"+str(url)+"', \
                '"+str(group)+"', '1' );"
        #print(add_entry)
        cursor.execute(add_entry)
        connection.commit()
    cursor.close()
    connection.close()

def write_into_ip_v4address(IPv4,group):
    from init_db_conn import get_db_connection
    connection = get_db_connection()
    with connection.cursor() as cursor:
        add_entry = "INSERT INTO ip ( ip4, gruppe, active) \
            Values ('"+str(IPv4)+"', \
                '"+str(group)+"', '1' );"
        cursor.execute(add_entry)
        connection.commit()
    cursor.close()
    connection.close()

def write_into_ip_v4net(IPv4,group):
    import ipaddress
    from init_db_conn import get_db_connection
    connection = get_db_connection()
    net4 = ipaddress.ip_network(IPv4)
    for x in net4.hosts():
        #print(x)
        with connection.cursor() as cursor:
            add_entry = "INSERT INTO ip ( ip4, gruppe, active) \
                Values ('"+str(x)+"', \
                '"+str(group)+"', '1' );"
            cursor.execute(add_entry)
        connection.commit()
    cursor.close()
    connection.close()

def read_ip_v4net():
    from init_db_conn import get_db_connection
    connection = get_db_connection()
    get_iplist = "SELECT ip4 FROM ip WHERE active='1';"
    with connection.cursor() as cursor:
        cursor.execute(get_iplist)
        connection.commit()
        cursor.close()
        connection.close()
    return(cursor)

def write_into_ip_open_port_v4(IPv4,port):
    from init_db_conn import get_db_connection
    connection = get_db_connection()
    add_entry = "INSERT INTO ip_open_port_v4 (ip4, port, status) \
            VALUES (\
            '"+IPv4+"', \
            '"+str(port)+"', \
            'open');"
    print(add_entry)
    try:
        with connection.cursor() as cursor:
          cursor.execute(add_entry)
          connection.commit()
          cursor.close()
          connection.close()
    except (connection.Error, connection.Warning) as e:
        print(e)
        return None

def write_into_ip_service_ssh(host,port,version):
    from init_db_conn import get_db_connection
    connection = get_db_connection()
    add_entry = "INSERT INTO ip_service_ssh (ip, port, softwareversion) \
            VALUES (\
            '"+host+"', \
            '"+port+"', \
            '"+version+"');" 
    print(add_entry)
    try:
        with connection.cursor() as cursor:
          cursor.execute(add_entry)
          connection.commit()
          cursor.close()
          connection.close()
    except (connection.Error, connection.Warning) as e:
        print(e)
        return None


def write_into_ip_service_http(host,port,headers,content):
    from init_db_conn import get_db_connection
    connection = get_db_connection()
    add_entry = "INSERT INTO ip_service_http (ip4, port, headers, content) \
            VALUES (\
            '"+host+"', \
            '"+port+"', \
            "+str(headers)+", \
            "+str(content)+");"
    print(add_entry)
    try:
        with connection.cursor() as cursor:
          cursor.execute(add_entry)
          connection.commit()
          cursor.close()
          connection.close()
    except (connection.Error, connection.Warning) as e:
        print(e)
        return None

def write_into_ip_service_https(host,port,headers,content):
    from init_db_conn import get_db_connection
    connection = get_db_connection()
    add_entry = "INSERT INTO ip_service_https (ip4, port, headers, content) \
            VALUES (\
            '"+host+"', \
            '"+port+"', \
            "+str(headers)+", \
            "+str(content)+");"
    print(add_entry)
    try:
        with connection.cursor() as cursor:
          cursor.execute(add_entry)
          connection.commit()
          cursor.close()
          connection.close()
    except (connection.Error, connection.Warning) as e:
        print(e)
        return None

def write_into_ip_service_ftp(host,port,response,message):
    from init_db_conn import get_db_connection
    connection = get_db_connection()
    add_entry = "INSERT INTO ip_service_ftp (ip4, port, ftp_response, ftp_message_login) \
            VALUES (\
            '"+host+"', \
            '"+port+"', \
            '"+str(response)+"', \
            '"+str(message)+"');"
    print(add_entry)
    try:
        with connection.cursor() as cursor:
          cursor.execute(add_entry)
          connection.commit()
          cursor.close()
          connection.close()
    except (connection.Error, connection.Warning) as e:
        print(e)
        return None

def write_into_ip_service_tls(host,port,allowed_ciphers,san):
    from init_db_conn import get_db_connection
    connection = get_db_connection()
    add_entry = "INSERT INTO ip_service_tls (ip4, port, allowed_ciphers, san) \
            VALUES (\
            '"+host+"', \
            '"+port+"', \
            '"+str(allowed_ciphers)+"', \
            '"+str(san)+"');"
    print(add_entry)
    try:
        with connection.cursor() as cursor:
          cursor.execute(add_entry)
          connection.commit()
          cursor.close()
          connection.close()
    except (connection.Error, connection.Warning) as e:
        print(e)
        return None


def read_ip_open_port_v4():
    from init_db_conn import get_db_connection
    connection = get_db_connection()
    read_open_ports = "SELECT ip.ip4,ip.gruppe,port \
                    FROM `ip` \
                    inner join ip_open_port_v4 \
                    on ip.ip4 = ip_open_port_v4.ip4 \
                    ORDER by ip4;"
    try:
        with connection.cursor() as cursor:
            cursor.execute(read_open_ports)
            connection.commit()
            cursor.close()
            connection.close()
            return(cursor)
    except (connection.Error, connection.Warning) as e:
        print(e)
        return None

def read_ip_open_port_v4_group(group):
    from init_db_conn import get_db_connection
    connection = get_db_connection()
    read_open_ports = "SELECT ip.ip4,ip.gruppe,(select group_concat(port) \
            from ip_open_port_v4 where ip.ip4 = ip_open_port_v4.ip4) As Ports, \
(select group_concat(port) from ip_service_http where ip.ip4 = ip_service_http.ip4) as HTTP_Ports,\
(select group_concat(port) from ip_service_ssh where ip.ip4 = ip_service_ssh.ip) as HTTP_Ports,\
(select group_concat(port) from ip_service_ftp where ip.ip4 = ip_service_ftp.ip4) as FTP_Ports\
       From ip where gruppe = '"+group+"' order by \
       (select group_concat(port) from ip_open_port_v4 where ip.ip4 = ip_open_port_v4.ip4) desc \
	"
    try:
        with connection.cursor() as cursor:
            cursor.execute(read_open_ports)
            connection.commit()
            cursor.close()
            connection.close()
            return(cursor)
    except (connection.Error, connection.Warning) as e:
        print(e)
        return None

def get_header_details(ip):
    from init_db_conn import get_db_connection
    connection = get_db_connection()
    read_http_details = "SELECT * from ip_service_http where ip4 = '"+ip+"';"
    try:
        with connection.cursor() as cursor:
            cursor.execute(read_http_details)
            connection.commit()
            cursor.close()
            connection.close()
            return(cursor)
    except (connection.Error, connection.Warning) as e:
        print(e)
        return None

def get_httpsheader_details(ip):
    from init_db_conn import get_db_connection
    connection = get_db_connection()
    read_http_details = "SELECT * from ip_service_https where ip4 = '"+ip+"';"
    print(read_http_details)
    try:
        with connection.cursor() as cursor:
            cursor.execute(read_http_details)
            connection.commit()
            cursor.close()
            connection.close()
            return(cursor)
    except (connection.Error, connection.Warning) as e:
        print(e)
        return None

def get_ssh_details(ip):
    from init_db_conn import get_db_connection
    connection = get_db_connection()
    read_ssh_details = "SELECT * from ip_service_ssh where ip = '"+ip+"';"
    try:
        with connection.cursor() as sshcursor:
            sshcursor.execute(read_ssh_details)
            connection.commit()
            sshcursor.close()
            connection.close()
            return(sshcursor)
    except (connection.Error, connection.Warning) as e:
        print(e)
        return None

def get_ftp_details(ip):
    from init_db_conn import get_db_connection
    connection = get_db_connection()
    read_ftp_details = "SELECT * from ip_service_ftp where ip4 = '"+ip+"';"
    print(read_ftp_details)
    try:
        with connection.cursor() as cursor:
            cursor.execute(read_ftp_details)
            connection.commit()
            cursor.close()
            connection.close()
            return(cursor)
    except (connection.Error, connection.Warning) as e:
        print(e)
        return None

def get_tls_details(ip):
    from init_db_conn import get_db_connection
    connection = get_db_connection()
    read_ssh_details = "SELECT * from ip_service_tls where ip4 = '"+ip+"';"
    try:
        with connection.cursor() as sshcursor:
            sshcursor.execute(read_ssh_details)
            connection.commit()
            sshcursor.close()
            connection.close()
            return(sshcursor)
    except (connection.Error, connection.Warning) as e:
        print(e)
        return None

