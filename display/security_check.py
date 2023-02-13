from flask import Flask, render_template, request, url_for
from flask_table import Table, Col, LinkCol
import pymysql.cursors
import base64
import sys
import os
sys.path.append("/usr/local/src/security/lib/")
from db_functions import get_httpsheader_details,get_ftp_details,get_tls_details,get_ssh_details,get_header_details,read_ip_open_port_v4_group,get_ip_group,get_siteids_rowcount_group,get_groups,get_siteids,get_siteids_rowcount,get_latest_scandata,get_URI_from_siteid,get_latest_headerdata,get_siteids_group,write_into_sites,write_into_ip_v4address,write_into_ip_v4net,get_ipgroups,read_ip_open_port_v4
from urllib.parse import urlparse
#from ssllabs_handling import extractDomain

app = Flask(__name__)
SCREENSHOTS_FOLDER = os.path.join('/static/' )
app.config['SCREENSHOTS_FOLDER'] = SCREENSHOTS_FOLDER
app.config['DEBUG'] = True

class RawCol(Col):
    """Class that will just output whatever it is given and will not
    escape it.
    """
    def td_format(self, content):
        return content


class ItemTable(Table):
    site = Col('Site')
    ssllabs_link = RawCol('ssllabs_link')
    timestamp = Col('Timestamp')
    ssllabs_grade = Col('ssllabs_Grade')
    hasWarnings = RawCol("hasWarnings")
    ipAddress = Col('ipAddress')
    expiration_date = Col('expiration_date')
    tlsversion = Col('tlsversion')
    altNames = Col('altNames')
    classes = ['sortable','table-bordered', 'table','table-striped']

class ItemTable_IP(Table):
    ip = RawCol('IP')
    ports = Col('Ports')
    classes = ['sortable','table-bordered', 'table','table-striped']

class ItemTable_IP_HTTP(Table):
    ip = Col('IP')
    http_port = Col('http_port')
    http_headers = Col('http_headers')
    http_content = Col('http_content')
    http_screenshot = RawCol('screenshot')
    classes = ['sortable','table-bordered', 'table','table-striped']

class ItemTable_IP_HTTPS(Table):
    ip = Col('IP')
    http_port = Col('https_port')
    http_headers = Col('https_headers')
    http_content = Col('https_content')
    http_screenshot = RawCol('screenshot')
    classes = ['sortable','table-bordered', 'table','table-striped']


class ItemTable_IP_SSH(Table):
    ip = Col('IP')
    ssh_port = Col('ssh_port')
    ssh_softwareversion = Col('softwareversion')
    classes = ['sortable','table-bordered', 'table','table-striped']

class ItemTable_IP_FTP(Table):
    ip4 = Col('IP')
    ftp_port = Col('ftp_port')
    ftp_response = Col('ftp_response')
    ftp_message_login = Col('ftp_message_login')
    classes = ['sortable','table-bordered', 'table','table-striped']

class ItemTable_IP_TLS(Table):
    ip4 = Col('IP')
    tls_port = Col('TLS_port')
    tls_allowed_ciphers = RawCol('allowed_ciphers')
    tls_san = RawCol('san')
    classes = ['sortable','table-bordered', 'table','table-striped']


class HeaderTable(Table):
    site = Col('Site')
    timestamp = Col('Timestamp')
    Software = Col('Software')
    waf = Col("waf")
    Server = Col('Server')
    Location = Col('Location')
    X_Powered_By = Col('X_Powered_By')
    X_XSS_Protection = Col('X_XSS_Protection')
    Strict_Transport_Security = Col('Strict_Transport_Security')
    X_Content_Type_Options = Col('X_Content_Type_Options')
    X_Frame_Options = Col('X_Frame_Options')
    Content_Security_Policy = Col('Content_Security_Policy')
    X_Content_Security_Policy = Col('X_Content_Security_Policy')
    X_WebKit_CSP = Col('X_WebKit_CSP')
    Referrer_Policy = Col('Referrer_Policy')
    Feature_Policy = Col('Feature_Policy')
    Expect_CT = Col('Expect_CT')
    Set_Cookie = Col("Set_Cookie")
    classes = ['sortable','table-bordered', 'table','table-striped']

    #allow_sort = True
    #def sort_url(self, col_key, reverse=False):
    #    if reverse:
    #        direction =  'desc'
    #    else:
    #        direction = 'asc'
    #    return '?sort={}&direction={}'.format(col_key, direction)

# Get some objects
class Item(object):
    def __init__(self, name, description):
        self.URI = site
        self.ssllabs_grade = ssllabs_grade
        self.timestamp = timestamp

@app.route("/")
def index():
    groups =  get_groups()
    #headerlinks= "<a href=\"./header?group=iv\">   Header checks, iv sites</a>"
    headerlinks = "<ul>"
    ssllabslinks = "<ul>" 
    for group in groups:
        print(group)
        headerlinks = headerlinks+"<li><a href=\"./header?group="+group['gruppe']+"\">   Header checks, "+group['gruppe']+" sites</a></li>"
        ssllabslinks = ssllabslinks+"<li><a href=\"./ssllabs?group="+group['gruppe']+"\">   SSLlabs checks, "+group['gruppe']+" sites</a></li>"
    headerlinks = headerlinks+"</ul>"
    ssllabslinks = ssllabslinks+"</ul>"
    ipchecklinks = "<ul>"
    ipgroups = get_ipgroups()
    for ipgroup in ipgroups:
        print(ipgroup)
        ipchecklinks = ipchecklinks+"<li><a href=\"./ipchecks?ipgroup="+ipgroup['gruppe']+"\">  IPscan cheks, "+ipgroup['gruppe']+" </a></li>"
    ipchecklinks = ipchecklinks+"</ul>"
    return render_template('index2.html',headerlinks=headerlinks,ssllabslinks=ssllabslinks,ipchecklinks=ipchecklinks)

@app.route("/add")
def form():
    import validators
    import re
    form = '<form> \
      <label for="url">URL:</label><br> \
      <input type="text" id="url" name="url"><br> \
      <label for="group">Group:</label><br> \
      <input type="text" id="group" name="group"> \
      <input type="submit" value="Einfuegen"> \
      </form> \
      <a href=\"/\" >Home</a> \
      '
    url = request.args.get('url', default = '')
    group = request.args.get('group', default = '')
    if validators.url(url):
        if  re.search(u'^[a-zA-Z]+$', group):
            write_into_sites(url,group)
    return render_template("form.html",form=form)

@app.route("/addip4")
def addip4():
    import re
    import ipaddress
    form = '<form> \
      <label for="IPv4">IPv4:</label><br> \
      <input type="text" id="IPv4" name="IPv4"><br> \
      <label for="group">Group:</label><br> \
      <input type="text" id="group" name="group"> \
      <input type="submit" value="Einfuegen"> \
      </form> \
      <a href=\"/\" >Home</a> \
      '
    IPv4 = request.args.get('IPv4', default = '')
    group = request.args.get('group', default = '')
    try:
       ip_object = ipaddress.ip_address(IPv4)
       #print("The IP address '{ip_object}' is valid.")
       form = form+IPv4
       write_into_ip_v4address(IPv4,group) 
    except ValueError:
       form = form+"Not a valid IP Address"
       print("The IP address '{ip_string}' is not valid")
    try:
       ip_network = ipaddress.ip_network(IPv4)
       form = form+IPv4
       write_into_ip_v4net(IPv4,group)
    except ValueError:
       form = form+"not a valid ip network"
    return render_template("form.html",form=form)

@app.route("/header")
def headerdisplay():
    getgroup = request.args.get('group', default = '')
    groups =  get_groups() 
    group = ''
    if getgroup == '':
        rowcount = get_siteids_rowcount()
        siteids = get_siteids()
    else:
        for row in groups:
            #print(row)
            if getgroup == row['gruppe']:
                group = getgroup
                #print('inside if')
                rowcount = get_siteids_rowcount_group(group)
                siteids = get_siteids_group(group)
                
    items = []
    headerdata = get_latest_headerdata(siteids,rowcount)
    for row in headerdata:
        site_id = row['site_id']
        site = get_URI_from_siteid(site_id)
        timestamp = row['timestamp_scan']
        Software = row['software']
        waf = row['waf']
        Server = row['Server']
        Location = row['Location']
        ssta = "test"
        X_Powered_By = "Text"
        X_Powered_By = row['X_Powered_By']
        Strict_Transport_Security = row["Strict_Transport_Security"]
        X_XSS_Protection = row['X_XSS_Protection']
        X_Content_Type_Options = row['X_Content_Type_Options']
        X_Frame_Options = row['X_Frame_Options']
        Content_Security_Policy = row['Content_Security_Policy']
        X_Content_Security_Policy = row['X_Content_Security_Policy']
        X_WebKit_CSP = row['X_WebKit_CSP']
        Referrer_Policy = row['Referrer_Policy']
        Feature_Policy = row['Feature_Policy']
        Expect_CT = row['Expect_CT']
        Cookie = str(row["Set_Cookie"])
        Set_Cookie = Cookie.replace(", ",",\n")
       # if row['hasWarnings'] == "False":
       #     hasWarnings = row['hasWarnings']
        #else:
         #   hasWarnings = row['hasWarnings']
            #hasWarnings = '<span class="p-3 mb-2 bg-danger text-white">'+str(row['hasWarnings'])+'<\span>'
        items.append(dict(site=site, timestamp=timestamp, \
            Software=Software, waf=waf, \
            Server=Server, Location=Location, \
            X_Powered_By=X_Powered_By, Strict_Transport_Security=Strict_Transport_Security, \
            X_XSS_Protection=X_XSS_Protection, X_Content_Type_Options=X_Content_Type_Options, \
            X_Frame_Options=X_Frame_Options, Content_Security_Policy=Content_Security_Policy, \
            X_Content_Security_Policy=X_Content_Security_Policy, X_WebKit_CSP=X_WebKit_CSP, \
            Referrer_Policy=Referrer_Policy, Feature_Policy=Feature_Policy, \
            Set_Cookie=Set_Cookie, Expect_CT=Expect_CT  ))

    # Declare your table
    table = HeaderTable(items)
    #print(table.__html__())
    #return table.__html__()
    #data = pd.read_excel('dummy_data.xlsx')
    #data.set_index(['Name'], inplace=True)
    #data.index.name=None
    return render_template('base.html', table=table)

@app.route("/ssllabs")

def hello():
    getgroup = request.args.get('group', default = '')
    groups =  get_groups() 
    group = ''
    if getgroup == '':
        rowcount = get_siteids_rowcount()
        siteids = get_siteids()
    else:
        for row in groups:
            #print(row)
            if getgroup == row['gruppe']:
                group = getgroup
                #print('inside if')
                rowcount = get_siteids_rowcount_group(group)
                siteids = get_siteids_group(group)    
    
    scandata = get_latest_scandata(siteids,rowcount)
    items = []
    for row in scandata:
        site_id = row['site_id']
        site = get_URI_from_siteid(site_id)
        ssllabs_link = "<a href=\"https://www.ssllabs.com/ssltest/analyze.html?d="+str(urlparse(site).netloc)+"\" target=\"_blank\" >ssllabs</a>"
        timestamp = row['timestamp_check']
        ssllabs_grade = row['grade']
        altNames = row['altNames']
        expiration_date = row['expiration_date']
        ipAddress = row['ipAddress']
        tlsversion = row['tlsversion']
        if row['hasWarnings'] == "False":
            hasWarnings = row['hasWarnings']
        else:
            #hasWarnings = row['hasWarnings']
            hasWarnings = '<a style="background-color: red;"><b>'+str(row['hasWarnings'])+'</b></a>'
        items.append(dict(site=site, timestamp=timestamp, \
            ssllabs_grade=ssllabs_grade, altNames=altNames, \
            expiration_date=expiration_date, tlsversion=tlsversion, \
            ipAddress=ipAddress, hasWarnings=hasWarnings, ssllabs_link=ssllabs_link ))

    # Declare your table
    table = ItemTable(items)
    
    return render_template('base.html', table=table)
    
@app.route("/ipchecks")

def ipcheckdisplay():
    getgroup = request.args.get('ipgroup', default = '')
    getip = request.args.get('ip', default = '')
    groups =  get_ipgroups()
    group = ''
    if getgroup == '':
        #rowcount = get_ip_rowcount()
        #ip = get_ip()
        print("no group")
        #scandata = get_ip_scans()
    else:
        for row in groups:
            if getgroup == row['gruppe']:
                group = getgroup
                print(group)
                #rowcount = get_ip_rowcount_group(group)
                #ips = get_ip_group(group)
                #print(ips)

    if getip == '':
        print(" no ip set")
    else:
        html = render_template('IP_details-start.html')
        try:
            items = []
            http_details = get_header_details(getip)
            for row in http_details:
                ip = row['ip4']
                http_port = row['port']
                headers_bytes = row['headers']
                headers_ascii = headers_bytes.decode('ascii')
                http_headers = base64.b64decode(headers_ascii)
  #          http_headers = row['headers']
                content_bytes = row['content']
                content_ascii = content_bytes.decode('ascii')
                http_content = base64.b64decode(content_ascii)
#          http_content = row['content']
                full_filename = os.path.join(app.config['SCREENSHOTS_FOLDER'])
                http_screenshot =  '<img src="'+url_for('static', filename="http-screenshots/"+ip+"-"+str(http_port)+".png")+'", alt="User Image">'
                items.append(dict(ip=ip, http_port=http_port, \
                    http_headers=http_headers, http_content=http_content, \
                    http_screenshot=http_screenshot ))
            table = ItemTable_IP_HTTP(items)
            html = html+render_template('table.html', table=table)
        except:
            print("no http site")
            html = html+"no HTTP Service found"
        #try:
        items = []
        https_details = get_httpsheader_details(getip)
        for row in https_details:
                ip = row['ip4']
                http_port = row['port']
                headers_bytes = row['headers']
                headers_ascii = headers_bytes.decode('ascii')
                http_headers = base64.b64decode(headers_ascii)
  #          http_headers = row['headers']
                content_bytes = row['content']
                content_ascii = content_bytes.decode('ascii')
                http_content = base64.b64decode(content_ascii)
#          http_content = row['content']
                full_filename = os.path.join(app.config['SCREENSHOTS_FOLDER'])
                http_screenshot =  '<img src="'+url_for('static', filename="http-screenshots/"+ip+"-"+str(http_port)+".png")+'", alt="User Image">'
                items.append(dict(ip=ip, http_port=http_port, \
                    http_headers=http_headers, http_content=http_content, \
                    http_screenshot=http_screenshot ))
        table = ItemTable_IP_HTTPS(items)
        html = html+render_template('table.html', table=table)
        #except:
        #    print("no https site")
        ##    html = html+"no HTTPS Service found"
        ssh_items=[]
        try:
            ssh_details = get_ssh_details(getip)
            for rowssh in ssh_details:
                ip = rowssh['ip']
                ssh_port = rowssh['port']
                ssh_softwareversion = rowssh['softwareversion']
                ssh_items.append(dict(ip=ip, ssh_port=ssh_port, \
                        ssh_softwareversion=ssh_softwareversion ))
                #print(ip)
            table = ItemTable_IP_SSH(ssh_items)
            html = html+render_template('table.html', table=table)
        except:
            print('no ssh service')
            html = html+"no SSH Service found"
        ftp_items=[]
        try:
            ftp_details = get_ftp_details(getip)
            print(ftp_details)
            for row in ftp_details:
                ip4 = row['ip4']
                ftp_port = row['port']
                ftp_response = row['ftp_response']
                ftp_message_login = row['ftp_message_login']
                ftp_items.append(dict(ip4=ip4, ftp_port=ftp_port, \
                        ftp_response=ftp_response, ftp_message_login=ftp_message_login ))
                #print(ip)
            table = ItemTable_IP_FTP(ftp_items)
            html = html+render_template('table.html', table=table)
        except:
            html = html+"no FTP Service at this IP"
            print('no ftp service')
        tls_items=[]
        try:
            tls_details = get_tls_details(getip)
            print(tls_details)
            for row in tls_details:
                ip4 = row['ip4']
                tls_port = row['port']
                tls_allowed_ciphers = row['allowed_ciphers']
                tls_san = row['san']
                tls_items.append(dict(ip4=ip4, tls_port=tls_port, \
                        tls_allowed_ciphers=tls_allowed_ciphers, tls_san=tls_san  ))
                #print(ip)
            table = ItemTable_IP_TLS(tls_items)
            html = html+render_template('table.html', table=table)
        except:
            html = html+"no TLS Service found at this location"
            print('no TLS service at this location')
        #print(html) 
        return html

    scandata = read_ip_open_port_v4_group(group)
    items = []

    for row in scandata:
        IP = '<a href=\"./ipchecks?ip='+row['ip4']+'\"> '+row["ip4"]+'</a>'
        ports = row['Ports']
        items.append(dict(ip=IP, ports=ports ))

    # Declare your table
    table = ItemTable_IP(items)

    return render_template('base.html', table=table)


if __name__ == "__main__":
    app.run(host='0.0.0.0')
