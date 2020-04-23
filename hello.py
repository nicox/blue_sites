import requests
import xlsxwriter
import json
import re
import cookies

#Todo

#### definitions
workbook = xlsxwriter.Workbook('output.xlsx')

file1 = open("sites.txt","r")
sites = file1.readlines()
file1.close()
#print (sites)
interesting_headers = ['Server','Location','X-Powered-By','Strict-Transport-Security','X-XSS-Protection','X-Content-Type-Options','X-Frame-Options','Content-Security-Policy','X-Content-Security-Policy','X-WebKit-CSP','Referrer-Policy','Feature-Policy','Expect-CT']
alphabet = list(map(chr, range(65, 90)))
software = { "Typo3" : "typo3", "Nextcloud" : "nextcloud", "Citrix Gateway" : "\/vpn\/login.js", "Wordpress" : "wp-content", "Nextcloud": "\/core\/js\/oc.js"}
waf = {"F5" : "Support ID"}
row = dict()
column = dict()

##### get the headers
def get_header(site,interesting_headers,workbook):
  response = requests.get(
    site,None,
  )
  headers_response = response.headers
  #print (headers_response)
  for x in interesting_headers:
    if x in headers_response:
      headervalue = headers_response[x]
      #print (site + headervalue)
      cell = str(alphabet[column[x]]) + str(row[site])
      worksheet.write(cell, headervalue)
  response_location = requests.get(
    site,allow_redirects = False,)
  headers_response_location = response_location.headers
  if 'Location' in headers_response_location:
    headervalue = headers_response_location['Location']
    cell = str(alphabet[column['Location']]) + str(row[site])
    worksheet.write(cell, headervalue)
   # print (headervalue)

###### get the body informations
def get_body(site,workbook,software):
  response = requests.get(
    site,None,
  )
  body_response = str(response.content)
  #print (body_response)
  for x in software:
    result = re.search(software[x],body_response, flags=re.IGNORECASE)
    if result is not None:
      cell = str(alphabet[column['software']]) + str(row[site])
      worksheet.write(cell, x)

##### sql injectioin test for WAF
def req_waf(site,workbook):
  error = ''
  #/'%20or%201=1'
  url = site +"/'%20or%201=1'"
  cell = str(alphabet[column['waf']]) + str(row[site])
 # print ('waftest jetzt')
  try:
    response = requests.get(
      url,None,
      )
  except requests.exceptions.RequestException as e:
    error = e
    print (error + ' when connecting to '+ site + ' for waf check')
    worksheet.write(cell, 'no response (IPS?)')
  #print (response.content)
  if error is '':
    waf_response = str(response.content)
    for x in waf:
      result = re.search(waf[x],waf_response, flags=re.IGNORECASE)
      if result is not None:
        worksheet.write(cell, x)


##### workbook initialisation
worksheet = workbook.add_worksheet()
worksheet.write('A1', 'Site')
highest_column = 0
highest_row = 1
for x in interesting_headers:
  column[x] = highest_column + 1
  highest_column = highest_column + 1
  cell = str(alphabet[column[x]]) + "1"
 #  print (cell)
  worksheet.write(cell, x)

#### column naming
column['software'] = highest_column + 1
highest_column = highest_column + 1
cell = alphabet[column['software']] + "1"
worksheet.write(cell, "Software")
column['waf'] = highest_column + 1
highest_column = highest_column + 1
cell = alphabet[column['waf']] + "1"
worksheet.write(cell, "waf")
column['cookie'] = highest_column + 1
highest_column = highest_column + 1
cell = alphabet[column['cookie']] + "1"
worksheet.write(cell, "cookie")

for site in sites:
  site = site.rstrip("\n")
  print (site)
  row[site] = highest_row + 1
  highest_row = highest_row + 1
  cell = "A" + str(row[site])
  worksheet.write(cell, site)

  get_header(site,interesting_headers,workbook)
  get_body(site,workbook,software)
  req_waf(site,workbook)
  cookies.get_cookies(site,workbook,alphabet,column,row,worksheet)

workbook.close()
