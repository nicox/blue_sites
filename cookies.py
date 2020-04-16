import requests
import re
import xlsxwriter


def get_cookies(site,workbook,alphabet,column,row,worksheet):
#  print('test')
  cell = str(alphabet[column['cookie']]) + str(row[site])
  response = requests.get(
    site ,None,
  )
  failed = 0
  failedtext = ''
  headers_response = response.headers
  if 'Set-Cookie' in headers_response:
    cookies = headers_response['Set-Cookie']
    for cookie in response.cookies:
      security_flags = 0
      if cookie.secure is not True:
        #print('secure is not set for cookie' + cookie.name)
        failed = failed + 1
        failedtext = failedtext + 'secure is not set for ' + cookie.name + '\n'
      result = re.search('httponly',str(cookie._rest), flags=re.IGNORECASE)
      if result is None:
        #print ('httponly is not set for cookie' + cookie.name)
        failed = failed + 1
        failedtext = failedtext + 'httponly is not set for ' + cookie.name + '\n'

  else:
    #print ('kein cookie wird gesetzt für die site ' + site)
    failed = 9999
  if failed is 0:
    worksheet.write(cell, 'cookies secure und httponly')
   # print ('cookies secure und httponly')
  elif failed is 9999:
    worksheet.write(cell, 'kein Cookie gesetzt')
  else:
    worksheet.write(cell, failedtext)