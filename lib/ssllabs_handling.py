from init_db_conn import get_db_connection
connection = get_db_connection()
import tldextract

def get_ssllabs_from_siteid(siteid):
    import ssllabsscanner
    with connection.cursor() as cursor:
        sql = "SELECT URI FROM sites where site_id = "+str(siteid)+""
        cursor.execute(sql)
        for row in cursor:
            site = row['URI']
            print("inside get_ssllabs_from_siteid site_id:"+str(site))
            data = ssllabsscanner.newScan(extractDomain(row['URI']))
            #data = ssllabsscanner.resultsFromCache(extractDomain(row['URI']))
        return data

def extractDomain(url):
    if "http" in str(url) or "www" in str(url):
        parsed = tldextract.extract(url)
        parsed = ".".join([i for i in parsed if i])
        return parsed
    else: return "NA"
