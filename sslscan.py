#!/usr/bin/python3
import sslyze

#try:
all_scan_requests = [
        ServerScanRequest(server_location=ServerNetworkLocation(hostname="cloudflare.com")),
        ServerScanRequest(server_location=ServerNetworkLocation(hostname="google.com")),
    ]
#except ServerHostnameCouldNotBeResolved:
    # Handle bad input ie. invalid hostnames
    #print("Error resolving the supplied hostnames")
#    return

scanner = Scanner()
scanner.queue_scans(all_scan_requests)
