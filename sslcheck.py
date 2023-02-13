#!/usr/bin/python3
import time
from datetime import datetime
import sys
sys.path.append("/usr/local/src/security/lib/")
from db_functions import read_ip_open_port_v4,write_into_ip_service_tls
from sslyze import (
    Scanner,
    ServerScanRequest,
    SslyzeOutputAsJson,
    ServerScanResultAsJson,
    ScanCommandAttemptStatusEnum,
    ServerNetworkLocation,
)
#from sslyze.plugins.certificate_info._cli_connector import _get_basic_certificate_text 
from sslyze.json.json_output import InvalidServerStringAsJson
from sslyze.mozilla_tls_profile.mozilla_config_checker import (
    MozillaTlsConfigurationChecker,
    ServerNotCompliantWithMozillaTlsConfiguration,
    ServerScanResultIncomplete,
)
from cryptography.x509 import Certificate
import ipaddress as ipa
import threading
import queue
import time
import socket
import ssl
from OpenSSL import crypto


def main() -> None:
    
    open_ports = read_ip_open_port_v4()
    for x in open_ports:
        host = str(x['ip4'])
        port = str(x['port'])
        sslyzescan(host,port)

def scan_host(ip, port):
    sslcontext = ssl.create_default_context()
    sslcontext.check_hostname = False
    sslcontext.verify_mode = ssl.CERT_NONE

    s = sslcontext.wrap_socket(socket.socket())
    #s.settimeout(args.timeout)
    try:
        s.connect((str(ip), int(port)))
        cert = crypto.load_certificate(crypto.FILETYPE_ASN1, s.getpeercert(True))
        names = []
    # parse the subject out of the certificate
        for elem in cert.get_subject().get_components():
            if elem[0] == b'CN':
                name = elem[1].decode()
                if name not in names:
                    names.append(name)

                # check for SAN extensions
        extension_count = cert.get_extension_count()
        if extension_count > 0:
            for count in range(extension_count):
                extension = cert.get_extension(count)
                if extension.get_short_name().decode() == 'subjectAltName':
                    values = extension.__str__().split()
                    for value in values:
                        name = value.strip('DNS:').strip(',')
                        if name not in names:
                            names.append(name)
    except:
        names = ["no connection"]
    san = ""
    for i in names:
        san = san+"<br>"+i
    return(san)


def sslyzescan(host,port):
    print("=> Starting the scans")
    date_scans_started = datetime.utcnow()

    # First create the scan requests for each server that we want to scan
    try:
        all_scan_requests = [
        ServerScanRequest(server_location=ServerNetworkLocation(hostname=host, port=port)),
        ]
    except ServerHostnameCouldNotBeResolved:
    # Handle bad input ie. invalid hostnames
        print("Error resolving the supplied hostnames")
        return
    # Then queue all the scans
    scanner = Scanner()
    scanner.queue_scans(all_scan_requests)


    for server_scan_result in scanner.get_results():
        #if str(server_scan_result.connectivity_result) != "None":
        print(str(server_scan_result.network_configuration))
        print(str(server_scan_result.server_location))
        print(str(server_scan_result.scan_result))
        if str(server_scan_result.scan_result) != "None":
            print(f"\n\n****Results for {server_scan_result.server_location.hostname}:"+port+"****")
            #if CLIENT_CERTIFICATE_NEEDED :
            san = scan_host(host,port)
            allowed_ciphers = ""
            for ssl2_0 in server_scan_result.scan_result.ssl_2_0_cipher_suites.result.accepted_cipher_suites:
                allowed_ciphers=allowed_ciphers+"ssl2.0-cipher:"+ssl2_0.cipher_suite.name+"<br>"
            for ssl3_0 in server_scan_result.scan_result.ssl_3_0_cipher_suites.result.accepted_cipher_suites:
                allowed_ciphers=allowed_ciphers+"ssl3.0-cipher:"+ssl3_0.cipher_suite.name+"<br>"
            for tls1_0 in server_scan_result.scan_result.tls_1_0_cipher_suites.result.accepted_cipher_suites:
                allowed_ciphers=allowed_ciphers+"tls1.0-cipher:"+tls1_0.cipher_suite.name+"<br>"

            for tls1_1 in server_scan_result.scan_result.tls_1_1_cipher_suites.result.accepted_cipher_suites:
                allowed_ciphers=allowed_ciphers+"tls1.1-cipher:"+tls1_1.cipher_suite.name+"<br>"

            for tls1_2 in server_scan_result.scan_result.tls_1_2_cipher_suites.result.accepted_cipher_suites:
                allowed_ciphers=allowed_ciphers+"tls1.2-cipher:"+tls1_2.cipher_suite.name+"<br>"

            for tls1_3 in server_scan_result.scan_result.tls_1_3_cipher_suites.result.accepted_cipher_suites:
                allowed_ciphers=allowed_ciphers+"tls1.3-cipher:"+tls1_3.cipher_suite.name+"<br>"
            
            write_into_ip_service_tls(host,port,allowed_ciphers,san)

if __name__ == "__main__":
    main()


#!/usr/bin/env python3


# TODO: import nmap XML or greppable
# TODO: pretty-print the results
# TODO: sqlite storage, then output data in different formats (csv, json)


