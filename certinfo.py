
from sslyze.server_connectivity import ServerConnectivityInfo, ServerConnectivityError
from sslyze.ssl_settings import HttpConnectTunnelingSettings, TlsWrappedProtocolEnum
from sslyze.plugins.certificate_info_plugin import CertificateInfoScanCommand
from sslyze.synchronous_scanner import SynchronousScanner
from cryptography.hazmat.backends.openssl import x509
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509 import DNSName, ExtensionNotFound, ExtensionOID, NameOID
from enum import Enum
import os
import json
import sys

def get_dns_subject_alternative_names(certificate):
    # type: (cryptography.x509.Certificate) -> List[Text]
    """Retrieve all the DNS entries of the Subject Alternative Name extension.
    """
    subj_alt_names = []
    try:
        san_ext = certificate.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        subj_alt_names = san_ext.value.get_values_for_type(DNSName)
    except ExtensionNotFound:
        pass
    return subj_alt_names

def get_basic_constraints(cert):
    # return true/false based on basic constraints
    try:
        ext = cert.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS)
        return ext.value.ca
    except ExtensionNotFound:
        pass
    return False

def certificate_to_json(cert):
    return {
            'id': str(cert.serial_number),
            'domains': list(map(lambda x: x.value, cert.subject)),
            "not_after": str(cert.not_valid_after),
            "not_before" : str(cert.not_valid_before),
            "issuer":  ", ".join(map(lambda x:x.value, cert.issuer)),
            "basic_constraints": False,
            "pem": cert.public_bytes(Encoding.PEM).decode('ascii'),
    "alt_names": get_dns_subject_alternative_names(cert),
    "basic_constraints": get_basic_constraints(cert)
    }

def object_to_json_dict(obj):
    """Convert an object to a dictionary suitable for the JSON output."""
    if obj is None:
        return None
    elif isinstance(obj, str):
        return obj
    elif isinstance(obj, int):
        return obj
    elif isinstance(obj, Enum):
        return obj.name
    elif isinstance(obj, x509._Certificate):
        return certificate_to_json(obj)
    elif isinstance(obj, object):
        result = {}
        for key, value in obj.__dict__.items():
            # Remove private attributes
            if key.startswith('_'):
                continue

            result[key] = value
        return result

    else:
        raise TypeError('Unknown type: {}'.format(repr(obj)))
    return ""


if __name__ == "__main__":
    try:
        server_info = ServerConnectivityInfo(hostname=sys.argv[1], port=443,
                            tls_wrapped_protocol=TlsWrappedProtocolEnum.HTTPS)
        server_info.test_connectivity_to_server()
    except ServerConnectivityError as e:
        print("Impossible to connect")
        sys.exit(1)

    synchronous_scanner = SynchronousScanner()
    command = CertificateInfoScanCommand()
    scan_result = synchronous_scanner.run_scan_command(server_info, command)
    result = {
            "success": True,
            "cert_info": {},
            "certificate_chain": [],
            "server_info": {}
    }
    for c in scan_result.certificate_chain:
        result["certificate_chain"].append(certificate_to_json(c))

    for p in scan_result.server_info.__dict__:
        result["server_info"][p] = object_to_json_dict(getattr(scan_result.server_info, p))
    for p in ["certificate_matches_hostname", "has_anchor_in_certificate_chain", "has_sha1_in_certificate_chain", "is_certificate_chain_order_valid", "is_leaf_certificate_ev", "is_ocsp_response_trusted", "ocsp_response"]:
        if hasattr(scan_result, p):
            result["cert_info"][p] = object_to_json_dict(getattr(scan_result, p))
    result["cert_info"]["cert"] = certificate_to_json(scan_result.certificate_chain[0])
    print(json.dumps(result, sort_keys=True, indent=4, separators=(',', ': ')))
