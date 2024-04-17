
import sys
sys.path.append(r"E:\global_ca_monitor")

import json
import base64
import requests
from app.parser.ct_parser import *
from app.logger.logger import my_logger
from OpenSSL import crypto
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

log_address = "oak.ct.letsencrypt.org/2024h1"
log_server_request = f'https://{log_address}/ct/v1/get-entries'
start = 5
end = 50
params = {'start': start, 'end': end}

entries = []
try:
    response = requests.get(log_server_request, params=params, verify=True)
except Exception as e:
    my_logger.warning(f"Exception {e} when requesting CT entries from {start} to {end}")

if response.status_code == 200:
    entries = json.loads(response.text)['entries']
else:
    my_logger.warning(f"Requesting CT entries from {start} to {end} failed.")

result = []
for entry in entries:

    leaf_cert = merkle_tree_header.parse(base64.b64decode(entry['leaf_input']))
    if leaf_cert.LogEntryType == "X509LogEntryType":
        # We have a normal x509 entry
        cert_data_string = certificate.parse(leaf_cert.Entry).CertData
        result.append(crypto.load_certificate(crypto.FILETYPE_ASN1, cert_data_string).to_cryptography().public_bytes(Encoding.PEM).decode('utf-8'))

        # Parse the `extra_data` structure for the rest of the chain
        extra_data = certificate_chain.parse(base64.b64decode(entry['extra_data']))
        for cert in extra_data.Chain:
            result.append(crypto.load_certificate(crypto.FILETYPE_ASN1, cert.CertData).to_cryptography().public_bytes(Encoding.PEM).decode('utf-8'))

    else:
        # We have a precert entry
        extra_data = pre_cert_entry.parse(base64.b64decode(entry['extra_data']))
        result.append(crypto.load_certificate(crypto.FILETYPE_ASN1, extra_data.LeafCert.CertData).to_cryptography().public_bytes(Encoding.PEM).decode('utf-8'))

        for cert in extra_data.CertChain.Chain:
            result.append(crypto.load_certificate(crypto.FILETYPE_ASN1, cert.CertData).to_cryptography().public_bytes(Encoding.PEM).decode('utf-8'))
print(result)
