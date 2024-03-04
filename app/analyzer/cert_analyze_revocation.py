
import re
import hashlib
import requests
import chardet
from enum import Enum

from typing import Optional
from datetime import datetime
from urllib.parse import urlparse
from typing import Dict, Tuple

from ..logger.logger import my_logger
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.hazmat.primitives.hashes import SHA256, SHA1
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.x509 import (
    Version,
    Name,
    DNSName,
    Certificate,
    ReasonFlags,
    ObjectIdentifier,
    AttributeNotFound,
    ExtensionNotFound,
    CertificateRevocationList,
    load_pem_x509_crl,
    load_der_x509_crl
)

from cryptography.x509.ocsp import (
    OCSPRequestBuilder,
    OCSPResponseStatus,
    OCSPCertStatus,
    OCSPResponse,
    load_der_ocsp_response
)


'''
    Create OCSP request:
        Contact OCSP server and check the cert OCSP status

    OCSP Request Data Structure Example:
        Version: 1 (0x0)
        Requestor List:
            Certificate ID:
            Hash Algorithm: sha1
            Issuer Name Hash: 52FECA108DB4E5AB5268930D27C82FF215E24BB5
            Issuer Key Hash: 00AB91FC216226979AA8791B61419060A96267FD
            Serial Number: 3300AB78D29C2E8D26F9DF8169000000AB78D2
        Request Extensions:
            OCSP Nonce: 
                0410CE52A9CC9405C6B438E23DB7607410A9
'''
def requestOCSPResponse(
        cert : Certificate,
        issuer : Certificate,
        server_url : str,
        hash : hashes = SHA1(),
        retry_times : int = 4
    ) -> Optional[OCSPResponse]:

    '''
        From doc:
        While RFC 5019 originally required SHA1,
        RFC 6960 updates that to SHA256.
        However, depending on your requirements you may need to use SHA1
        for compatibility reasons.

        So we do the following:
        Use SHA1 first, if return status is OCSPResponseStatus.UNAUTHORIZED,
        we switch to SHA256 next
    '''
    builder = OCSPRequestBuilder()
    builder = builder.add_certificate(cert, issuer, hash)
    request = builder.build()

    try:
        try:
            my_logger.debug(f"Requesting OCSP response from {server_url}...")
            raw_response = requests.post(
                server_url,
                data=request.public_bytes(serialization.Encoding.DER),
                headers={"Content-Type": "application/ocsp-request"},
                timeout=5
            )
        except requests.exceptions.RequestException as e:
            '''
                10/19/23 update:
                To avoid OCSP server not responding, we retry serveral times
            '''
            if retry_times <= 0:
                my_logger.error(f"OCSP server {server_url} does not respond after retrying several times...")
                return None
            else:
                return requestOCSPResponse(cert, issuer, server_url, hash, retry_times - 1)


        response = load_der_ocsp_response(raw_response.content)
        if hash == SHA1() and response.response_status == OCSPResponseStatus.UNAUTHORIZED:
            return requestOCSPResponse(cert, issuer, SHA256())
        return response

    # Sometimes, the response may not complete...
    except ValueError as e:
        my_logger.warn(f"OCSP response from {server_url} is not complete, retrying...")
        return requestOCSPResponse(cert, issuer, server_url, hash, retry_times - 1)
    except Exception as e:
        my_logger.error(f"Error when getting OCSP response: {e}")
        return None


# Cache for CRL file
crl_cache : Dict[str, CertificateRevocationList] = {}

def requestCRLResponse(
        crl_url : str,
        retry_times : int = 4
    ) -> Optional[CertificateRevocationList]:

    # Check cache hit
    if crl_url in crl_cache.keys():
        return crl_cache[crl_url]
    
    try:
        my_logger.debug(f"Requesting CRL from {crl_url}...")
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36'
        }
        crl_response = requests.get(crl_url, headers=headers)
        if not crl_response.status_code == 200:
            my_logger.warn(f"Server {crl_url} rejected CRL reqeust")
            return None
        crl = load_pem_x509_crl(crl_response.content, default_backend())
        crl_cache[crl_url] = crl
        return crl

    except requests.exceptions.RequestException:
        if retry_times <= 0:
            my_logger.error(f"Can not retrieve CRL after retrying several times...")
            return None
        else:
            return requestCRLResponse(crl_url, retry_times - 1)

    except ValueError:
        my_logger.debug("CRL response is encoded with DER")
        return load_der_x509_crl(crl_response.content, default_backend())


