
'''
    Created on 10/10/23
    Common helpers when analyzing x509 cert
'''
import re
import socket
import dns.resolver
from OpenSSL import SSL

import hashlib
import requests
import chardet
from enum import Enum

from bidict import bidict
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


# Identifiers for X509 cert type based on its position in the cert chain
class CertType(Enum):
    LEAFCERT = 0
    INTERMEDIATECERT = 1
    ROOTCERT =  2

BIMAP_CERTIFICATE_TYPE_AND_NAME : bidict = bidict({
    CertType.LEAFCERT : "Leaf",
    CertType.INTERMEDIATECERT : "Intermediate",
    CertType.ROOTCERT : "Root"    
})

# Identifiers for x509 leaf cert basd on its policies
class LeafCertType(Enum):
    DV = 0
    IV = 1
    OV = 2
    EV = 3

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


# For a given file, detect its encoding and return the content
def detectFileEncoding(file_path : str) -> Tuple[bytes, str]:
    with open(file_path, 'rb') as cert_file:
        raw_data = cert_file.read()
        result = chardet.detect(raw_data)
    return raw_data, result['encoding']


def getNameAttribute(
        name : Name,
        oid : ObjectIdentifier,
        value_if_exception : any
    ) -> any:

    '''
        Edited 11/05/23
        This function also checks if one RDN has multiple attribute and value
    '''
    try:
        attributes = name.get_attributes_for_oid(oid)
        return attributes[0].value

    except (AttributeNotFound, IndexError):
        # my_logger.warn(f"Name attribute {oid} in {name} not found")
        return value_if_exception


# Extract domain from given URL
def extractDomain(url : str):
    parsed_url = urlparse(url)
    if parsed_url.netloc:
        return parsed_url.netloc
    else:
        return None


def isDomainMatch(source_domain : str, dest_domain : str):
    # if wilicard domain, convert to regular expression representing the whole
    pattern = dest_domain.replace(".", r"\.").replace("*", ".*")
    # pattern = pattern.replace("[", "\[").replace("]", "\]")
    # pattern = pattern.replace("(", "\(").replace(")", "\)")
    pattern = f"^{pattern}$"

    if bool(re.match(pattern, source_domain)) == False:
        my_logger.warn(f"{pattern} and {source_domain} does not match...")
        return False
    return True


def utcTimeDifferenceInDays(first : datetime, second : datetime) -> int:
    # return first - second in days
    time_difference = first - second
    return time_difference.days


def checkLocalDomain(domain : str) -> bool:
    return "local" in domain

def checkLocalIP(ip : str) -> bool:
    return True


def get_dns_caa_records(domain : str, timeout=5) -> Tuple[list[str], list[str]]:

    try:
        resolver = dns.resolver.Resolver(configure=False)
        resolver.timeout = timeout

        # answers = dns.resolver.resolve(domain, 'A')  # A记录
        # print(f"A records for {domain}:")
        # for rdata in answers:
        #     print(rdata.address)

        # answers = dns.resolver.resolve(domain, 'AAAA')  # AAAA记录 (IPv6)
        # print(f"AAAA records for {domain}:")
        # for rdata in answers:
        #     print(rdata.address)

        # answers = dns.resolver.resolve(domain, 'CNAME')  # CNAME记录
        # print(f"CNAME records for {domain}:")
        # for rdata in answers:
        #     print(rdata.target)

        # answers = dns.resolver.resolve(domain, 'MX')  # MX记录
        # print(f"MX records for {domain}:")
        # for rdata in answers:
        #     print(f"Preference: {rdata.preference}, Mail Server: {rdata.exchange}")

        # answers = dns.resolver.resolve(domain, 'TXT')  # TXT记录
        # print(f"TXT records for {domain}:")
        # for rdata in answers:
        #     print(rdata.strings)

        # answers = dns.resolver.resolve(domain, 'NS')  # NS记录
        # print(f"NS records for {domain}:")
        # for rdata in answers:
        #     print(rdata.target)

        issue_ca = []
        issue_wildcard_ca = []
        answers = resolver.resolve(domain, 'CAA')  # CAA记录
        print(answers)

        for rdata in answers:
            if rdata.flags == 0 and rdata.tag == "issue":
                issue_ca.append(rdata.value)
            if rdata.flags == 0 and rdata.tag == "issuewild":
                issue_wildcard_ca.append(rdata.value)

        return (issue_ca, issue_wildcard_ca)

    except dns.resolver.NoAnswer:
        my_logger.debug(f"No DNS records found for {domain}")
        return [], []

    except dns.resolver.NXDOMAIN:
        my_logger.debug(f"Domain {domain} does not exist")
        return [], []

    except dns.resolver.NoNameservers:
        my_logger.debug(f"No nameservers found for {domain}")
        return [], []

    except dns.resolver.Timeout:
        my_logger.warn(f"DNS query for {domain} timed out")
        return [], []

    except Exception as e:
        my_logger.warn(f"Error: {e}")
        return [], []


def get_cert_sha256_hex(cert : Certificate) -> str:
    sha256_hash = hashlib.sha256(cert.public_bytes(Encoding.PEM))
    sha256_hex = sha256_hash.hexdigest()
    return sha256_hex
