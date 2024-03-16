import re
import hashlib
from datetime import datetime
from urllib.parse import urlparse
from ..logger.logger import my_logger

from cryptography.hazmat.primitives.serialization import Encoding
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

def get_name_attribute(
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
def domain_extract(url : str):
    parsed_url = urlparse(url)
    if parsed_url.netloc:
        return parsed_url.netloc
    else:
        return None

def is_domain_match(source_domain : str, dest_domain : str):
    # if wilicard domain, convert to regular expression representing the whole
    pattern = dest_domain.replace(".", r"\.").replace("*", ".*")
    # pattern = pattern.replace("[", "\[").replace("]", "\]")
    # pattern = pattern.replace("(", "\(").replace(")", "\)")
    pattern = f"^{pattern}$"

    if bool(re.match(pattern, source_domain)) == False:
        my_logger.warn(f"{pattern} and {source_domain} does not match...")
        return False
    return True

def utc_time_diff_in_days(first : datetime, second : datetime) -> int:
    # return first - second in days
    time_difference = first - second
    return time_difference.days

def check_local_domain(domain : str) -> bool:
    return "local" in domain

def check_local_ip(ip : str) -> bool:
    return True

def get_cert_sha256_hex_from_object(cert : Certificate) -> str:
    sha256_hash = hashlib.sha256(cert.public_bytes(Encoding.PEM))
    sha256_hex = sha256_hash.hexdigest()
    return sha256_hex

def get_cert_sha256_hex_from_str(cert : str) -> str:
    sha256_hash = hashlib.sha256(cert.encode())
    sha256_hex = sha256_hash.hexdigest()
    return sha256_hex
