
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
# from cryptography.hazmat.backends.openssl import rsa, ec
from cryptography.hazmat.primitives.asymmetric import dsa as primitive_dsa, rsa as primitive_rsa, ec as primitive_ec, dh as primitive_dh
from cryptography.hazmat.primitives.asymmetric import types, padding
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.x509 import (
    Version,
    Name,
    DNSName,
    Certificate,
    ReasonFlags,
    ExtensionType,
    ObjectIdentifier,
    AttributeNotFound,
    ExtensionNotFound,
    KeyUsage,
    ExtendedKeyUsage,
    CRLDistributionPoints,
    AuthorityInformationAccess,
    BasicConstraints,
    SubjectAlternativeName,
    CertificatePolicies,
    load_pem_x509_certificate,
)
import cryptography.hazmat.bindings
from cryptography.x509 import Extensions
from cryptography.x509.oid import NameOID, ExtensionOID, SignatureAlgorithmOID, ExtendedKeyUsageOID
from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from ..logger.logger import my_logger

from ..utils.cert import (
    domain_extract,
    is_domain_match,
    utc_time_diff_in_days,
    get_name_attribute,
    get_cert_sha256_hex_from_object
)

from datetime import datetime, timezone
from dataclasses import dataclass, asdict
from typing import Optional, Dict, List, Union, Tuple
from ..utils.type import CertType, LeafCertType
from ..utils.exception import ParseError
from .cert_parser_extension import X509CertExtensionParser, ExtensionResult, ExtensionResultWarpper


@dataclass
class X509ParsedInfo():

    version : Version
    serial_number : int

    issuer_cn : str
    issuer_org : str
    issuer_country : str

    not_valid_before_utc : datetime
    not_valid_after_utc : datetime
    validation_period : int     # in days

    subject_cn : str             # only for subject_cn field
    subject_org : Optional[str]
    subject_country : Optional[str]

    subject_pub_key_algo : types.CertificatePublicKeyTypes
    subject_pub_key_size : int

    # cert_signature_algorithm : str
    cert_signature_hash_algorithm : str
    cert_type : CertType
    sha_256 : str

    extension_parsed_info : ExtensionResultWarpper
    cert_raw : str
    pub_key_raw : str


# main stuff here
class X509CertParser():

    def __init__(
            self,
            cert : str
        ) -> None:

        try:
            self.cert = (load_pem_x509_certificate(cert.encode("utf-8"), default_backend()))
            self.extension_parser = X509CertExtensionParser(self.cert.extensions)
            self.parsed_info = self.parse_cert_base()
        except Exception as e:
            my_logger.warn(e)
            my_logger.warn("Meet cert ASN.1 format violation, skip it")
            raise ParseError


    def parse_cert_base(self) -> X509ParsedInfo:

        subject = self.cert.subject
        subject_cn = get_name_attribute(subject, NameOID.COMMON_NAME, None)
        subject_org = get_name_attribute(subject, NameOID.ORGANIZATION_NAME, None)
        subject_country = get_name_attribute(subject, NameOID.COUNTRY_NAME, None)

        issuer = self.cert.issuer
        issuer_cn = get_name_attribute(issuer, NameOID.COMMON_NAME, None)
        issuer_org = get_name_attribute(issuer, NameOID.ORGANIZATION_NAME, None)
        issuer_country = get_name_attribute(issuer, NameOID.COUNTRY_NAME, None)

        time_begin = self.cert.not_valid_before_utc
        time_end = self.cert.not_valid_after_utc
        cert_period = utc_time_diff_in_days(time_end, time_begin)


        pub_key_type = self.cert.public_key()
        try:
            pub_key_size = pub_key_type.key_size
        except:
            # AttributeError: 'cryptography.hazmat.bindings._rust.openssl.ed25519' object has no attribute 'key_size'
            pub_key_size = -1

        try:
            signature_hash_algorithm = self.cert.signature_hash_algorithm
            signature_hash_algorithm_name = signature_hash_algorithm.name
        except UnsupportedAlgorithm:
            '''
                cryptography.exceptions.UnsupportedAlgorithm: 
                Signature algorithm OID: 1.2.840.113549.1.1.10 not recognized
            '''
            signature_hash_algorithm = None
            signature_hash_algorithm_name = "Unsupported"
        except AttributeError:
            signature_hash_algorithm = None
            signature_hash_algorithm_name = "None"

        # SHA256
        sha256_hex = get_cert_sha256_hex_from_object(self.cert)

        # Check cert type
        try:
            basic_constraints_result = self.cert.extensions.get_extension_for_oid(oid=ExtensionOID.BASIC_CONSTRAINTS)
            if basic_constraints_result.value.ca:
                if subject == issuer:
                    cert_type = CertType.ROOT
                else:
                    cert_type = CertType.INTERMEDIATE
            else:
                cert_type = CertType.LEAF
        except ExtensionNotFound:
            cert_type = CertType.LEAF

        return X509ParsedInfo(
            self.cert.version,
            self.cert.serial_number,
            issuer_cn,
            issuer_org,
            issuer_country,
            time_begin,
            time_end,
            cert_period,
            subject_cn,
            subject_org,
            subject_country,
            pub_key_type,
            pub_key_size,
            signature_hash_algorithm_name,
            cert_type,
            sha256_hex,
            self.extension_parser.analyzeExtensions(),
            self.cert.public_bytes(Encoding.PEM).decode(),
            self.cert.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo).decode()
        )
    

    def to_json(self):
        KEY_TYPE_MAPPING = {
            primitive_rsa.RSAPublicKey : 0,
            primitive_ec.EllipticCurvePublicKey : 1,
            cryptography.hazmat.bindings._rust.openssl.rsa.RSAPublicKey : 0,
            cryptography.hazmat.bindings._rust.openssl.ec.ECPublicKey : 1,
            cryptography.hazmat.bindings._rust.openssl.ed25519.Ed25519PublicKey : 2
        }

        return {
            "version" : self.parsed_info.version.name,
            "serial_number" : self.parsed_info.serial_number,
            "issuer_cn" : self.parsed_info.issuer_cn,
            "issuer_org" : self.parsed_info.issuer_org,
            "issuer_country" : self.parsed_info.issuer_country,
            "not_valid_before_utc" : self.parsed_info.not_valid_before_utc,
            "not_valid_after_utc" : self.parsed_info.not_valid_after_utc,
            "validation_period" : self.parsed_info.validation_period,
            "subject_cn" : self.parsed_info.subject_cn,
            "subject_org" : self.parsed_info.subject_org,
            "subject_country" : self.parsed_info.subject_country,
            "subject_pub_key_algo" : KEY_TYPE_MAPPING[self.parsed_info.subject_pub_key_algo.__class__],
            "subject_pub_key_size" : self.parsed_info.subject_pub_key_size,
            "cert_signature_hash_algorithm" : self.parsed_info.cert_signature_hash_algorithm,
            "cert_type" : self.parsed_info.cert_type.value,
            "sha_256" : self.parsed_info.sha_256,

            # self.cert.public_key().public_bytes(
            #     encoding=Encoding.PEM,
            #     format=PublicFormat.SubjectPublicKeyInfo
            # ).decode(),
            # self.cert.public_key().public_numbers().n,
            # self.cert.public_key().public_numbers().e,
        }
    
