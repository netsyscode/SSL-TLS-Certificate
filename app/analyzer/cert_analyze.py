
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
    load_pem_x509_certificates
)

from cryptography.x509.oid import NameOID, ExtensionOID, SignatureAlgorithmOID, ExtendedKeyUsageOID
from cryptography.x509.ocsp import OCSPCertStatus, OCSPResponseStatus, OCSPResponse
from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.x509 import Extensions

from .utils import (
    CertType,
    LeafCertType,
    requestCRLResponse,
    requestOCSPResponse,
    extractDomain,
    isDomainMatch,
    utcTimeDifferenceInDays,
    getNameAttribute,
    get_dns_caa_records,
    getCertSHA256Hex
)

from ..logger.logger import my_logger

from abc import ABC, abstractmethod
from datetime import datetime, timezone
from dataclasses import dataclass, asdict
from typing import Optional, Dict, List, Union, Tuple
from queue import Queue
import hashlib
import jsonlines
import json
import os


from sqlalchemy.exc import IntegrityError
from sqlalchemy import insert
from ..models import CertAnalysisStats, CertStoreContent
from app import app, db
from threading import Lock
import threading
import time

@dataclass
class X509SingleCertResult():

    cert_type : CertType

    # Subject analysis
    subject_cn : str             # only for subject_cn field
    subject_cns : List[str]      # SAN included 
    subject_org : Optional[str]
    subject_country : Optional[str]

    # Issuer analysis
    issuer_cn : str
    issuer_org : str
    issuer_country : str
    # is_issuer_name_matched : bool

    # Expiration analysis
    not_valid_before : datetime
    validation_period : int     # in days
    has_expired : bool

    # crypto checking
    pub_key : str
    subject_pub_key_type : types.CertificatePublicKeyTypes
    subject_pub_key_size : int
    cert_signature_hash_algorithm : str
    # cert_signature_algorithm : Union[None, padding.PKCS1v15, padding.PSS, ec.ECDSA]
    # cert_signature_algorithm : str
    # cert_signature_verified : bool

    '''
        Revocation analysis: CRL and OCSP
        1. CRL:
            is_revoked_from_CRL:
                Check from CRL, has None if:
                    the CRL server does not respond
                    the cert does not support CRL (CRL Distribution Points) extension
        2. OCSP:
            ocsp_response_status:
                Check OCSP server status, has None if:
                    the server does not respond
                    the cert has no AIA (Authority Information Access) extension
    '''
    is_revoked_from_CRL : Optional[bool]
    ocsp_response_status : Optional[OCSPResponseStatus]
    ocsp_cert_status : Optional[OCSPCertStatus]
    # revocation_time : Optional[datetime]
    # revocation_reason : Optional[ReasonFlags]

    raw_str : str
    sha_256 : str


# main stuff here
class X509SingleCertAnalyzer():

    def __init__(
            self,
            host_name: str,
            cert_type: CertType,
            cert: Certificate,
            issuer_cert: Optional[Certificate],
        ) -> None:

        self.host_name = host_name
        self.cert_type = cert_type
        self.cert = cert
        self.issuer_cert = issuer_cert


    def checkRevocationStatusFromOCSP(
            self
        )-> Tuple[Optional[OCSPResponseStatus], Optional[OCSPCertStatus], Optional[datetime], Optional[ReasonFlags]]:

        if self.issuer_cert is None: return None
        try:
            ocsp_server_url = None
            ocsp_info = self.cert.extensions.get_extension_for_oid(ExtensionOID.AUTHORITY_INFORMATION_ACCESS)
            if ocsp_info:
                for access_description in ocsp_info.value:
                    if access_description.access_method._name == "OCSP":
                        ocsp_server_url = access_description.access_location.value

            ocsp_response = requestOCSPResponse(self.cert, self.issuer_cert, ocsp_server_url)
            if not ocsp_response:
                my_logger.warn(f"OCSP server for certificate {self.cert.serial_number} does not respond")
                return None
            
            ocsp_status = ocsp_response.response_status
            cert_status = None
            revocation_time = None
            revocation_reason = None
            if ocsp_status == OCSPResponseStatus.SUCCESSFUL:
                cert_status = ocsp_response.certificate_status
                if cert_status == OCSPCertStatus.REVOKED:
                    revocation_time = ocsp_response.revocation_time
                    revocation_reason = ocsp_response.revocation_reason

            return ocsp_status, cert_status, revocation_time, revocation_reason
        
        except ExtensionNotFound as e:
            my_logger.warn(f"Cert extension {e.oid} not found")
            return None


    def checkRevocationStatusFromCRL(self) -> Optional[bool]:

        '''
            Warning: return False does not always mean the cert is not revoked
            
            Sometimes, the CA might remove the cert from CRL after a period of time of expiration to reduce the CRL size
            So make sure to check whether the cert is expired in the caller
        '''
        try:
            crl_distribution_points = self.cert.extensions.get_extension_for_oid(ExtensionOID.CRL_DISTRIBUTION_POINTS)
            crl_distribution_points = crl_distribution_points.value

            crl_url = crl_distribution_points[0].full_name[0].value
            crl = requestCRLResponse(crl_url)

            if crl:
                crl_entry = crl.get_revoked_certificate_by_serial_number(self.cert.serial_number)
                if crl_entry: return True
                else: return False

            # No CRL response
            return None
        
        except ExtensionNotFound as e:
            my_logger.warn(f"Cert extension {e.oid} not found")
            return None


    def verifySignature(self) -> bool:
        sig_verified = False

        if self.issuer_cert is not None:
            issuer_pub_key = self.issuer_cert.public_key()
            try:
                if issuer_pub_key.__class__ == primitive_rsa.RSAPublicKey:
                    issuer_pub_key.verify(
                        self.cert.signature,
                        self.cert.tbs_certificate_bytes,
                        # Depends on the algorithm used to create the certificate
                        padding.PKCS1v15(),
                        self.cert.signature_hash_algorithm
                    )
                elif issuer_pub_key.__class__ == primitive_ec.EllipticCurvePublicKey:
                    issuer_pub_key.verify(
                        self.cert.signature,
                        self.cert.tbs_certificate_bytes,
                        primitive_ec.ECDSA(hashes.SHA256())
                    )
                elif issuer_pub_key.__class__ == primitive_dsa.DSAPublicKey:
                    issuer_pub_key.verify(
                        self.cert.signature,
                        self.cert.tbs_certificate_bytes,
                        self.cert.signature_hash_algorithm
                    )
                else:
                    issuer_pub_key.verify(
                        self.cert.signature,
                        self.cert.tbs_certificate_bytes
                    )
                sig_verified = True
            except InvalidSignature:
                my_logger.warn(f"Cert {self.cert.serial_number} signature checking failed")
                sig_verified = False
        else:
            my_logger.warn(f"Cert {self.cert.serial_number} has no issuer cert avaliable")

        return sig_verified
    

    def analyzeSingleCertBase(self) -> X509SingleCertResult:

        subject = self.cert.subject
        subject_cn, is_subject_cn_mult = getNameAttribute(subject, NameOID.COMMON_NAME, None)
        subject_org, is_subject_org_mult = getNameAttribute(subject, NameOID.ORGANIZATION_NAME, None)
        subject_country, is_subject_country_mult = getNameAttribute(subject, NameOID.COUNTRY_NAME, None)

        issuer = self.cert.issuer
        issuer_cn, is_issuer_cn_mult = getNameAttribute(issuer, NameOID.COMMON_NAME, None)
        issuer_org, is_issuer_org_mult = getNameAttribute(issuer, NameOID.ORGANIZATION_NAME, None)
        issuer_country, is_issuer_country_mult = getNameAttribute(issuer, NameOID.COUNTRY_NAME, None)

        time_begin = self.cert.not_valid_before_utc
        time_end = self.cert.not_valid_after_utc
        cert_period = utcTimeDifferenceInDays(time_end, time_begin)
        current_utc_time = datetime.now(timezone.utc)

        # 通过添加时区信息确保 time_end 也是 UTC 时间
        time_end_utc = time_end.replace(tzinfo=timezone.utc)
        has_expired = (current_utc_time > time_end_utc)

        pub_key_type = self.cert.public_key()
        pub_key_size = pub_key_type.key_size

        try:
            signature_hash_algorithm = self.cert.signature_hash_algorithm
            signature_hash_algorithm_name = self.cert.signature_hash_algorithm.name
        except UnsupportedAlgorithm:
            '''
                cryptography.exceptions.UnsupportedAlgorithm: 
                Signature algorithm OID: 1.2.840.113549.1.1.10 not recognized
            '''
            signature_hash_algorithm = None
            signature_hash_algorithm_name = "Unsupported"

        # Check CRL
        # crl_revoked = self.checkRevocationStatusFromCRL()
        crl_revoked = None
        # Check OCSP:
        ocsp_status, cert_status, revocation_time, revocation_reason = None, None, None, None
        # ocsp_result = self.checkRevocationStatusFromOCSP()
        # if ocsp_result is not None:
            # ocsp_status, cert_status, revocation_time, revocation_reason = ocsp_result

        # SHA256
        sha256_hex = getCertSHA256Hex(self.cert)

        return X509SingleCertResult(

            self.cert_type,
            subject_cn,
            [subject_cn],
            subject_org,
            subject_country,
            issuer_cn,
            issuer_org,
            issuer_country,
            time_begin,
            cert_period,
            has_expired,
            self.cert.public_key().public_bytes(
                encoding=Encoding.PEM,
                format=PublicFormat.SubjectPublicKeyInfo
            ).decode(),
            pub_key_type,
            pub_key_size,
            signature_hash_algorithm_name,
            crl_revoked,
            ocsp_status,
            cert_status,
            self.cert.public_bytes(Encoding.PEM).decode("utf-8"),
            sha256_hex
        )


class CertScanAnalyzer():

    def __init__(
            self,
            scan_id : str,
            scan_input_table_name : str,
        ) -> None:

        self.scan_id = scan_id
        self.result_list = []
        self.result_list_lock = Lock()
        self.scan_input_table = db.Model.metadata.tables[scan_input_table_name]
        # self.result_table = generate_cert_analysis_table(f"cert_analysis{scan_input_table_name[-14:]}")
        self.existing_cert_analysis_store : CertAnalysisStats = CertAnalysisStats.query.filter_by(SCAN_ID=scan_id).first()

        self.num = 0
        self.expired = 0
        self.issuer = []
        self.algo = []
        self.length = []
        self.valid = []


    def analyzeCertScanResult(self):
        my_logger.info(f"Starting {self.scan_input_table} scan analysis...")
        # timer_thread = threading.Thread(target=self.async_update_info)
        # timer_thread.daemon = True  # 设置为守护线程，以便主线程退出时自动退出定时器线程
        # timer_thread.start()

        
        from sqlalchemy import select
        with app.app_context():
            query = select(self.scan_input_table)
            rows = db.session.execute(query).all()

            for row in rows:

                # 'sha256_id': self.CERT_ID,
                # 'raw': self.CERT_RAW,
                cert_id = row[0]
                try:
                    certs_as_x509 = (load_pem_x509_certificate(row[1].encode("utf-8"), default_backend()))
                except:
                    my_logger.warn("Meet cert ASN.1 format violation")
                    continue

                #     # Check cert type
                #     cert_type = X509CertType.LEAFCERT
                #     basic_constraints_result = Extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS)

                #     if basic_constraints_result:
                #         if basic_constraints_result.ca_bit:
                #             if cert.subject == cert.issuer:
                #                 cert_type = X509CertType.ROOTCERT
                #                 continue
                #             else:
                #                 cert_type = X509CertType.INTERMEDIATECERT
                #                 continue

                single_cert_analyzer = X509SingleCertAnalyzer("", CertType.LEAFCERT, certs_as_x509, certs_as_x509)
                cert_analysis_result = single_cert_analyzer.analyzeSingleCertBase()
                self.result_list.append(cert_analysis_result)

        my_logger.info("Cert scan analysis completed")
        self.sync_update_info()


    def async_update_info(self):
        self.sync_update_info()
        time.sleep(10)


    def sync_update_info(self):
        my_logger.info(f"Updating...")
        with self.result_list_lock:
            with app.app_context():

                from collections import Counter
                # insert_analysis_data_statement = insert(self.result_table)
                cert_store_data_to_insert = []

                KEY_TYPE_MAPPING = {
                    primitive_rsa.RSAPublicKey : 0,
                    primitive_ec.EllipticCurvePublicKey : 1
                }

                for result in self.result_list:
                    result : X509SingleCertResult
                    cert_store_data_to_insert.append({
                        'CERT_ID' : result.sha_256,
                        'CERT_RAW' : result.raw_str,                      
                        'CERT_TYPE' : result.cert_type.value,
                        'ISSUER_ORG' : result.issuer_cn,
                        'ISSUER_CERT_ID' : "",
                        'KEY_SIZE' : result.subject_pub_key_size,
                        'KEY_TYPE' : KEY_TYPE_MAPPING[result.subject_pub_key_type.__class__],
                        'NOT_VALID_BEFORE' : result.not_valid_before,
                        'NOT_VALID_BEFORE' : result.not_valid_before,
                        'VALIDATION_PERIOD' : result.validation_period,
                        'EXPIRED' : result.has_expired
                    })
                            # CERT_ID = result.sha_256,
                            # CERT_RAW = result.raw_str,                      
                            # CERT_TYPE = result.cert_type.value,
                            # ISSUER_ORG = result.issuer_cn,
                            # ISSUER_CERT_ID = "",
                            # KEY_SIZE = result.subject_pub_key_size,
                            # KEY_TYPE = KEY_TYPE_MAPPING[result.subject_pub_key_type.__class__],
                            # NOT_VALID_BEFORE = result.not_valid_before,
                            # NOT_VALID_BEFORE = result.not_valid_before,
                            # VALIDATION_PERIOD = result.validation_period,
                            # EXPIRED = result.has_expired
                    if result.has_expired:
                        self.expired += 1
                    self.algo.append(str(result.subject_pub_key_type.__class__))
                    self.length.append(result.subject_pub_key_size)
                    self.issuer.append(result.issuer_cn)
                    self.valid.append(result.validation_period)
                    self.num += 1

                if cert_store_data_to_insert == []:
                    return

                # There will be many duplicate mappings on insertions, so we use bulk_insert_mappings
                db.session.bulk_insert_mappings(CertStoreContent, cert_store_data_to_insert)
                db.session.commit()

                counter = Counter(self.algo)
                algo_dict = dict(counter)
                counter = Counter(self.length)
                length_dict = dict(counter)
                counter = Counter(self.issuer)
                issuer_dict = dict(counter)
                counter = Counter(self.valid)
                valid_dict = dict(counter)

                self.existing_cert_analysis_store.SCAN_ID = self.scan_id
                self.existing_cert_analysis_store.SCANNED_CERT_NUM = self.num
                self.existing_cert_analysis_store.ISSUER_COUNT = issuer_dict
                self.existing_cert_analysis_store.KEY_SIZE_COUNT = length_dict
                self.existing_cert_analysis_store.KEY_TYPE_COUNT = algo_dict

                self.existing_cert_analysis_store.VALIDATION_PERIOD_COUNT = valid_dict
                self.existing_cert_analysis_store.EXPIRED_PERCENT = self.expired / self.num

                db.session.add(self.existing_cert_analysis_store)
                db.session.commit()
        
            self.result_list = []
