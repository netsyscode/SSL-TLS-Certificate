
import re
import hashlib
import requests
import chardet
from enum import Enum

from typing import Optional
from datetime import datetime, timezone
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
from cryptography.x509.oid import NameOID, ExtensionOID, SignatureAlgorithmOID, ExtendedKeyUsageOID
from ..utils.type import CertType

from cryptography.x509.ocsp import (
    OCSPRequestBuilder,
    OCSPResponseStatus,
    OCSPCertStatus,
    OCSPResponse,
    load_der_ocsp_response
)
from threading import Lock
from sqlalchemy.dialects.mysql import insert
from sqlalchemy import Table
from ..models import CertAnalysisStats, CertStoreContent, CertStoreRaw, CaCertStore, CertRevocationStatusOCSP

from sqlalchemy.exc import IntegrityError
from ..parser.cert_parser_base import X509ParsedInfo
from app import app, db
from OpenSSL import crypto
from ..utils.cert import (
    domain_extract,
    is_domain_match,
    utc_time_diff_in_days,
    get_name_attribute,
    get_cert_sha256_hex_from_object,
    get_cert_sha256_hex_from_str
)

# class data():
#     # cert_signature_verified : bool

#     '''
#         Revocation analysis: CRL and OCSP
#         1. CRL:
#             is_revoked_from_CRL:
#                 Check from CRL, has None if:
#                     the CRL server does not respond
#                     the cert does not support CRL (CRL Distribution Points) extension
#         2. OCSP:
#             ocsp_response_status:
#                 Check OCSP server status, has None if:
#                     the server does not respond
#                     the cert has no AIA (Authority Information Access) extension
#     '''
#     # is_revoked_from_CRL : Optional[bool]
#     # ocsp_response_status : Optional[OCSPResponseStatus]
#     # ocsp_cert_status : Optional[OCSPCertStatus]
#     # revocation_time : Optional[datetime]
#     # revocation_reason : Optional[ReasonFlags]


class CertRevocationAnalyzer():

    def __init__(
            self,
            scan_id : str,
            scan_input_table : Table,
        ) -> None:

        self.scan_id = scan_id
        self.result_list = []
        self.result_list_lock = Lock()
        self.save_scan_chunk_size = 5000
        self.scan_input_table = scan_input_table
        # Cache for CRL file
        self.crl_cache : Dict[str, CertificateRevocationList] = {}
        self.cert_store = crypto.X509Store()


    def analyze_cert_revocation(self):
        my_logger.info(f"Starting {self.scan_input_table.name} revocation analysis...")
        
        with app.app_context():
            # Prepare root store
            ca_certs = CaCertStore.query.filter()
            ca_certs = [cert.get_raw() for cert in ca_certs]

            for cert in ca_certs:
                root_cert = crypto.load_certificate(crypto.FILETYPE_PEM, cert)
                self.cert_store.add_cert(root_cert)

            # Analyze
            query = self.scan_input_table.select()
            result_proxy = db.session.execute(query)
            
            while True:
                rows = result_proxy.fetchmany(self.save_scan_chunk_size)
                if not rows:
                    # self.sync_update_info()
                    break

                for row in rows:
                    try:
                        cert = crypto.load_certificate(crypto.FILETYPE_PEM, row[1])
                        issuer = self.get_issuer(cert)
                        if issuer:
                            res, url = self.checkRevocationStatusFromOCSP(cert.to_cryptography(), issuer.to_cryptography())
                            self.sync_update_info(cert, res, url)
                    except ValueError:
                        continue

        my_logger.info("Cert chain revocation completed")


    def get_issuer(self, cert):
        try:
            store_ctx = crypto.X509StoreContext(self.cert_store, cert)
            chain = store_ctx.get_verified_chain()
            if len(chain) == 1:
                return chain[0]
            else:
                return chain[1]
        
        except crypto.X509StoreContextError as e:
            # my_logger.error(f"Cert chain analysis failed for cert {get_cert_sha256_hex_from_object(e.certificate.to_cryptography())}...")
            return None


    def sync_update_info(self, cert : crypto.X509, res, url):
        # with app.app_context():
            OCSP_STATUS_MAPPING = {
                None : 0,
                OCSPCertStatus.GOOD : 1,
                OCSPCertStatus.REVOKED : 2,
                OCSPCertStatus.UNKNOWN : 3
            }

            if res:
                status = OCSP_STATUS_MAPPING[res[1]]
            else:
                status = 0

            data = {
                'CERT_ID' : get_cert_sha256_hex_from_object(cert.to_cryptography()),
                'CHECK_TIME' : datetime.now(timezone.utc),
                'AIA_LOCATION' : url,
                'REVOCATION_STATUS' : status
            }
            insert_cert_store_statement = insert(CertRevocationStatusOCSP).values(data)
            db.session.execute(insert_cert_store_statement)


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
            self,
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
                    return self.requestOCSPResponse(cert, issuer, server_url, hash, retry_times - 1)


            response = load_der_ocsp_response(raw_response.content)
            if hash == SHA1() and response.response_status == OCSPResponseStatus.UNAUTHORIZED:
                return self.requestOCSPResponse(cert, issuer, SHA256())
            return response

        # Sometimes, the response may not complete...
        except ValueError as e:
            my_logger.warn(f"OCSP response from {server_url} is not complete, retrying...")
            return self.requestOCSPResponse(cert, issuer, server_url, hash, retry_times - 1)
        except Exception as e:
            my_logger.error(f"Error when getting OCSP response: {e}")
            return None


    def requestCRLResponse(
            self,
            crl_url : str,
            retry_times : int = 4
        ) -> Optional[CertificateRevocationList]:

        # Check cache hit
        if crl_url in self.crl_cache.keys():
            return self.crl_cache[crl_url]
        
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
            self.crl_cache[crl_url] = crl
            return crl

        except requests.exceptions.RequestException:
            if retry_times <= 0:
                my_logger.error(f"Can not retrieve CRL after retrying several times...")
                return None
            else:
                return self.requestCRLResponse(crl_url, retry_times - 1)

        except ValueError:
            my_logger.debug("CRL response is encoded with DER")
            return load_der_x509_crl(crl_response.content, default_backend())


    def checkRevocationStatusFromOCSP(
            self,
            cert : Certificate,
            issuer_cert : Certificate
        )-> Tuple[Tuple[Optional[OCSPResponseStatus], Optional[OCSPCertStatus], Optional[datetime], Optional[ReasonFlags]], str]:

        if issuer_cert is None: return None, None
        try:
            ocsp_server_url = None
            ocsp_info = cert.extensions.get_extension_for_oid(ExtensionOID.AUTHORITY_INFORMATION_ACCESS)
            if ocsp_info:
                for access_description in ocsp_info.value:
                    if access_description.access_method._name == "OCSP":
                        ocsp_server_url = access_description.access_location.value

            ocsp_response = self.requestOCSPResponse(cert, issuer_cert, ocsp_server_url)
            if not ocsp_response:
                my_logger.warn(f"OCSP server for certificate {cert.serial_number} does not respond")
                return None, ocsp_server_url
            
            ocsp_status = ocsp_response.response_status
            cert_status = None
            revocation_time = None
            revocation_reason = None
            if ocsp_status == OCSPResponseStatus.SUCCESSFUL:
                cert_status = ocsp_response.certificate_status
                if cert_status == OCSPCertStatus.REVOKED:
                    revocation_time = ocsp_response.revocation_time
                    revocation_reason = ocsp_response.revocation_reason

            return (ocsp_status, cert_status, revocation_time, revocation_reason), ocsp_server_url
        
        except ExtensionNotFound as e:
            my_logger.warn(f"Cert extension {e.oid} not found")
            return None, None


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
            crl = self.requestCRLResponse(crl_url)

            if crl:
                crl_entry = crl.get_revoked_certificate_by_serial_number(self.cert.serial_number)
                if crl_entry: return True
                else: return False

            # No CRL response
            return None
        
        except ExtensionNotFound as e:
            my_logger.warn(f"Cert extension {e.oid} not found")
            return None


# class certTmep():
#     def __init__(
#             self,
#             host_name: str,
#             cert_type: CertType,
#             cert: Certificate,
#             issuer_cert: Optional[Certificate],
#         ) -> None:

#         self.host_name = host_name
#         self.cert_type = cert_type
#         self.cert = cert
#         self.issuer_cert = issuer_cert

#         # Check CRL
#         # crl_revoked = self.checkRevocationStatusFromCRL()
#         crl_revoked = None
#         # Check OCSP:
#         ocsp_status, cert_status, revocation_time, revocation_reason = None, None, None, None
#         # ocsp_result = self.checkRevocationStatusFromOCSP()
#         # if ocsp_result is not None:
#             # ocsp_status, cert_status, revocation_time, revocation_reason = ocsp_result
        