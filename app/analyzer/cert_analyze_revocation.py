
import requests
from requests.exceptions import RequestException
from datetime import datetime, timezone
from typing import Dict, Tuple, List, Optional

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.hashes import SHA256, SHA1
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509 import (
    Certificate,
    ReasonFlags,
    CRLReason,
    ExtensionNotFound,
    CertificateRevocationList,
    load_pem_x509_certificate,
    load_der_x509_certificate,
    load_pem_x509_crl,
    load_der_x509_crl
)
from cryptography.x509.oid import ExtensionOID, AuthorityInformationAccessOID
from cryptography.x509.ocsp import (
    OCSPRequestBuilder,
    OCSPResponseStatus,
    OCSPCertStatus,
    OCSPResponse,
    load_der_ocsp_response
)

from app import app, db
from threading import Lock
from sqlalchemy.dialects.mysql import insert
from ..models import CertRevocationStatusOCSP, CertRevocationStatusCRL, CRLArchive
from ..logger.logger import my_logger
from ..utils.exception import ParseError
from ..utils.cert import (
    get_cert_sha256_hex_from_object,
    get_cert_sha256_hex_from_str
)


class CertRevocationAnalyzer():

    def __init__(
            self,
            scan_chunk_size : int = 5000
        ) -> None:

        self.scan_chunk_size = scan_chunk_size
        self.proxies = {
            "http": "http://127.0.0.1:33210",
            "https": "http://127.0.0.1:33210",
        }

        # Revocation result cache
        self.ocsp_result_list = []
        self.ocsp_result_list_lock = Lock()

        self.crl_result_list = []
        self.crl_result_list_lock = Lock()

        # Cache for CRL file
        self.stored_crl_key = []
        self.crl_cache : Dict[str, Tuple[datetime, CertificateRevocationList]] = {}
        self.crl_cache_lock = Lock()


    def analyze_cert_revocation(self, rows):
        for row in rows:
            try:
                cert = load_pem_x509_certificate(row[1].encode('utf-8'), default_backend())
                crl_result = self.check_revocation_status_from_crl(cert)
                with self.crl_result_list_lock:
                    self.crl_result_list += crl_result

                issuers = self.get_issuer(cert, use_proxy=False)
                if len(issuers) == 0:
                    issuers = self.get_issuer(cert, use_proxy=True)

                for issuer in issuers:
                    ocsp_result = self.check_revocation_status_from_ocsp(cert, issuer)
                    with self.ocsp_result_list_lock:
                        self.ocsp_result_list += ocsp_result

                if len(self.crl_result_list) > self.scan_chunk_size or len(self.ocsp_result_list) > self.scan_chunk_size:
                    self.sync_update_info()
            except ParseError:
                pass
            except Exception as e:
                my_logger.error(f"Error analyze revocation: {e}")

        self.sync_update_info()


    def check_revocation_status_from_crl(self, cert : Certificate) -> List[Tuple[str, datetime, str, int, datetime, ReasonFlags]]:
        '''
            'cert_id': self.CERT_ID,
            'check_time': self.CHECK_TIME,
            'crl_position': self.CRL_POSITION,
            'revocation_status' : self.REVOCATION_STATUS,
            'revocation_time' : self.REVOCATION_TIME,
            'revocation_reason' : self.REVOCATION_REASON
        '''
        '''
            Warning: return False does not always mean the cert is not revoked
            
            Sometimes, the CA might remove the cert from CRL after a period of time of expiration to reduce the CRL size
            So make sure to check whether the cert is expired in the caller
        '''
        try:
            result_list = []
            crl_distribution_points = cert.extensions.get_extension_for_oid(ExtensionOID.CRL_DISTRIBUTION_POINTS)
            crl_distribution_points = crl_distribution_points.value
        except ExtensionNotFound as e:
            # my_logger.warn(f"Cert extension {e.oid} not found")
            return []

        for crl_distribution_point in crl_distribution_points:
            crl_url = crl_distribution_point.full_name[0].value
            crl_response = self.request_crl_response(crl_url, use_proxy=False)
            if not crl_response[1]:
                crl_response = self.request_crl_response(crl_url, use_proxy=True)

            if crl_response[1]:
                crl_entry = crl_response[1].get_revoked_certificate_by_serial_number(cert.serial_number)
                if crl_entry:
                    # revoked
                    result_list.append((get_cert_sha256_hex_from_object(cert), crl_response[0], crl_url, 0, crl_entry.revocation_date_utc, crl_entry.extensions.get_extension_for_class(CRLReason).value.reason))
                else:
                    # not revoked
                    result_list.append((get_cert_sha256_hex_from_object(cert), crl_response[0], crl_url, 1, None, None))
            else:
                # No CRL response
                result_list.append((get_cert_sha256_hex_from_object(cert), crl_response[0], crl_url, 2, None, None))
        return result_list
        

    def request_crl_response(
            self,
            crl_url : str,
            retry_times : int = 2,
            use_proxy : bool = False
        ) -> Tuple[datetime, CertificateRevocationList]:

        if retry_times <= 0:
            # my_logger.error(f"Can not retrieve CRL after retrying several times...")
            return (datetime.now(timezone.utc), None)

        # Check cache hit
        if crl_url in self.crl_cache.keys():
            return self.crl_cache[crl_url]
        
        try:
            my_logger.debug(f"Requesting CRL from {crl_url}...")
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36'
            }
            request_time = datetime.now(timezone.utc)
            if use_proxy:
                crl_response : requests.Response = requests.get(crl_url, headers=headers, timeout=3, proxies=self.proxies)
            else:
                crl_response : requests.Response = requests.get(crl_url, headers=headers, timeout=3)

            if not crl_response.status_code == 200:
                my_logger.warn(f"Server {crl_url} rejected CRL reqeust")
                return (request_time, None)

            crl = load_pem_x509_crl(crl_response.content, default_backend())
            with self.crl_cache_lock:
                self.crl_cache[crl_url] = (request_time, crl)
            return (request_time, crl)

        except requests.exceptions.RequestException:
            return self.request_crl_response(crl_url, retry_times - 1)
        except ValueError:
            try:
                crl = load_der_x509_crl(crl_response.content, default_backend())
                my_logger.warn("CRL response is encoded with DER")
                with self.crl_cache_lock:
                    self.crl_cache[crl_url] = (request_time, crl)
                return (request_time, crl)
            except:
                return self.request_crl_response(crl_url, retry_times - 1)


    def check_revocation_status_from_ocsp(
            self,
            cert : Certificate,
            issuer_cert : Certificate
        )-> List[Tuple[str, datetime, str, str, OCSPResponseStatus, Optional[OCSPCertStatus], Optional[datetime], Optional[ReasonFlags]]]:
        '''
            'cert_id': self.CERT_ID,
            'check_time': self.CHECK_TIME,
            'aia_location': self.AIA_LOCATION,
            'issuer_id' : self.ISSUER_ID,
            'revocation_status' : self.REVOCATION_STATUS,
            'revocation_time' : self.REVOCATION_TIME,
            'revocation_reason' : self.REVOCATION_REASON
        '''

        if issuer_cert is None: return []
        try:
            result_list = []
            ocsp_server_url = None
            ocsp_info = cert.extensions.get_extension_for_oid(ExtensionOID.AUTHORITY_INFORMATION_ACCESS)
        except ExtensionNotFound as e:
            # my_logger.warn(f"Cert extension {e.oid} not found")
            return []
        
        for access_description in ocsp_info.value:
            if access_description.access_method._name == "OCSP":
                ocsp_server_url = access_description.access_location.value

                ocsp_response = self.request_ocsp_response(cert, issuer_cert, ocsp_server_url, use_proxy=False)
                if not ocsp_response[1]:
                    ocsp_response = self.request_ocsp_response(cert, issuer_cert, ocsp_server_url, use_proxy=True)

                if not ocsp_response[1]:
                    # No response
                    # my_logger.warn(f"OCSP server for certificate {cert.serial_number} does not respond")
                    result_list.append((get_cert_sha256_hex_from_object(cert), ocsp_response[0], ocsp_server_url, get_cert_sha256_hex_from_object(issuer_cert), None, None, None, None))
                    continue
                
                ocsp_status : OCSPResponseStatus = ocsp_response[1].response_status
                cert_status : OCSPCertStatus = None
                revocation_time = None
                revocation_reason = None
                if ocsp_status == OCSPResponseStatus.SUCCESSFUL:
                    cert_status = ocsp_response[1].certificate_status
                    if cert_status == OCSPCertStatus.REVOKED:
                        revocation_time = ocsp_response[1].revocation_time
                        revocation_reason = ocsp_response[1].revocation_reason

                result_list.append((get_cert_sha256_hex_from_object(cert), ocsp_response[0], ocsp_server_url, get_cert_sha256_hex_from_object(issuer_cert), ocsp_status, cert_status, revocation_time, revocation_reason))
        return result_list
        

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
    def request_ocsp_response(
            self,
            cert : Certificate,
            issuer : Certificate,
            server_url : str,
            hash : hashes = SHA256(),
            retry_times : int = 2,
            use_proxy : bool = False
        ) -> Tuple[datetime, OCSPResponse]:

        if retry_times <= 0:
            # my_logger.error(f"OCSP server {server_url} does not respond after retrying several times...")
            return (datetime.now(timezone.utc), None)

        '''
            From doc:
            While RFC 5019 originally required SHA1,
            RFC 6960 updates that to SHA256.
            However, depending on your requirements you may need to use SHA1
            for compatibility reasons.

            So we do the following:
            Use SHA1 first, if return status is OCSPResponseStatus.UNAUTHORIZED,
            we switch to SHA256 next

            Update on 24/05/21:
            Skip SHA1, use SHA256 directly to save time
        '''
        builder = OCSPRequestBuilder()
        builder = builder.add_certificate(cert, issuer, hash)
        request = builder.build()

        try:
            try:
                my_logger.debug(f"Requesting OCSP response from {server_url}...")
                request_time = datetime.now(timezone.utc)
                if use_proxy:
                    raw_response = requests.post(
                        server_url,
                        data=request.public_bytes(serialization.Encoding.DER),
                        headers={"Content-Type": "application/ocsp-request"},
                        timeout=2,
                        proxies=self.proxies
                    )
                else:
                    raw_response = requests.post(
                        server_url,
                        data=request.public_bytes(serialization.Encoding.DER),
                        headers={"Content-Type": "application/ocsp-request"},
                        timeout=2
                    )
                if not raw_response.status_code == 200:
                    my_logger.warn(f"Server {server_url} rejected OCSP reqeust")
                    return (request_time, None)

            except requests.exceptions.RequestException as e:
                return self.request_ocsp_response(cert, issuer, server_url, hash, retry_times - 1)

            response = load_der_ocsp_response(raw_response.content)
            return (request_time, response)

        # Sometimes, the response may not complete...
        except ValueError as e:
            # my_logger.warn(f"OCSP response from {server_url} is not complete, retrying...")
            return self.request_ocsp_response(cert, issuer, server_url, hash, retry_times - 1)
        except Exception as e:
            my_logger.error(f"Error when getting OCSP response: {e}")
            return (request_time, None)


    def get_issuer(self, cert: Certificate, use_proxy = False) -> List[Certificate]:
        '''
            Three steps to get issuer:
            1. Try to get the issuer in AIA extension
            2. Try to get the issuer with the help of cert_chain Table (No implementation right now TODO:)
            3. Manually find issuer in the CaCertStore (No implementation right now TODO:)
        '''
        issuers = []
        try:
            ocsp_info = cert.extensions.get_extension_for_oid(ExtensionOID.AUTHORITY_INFORMATION_ACCESS)
        except ExtensionNotFound as e:
            # my_logger.warn(f"Cert extension {e.oid} not found")
            return []
        
        for access_description in ocsp_info.value:
            if (access_description.access_method == AuthorityInformationAccessOID.CA_ISSUERS) \
                    and (access_description.access_location is not None):
                issuer_url = access_description.access_location.value

                for i in range(2):  # 限制最大重试次数
                    try:
                        if use_proxy:
                            raw_response : requests.Response = requests.get(issuer_url, timeout=2, proxies=self.proxies)
                        else:
                            raw_response : requests.Response = requests.get(issuer_url, timeout=2)
                        raw_response.raise_for_status()
                        
                        # 检查是否成功获取了证书内容
                        if b'-----BEGIN CERTIFICATE-----' in raw_response.content:
                            start_index = raw_response.content.find(b'-----BEGIN CERTIFICATE-----')
                            certificate_content = raw_response.content[start_index:]
                            issuer = self.load_certificate(certificate_content)
                        else:
                            issuer = self.load_certificate(raw_response.content)
                        issuers.append(issuer)
                        break  # 如果成功获取和加载了证书，则退出循环
                    except RequestException as e:
                        # my_logger.warn(f"Request failed: {e}")
                        continue
                    except Exception as e:
                        my_logger.error(f"An unexpected error occurred: {e}")

        return issuers


    def load_certificate(self, raw_content: bytes) -> Certificate:
        try:
            return load_pem_x509_certificate(raw_content, default_backend())
        except ValueError:
            pass  # 如果是 PEM 格式加载失败，尝试加载 DER 格式
        try:
            return load_der_x509_certificate(raw_content, default_backend())
        except ValueError as e:
            # 记录错误信息或者采取其他适当的措施
            my_logger.error(f"Error loading certificate: {e}")
            raise


    def sync_update_info(self):
        with app.app_context():
            my_logger.info(f"Updating cert revocation data...")

            REASONFLAG_MAPPING = {
                None : None,
                ReasonFlags.key_compromise: 1,
                ReasonFlags.ca_compromise: 2,
                ReasonFlags.affiliation_changed: 3,
                ReasonFlags.superseded: 4,
                ReasonFlags.cessation_of_operation: 5,
                ReasonFlags.certificate_hold: 6,
                ReasonFlags.privilege_withdrawn: 7,
                ReasonFlags.aa_compromise: 8,
            }

            OCSP_STATUS_MAPPING = {
                None : 0,   # Unauthorized
                OCSPCertStatus.GOOD : 1,
                OCSPCertStatus.REVOKED : 2,
                OCSPCertStatus.UNKNOWN : 3
            }

            with self.crl_result_list_lock:
                crl_data = []
                my_logger.info(f"Converting crl {len(self.crl_result_list)} data...")
                for res in self.crl_result_list:
                    crl_data.append({
                        'CERT_ID' :  res[0],
                        'CHECK_TIME' : res[1],
                        'CRL_POSITION' : res[2],
                        'REVOCATION_STATUS' : res[3],
                        'REVOCATION_TIME' : res[4],
                        'REVOCATION_REASON' : REASONFLAG_MAPPING[res[5]]
                    })
                try:
                    insert_crl_store_statement = insert(CertRevocationStatusCRL).values(crl_data).prefix_with('IGNORE')
                    db.session.execute(insert_crl_store_statement)
                    db.session.commit()
                except Exception as e:
                    my_logger.error(f"Error insertion CRL data: {e} \n {e.with_traceback()}")
                finally:
                    self.crl_result_list = []

            with self.ocsp_result_list_lock:
                ocsp_data = []
                my_logger.info(f"Converting ocsp {len(self.ocsp_result_list)} data...")
                for res in self.ocsp_result_list:
                    if res[4]:
                        if res[4] == OCSPResponseStatus.UNAUTHORIZED:
                            status = 0
                        elif res[4] == OCSPResponseStatus.SUCCESSFUL:
                            status = OCSP_STATUS_MAPPING[res[5]]
                        else:
                            status = None
                    else:
                        status = None

                    ocsp_data.append({
                        'CERT_ID' : res[0],
                        'CHECK_TIME' : res[1],
                        'AIA_LOCATION' : res[2],
                        'ISSUER_ID' : res[3],
                        'REVOCATION_STATUS' : status,
                        'REVOCATION_TIME' : res[6],
                        'REVOCATION_REASON' : REASONFLAG_MAPPING[res[7]]
                    })
                try:
                    insert_ocsp_store_statement = insert(CertRevocationStatusOCSP).values(ocsp_data).prefix_with('IGNORE')
                    db.session.execute(insert_ocsp_store_statement)
                    db.session.commit()
                except Exception as e:
                    my_logger.error(f"Error insertion OCSP data: {e} \n {e.with_traceback()}")
                finally:
                    self.ocsp_result_list = []

            my_logger.info(f"Converting crl_cache data...")
            with self.crl_cache_lock:
                for entry in self.crl_cache:
                    if entry in self.stored_crl_key:
                        continue

                    a : CertificateRevocationList = self.crl_cache[entry][1]
                    data = {
                        'CRL_POSITION' : entry,
                        'STORE_TIME' : self.crl_cache[entry][0],
                        'FINGERPRINT' : a.fingerprint(SHA256()).hex(),
                        'CRL_DATA' : a.public_bytes(Encoding.PEM)
                    }
                    try:
                        insert_crl_archive_statement = insert(CRLArchive).values([data]).prefix_with('IGNORE')
                        db.session.execute(insert_crl_archive_statement)
                        db.session.commit()
                    except Exception as e:
                        my_logger.error(f"Error insertion CRL entry: {e} \n {e.with_traceback()}")
                    finally:
                        self.stored_crl_key.append(entry)
