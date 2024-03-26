
import time
import cryptography.hazmat.bindings
from cryptography.hazmat.primitives.asymmetric import dsa as primitive_dsa, rsa as primitive_rsa, ec as primitive_ec, dh as primitive_dh

from ..logger.logger import my_logger
from ..parser.cert_parser_base import X509CertParser
from ..utils.type import CertType
from ..utils.exception import ParseError
from ..models import CertAnalysisStats, CertStoreContent, CertStoreRaw, CaCertStore
from ..parser.cert_parser_base import X509ParsedInfo
from .cert_analyze_chain import CertScanChainAnalyzer

from app import app, db
from threading import Lock, Thread
from sqlalchemy import insert, Table
from datetime import datetime, timezone

class CertScanAnalyzer():

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
        self.existing_cert_analysis_store : CertAnalysisStats = CertAnalysisStats.query.filter_by(SCAN_ID=scan_id).first()

        self.num = 0
        self.expired = 0
        self.issuer = {}
        self.key_type = {}
        self.length = {}
        self.valid = {}
        self.sig_algo = {}


    def analyze_cert_scan_result(self):
        my_logger.info(f"Starting {self.scan_input_table.name} scan analysis...")
        
        with app.app_context():
            query = self.scan_input_table.select()
            result_proxy = db.session.execute(query)
            
            while True:
                rows = result_proxy.fetchmany(self.save_scan_chunk_size)
                if not rows:
                    self.sync_update_info()
                    break

                for row in rows:
                    try:
                        # 'sha256_id': self.CERT_ID,
                        # 'raw': self.CERT_RAW,
                        single_cert_analyzer = X509CertParser(row[1])
                        cert_parse_result = single_cert_analyzer.parse_cert_base()
                        self.result_list.append(cert_parse_result)
                    except ParseError:
                        self.result_list.append(None)

                self.sync_update_info()
            my_logger.info("Cert scan analysis completed")
        # chain_analyzer = CertScanChainAnalyzer(self.scan_id, self.scan_input_table)
        # chain_analyzer.analyze_cert_chain()
        # my_logger.info("Cert chain analysis completed")


    def sync_update_info(self):
        my_logger.info(f"Updating...")
        with self.result_list_lock:
            with app.app_context():

                from collections import Counter
                # insert_analysis_data_statement = insert(self.result_table)
                cert_store_data_to_insert = []
                ca_cert_store_data_to_insert = []

                KEY_TYPE_MAPPING = {
                    primitive_rsa.RSAPublicKey : 0,
                    primitive_ec.EllipticCurvePublicKey : 1,
                    cryptography.hazmat.bindings._rust.openssl.rsa.RSAPublicKey : 0,
                    cryptography.hazmat.bindings._rust.openssl.ec.ECPublicKey : 1,
                    cryptography.hazmat.bindings._rust.openssl.ed25519.Ed25519PublicKey : 2
                }

                for result in self.result_list:
                    if not result: continue
                    result : X509ParsedInfo
                    current_utc_time = datetime.now(timezone.utc)

                    # 通过添加时区信息确保 time_end 也是 UTC 时间
                    time_end_utc = result.not_valid_after.replace(tzinfo=timezone.utc)
                    has_expired = (current_utc_time > time_end_utc)

                    cert_store_data_to_insert.append({
                        'CERT_ID' : result.sha_256,
                        # 'CERT_RAW' : result.raw_str,
                        'CERT_TYPE' : result.cert_type.value,
                        'SUBJECT_CN' : result.subject_cn,
                        'ISSUER_ORG' : result.issuer_org,
                        'ISSUER_CERT_ID' : "",
                        'KEY_SIZE' : result.subject_pub_key_size,
                        'KEY_TYPE' : KEY_TYPE_MAPPING[result.subject_pub_key_algo.__class__],
                        'NOT_VALID_BEFORE' : result.not_valid_before,
                        'NOT_VALID_AFTER' : result.not_valid_after,
                        'VALIDATION_PERIOD' : result.validation_period,
                        'EXPIRED' : has_expired
                    })

                    if result.cert_type != CertType.LEAF:
                        ca_cert_store_data_to_insert.append({
                            'CERT_ID' : result.sha_256,
                            'CERT_RAW' : result.raw,
                            'CERT_TYPE' : result.cert_type.value,
                        })


                    def update_dict(dict, key):
                        if key in dict:
                            dict[key] += 1
                        else:
                            dict[key] = 1

                    if has_expired:
                        self.expired += 1
                    update_dict(self.key_type, result.subject_pub_key_algo.__class__.__name__)
                    update_dict(self.length, result.subject_pub_key_size)
                    update_dict(self.issuer, result.issuer_org)
                    update_dict(self.valid, result.validation_period)
                    update_dict(self.sig_algo, result.cert_signature_hash_algorithm)
                    self.num += 1

                if cert_store_data_to_insert == []:
                    return

                insert_cert_store_statement = insert(CertStoreContent).values(cert_store_data_to_insert).prefix_with('IGNORE')
                db.session.execute(insert_cert_store_statement)

                insert_ca_cert_store_statement = insert(CaCertStore).values(ca_cert_store_data_to_insert).prefix_with('IGNORE')
                db.session.execute(insert_ca_cert_store_statement)

                # counter = Counter(self.key_type)
                # algo_dict = dict(counter)
                # counter = Counter(self.length)
                # length_dict = dict(counter)
                # counter = Counter(self.issuer)
                # issuer_dict = dict(counter)
                # counter = Counter(self.valid)
                # valid_dict = dict(counter)
                # counter = Counter(self.sig_algo)
                # sig_algo_dict = dict(counter)

                self.existing_cert_analysis_store.SCANNED_CERT_NUM = self.num
                self.existing_cert_analysis_store.ISSUER_ORG_COUNT = self.issuer
                self.existing_cert_analysis_store.KEY_SIZE_COUNT = self.length
                self.existing_cert_analysis_store.KEY_TYPE_COUNT = self.key_type
                self.existing_cert_analysis_store.SIG_ALG_COUNT = self.sig_algo
                self.existing_cert_analysis_store.VALIDATION_PERIOD_COUNT = self.valid
                self.existing_cert_analysis_store.EXPIRED_PERCENT = self.expired / self.num

                # db.session.add(self.existing_cert_analysis_store)
                db.session.flush()
                db.session.commit()
        
            self.result_list = []
