
from app import app, db
from threading import Lock, Thread
from sqlalchemy.dialects.mysql import insert
from datetime import datetime, timezone
import cryptography.hazmat.bindings
from cryptography.hazmat.primitives.asymmetric import dsa as primitive_dsa, rsa as primitive_rsa, ec as primitive_ec, dh as primitive_dh

from ..logger.logger import my_logger
from ..parser.cert_parser_base import X509CertParser
from ..utils.type import CertType
from ..utils.exception import ParseError, UnknownTableError
from ..models import CertAnalysisStats, CertStoreContent, ScanStatus, CaCertStore
from ..parser.cert_parser_base import X509ParsedInfo

class CertParseAnalyzer():

    def __init__(
            self,
            scan_id : str,
            save_chunk_size : int = 10000
        ) -> None:

        self.save_chunk_size = save_chunk_size
        self.result_list_lock = Lock()
        self.result_list = []

        self.num_cert = 0
        self.num_expired_cert = 0
        self.issuer_org_dict = {}
        self.key_type_dict = {}
        self.key_length_dict = {}
        self.valid_period_dict = {}
        self.sig_algo_dict = {}

        '''
            Check if the cert stat result has been stored before
            If so, we overwrite it
        '''
        scan_process : ScanStatus = ScanStatus.query.filter_by(ID=scan_id).first()
        self.cert_stat_entry : CertAnalysisStats = CertAnalysisStats.query.filter_by(SCAN_ID=scan_process.ID).first()

        if self.cert_stat_entry:
            self.cert_stat_entry.SCAN_TIME = scan_process.START_TIME
            self.cert_stat_entry.SCAN_TYPE = scan_process.TYPE
            self.cert_stat_entry.SCANNED_CERT_NUM = 0
            self.cert_stat_entry.ISSUER_ORG_COUNT = {}
            self.cert_stat_entry.KEY_SIZE_COUNT = {}
            self.cert_stat_entry.KEY_TYPE_COUNT = {}
            self.cert_stat_entry.SIG_ALG_COUNT = {}
            self.cert_stat_entry.VALIDATION_PERIOD_COUNT = {}
            self.cert_stat_entry.EXPIRED_PERCENT = 0.01
        else:
            self.cert_stat_entry = CertAnalysisStats(
                SCAN_ID = scan_process.ID,
                SCAN_TIME = scan_process.START_TIME,
                SCAN_TYPE = scan_process.TYPE,
                SCANNED_CERT_NUM = 0,
                ISSUER_ORG_COUNT = {},
                KEY_SIZE_COUNT = {},
                KEY_TYPE_COUNT = {},
                SIG_ALG_COUNT = {},
                VALIDATION_PERIOD_COUNT = {},
                EXPIRED_PERCENT = 0
            )
            db.session.add(self.cert_stat_entry)
        db.session.commit()
        db.session.expunge(self.cert_stat_entry)


    def analyze_cert_parse(self, rows):
        '''
            Each row in rows has the following structure:
                'sha256_id': self.CERT_ID,
                'raw': self.CERT_RAW
        '''
        for row in rows:
            try:
                single_cert_analyzer = X509CertParser(row[1])
                cert_parse_result = single_cert_analyzer.parse_cert_base()
                with self.result_list_lock:
                    self.result_list.append(cert_parse_result)
                if len(self.result_list) > self.save_chunk_size:
                    self.sync_update_info()
            except ParseError:
                pass
        print("xxx")
        self.sync_update_info()


    def sync_update_info(self):
        with self.result_list_lock:
            my_logger.info(f"Updating cert parsing data...")

            with app.app_context():
                cert_store_data_to_insert = []
                ca_cert_store_data_to_insert = []

                KEY_TYPE_MAPPING = {
                    primitive_rsa.RSAPublicKey : 0,
                    primitive_ec.EllipticCurvePublicKey : 1,
                    cryptography.hazmat.bindings._rust.openssl.rsa.RSAPublicKey : 0,
                    cryptography.hazmat.bindings._rust.openssl.ec.ECPublicKey : 1,
                    cryptography.hazmat.bindings._rust.openssl.ed25519.Ed25519PublicKey : 2
                }

                my_logger.info(f"Converting {len(self.result_list)} data...")
                for result in self.result_list:
                    if not result: continue
                    result : X509ParsedInfo
                    current_utc_time = datetime.now(timezone.utc)

                    # 通过添加时区信息确保 time_end 也是 UTC 时间
                    time_end_utc = result.not_valid_after.replace(tzinfo=timezone.utc)
                    has_expired = (current_utc_time > time_end_utc)

                    try:
                        key_type = KEY_TYPE_MAPPING[result.subject_pub_key_algo.__class__]
                    except KeyError:
                        my_logger.warning(f"Unknown key type {result.subject_pub_key_algo.__class__}")
                        key_type = -1

                    cert_store_data = {
                        'CERT_ID' : result.sha_256,
                        'CERT_TYPE' : result.cert_type.value,
                        'SUBJECT_CN' : result.subject_cn,
                        'ISSUER_ORG' : result.issuer_org,
                        'ISSUER_CERT_ID' : "",
                        'KEY_SIZE' : result.subject_pub_key_size,
                        'KEY_TYPE' : key_type,
                        'NOT_VALID_BEFORE' : result.not_valid_before,
                        'NOT_VALID_AFTER' : result.not_valid_after,
                        'VALIDATION_PERIOD' : result.validation_period,
                        'EXPIRED' : has_expired
                    }
                    # cert_store_data_to_insert.append(cert_store_data)
                    insert_cert_store_statement = insert(CertStoreContent).values([cert_store_data]).prefix_with('IGNORE')
                    db.session.execute(insert_cert_store_statement)

                    if result.cert_type != CertType.LEAF:
                        ca_cert_data = {
                            'CERT_ID' : result.sha_256,
                            'CERT_RAW' : result.raw,
                            'CERT_TYPE' : result.cert_type.value,
                        }
                        # ca_cert_store_data_to_insert.append(ca_cert_data)
                        insert_ca_cert_store_statement = insert(CaCertStore).values([ca_cert_data]).prefix_with('IGNORE')
                        db.session.execute(insert_ca_cert_store_statement)

                    def update_dict(dict, key):
                        if key in dict:
                            dict[key] += 1
                        else:
                            dict[key] = 1

                    if has_expired:
                        self.num_expired_cert += 1
                    update_dict(self.key_type_dict, result.subject_pub_key_algo.__class__.__name__)
                    update_dict(self.key_length_dict, result.subject_pub_key_size)
                    update_dict(self.issuer_org_dict, result.issuer_org)
                    update_dict(self.valid_period_dict, result.validation_period)
                    update_dict(self.sig_algo_dict, result.cert_signature_hash_algorithm)
                    self.num_cert += 1

                my_logger.info(f"Finished {len(cert_store_data_to_insert)} data...")
                # if cert_store_data_to_insert == []:
                #     self.result_list = []
                #     return

                self.cert_stat_entry.SCANNED_CERT_NUM = self.num_cert
                self.cert_stat_entry.ISSUER_ORG_COUNT = self.issuer_org_dict
                self.cert_stat_entry.KEY_SIZE_COUNT = self.key_length_dict
                self.cert_stat_entry.KEY_TYPE_COUNT = self.key_type_dict
                self.cert_stat_entry.SIG_ALG_COUNT = self.sig_algo_dict
                self.cert_stat_entry.VALIDATION_PERIOD_COUNT = self.valid_period_dict
                self.cert_stat_entry.EXPIRED_PERCENT = self.num_expired_cert / self.num_cert

                print("1")
                db.session.add(self.cert_stat_entry)
                db.session.commit()

                '''
                    TODO: Do not ask me why I store one line of data at a time, not 
                    a batch of data.
                    If I do the latter, the sql server does not responding...
                    and the program stucks...
                    Need to figure out why...
                '''
        
                # print("2")
                # insert_cert_store_statement = insert(CertStoreContent).values(cert_store_data_to_insert).prefix_with('IGNORE')
                # db.session.execute(insert_cert_store_statement)

                # print("3")
                # insert_ca_cert_store_statement = insert(CaCertStore).values(ca_cert_store_data_to_insert).prefix_with('IGNORE')
                # db.session.execute(insert_ca_cert_store_statement)

            print("end")
            self.result_list = []
