
import uuid
from app import app, db
from typing import Dict, List, Set
from dataclasses import dataclass, field
from threading import Lock, Thread
from sqlalchemy.dialects.mysql import insert
# from sqlalchemy import insert
from datetime import datetime, timezone
import cryptography.hazmat.bindings
from cryptography.hazmat.primitives.asymmetric import dsa as primitive_dsa, rsa as primitive_rsa, ec as primitive_ec, dh as primitive_dh
from cryptography.hazmat.backends import default_backend
from cryptography.x509 import load_pem_x509_certificate

from ..logger.logger import my_logger
from ..parser.cert_parser_base import X509CertParser
from ..parser.cert_parser_extension import X509CertExtensionParser, ExtensionResult
from ..parser.cert_parser_extension import (
    AIAResult,
    KeyUsageResult,
    CertPoliciesResult,
    BasicConstraintsResult,
    ExtendedKeyUsageResult,
    CRLResult
)
from ..utils.type import CertType
from ..utils.exception import ParseError, UnknownTableError
from ..models import CertAnalysisStats, CertStoreContent, ScanStatus, CaCertStore, generate_ca_analysis_table
from ..parser.cert_parser_base import X509ParsedInfo


@dataclass
class CaStatResult:
    id : int
    cn: str
    org: str
    country: str

    signed_cert_num: int = 0
    expired_num: int = 0

    ca_cert_server: Set[str] = field(default_factory=set)
    crl_server: Set[str] = field(default_factory=set)
    ocsp_server: Set[str] = field(default_factory=set)

    serial_len_count: Dict[int, int] = field(default_factory=dict)
    subject_country_count: Dict[str, int] = field(default_factory=dict)
    basic_constraint_count: Dict[bool, int] = field(default_factory=dict)
    signed_day_count: Dict[int, int] = field(default_factory=dict)
    validity_period_count: Dict[int, int] = field(default_factory=dict)

    key_size_count: Dict[int, int] = field(default_factory=dict)
    key_type_count: Dict[str, int] = field(default_factory=dict)
    sig_type_count: Dict[str, int] = field(default_factory=dict)
    crypto_use_count: Dict[str, int] = field(default_factory=lambda: {
        'digital_sig': 0,
        'key_encipherment': 0,
        'data_encipherment': 0,
        'key_agreement': 0,
        'others': 0
    })
    eku_count: Dict[str, int] = field(default_factory=dict)
    issued_policy_count: Dict[str, int] = field(default_factory=dict)


class CaParseAnalyzer():

    def __init__(
            self,
            scan_id : str
        ) -> None:

        self.result_list_lock = Lock()
        self.result_list = {}

        self.ca_id_lock = Lock()
        self.ca_id = 1

        scan_process : ScanStatus = ScanStatus.query.filter_by(ID=scan_id).first()
        time_to_str = scan_process.START_TIME.strftime("%Y%m%d%H%M%S")
        self.storage_table = generate_ca_analysis_table(f"ca_parse_{time_to_str}")

        # self.cert_stat_entry : CertAnalysisStats = CertAnalysisStats.query.filter_by(SCAN_ID=scan_process.ID).first()
        # if self.cert_stat_entry:
        #     self.cert_stat_entry.SCAN_TIME = scan_process.START_TIME
        #     self.cert_stat_entry.SCAN_TYPE = scan_process.TYPE
        #     self.cert_stat_entry.SCANNED_CERT_NUM = 0
        #     self.cert_stat_entry.ISSUER_ORG_COUNT = {}
        #     self.cert_stat_entry.KEY_SIZE_COUNT = {}
        #     self.cert_stat_entry.KEY_TYPE_COUNT = {}
        #     self.cert_stat_entry.SIG_ALG_COUNT = {}
        #     self.cert_stat_entry.VALIDATION_PERIOD_COUNT = {}
        #     self.cert_stat_entry.EXPIRED_PERCENT = 0.01
        # else:
        #     self.cert_stat_entry = CertAnalysisStats(
        #         SCAN_ID = scan_process.ID,
        #         SCAN_TIME = scan_process.START_TIME,
        #         SCAN_TYPE = scan_process.TYPE,
        #         SCANNED_CERT_NUM = 0,
        #         ISSUER_ORG_COUNT = {},
        #         KEY_SIZE_COUNT = {},
        #         KEY_TYPE_COUNT = {},
        #         SIG_ALG_COUNT = {},
        #         VALIDATION_PERIOD_COUNT = {},
        #         EXPIRED_PERCENT = 0
        #     )
        #     db.session.add(self.cert_stat_entry)
        # db.session.commit()
        # db.session.expunge(self.cert_stat_entry)


    def analyze_ca_parse(self, rows):
        '''
            Each row in rows has the following structure:
                'sha256_id': self.CERT_ID,
                'raw': self.CERT_RAW
        '''
        for row in rows:
            try:
                single_cert_parser = X509CertParser(row[1])
                cert_parse_result = single_cert_parser.parse_cert_base()

                identity = (cert_parse_result.issuer_cn, cert_parse_result.issuer_org, cert_parse_result.issuer_country)
                if identity not in self.result_list.keys():
                    with self.ca_id_lock:
                        self.result_list[identity] = CaStatResult(id=self.ca_id, cn=identity[0], org=identity[1], country=identity[2])
                        self.ca_id += 1

                self.sync_update_info(identity, cert_parse_result)
            except ParseError:
                pass
        self.dump()


    def sync_update_info(self, identity, cert_parse_result : X509ParsedInfo):

        with self.result_list_lock:
            stat_result : CaStatResult = self.result_list[identity]

            stat_result.signed_cert_num += 1

            current_utc_time = datetime.now(timezone.utc)
            time_end_utc = cert_parse_result.not_valid_after_utc.replace(tzinfo=timezone.utc)
            stat_result.expired_num += (current_utc_time > time_end_utc)
            
            def update_dict(dict, key):
                if key in dict:
                    dict[key] += 1
                else:
                    dict[key] = 1

            update_dict(stat_result.serial_len_count, (cert_parse_result.serial_number.bit_length() + 7) // 8)  # byte length
            update_dict(stat_result.subject_country_count, cert_parse_result.subject_country)
            update_dict(stat_result.signed_day_count, cert_parse_result.not_valid_before_utc.strftime("%Y%m%d"))
            update_dict(stat_result.validity_period_count, cert_parse_result.validation_period)
            update_dict(stat_result.key_size_count, cert_parse_result.subject_pub_key_size)
            update_dict(stat_result.key_type_count, cert_parse_result.subject_pub_key_algo.__class__.__name__)
            update_dict(stat_result.sig_type_count, cert_parse_result.cert_signature_hash_algorithm)

            for ext_result in cert_parse_result.extension_parsed_info:
                if type(ext_result) == AIAResult:
                    for issuer_url in ext_result.issuer_url_list:
                        stat_result.ca_cert_server.add(issuer_url)
                    for ocsp_url in ext_result.ocsp_url_list:
                        stat_result.ocsp_server.add(ocsp_url)
                if type(ext_result) == CRLResult:
                    for crl_url in ext_result.crl_url_list:
                        stat_result.crl_server.add(crl_url)
                if type(ext_result) == BasicConstraintsResult:
                    update_dict(stat_result.basic_constraint_count, ext_result.ca_bit)
                if type(ext_result) == KeyUsageResult:
                    stat_result.crypto_use_count['digital_sig'] += ext_result.digital_sig
                    stat_result.crypto_use_count['key_encipherment'] += ext_result.key_encipherment
                    stat_result.crypto_use_count['data_encipherment'] += ext_result.data_encipherment
                    stat_result.crypto_use_count['key_agreement'] += ext_result.key_agreement
                    stat_result.crypto_use_count['others'] += ext_result.others
                if type(ext_result) == ExtendedKeyUsageResult:
                    for usage in ext_result.ext_usage_list:
                        update_dict(stat_result.eku_count, usage.__str__())
                if type(ext_result) == CertPoliciesResult:
                    update_dict(stat_result.issued_policy_count, ext_result.issuer_policy)


    def dump(self):
        with self.result_list_lock:
            for result in self.result_list.values():
                if not result: continue
                result : CaStatResult

                ca_store_data = {
                    'CA_ID' : result.id,
                    'CA_COMMON_NAME' : result.cn,
                    'CA_ORG_NAME' : result.org,
                    'CA_COUNTRY_NAME' : result.country,
                    'ISSUED_CERT_NUM' : result.signed_cert_num,
                    'ISSUED_EXPIRED_NUM' : result.expired_num,
                    'ISSUED_SERIAL_LEN_COUNT' : result.serial_len_count,
                    'ISSUED_SIG_TYPE_COUNT' : result.sig_type_count,
                    'ISSUED_SUBJECT_COUNTRY_COUNT' : result.subject_country_count,
                    'ISSUED_CERT_DAY_COUNT' : result.signed_day_count,
                    'ISSUED_VALIDITY_PERIOD_COUNT' : result.validity_period_count,
                    'ISSUED_KEY_TYPE_COUNT' : result.key_type_count,
                    'ISSUED_KEY_SIZE_COUNT' : result.key_size_count,
                    'ISSUED_BASIC_CONSTRAINTS_COUNT' : result.basic_constraint_count,
                    'ISSUED_KEY_USAGE_COUNT' : result.crypto_use_count,
                    'ISSUED_EKU_COUNT' : result.eku_count,
                    'ISSUED_POLICY_COUNT' : result.issued_policy_count,
                    'CRL_POINTS' : list(result.crl_server),
                    'OCSP_SERVER' : list(result.ocsp_server),
                    'CA_CERT_SERVER' : list(result.ca_cert_server)
                }
                with app.app_context():
                    insert_ca_data_statement = insert(self.storage_table).values(ca_store_data)
                    update_values = {key: insert_ca_data_statement.inserted[key] for key in ca_store_data.keys()}
                    on_duplicate_key_statement = insert_ca_data_statement.on_duplicate_key_update(**update_values)
                    db.session.execute(on_duplicate_key_statement)
                    db.session.commit()

            # self.cert_stat_entry.SCANNED_CERT_NUM = self.num_cert
            # self.cert_stat_entry.ISSUER_ORG_COUNT = self.issuer_org_dict
            # self.cert_stat_entry.KEY_SIZE_COUNT = self.key_length_dict
            # self.cert_stat_entry.KEY_TYPE_COUNT = self.key_type_dict
            # self.cert_stat_entry.SIG_ALG_COUNT = self.sig_algo_dict
            # self.cert_stat_entry.VALIDATION_PERIOD_COUNT = self.valid_period_dict
            # self.cert_stat_entry.EXPIRED_PERCENT = self.num_expired_cert / self.num_cert

            # db.session.add(self.cert_stat_entry)
            # db.session.commit()

        print("end")
