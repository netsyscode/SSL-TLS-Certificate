
from app import app, db
from threading import Lock, Thread
from sqlalchemy.dialects.mysql import insert
from datetime import datetime, timezone
import cryptography.hazmat.bindings
from cryptography.hazmat.primitives.asymmetric import dsa as primitive_dsa, rsa as primitive_rsa, ec as primitive_ec, dh as primitive_dh

from ..logger.logger import my_logger
from ..parser.cert_parser_base import X509CertParser
from ..parser.cert_parser_extension import (
    AIAResult,
    KeyUsageResult,
    CertPoliciesResult,
    BasicConstraintsResult,
    ExtendedKeyUsageResult,
    CRLResult,
    AuthorityKeyIdentifierResult,
    SubjectKeyIdentifierResult,
    PrecertificateSignedCertificateTimestampsResult,
    SANResult
)
from ..utils.type import CertType
from ..utils.exception import ParseError, UnknownTableError
from ..utils.cert import get_cert_sha256_hex_from_str
from ..models import CertAnalysisStats, CertStoreContent, ScanStatus, CaCertStore, CaKeyStore, generate_ca_analysis_table
from ..parser.cert_parser_base import X509ParsedInfo
from sklearn.preprocessing import LabelEncoder
from dataclasses import dataclass, field
from typing import Dict, List, Tuple, Set

label_encoder = LabelEncoder()

def encode_label(label : str):
    encoded_label = label_encoder.fit_transform([label])[0]
    return encoded_label

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
        'key_agreement': 0
    })
    eku_count: Dict[str, int] = field(default_factory=dict)
    issued_policy_count: Dict[str, int] = field(default_factory=dict)

    issuing_cert_storage : List[str] = field(default_factory=list)
    issuing_key_storage : Dict[str, List[str]] = field(default_factory=dict)


class CertParseAnalyzer():

    def __init__(
            self,
            scan_id : str,
            save_chunk_size : int = 10000
        ) -> None:

        self.save_chunk_size = save_chunk_size
        self.cert_result_list_lock = Lock()
        self.cert_result_list = []
        self.ca_result_dict_lock = Lock()
        self.ca_result_dict = {}
        self.ca_id_lock = Lock()
        self.ca_id = 1

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
        time_to_str = scan_process.START_TIME.strftime("%Y%m%d%H%M%S")
        self.ca_stat_table = generate_ca_analysis_table(f"ca_parse_{time_to_str}")

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

                # Part 1
                fp = self.build_cert_fp_all(cert_parse_result)
                with self.cert_result_list_lock:
                    self.cert_result_list.append((cert_parse_result, fp))
                if len(self.cert_result_list) > self.save_chunk_size:
                    self.sync_update_cert_info()

                # Part 2
                identity = (cert_parse_result.issuer_cn, cert_parse_result.issuer_org, cert_parse_result.issuer_country)
                if identity not in self.ca_result_dict.keys():
                    with self.ca_id_lock:
                        self.ca_result_dict[identity] = CaStatResult(id=self.ca_id, cn=identity[0], org=identity[1], country=identity[2])
                        self.ca_id += 1
                self.update_ca_info(identity, cert_parse_result)

            except ParseError:
                pass
        self.sync_update_cert_info()
        self.sync_update_ca_info()


    def build_cert_fp_all(self, cert_parse_result : X509ParsedInfo) -> List[int]:
        '''
            The idea is similar to Ma's
            But I trim some unimportant features
        '''
        NUL = -1
        fp = []

        # Basic stuff
        fp.append(cert_parse_result.version.value)
        fp.append(int((cert_parse_result.serial_number.bit_length() + 7) // 8))  # byte length
        fp.append(int(encode_label(cert_parse_result.cert_signature_hash_algorithm)))
        fp.append(int(encode_label(cert_parse_result.subject_pub_key_algo.__str__())))
        fp.append(cert_parse_result.subject_pub_key_size)
        fp.append(cert_parse_result.validation_period / 10)

        # Issuer & Subject
        fp.append(int(encode_label(cert_parse_result.issuer_cn)))
        fp.append(int(encode_label(cert_parse_result.issuer_org)))
        fp.append(int(encode_label(cert_parse_result.issuer_country)))
        fp.append(int(encode_label(cert_parse_result.subject_country)))

        # Basic constraints
        ext_result : BasicConstraintsResult = cert_parse_result.extension_parsed_info.get_result_by_type(BasicConstraintsResult)
        if ext_result:
            fp.append(int(ext_result.ca_bit))
            if ext_result.path_len_constraint:
                fp.append(ext_result.path_len_constraint)
            else:
                fp.append(NUL)
        else:
            fp += [NUL, NUL]

        # Key usage
        ext_result : KeyUsageResult = cert_parse_result.extension_parsed_info.get_result_by_type(KeyUsageResult)
        if ext_result:
            fp.append(int(ext_result.digital_sig))
            fp.append(int(ext_result.non_reputation))
            fp.append(int(ext_result.key_encipherment))
            fp.append(int(ext_result.data_encipherment))
            fp.append(int(ext_result.key_agreement))
            fp.append(int(ext_result.key_cert_sign))
            fp.append(int(ext_result.crl_sign))
            # fp.append(int(ext_result.encipher_only))
            # fp.append(int(ext_result.decipher_only))
        else:
            fp += [NUL] * 7

        # Extended key usage
        ext_result : ExtendedKeyUsageResult = cert_parse_result.extension_parsed_info.get_result_by_type(ExtendedKeyUsageResult)
        if ext_result:
            fp.append(len(ext_result.ext_usage_list))
            fp.append(int(ext_result.server_auth))
            fp.append(int(ext_result.client_auth))
            fp.append(int(ext_result.code_sign))
            fp.append(int(ext_result.email_prot))
            fp.append(int(ext_result.time_stamp))
            fp.append(int(ext_result.ocsp_sign))
            fp.append(int(ext_result.others))
        else:
            fp += [NUL] * 8

        # Authority Key ID
        ext_result : AuthorityKeyIdentifierResult = cert_parse_result.extension_parsed_info.get_result_by_type(AuthorityKeyIdentifierResult)
        if ext_result:
            fp.append(len(ext_result.key_identifier))
        else:
            fp.append(NUL)

        # Subject Key ID
        ext_result : SubjectKeyIdentifierResult = cert_parse_result.extension_parsed_info.get_result_by_type(SubjectKeyIdentifierResult)
        if ext_result:
            fp.append(len(ext_result.key_identifier))
        else:
            fp.append(NUL)

        # SAN
        ext_result : SANResult = cert_parse_result.extension_parsed_info.get_result_by_type(SANResult)
        if ext_result:
            fp.append(len(ext_result.name_list) + len(ext_result.ip_list))
        else:
            fp.append(NUL)

        # Authority info access (AIA)
        ext_result : AIAResult = cert_parse_result.extension_parsed_info.get_result_by_type(AIAResult)
        if ext_result:
            fp.append(len(ext_result.issuer_url_list))
            fp.append(len(ext_result.ocsp_url_list))
        else:
            fp += [NUL] * 2

        # CRL distribution points
        ext_result : CRLResult = cert_parse_result.extension_parsed_info.get_result_by_type(CRLResult)
        if ext_result:
            fp.append(len(ext_result.crl_url_list))
        else:
            fp.append(NUL)
            
        # Policy identifiers
        ext_result : CertPoliciesResult = cert_parse_result.extension_parsed_info.get_result_by_type(CertPoliciesResult)
        if ext_result:
            fp.append(int(encode_label(ext_result.issuer_policy)))
        else:
            fp.append(NUL)
        
        # SCTs
        ext_result : PrecertificateSignedCertificateTimestampsResult = cert_parse_result.extension_parsed_info.get_result_by_type(PrecertificateSignedCertificateTimestampsResult)
        if ext_result:
            fp.append(ext_result.sct_length)
        else:
            fp.append(NUL)

        # Set of X.509 extensions
        fp.append(len(cert_parse_result.extension_parsed_info.ext_result_list))
        return fp


    def update_ca_info(self, identity, cert_parse_result : X509ParsedInfo):

        with self.ca_result_dict_lock:
            stat_result : CaStatResult = self.ca_result_dict[identity]

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

            for ext_result in cert_parse_result.extension_parsed_info.ext_result_list:
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
                if type(ext_result) == ExtendedKeyUsageResult:
                    for usage in ext_result.ext_usage_list:
                        update_dict(stat_result.eku_count, usage.__str__())
                if type(ext_result) == CertPoliciesResult:
                    update_dict(stat_result.issued_policy_count, ext_result.issuer_policy)

            # Added for CA crypto storage (cert and key)
            if cert_parse_result.cert_type != CertType.LEAF:
                stat_result.issuing_cert_storage.append(cert_parse_result.sha_256)
                if cert_parse_result.subject_pub_key_algo.__class__.__name__ not in stat_result.issuing_key_storage:
                    stat_result.issuing_key_storage[cert_parse_result.subject_pub_key_algo.__class__.__name__] = []
                stat_result.issuing_key_storage[cert_parse_result.subject_pub_key_algo.__class__.__name__].append(cert_parse_result.pub_key_raw)


    def sync_update_cert_info(self):
        with self.cert_result_list_lock:
            my_logger.info(f"Updating cert parsing data...")

            with app.app_context():
                cert_store_data_to_insert = []
                ca_cert_store_data_to_insert = []
                ca_key_data_to_insert = []

                KEY_TYPE_MAPPING = {
                    primitive_rsa.RSAPublicKey : 0,
                    primitive_ec.EllipticCurvePublicKey : 1,
                    cryptography.hazmat.bindings._rust.openssl.rsa.RSAPublicKey : 0,
                    cryptography.hazmat.bindings._rust.openssl.ec.ECPublicKey : 1,
                    cryptography.hazmat.bindings._rust.openssl.ed25519.Ed25519PublicKey : 2
                }

                my_logger.info(f"Converting {len(self.cert_result_list)} data...")
                for result in self.cert_result_list:
                    parse_result : X509ParsedInfo = result[0]
                    if not parse_result: continue
                    current_utc_time = datetime.now(timezone.utc)

                    # 通过添加时区信息确保 time_end 也是 UTC 时间
                    time_end_utc = parse_result.not_valid_after_utc.replace(tzinfo=timezone.utc)
                    has_expired = (current_utc_time > time_end_utc)

                    try:
                        key_type = KEY_TYPE_MAPPING[parse_result.subject_pub_key_algo.__class__]
                    except KeyError:
                        my_logger.warning(f"Unknown key type {parse_result.subject_pub_key_algo.__class__}")
                        key_type = -1

                    cert_store_data = {
                        'CERT_ID' : parse_result.sha_256,
                        'CERT_TYPE' : parse_result.cert_type.value,
                        'SUBJECT_CN' : parse_result.subject_cn,
                        'ISSUER_CN' : parse_result.issuer_cn,
                        'ISSUER_ORG' : parse_result.issuer_org,
                        'ISSUER_COUNTRY' : parse_result.issuer_country,
                        'KEY_SIZE' : parse_result.subject_pub_key_size,
                        'KEY_TYPE' : key_type,
                        'NOT_VALID_BEFORE' : parse_result.not_valid_before_utc,
                        'NOT_VALID_AFTER' : parse_result.not_valid_after_utc,
                        'VALIDATION_PERIOD' : parse_result.validation_period,
                        'FINGERPRINT' : result[1]
                    }
                    cert_store_data_to_insert.append(cert_store_data)
                    insert_cert_store_statement = insert(CertStoreContent).values(cert_store_data)
                    # update_values = {key: insert_cert_store_statement.inserted[key] for key in cert_store_data.keys()}
                    update_values = {'FINGERPRINT': insert_cert_store_statement.inserted['FINGERPRINT']}
                    on_duplicate_key_statement = insert_cert_store_statement.on_duplicate_key_update(**update_values)
                    db.session.execute(on_duplicate_key_statement)
                    db.session.commit()

                    if parse_result.cert_type != CertType.LEAF:
                        ca_cert_data = {
                            'CERT_ID' : parse_result.sha_256,
                            'CERT_RAW' : parse_result.cert_raw,
                            'CERT_TYPE' : parse_result.cert_type.value,
                            'CA_COMMON_NAME' : parse_result.subject_cn,
                            'CA_ORG_NAME' : parse_result.subject_org,
                            'CA_COUNTRY_NAME' : parse_result.subject_country
                        }
                        ca_cert_store_data_to_insert.append(ca_cert_data)
                        # insert_ca_cert_store_statement = insert(CaCertStore).values([ca_cert_data]).prefix_with('IGNORE')
                        # db.session.execute(insert_ca_cert_store_statement)

                        kid = get_cert_sha256_hex_from_str(parse_result.pub_key_raw)
                        for ext_result in parse_result.extension_parsed_info.ext_result_list:
                            if type(ext_result) == SubjectKeyIdentifierResult:
                                kid = ext_result.key_identifier

                        ca_key_data = {
                            'KEY_ID' : kid,
                            'KEY_RAW' : parse_result.pub_key_raw,
                            'KEY_TYPE' : parse_result.cert_type.value,
                            'CA_COMMON_NAME' : parse_result.subject_cn,
                            'CA_ORG_NAME' : parse_result.subject_org,
                            'CA_COUNTRY_NAME' : parse_result.subject_country
                        }
                        ca_key_data_to_insert.append(ca_key_data)
                        # insert_ca_key_store_statement = insert(CaKeyStore).values([ca_key_data]).prefix_with('IGNORE')
                        # db.session.execute(insert_ca_key_store_statement)

                    def update_dict(dict, key):
                        if key in dict:
                            dict[key] += 1
                        else:
                            dict[key] = 1

                    if has_expired:
                        self.num_expired_cert += 1
                    update_dict(self.key_type_dict, parse_result.subject_pub_key_algo.__class__.__name__)
                    update_dict(self.key_length_dict, parse_result.subject_pub_key_size)
                    update_dict(self.issuer_org_dict, parse_result.issuer_org)
                    update_dict(self.valid_period_dict, parse_result.validation_period)
                    update_dict(self.sig_algo_dict, parse_result.cert_signature_hash_algorithm)
                    self.num_cert += 1

                # my_logger.info(f"Finished {len(cert_store_data_to_insert)} data...")
                # if cert_store_data_to_insert == []:
                #     self.cert_result_list = []
                #     return

                try:
                    self.cert_stat_entry.SCANNED_CERT_NUM = self.num_cert
                    self.cert_stat_entry.ISSUER_ORG_COUNT = self.issuer_org_dict
                    self.cert_stat_entry.KEY_SIZE_COUNT = self.key_length_dict
                    self.cert_stat_entry.KEY_TYPE_COUNT = self.key_type_dict
                    self.cert_stat_entry.SIG_ALG_COUNT = self.sig_algo_dict
                    self.cert_stat_entry.VALIDATION_PERIOD_COUNT = self.valid_period_dict
                    self.cert_stat_entry.EXPIRED_PERCENT = self.num_expired_cert / self.num_cert

                    db.session.add(self.cert_stat_entry)
                    db.session.commit()

                    '''
                        TODO: Do not ask me why I store one line of data at a time, not 
                        a batch of data.
                        If I do the latter, the sql server does not responding...
                        and the program stucks...
                        Need to figure out why...
                        I know why, the insertion succeeds, but I did not use 
                        db.session.commit()
                        so the inserted data stored in cache and not instantly show in workbench
                    '''

                    # update_values = {key: insert_cert_store_statement.inserted[key] for key in cert_store_data.keys()}
                    # on_duplicate_key_statement = insert_cert_store_statement.on_duplicate_key_update(**update_values)
                    # db.session.execute(on_duplicate_key_statement)
                    # insert_cert_store_statement = insert(CertStoreContent).values(cert_store_data_to_insert).prefix_with('IGNORE')
                    # db.session.execute(insert_cert_store_statement)
                    # db.session.commit()

                    insert_ca_cert_store_statement = insert(CaCertStore).values(ca_cert_store_data_to_insert).prefix_with('IGNORE')
                    db.session.execute(insert_ca_cert_store_statement)
                    db.session.commit()

                    insert_ca_key_store_statement = insert(CaKeyStore).values(ca_key_data_to_insert).prefix_with('IGNORE')
                    db.session.execute(insert_ca_key_store_statement)
                    db.session.commit()
                except Exception as e:
                    my_logger.error(f"Error inserting cert parsing data: {e} \n {e.with_traceback()}")

            print("end")
            self.cert_result_list = []


    def sync_update_ca_info(self):
        with self.ca_result_dict_lock:
            for result in self.ca_result_dict.values():
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
                    try:
                        insert_ca_data_statement = insert(self.ca_stat_table).values(ca_store_data)
                        update_values = {key: insert_ca_data_statement.inserted[key] for key in ca_store_data.keys()}
                        on_duplicate_key_statement = insert_ca_data_statement.on_duplicate_key_update(**update_values)
                        db.session.execute(on_duplicate_key_statement)
                        db.session.commit()
                    except Exception as e:
                        my_logger.error(f"Error inserting ca parsing data: {e} \n {e.with_traceback()}")
            print("ca end")
