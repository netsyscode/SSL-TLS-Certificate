
from app import db, app
from ..parser.cert_parser_base import X509CertParser, X509ParsedInfo
from ..parser.cert_parser_extension import (
    AIAResult,
    KeyUsageResult,
    CertPoliciesResult,
    BasicConstraintsResult,
    ExtendedKeyUsageResult,
    CRLResult
)

from ..utils.exception import ParseError, UnknownTableError
from ..models.CaProfiling import generate_ca_profiling_table
from ..parser.cert_parser_base import X509ParsedInfo
from ..logger.logger import my_logger

from typing import Dict, List, Tuple
from threading import Lock
from sqlalchemy import MetaData
from sqlalchemy.dialects.mysql import insert
from sklearn.preprocessing import LabelEncoder

label_encoder = LabelEncoder()

def encode_label(label : str):
    encoded_label = label_encoder.fit_transform([label])[0]
    return encoded_label

ca_org_list = []
# Read CA Org Name from file
with open(r"E:/global_ca_monitor/tool/domain_collector/data/seed_ca_org_name", "r", encoding='utf-8') as file:
    for line in file:
        ca_org_list.append(line.strip())
print(ca_org_list)

class CaSignedCertProfilingAnalyzer:

    def __init__(self) -> None:
        
        # try:
        #     parser = configparser.ConfigParser()
        #     config_path = convertRelativePathToAbsPath(__file__, config_path)
        #     my_logger.debug(f"Reading cluster config file: {config_path}")
        #     parser.read(config_path)

        #     # cluster distance weight
        #     self.issuer_weight = float(parser.get("distance_weight", "issuer"))
        #     self.signature_algorithm_weight = float(parser.get("distance_weight", "signature_algorithm"))
        #     self.key_algorithm_weight = float(parser.get("distance_weight", "key_algorithm"))
        #     self.extension_set_weight = float(parser.get("distance_weight", "extension_set"))
        #     self.policy_id_weight = float(parser.get("distance_weight", "policy_id"))
        #     self.aia_info_weight = float(parser.get("distance_weight", "aia_info"))
        #     self.key_usage_weight = float(parser.get("distance_weight", "key_usage"))
        #     self.basic_constraints_weight = float(parser.get("distance_weight", "basic_constraints"))

        #     self.subject_weight = float(parser.get("distance_weight", "subject"))
        #     self.crl_info_weight = float(parser.get("distance_weight", "crl_info"))
        #     self.extend_key_usage_weight = float(parser.get("distance_weight", "extend_key_usage"))

        #     self.key_size_weight = float(parser.get("distance_weight", "key_size"))
        #     self.issuance_date_weight = float(parser.get("distance_weight", "issuance_date"))
        #     self.valid_period_weight = float(parser.get("distance_weight", "valid_period"))
        #     self.serial_len_weight = float(parser.get("distance_weight", "serial_len"))

        #     # cluster parameters
        #     self.num_medoids = int(parser.get("cluster", "num_medoids"))
        #     self.num_iter = int(parser.get("cluster", "num_iter"))

        #     # score metric
        #     self.subject_score_weight = float(parser.get("score_metric", "subject"))
        #     self.issuer_score_weight = float(parser.get("score_metric", "issuer"))
        #     self.crypto_score_weight = float(parser.get("score_metric", "crypto"))
        #     self.extension_score_weight = float(parser.get("score_metric", "extension"))

        # except FileNotFoundError as e:
        #     my_logger.error("Cluster config file does not exist")

        # except (configparser.MissingSectionHeaderError, configparser.ParsingError, configparser.NoSectionError) as e:
        #     my_logger.error(f"Error reading cluster config file: {e}")

        self.feature_lock= Lock()
        self.feature_dict_by_ca : Dict[Tuple[str, str, str], List[Tuple[float, float, float]]]= {}


    def analyze_ca_profiling(self, rows):
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
                with self.feature_lock:
                    if identity not in self.feature_dict_by_ca.keys():
                        self.feature_dict_by_ca[identity] = []

                feature_value = self.calculate_cert_feature(cert_parse_result)
                with self.feature_lock:
                    self.feature_dict_by_ca[identity].append(feature_value)

            except ParseError:
                pass

        self.sync_update_info()


    def sync_update_info(self):

        with app.app_context():
            with self.feature_lock:
                metadata = MetaData()
                metadata.reflect(bind=db.engine)

                for ca_org in self.feature_dict_by_ca:
                    
                    if ca_org[1] not in ca_org_list: continue
                    ca_org_name = ca_org[1].replace(" ", "").lower()
                    table_name = f"profiling_{ca_org_name}"

                    if table_name in metadata.tables:
                        table = metadata.tables[table_name]
                    else:
                        table = generate_ca_profiling_table(ca_org[1])

                    feature_data = []
                    for feature in self.feature_dict_by_ca[ca_org]:
                        feature_data.append({
                            "HIGH_FEATURE_VALUE" : int(feature[0]),
                            "MEDIUM_FEATURE_VALUE" : int(feature[1]),
                            "LOW_FEATURE_VALUE" : int(feature[2])
                        })

                    insert_ca_data_statement = insert(table).values(feature_data)
                    db.session.execute(insert_ca_data_statement)
                    db.session.commit()

                self.feature_dict_by_ca = {}


    def calculate_cert_feature(self, cert_parse_result : X509ParsedInfo) -> Tuple[float, float, float]:
        high = 0
        med = 0
        low = 0

        # Signature and Key algorithms
        high += encode_label(cert_parse_result.cert_signature_hash_algorithm)
        high += encode_label(cert_parse_result.subject_pub_key_algo.__str__())
        low += cert_parse_result.subject_pub_key_size / 100

        # Set of X.509 extensions
        high += len(cert_parse_result.extension_parsed_info)

        for ext_result in cert_parse_result.extension_parsed_info:
            # Authority info access (AIA)
            if type(ext_result) == AIAResult:
                for issuer_url in ext_result.issuer_url_list:
                    high += len(issuer_url) / 10
                for ocsp_url in ext_result.ocsp_url_list:
                    high += len(ocsp_url) / 10

            # CRL distribution points
            if type(ext_result) == CRLResult:
                for crl_url in ext_result.crl_url_list:
                    med += len(crl_url) / 10

            # Basic constraints
            if type(ext_result) == BasicConstraintsResult:
                high += ext_result.ca_bit
            
            # Key usage & Basic constraint
            if type(ext_result) == KeyUsageResult:
                high += ext_result.digital_sig
                high += ext_result.key_encipherment
                high += ext_result.data_encipherment
                high += ext_result.key_agreement
                high += ext_result.others
            
            # Extended key usage
            if type(ext_result) == ExtendedKeyUsageResult:
                med += len(ext_result.ext_usage_list)
                # for usage in ext_result.ext_usage_list:
                    # med += usage.__str__()
            
            # Policy identifiers
            if type(ext_result) == CertPoliciesResult:
                high += encode_label(ext_result.issuer_policy)

        # Validity period
        low += cert_parse_result.validation_period / 100

        # Serial number length
        low += (cert_parse_result.serial_number.bit_length() + 7) // 8  # byte length
        
        return (high, med, low)

