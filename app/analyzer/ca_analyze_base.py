
from ..utils.cert import LeafCertType, CertType
from .cert_analyze_base import CertScanAnalyzer
from ..logger.logger import my_logger

from collections import Counter
from dataclasses import dataclass, asdict
from typing import Optional, Dict, Tuple, Union, List
from datetime import datetime
import json
import os

from sqlalchemy.exc import IntegrityError
from sqlalchemy import insert
from .. import db

from ..models import CertAnalysisStats, generate_cert_analysis_table
from ..scanner import app, db
from threading import Lock
import threading
import time


@dataclass
class AnalysisSupportDataStructure:
    # Check if one single domain has multiple certificates
    domain_cert_mapping : Dict[str, set]
    domain_ca_mapping : Dict[str, list[str]]
    # Check cross-sign instances: one public key binds multiple certificates
    key_cert_mapping : Dict[str, set]
    key_ca_mapping : Dict[str, list[str]]


@dataclass
class CAMetricResult():

    cn : str
    org : str
    country : str

    issuer_info : List[dict]

    unique_signed_cert_num : int
    signed_cert_hash_list : set

    unique_signing_cert_num : int
    signing_cert_hash_list : set

    signed_day_count : Dict[int, int]
    expired_num : int
    validity_period : Dict[int, int]
    validity_valid_percent : float

    key_size_count : dict
    key_type_count : dict
    hash_count : dict

    caa_not_match : int
    leaf_dv_num : int
    leaf_ov_num : int
    leaf_ev_num : int
    # crypto_rsa_size : Dict[int, int]
    # crypto_ec_size : Dict[int, int]

    # crypto_use : list[list[int]]
    # trusted_hosting_provider : set
    # crl_server_url : set
    # ocsp_server_url : set


class CAMetricAnalyzer():

    def __init__(self, cert_scan_analyzer : CertScanAnalyzer) -> None:
        self.cert_scan_analyzer : CertScanAnalyzer = cert_scan_analyzer
        self.ca_dict : Dict[Tuple[str, str, str], CAMetricResult] = {}
        self.support_data = AnalysisSupportDataStructure({}, {}, {}, {})
        self.analyzeFromCertScanResult()


    def analyzeFromCertScanResult(self):
        '''
            We do not use trusted root store for CA ananysis
            as trusted root certs can not reveal anything unusual
        '''
        cert_store_list = [
            self.cert_scan_analyzer.scanned_leaf_cert_store,
            self.cert_scan_analyzer.scanned_intermediate_cert_store,
            self.cert_scan_analyzer.scanned_root_cert_store
        ]

        for cert_store in cert_store_list:
            for sha256, cert_result in cert_store.content.items():
                ca_tuple = (cert_result.issuer_cn, cert_result.issuer_org, cert_result.issuer_country)
                if ca_tuple not in self.ca_dict:
                    self.ca_dict[ca_tuple] = CAMetricResult(
                        ca_tuple[0], ca_tuple[1], ca_tuple[2],
                        0, set(), 0, set(), {}, {},
                        0.0, 0, 0, 0, 0,
                        {}, {}, {},
                        0, 0, 0
                    )

                target_ca_result = self.ca_dict[ca_tuple]
                if sha256 not in target_ca_result.signed_cert_hash_list:
                    target_ca_result.signed_cert_hash_list.add(sha256)
                    target_ca_result.unique_signed_cert_num += 1

                if cert_store.type == CertType.LEAFCERT:
                    continue

                ca_tuple = (cert_result.subject_cn, cert_result.subject_org, cert_result.subject_country)
                if ca_tuple not in self.ca_dict:
                    self.ca_dict[ca_tuple] = CAMetricResult(
                        ca_tuple[0], ca_tuple[1], ca_tuple[2],
                        0, set(), 0, set(), {}, {},
                        0.0, 0, 0, 0, 0,
                        {}, {}, {},
                        0, 0, 0
                    )

                target_ca_result = self.ca_dict[ca_tuple]
                if sha256 not in target_ca_result.signing_cert_hash_list:
                    target_ca_result.signing_cert_hash_list.add(sha256)
                    target_ca_result.unique_signing_cert_num += 1


    # @deprecated, currently do not use
    def analyzeCertFromFile(self, file_name : str):

        with open(file_name, "r") as cert_file:
            data = json.load(cert_file)

            for single_server_scan_result in data:
                host_name = single_server_scan_result["Host Name"]

                for cert_result in single_server_scan_result["Cert Result"]:
                    ca : str = cert_result["Issuer Org"]

                    if ca not in self.ca_dict.keys():
                        self.ca_dict[ca] = CAMetricResult(
                            ca, set(), 0,
                            set(), {}, {},
                            0.0, 0, 0, 0, 0, 0,
                            {}, {}, {},
                            0, 0, 0
                        )

                    current_metrics = self.ca_dict[ca]
                    current_metrics.signing_cert_hash_list.add(cert_result["Issuer CN"])

                    if cert_result["SHA256"] in current_metrics.signed_cert_hash_list: continue
                    current_metrics.signed_cert_hash_list.add(cert_result["SHA256"])

                    valid_period = int(cert_result["Validation Period in days"])
                    updateDictByPlusOne(current_metrics.validity_period, valid_period)

                    start_date = int(cert_result["Not Valid Before"])
                    updateDictByPlusOne(current_metrics.signed_day_count, start_date)
                    
                    key_not_ok = False
                    hash_not_ok = False

                    key_size = int(cert_result["Subject Public Key Size"])
                    if cert_result["Subject Public Key Type"] == "RSA Key":
                        if key_size < 2048:
                            key_not_ok = True
                        updateDictByPlusOne(current_metrics.crypto_rsa_size, key_size)

                    if cert_result["Subject Public Key Type"] == "Elliptic Curve":
                        if key_size < 256:
                            key_not_ok = True
                        updateDictByPlusOne(current_metrics.crypto_ec_size, key_size)
                    
                    hash_algorithm = cert_result["Signature Hash Algorithm"]
                    if "sha1" in hash_algorithm or "md5" in hash_algorithm:
                        hash_not_ok = True
                    updateDictByPlusOne(current_metrics.crypto_sig_algorithm, hash_algorithm)

                    if key_not_ok:
                        if hash_not_ok:
                            current_metrics.both_violation += 1
                        else:
                            current_metrics.key_violation += 1
                    else:
                        if hash_not_ok:
                            current_metrics.hash_violation += 1

                    if cert_result["Type"] == "Leaf":
                        current_metrics.unique_signed_cert_num += 1

                        cert_type = cert_result["Leaf Cert Type"]
                        if cert_type == "DV":
                            current_metrics.leaf_dv_num += 1
                        elif cert_type == "OV":
                            current_metrics.leaf_ov_num += 1
                        elif cert_type == "EV":
                            current_metrics.leaf_ev_num += 1

                        caa_record = cert_result["CAA Records"]
                        for cn, ca_list in caa_record.items():
                            if len(ca_list) == 0: continue
                            if ca not in ca_list:
                                current_metrics.caa_not_match += 1
                                break

                    # Update support data structures:
                    subject_names = cert_result["Subject CN"]
                    for subject_name in subject_names:
                        if subject_name not in self.support_data.domain_ca_mapping:
                            self.support_data.domain_ca_mapping[subject_name] = []
                        if subject_name not in self.support_data.domain_cert_mapping:
                            self.support_data.domain_cert_mapping[subject_name] = set()
                        if cert_result["SHA256"] not in self.support_data.domain_cert_mapping[subject_name]:
                            self.support_data.domain_cert_mapping[subject_name].add((cert_result["Type"], cert_result["SHA256"]))
                            self.support_data.domain_ca_mapping[subject_name].append((cert_result["SHA256"], ca))

                    pub_key = cert_result["Public Key"]
                    if pub_key not in self.support_data.key_ca_mapping:
                        self.support_data.key_ca_mapping[pub_key] = []
                    if pub_key not in self.support_data.key_cert_mapping:
                        self.support_data.key_cert_mapping[pub_key] = set()
                    if cert_result["SHA256"] not in self.support_data.key_cert_mapping[pub_key]:
                        self.support_data.key_cert_mapping[pub_key].add((cert_result["Type"], cert_result["SHA256"]))
                        self.support_data.key_ca_mapping[pub_key].append((cert_result["SHA256"], ca))

                    # subject_org = cert_result["Subject Org"]
                    # for use in range(len(cert_result.key_usage)):
                    #     current_metrics.crypto_use[index][use] += cert_result.key_usage[use]
                    # if (subject and "cdn" in subject) or (subject_org and "cdn" in subject_org):
                    #     current_metrics.trusted_hosting_provider.add(subject)
                    # for crl in cert_result.crl_url_list:
                    #     current_metrics.crl_server_url.add(crl)
                    # for ocsp in cert_result.ocsp_url_list:
                    #     current_metrics.ocsp_server_url.add(ocsp)
                    #  \ "Intermediate" \ "Root"


    def analyze(self):
        file_path = r"..\certAnalyzer\output\json_output_20231211.json"
        self.analyzeCertFromFile(file_path)

        # compute average
        for key, ca in self.ca_dict.items():

            ca.signing_cert_hash_list = list(ca.signing_cert_hash_list)
            ca.unique_signed_cert_num = len(ca.signed_cert_hash_list)
            ca.signed_cert_hash_list = None
            ca.signed_day_count = dict(sorted(ca.signed_day_count.items()))

            # ca.trusted_hosting_provider = list(ca.trusted_hosting_provider)
            # ca.crl_server_url = list(ca.crl_server_url)
            # ca.ocsp_server_url = list(ca.ocsp_server_url)
            self.ca_dict[key] = asdict(ca)


    def dump(self):
        self.ca_dict = sorted(self.ca_dict.items(), key=lambda x: x[1]['unique_cert_num'], reverse=True)

        timestamp = datetime.now().strftime("%Y%m%d")
        output_dir = convertRelativePathToAbsPath(__file__, "output")
        output_file_name = os.path.join(output_dir, f"ca_metrics_result_{timestamp}.json")
        my_logger.dumpLog(INFO, f"Dumping result to {output_file_name}")

        self.dumpSupportStructures()
        with open(output_file_name, 'w') as json_file:
            json.dump(self.ca_dict, json_file, indent = 4)


    def dumpSupportStructures(self, output_dir = "output"):

        timestamp = datetime.now().strftime("%Y%m%d")
        output_dir = convertRelativePathToAbsPath(__file__, output_dir)

        for key, value in self.support_data.domain_ca_mapping.items():
            self.support_data.domain_ca_mapping[key] = list(value)

        for key, value in self.support_data.key_ca_mapping.items():
            self.support_data.key_ca_mapping[key] = list(value)

        output_file_name = os.path.join(output_dir, f"domain_ca_mapping_{timestamp}.json")
        with open(output_file_name, "w") as f1:
            json.dump(self.support_data.domain_ca_mapping, f1, indent=4)

        output_file_name = os.path.join(output_dir, f"key_ca_mapping_{timestamp}.json")
        with open(output_file_name, "w") as f2:
            json.dump(self.support_data.key_ca_mapping, f2, indent=4)


    def dumpToSQL(self, connector : SQLConnection, scan_time : str):

        ca_storage_table_name = f"{scan_time}_ca_basic_info"

        try:
            drop_table_query = f"""
                drop table {ca_storage_table_name}
            """
            connector.cursor.execute(drop_table_query)
            connector.connection.commit()

        except Error as err:
            my_logger.dumpLog(WARNING, f"{err}")

        try:
            create_table_query = f"""
            CREATE TABLE {ca_storage_table_name} (
                id INT AUTO_INCREMENT PRIMARY KEY,
                ca_cn VARCHAR(128),
                ca_org VARCHAR(64),
                ca_country VARCHAR(8),
                num_signed_certs INT,
                signed_certs JSON,
                num_signing_certs INT,
                signing_certs JSON,
                crl_server TEXT,
                ocsp_server TEXT
            )
            """
            connector.cursor.execute(create_table_query)
            connector.connection.commit()

            insert_query = f"""
                INSERT INTO {ca_storage_table_name}
                (ca_cn, ca_org, ca_country, num_signed_certs, signed_certs,
                num_signing_certs, signing_certs, crl_server, ocsp_server)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
            """

            for ca, ca_result in self.ca_dict.items():
                data = (
                    ca_result.cn,
                    ca_result.org,
                    ca_result.country,
                    ca_result.unique_signed_cert_num,
                    json.dumps(list(ca_result.signed_cert_hash_list)),
                    ca_result.unique_signing_cert_num,
                    json.dumps(list(ca_result.signing_cert_hash_list)),
                    "",
                    ""
                )
                connector.cursor.execute(insert_query, data)
                connector.connection.commit()

        except Error as err:
            my_logger.dumpLog(ERROR, f"Other error: {err}")

    # def collectRevokedCerts(self, crl_list : list[str]):
    #     for crl_url in crl_list:
