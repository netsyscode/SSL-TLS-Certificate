
'''
    Created on 11/04/23
    Certificate cluster based on NDSS'14 paper
'''
from cryptography.x509 import (
    Certificate,
    ObjectIdentifier,
    ExtensionOID,
    AuthorityInformationAccessOID,
    PolicyInformation,
    AccessDescription,
    DistributionPoint,
    ExtendedKeyUsage,
    ExtensionNotFound
)
from ..parser.cert_parser_extension import (
    AIAResult,
    KeyUsageResult,
    CertPoliciesResult,
    BasicConstraintsResult,
    ExtendedKeyUsageResult,
    CRLResult
)
from app.parser.cert_parser_base import X509CertParser, X509ParsedInfo
from ..utils.exception import ParseError, UnknownTableError
from ..models import CertAnalysisStats, CertStoreContent, ScanStatus, CaCertStore, generate_ca_analysis_table
from ..parser.cert_parser_base import X509ParsedInfo
from ..logger.logger import my_logger


from cryptography.x509.oid import NameOID
from webPKIScanner.certAnalyzer.x509CertUtils import (
    utcTimeDifferenceInDays,
    getNameAttribute
)
from webPKIScanner.commonHelpers.pathHelpers.pathLocate import convertRelativePathToAbsPath
from sklearn.cluster import KMeans, MiniBatchKMeans
from typing import Dict, List
import concurrent.futures
import threading
import numpy as np
import configparser
import os


class X509CertCluster:

    def __init__(
            self,
            config_path : str = r"config\clusterConfig.cfg"
        ) -> None:
        
        try:
            parser = configparser.ConfigParser()
            config_path = convertRelativePathToAbsPath(__file__, config_path)
            my_logger.debug(f"Reading cluster config file: {config_path}")
            parser.read(config_path)

            # cluster distance weight
            self.issuer_weight = float(parser.get("distance_weight", "issuer"))
            self.signature_algorithm_weight = float(parser.get("distance_weight", "signature_algorithm"))
            self.key_algorithm_weight = float(parser.get("distance_weight", "key_algorithm"))
            self.extension_set_weight = float(parser.get("distance_weight", "extension_set"))
            self.policy_id_weight = float(parser.get("distance_weight", "policy_id"))
            self.aia_info_weight = float(parser.get("distance_weight", "aia_info"))
            self.key_usage_weight = float(parser.get("distance_weight", "key_usage"))
            self.basic_constraints_weight = float(parser.get("distance_weight", "basic_constraints"))

            self.subject_weight = float(parser.get("distance_weight", "subject"))
            self.crl_info_weight = float(parser.get("distance_weight", "crl_info"))
            self.extend_key_usage_weight = float(parser.get("distance_weight", "extend_key_usage"))

            self.key_size_weight = float(parser.get("distance_weight", "key_size"))
            self.issuance_date_weight = float(parser.get("distance_weight", "issuance_date"))
            self.valid_period_weight = float(parser.get("distance_weight", "valid_period"))
            self.serial_len_weight = float(parser.get("distance_weight", "serial_len"))

            # cluster parameters
            self.num_medoids = int(parser.get("cluster", "num_medoids"))
            self.num_iter = int(parser.get("cluster", "num_iter"))

            # score metric
            self.subject_score_weight = float(parser.get("score_metric", "subject"))
            self.issuer_score_weight = float(parser.get("score_metric", "issuer"))
            self.crypto_score_weight = float(parser.get("score_metric", "crypto"))
            self.extension_score_weight = float(parser.get("score_metric", "extension"))

        except FileNotFoundError as e:
            my_logger.error("Cluster config file does not exist")

        except (configparser.MissingSectionHeaderError, configparser.ParsingError, configparser.NoSectionError) as e:
            my_logger.error(f"Error reading cluster config file: {e}")


        self.cert_dict_based_on_issuer : Dict[(str,str,str), List[Certificate]]= {}



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
                if identity not in self.cert_dict_based_on_issuer.keys():
                    with self.ca_id_lock:
                        self.cert_dict_based_on_issuer[identity] = []

                with self.result_list_lock:
                    self.cert_dict_based_on_issuer[identity].append(cert_parse_result)

            except ParseError:
                pass

        for k, v in self.cert_dict_based_on_issuer.items():

            self.size = len(self.cert_list)
            self.distance_matrix = np.zeros((self.size, self.size))
            self.cluster_result = {}    # Key is the cluster index, value is the index of the certificate
            self.medoids = []   # contain index

            m = self.buildDistanceMatrix()
            self.kMedoidsWithKMeansPP(m)

        self.dump()


    def sync_update_info(self, identity, cert_parse_result : X509ParsedInfo):

        with self.result_list_lock:
            stat_result : CaStatResult = self.result_list[identity]

            stat_result.signed_cert_num += 1

            current_utc_time = datetime.now(timezone.utc)
            time_end_utc = cert_parse_result.not_valid_after.replace(tzinfo=timezone.utc)
            stat_result.expired_num += (current_utc_time > time_end_utc)
            
            def update_dict(dict, key):
                if key in dict:
                    dict[key] += 1
                else:
                    dict[key] = 1

            update_dict(stat_result.serial_len_count, (cert_parse_result.serial_number.bit_length() + 7) // 8)  # byte length
            update_dict(stat_result.subject_country_count, cert_parse_result.subject_country)
            update_dict(stat_result.signed_day_count, cert_parse_result.not_valid_before.strftime("%Y%m%d"))
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



    '''
        Distance calculation
    '''
    def calculateCertDistance(self, cert1 : X509ParsedInfo, cert2 : X509ParsedInfo) -> float:
        distance = 0
        high = 0
        med = 0
        low = 0

        '''
            High weight stuffs
        '''
        # Parent CA
        distance += (not (cert1.issuer == cert2.issuer)) * self.issuer_weight

        # Signature and Key algorithms
        distance += (not cert1.cert.signature_algorithm_oid == cert2.cert.signature_algorithm_oid) * self.signature_algorithm_weight
        distance += (not cert1.cert.public_key().__class__ == cert2.cert.public_key().__class__) * self.key_algorithm_weight

        # Set of X.509 extensions
        distance += self.computeJaccardDistance(cert1.extension_set, cert2.extension_set, self.extension_set_weight)

        # Policy identifiers
        distance += self.computeJaccardDistance(cert1.policy_set, cert2.policy_set, self.policy_id_weight)

        # Authority info access (AIA)
        distance += self.computeJaccardDistance(cert1.aia_set, cert2.aia_set, self.aia_info_weight)

        # Key usage & Basic constraint
        distance += self.compareCertExtensionWithOid(cert1.cert, cert2.cert, ExtensionOID.KEY_USAGE) * self.key_usage_weight
        distance += self.compareCertExtensionWithOid(cert1.cert, cert2.cert, ExtensionOID.BASIC_CONSTRAINTS) * self.basic_constraints_weight
        high = distance

        '''
            Medium weight stuffs
        '''
        # Subject name fields
        distance += (not (cert1.subject == cert2.subject)) * self.subject_weight

        # CRL distribution points
        distance += self.computeJaccardDistance(cert1.crl_set, cert2.crl_set, self.crl_info_weight)

        # Extended key usage
        distance += self.computeJaccardDistance(cert1.ext_set, cert2.ext_set, self.extend_key_usage_weight)
        med = distance - high

        '''
            Low weight stuffs
        '''
        # Key size
        distance += abs(cert1.cert.public_key().key_size - cert2.cert.public_key().key_size) * self.key_size_weight

        # Issuance date
        distance += abs(utcTimeDifferenceInDays(cert1.cert.not_valid_before, cert2.cert.not_valid_before)) * self.issuance_date_weight

        # Validity period
        distance += abs(cert1.cert_period - cert2.cert_period) * self.valid_period_weight

        # Serial number length
        distance += abs(len(str(cert1.cert.serial_number)) - len(str(cert2.cert.serial_number))) * self.serial_len_weight
        low = distance - high - med

        my_logger.dumpLog(DEBUG, f"High distance: {high}\nMedium distance: {med}\nLow distance: {low}")
        return distance


    def compareCertExtensionWithOid(
            self,
            cert1 : Certificate,
            cert2 : Certificate,
            extension_oid :ExtensionOID
        ) -> bool:

        try:
            cert1_extension_info = cert1.extensions.get_extension_for_oid(extension_oid)
        except ExtensionNotFound:
            cert1_extension_info = None

        try:
            cert2_extension_info = cert2.extensions.get_extension_for_oid(extension_oid)
        except ExtensionNotFound:
            cert2_extension_info = None

        my_logger.dumpLog(DEBUG, f"{cert1_extension_info}\n{cert2_extension_info}")
        return not cert1_extension_info.__eq__(cert2_extension_info)


    def computeJaccardDistance(self, set1 : set, set2 : set, weight : float) -> float:

        or_len = len(set1 | set2)
        if or_len == 0: return 0
        return (1 - len(set1 & set2) / len(set1 | set2)) * weight
    

    '''
        k-medoid algorithm implementation
    '''
    # def calculate_and_store_distance(self, i, j):
    #     distance = self.calculateCertDistance(self.cert_list[i], self.cert_list[j])
    #     rounded_distance = round(distance, 3)
    #     self.distance_matrix[i, j] = rounded_distance
    #     self.distance_matrix[j, i] = rounded_distance

    # def buildDistanceMatrix(self):

    #     threads = []
    #     for i in range(self.size):
    #         for j in range(i + 1, self.size):
    #             thread = threading.Thread(target=self.calculate_and_store_distance, args=(i, j))
    #             threads.append(thread)
    #             thread.start()

    #     for thread in threads:
    #         thread.join()

    def buildDistanceMatrix(self):

        size = len(self.cert_list)
        distance_matrix = np.zeros((size, size))

        for i in range(size):
            for j in range(i+1, size):
                distance = self.calculateCertDistance(self.cert_list[i], self.cert_list[j])
                rounded_distance = round(distance, 3)
                distance_matrix[i,j] = rounded_distance
                distance_matrix[j,i] = rounded_distance

        my_logger.dumpLog(INFO, "Distance matrix finished...")
        return distance_matrix


    def kMedoidsWithKMeansPP(self, distance_matrix):
        m, n = distance_matrix.shape
        if self.num_medoids > n:
            raise Exception('too many medoids')

        # Use K-Means++ initialization to select initial medoids
        kmeans = MiniBatchKMeans(n_clusters=self.num_medoids, init='k-means++', n_init=1)
        kmeans.fit(distance_matrix)

        return kmeans.labels_
    
        M = kmeans.cluster_centers_
        print(kmeans.cluster_centers_, kmeans.labels_)
        print(kmeans.inertia_, kmeans.n_features_in_, kmeans.n_iter_)

        # Rest of the K-Medoids algorithm remains the same
        # C = {}
        # for t in range(self.num_iter):
        #     J = np.argmin(distance_matrix[:, M], axis=1)
        #     for kappa in range(self.num_medoids):
        #         C[kappa] = np.where(J == kappa)[0]

        #     Mnew = np.copy(M)
        #     for kappa in range(self.num_medoids):
        #         J = np.mean(distance_matrix[np.ix_(C[kappa], C[kappa])], axis=1)
        #         j = np.argmin(J)
        #         Mnew[kappa] = C[kappa][j]
        #     Mnew.sort()

        #     if np.array_equal(M, Mnew):
        #         break
        #     M = np.copy(Mnew)
        # else:
        #     J = np.argmin(distance_matrix[:, M], axis=1)
        #     for kappa in range(self.num_medoids):
        #         C[kappa] = np.where(J == kappa)[0]

        # return M, C
