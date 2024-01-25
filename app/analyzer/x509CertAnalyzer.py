
'''
    Created on 10/9/23
    Base class for certificate analysis
    This file would be the main entry point of the wholw webPKIscanner program

    10/19/23
    Finish all the basic features of X509 certificate

    11/05/23
    Modify the analyzer to fit the CAB-BR specifics

    11/12/23
    Add result type for CA metric analysis

    11/26/23
    Make this module as the entry point of the whole system
    Modify input and output format
    Add analyzer for intermediate and root certs
    Add new analysis metrics

    12/09/23
    Add data structure for quick cert indexing and searching
    Prepare for analyzing rogue certificates

    12/24/23
    Add SQL connector for cert Storage
    Prepare for cert linter

    12/28/23
    Combine certAnalyzer and caMetricAnalyzer together
    Merge certLint analysis stuff
    Split certStore and SingleCertResult to x509CertStore.py
'''

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends.openssl import dsa, rsa, ec, dh
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

from webPKIScanner.certAnalyzer.x509AnalysisConfig import Configuration
from webPKIScanner.certAnalyzer.x509CertStore import (
    X509CertStore,
    X509SingleCertResult,
    X509SingleLeafCertResult,
    X509SingleIntermediateCACertResult,
    X509SingleRootCACertResult,
    CERT_TYPE_TO_RESULT_MAP
)

from webPKIScanner.certAnalyzer.x509ExtensionAnalyzer import (
    X509CertExtensionAnalyzer,
    ExtensionResult,
    AIAResult,
    BasicConstraintsResult,
    ExtendedKeyUsageResult,
    KeyUsageResult,
    CertPoliciesResult,
    CRLResult,
    SANResult,
    LEAFCERTTYPEMAPPING
)

from webPKIScanner.certAnalyzer.x509CertUtils import (
    X509CertType,
    X509LeafCertType,
    requestCRLResponse,
    requestOCSPResponse,
    extractDomain,
    isDomainMatch,
    utcTimeDifferenceInDays,
    getNameAttribute,
    get_dns_caa_records,
    getCertSHA256Hex
)

from webPKIScanner.certLinter.lintBase import LintAnalyzer
from webPKIScanner.certLinter.lintResult import LintResult

from webPKIScanner.commonHelpers.pathHelpers.pathLocate import convertRelativePathToAbsPath
from webPKIScanner.logger.customException import CertificateHostNameMismatch
from webPKIScanner.logger.logger import DEBUG, INFO, WARNING, ERROR
from webPKIScanner.logger.logger import my_logger

from abc import ABC, abstractmethod
from datetime import datetime
from dataclasses import dataclass, asdict
from typing import Optional, Dict, List, Union
from queue import Queue
import hashlib
import json
import os

'''
    TBD
'''
SIGNATUREPADDINGMAPPING = {
    SignatureAlgorithmOID.ECDSA_WITH_SHA256 : padding.PSS,
    SignatureAlgorithmOID.RSA_WITH_SHA256 : padding.PKCS1v15,
}

def findExtensionResultByClass(
        extention_alanysis_result : List[ExtensionResult],
        _class : any
    ) -> any:

    for result in extention_alanysis_result:
        if result.__class__ == _class:
            return result
    return None


@dataclass
class SingleServerScanResult():

    # # This length refers to the one after reconstruction
    # chain_length : int
    # # verification info matches the result to chosen root store
    # chain_verification_info : Dict[str, bool]
    
    # is_root_cert_received : bool
    # root_ca_country : str

    retrieved_host_name : str
    cert_result_list : List[X509SingleCertResult]

@dataclass
class X509CertScanAnalysisResult():

    total_certs : int
    scan_result_list : List[SingleServerScanResult]


# main stuff here
class X509SingleCertAnalyzer():

    def __init__(
            self,
            host_name: str,
            cert_type: X509CertType,
            cert: Certificate,
            issuer_cert: Optional[Certificate],
            extension_result : List[ExtensionResult],
            lint_analyzer : LintAnalyzer
        ) -> None:

        self.host_name = host_name
        self.cert_type = cert_type
        self.cert = cert
        self.issuer_cert = issuer_cert
        self.extention_alanysis_result = extension_result
        self.lint_analyzer = lint_analyzer


    def checkRevocationStatusFromOCSP(
            self
        )-> (Optional[OCSPResponseStatus], Optional[OCSPCertStatus], Optional[datetime], Optional[ReasonFlags]):

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
                my_logger.dumpLog(WARNING, f"OCSP server for certificate {self.cert.serial_number} does not respond")
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
            my_logger.dumpLog(WARNING, f"Cert extension {e.oid} not found")
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
            my_logger.dumpLog(WARNING, f"Cert extension {e.oid} not found")
            return None


    def verifySignature(self) -> bool:
        sig_verified = False

        if self.issuer_cert is not None:
            issuer_pub_key = self.issuer_cert.public_key()
            try:
                if issuer_pub_key.__class__ == rsa._RSAPublicKey:
                    issuer_pub_key.verify(
                        self.cert.signature,
                        self.cert.tbs_certificate_bytes,
                        # Depends on the algorithm used to create the certificate
                        padding.PKCS1v15(),
                        self.cert.signature_hash_algorithm
                    )
                elif issuer_pub_key.__class__ == ec._EllipticCurvePublicKey:
                    issuer_pub_key.verify(
                        self.cert.signature,
                        self.cert.tbs_certificate_bytes,
                        primitive_ec.ECDSA(hashes.SHA256())
                    )
                elif issuer_pub_key.__class__ == dsa._DSAPublicKey:
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
                my_logger.dumpLog(WARNING, f"Cert {self.cert.serial_number} signature checking failed")
                sig_verified = False
        else:
            my_logger.dumpLog(WARNING, f"Cert {self.cert.serial_number} has no issuer cert avaliable")

        return sig_verified
    

    def analyzeSingleCertBase(self) -> X509SingleCertResult:

        # Check CA bit
        basic_constraints_result = findExtensionResultByClass(self.extention_alanysis_result, BasicConstraintsResult)
        if basic_constraints_result:
            if basic_constraints_result.ca_bit: ca_bit = True
            else : ca_bit = False
        else:
            ca_bit = None

        subject = self.cert.subject
        subject_cn, is_subject_cn_mult = getNameAttribute(subject, NameOID.COMMON_NAME, None)
        subject_org, is_subject_org_mult = getNameAttribute(subject, NameOID.ORGANIZATION_NAME, None)
        subject_country, is_subject_country_mult = getNameAttribute(subject, NameOID.COUNTRY_NAME, None)

        issuer = self.cert.issuer
        issuer_cn, is_issuer_cn_mult = getNameAttribute(issuer, NameOID.COMMON_NAME, None)
        issuer_org, is_issuer_org_mult = getNameAttribute(issuer, NameOID.ORGANIZATION_NAME, None)
        issuer_country, is_issuer_country_mult = getNameAttribute(issuer, NameOID.COUNTRY_NAME, None)

        time_begin = self.cert.not_valid_before
        time_end = self.cert.not_valid_after
        cert_period = utcTimeDifferenceInDays(time_end, time_begin)

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

        # # Check CRL
        # crl_revoked = self.checkRevocationStatusFromCRL()
        # # Check OCSP:
        # ocsp_status, cert_status, revocation_time, revocation_reason = None, None, None, None
        # ocsp_result = self.checkRevocationStatusFromOCSP()
        # if ocsp_result is not None:
        #     ocsp_status, cert_status, revocation_time, revocation_reason = ocsp_result

        # SHA256
        sha256_hex = getCertSHA256Hex(self.cert)

        '''
            Lint Analysis
        '''
        has_lint_error = False
        lint_error_list = []

        for lint_name, lint_result in self.lint_analyzer.analyzeSingle(self.cert).items():
            if lint_result == LintResult.ERROR or lint_result == LintResult.FATAL:
                has_lint_error = True
                lint_error_list.append(lint_name)
        
        return X509SingleCertResult(
            self.cert_type,
            ca_bit,
            sha256_hex,
            subject_cn,
            [subject_cn],
            subject_org,
            subject_country,
            issuer_cn,
            issuer_org,
            issuer_country,
            time_begin,
            cert_period,
            self.cert.public_key().public_bytes(
                encoding=Encoding.PEM,
                format=PublicFormat.SubjectPublicKeyInfo
            ).decode(),
            pub_key_type,
            pub_key_size,
            signature_hash_algorithm_name,

            # Lint analysis
            self.cert.public_bytes(Encoding.PEM).decode("utf-8"),
            has_lint_error,
            lint_error_list
        )


class X509LeafCertAnalyzer(X509SingleCertAnalyzer):

    def __init__(
            self,
            host_name: str,
            cert_type: X509CertType,
            cert: Certificate,
            issuer_cert: Optional[Certificate],
            extension_result : List[ExtensionResult],
            lint_analyzer : LintAnalyzer
        ) -> None:
        super().__init__(host_name, cert_type, cert, issuer_cert, extension_result, lint_analyzer)


    def verifyHostAndSubjectName(
            self,
            subject_name : str,
            alternative_subject_name : List[DNSName],
        ) -> bool:

        '''
            Complete implementation needs to consider alternative
            IP address inside SubjectAlternativeName

            we currently do not consider these
        '''
        host_domain = extractDomain(self.host_name)
        if not host_domain: return False

        if isDomainMatch(host_domain, subject_name):
            return True
        for name in alternative_subject_name:
            if isDomainMatch(host_domain, name):
                return True

        return False


    def analyzeSingleCert(self) -> X509SingleLeafCertResult:

        if not self.cert_type == X509CertType.LEAFCERT:
            my_logger.dumpLog(ERROR, f"Why you pass a non-leaf cert into leaf cert analyzer?")
            return None

        result_base = self.analyzeSingleCertBase()
        score = 0
        '''
            Subject Name and Related Extensions
        '''
        subject = self.cert.subject
        subject_info = {}
        for attribute in subject._attributes:
            for name in attribute:
                if name.oid in subject_info.keys():
                    subject_info[name.oid].append(name.value)
                else:
                    subject_info[name.oid] = [name.value]

        # RDN must be unique
        unique_rdn = True
        for oid in subject_info.keys():
            if len(subject_info[oid]) > 1:
                unique_rdn = False
                break

        # Must have SAN and CertPolicies
        has_san = False
        has_cert_policies = False
        san_result = findExtensionResultByClass(self.extention_alanysis_result, SANResult)
        cert_policies_result = findExtensionResultByClass(self.extention_alanysis_result, CertPoliciesResult)
        if san_result:
            subject_cns = san_result.name_list
            if result_base.subject_cns[0] not in subject_cns: subject_cns.append(result_base.subject_cns[0])
            has_san = True
        else:
            subject_cns = result_base.subject_cns
        
        # NOTE: add hostname here to verify CAA
        subject_cns.append(self.host_name)
        if cert_policies_result : has_cert_policies = True

        # If has Subject CN, SAN must have the name one
        san_has_subject_cn = True
        if NameOID.COMMON_NAME in subject_info.keys():
            for cn in subject_info[NameOID.COMMON_NAME]:
                if (not has_san) or (not cn in san_result.name_list):
                    san_has_subject_cn = False

        # If no Subject CN, SAN must be critical
        san_critical = True
        if not NameOID.COMMON_NAME in subject_info.keys():
            if (not has_san) or (not san_result.is_critical):
                san_critical = False

        # DV, OV, EV check
        leaf_cert_policy_ok = True
        leaf_cert_type = X509LeafCertType.DV
        if has_cert_policies:
            leaf_cert_type = LEAFCERTTYPEMAPPING[cert_policies_result.issuer_policy]

        if leaf_cert_type == X509LeafCertType.DV:
            if NameOID.ORGANIZATION_NAME in subject_info.keys():
                leaf_cert_policy_ok = False
        else:
            if (NameOID.ORGANIZATION_NAME not in subject_info.keys()) \
                or (NameOID.COUNTRY_NAME not in subject_info.keys()) \
                or ((NameOID.LOCALITY_NAME not in subject_info.keys()) \
                    and (NameOID.STATE_OR_PROVINCE_NAME not in subject_info.keys())):
                leaf_cert_policy_ok = False

        # Score
        if unique_rdn: score += 4
        if has_san: score += 4
        if has_cert_policies: score += 4
        if san_has_subject_cn: score += 3
        if san_critical: score += 3
        if has_san:
            if not san_result.has_other_name_type:
                score += 4
            if (not san_result.has_local_domain) and (not san_result.has_local_ip):
                score += 3
        if leaf_cert_policy_ok: score += 5
        # print(score)

        subject_cn, is_subject_cn_mult = getNameAttribute(subject, NameOID.COMMON_NAME, None)
        subject_org, is_subject_org_mult = getNameAttribute(subject, NameOID.ORGANIZATION_NAME, None)
        # subject_locailty, is_subject_locality_mult = getNameAttribute(subject, NameOID.LOCALITY_NAME, None)
        # subject_state, is_subject_state_mult = getNameAttribute(subject, NameOID.STATE_OR_PROVINCE_NAME, None)
        subject_country, is_subject_country_mult = getNameAttribute(subject, NameOID.COUNTRY_NAME, None)
        # try:
        #     alternative_ext = self.cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        #     alternative_name = alternative_ext.value.get_values_for_type(DNSName)
        # except ExtensionNotFound:
        #     alternative_name = []

        # is_subject_name_match = self.verifySubjectName(subject_cn, alternative_name)


        '''
            Issuer Name
        '''
        issuer = self.cert.issuer
        issuer_cn, is_issuer_cn_mult = getNameAttribute(issuer, NameOID.COMMON_NAME, None)
        issuer_org, is_issuer_org_mult = getNameAttribute(issuer, NameOID.ORGANIZATION_NAME, None)
        issuer_country, is_issuer_country_mult = getNameAttribute(issuer, NameOID.COUNTRY_NAME, None)

        # Issuer name must match subject name of issuer cert
        is_issuer_name_match = False
        if self.issuer_cert is not None:
            is_issuer_name_match = (issuer.public_bytes() == self.issuer_cert.subject.public_bytes())

        # Issuer name must have O, C
        issuer_name_type_ok = True
        if (issuer_org is None) or (issuer_country is None):
            issuer_name_type_ok = False

        # Score
        if is_issuer_name_match: score += 7
        if issuer_name_type_ok: score += 3
        # print(score)


        '''
            Validity
        '''
        time_begin = self.cert.not_valid_before
        time_end = self.cert.not_valid_after
        cert_period = utcTimeDifferenceInDays(time_end, time_begin)

        valid_period_ok = False
        if time_begin >= datetime(2020, 9, 1):
            if cert_period < 397:
                valid_period_ok = True
        elif time_begin >= datetime(2018, 3, 1):
            if cert_period <= 825:
                valid_period_ok = True
        elif time_begin >= datetime(2016, 7, 1):
            if cert_period <= 30 * 39:
                valid_period_ok = True

        # Score
        if valid_period_ok: score += 10
        # print(score)
        # is_expired = False
        # if utcTimeDifferenceInDays(time_end, datetime.now()) <= 0:
        #     my_logger.dumpLog(WARNING, f"Cert {self.cert.serial_number} has expired")
        #     is_expired = True


        '''
            Public Key and Signature
        '''
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

        # Key length
        safe_key_length = False
        if pub_key_type.__class__ == rsa._RSAPublicKey:
            if time_begin >= datetime(2014, 1, 1):
                safe_key_length = (pub_key_size >= 2048)
            else:
                safe_key_length = (pub_key_size >= 1024)
        elif pub_key_type.__class__ == dsa._DSAPublicKey:
            safe_key_length = (pub_key_size >= 2048)
        elif pub_key_type.__class__ == ec._EllipticCurvePublicKey:
            safe_key_length = (pub_key_size >= 256)

        # Hash algorithm
        safe_hash = True
        if isinstance(signature_hash_algorithm, hashes.SHA1) or isinstance(signature_hash_algorithm, hashes.MD5):
            safe_hash = False

        # Score
        if safe_key_length: score += 10
        if safe_hash: score += 10
        # print(score)
        # signature_algorithm = self.cert.signature_algorithm_oid._name
        # sig_verified = self.verifySignature()


        '''
            Other Extensions
        '''
        # AIA
        aia_result = findExtensionResultByClass(self.extention_alanysis_result, AIAResult)
        ocsp_url_list = []
        if aia_result:
            score += 4
            if aia_result.has_ocsp_server_url:
                ocsp_url_list = aia_result.ocsp_url_list
                score += 4

        # Basic Constraints
        basic_constraints_result = findExtensionResultByClass(self.extention_alanysis_result, BasicConstraintsResult)
        if basic_constraints_result:
            if not basic_constraints_result.ca_bit:
                score += 4
            if basic_constraints_result.path_len_constraint is None:
                score += 4
        else:
            score += 8

        # Extended key usage
        ext_key_use_result = findExtensionResultByClass(self.extention_alanysis_result, ExtendedKeyUsageResult)
        if ext_key_use_result:
            score += 2
            if ExtendedKeyUsageOID.SERVER_AUTH in ext_key_use_result.ext_usage_list:
                score += 2
                if ExtendedKeyUsageOID.CLIENT_AUTH in ext_key_use_result.ext_usage_list \
                    and len(ext_key_use_result.ext_usage_list) < 3:
                    score += 1

        # Key usage
        key_use_result = findExtensionResultByClass(self.extention_alanysis_result, KeyUsageResult)
        key_usage_list = []
        if key_use_result:
            key_usage_list.append(key_use_result.digital_sig)
            key_usage_list.append(key_use_result.key_encipherment)
            key_usage_list.append(key_use_result.data_encipherment)
            key_usage_list.append(key_use_result.key_agreement)
            key_usage_list.append(key_use_result.others)

            if pub_key_type.__class__ == rsa._RSAPublicKey or pub_key_type.__class__ == dsa._DSAPublicKey:
                if (not key_use_result.key_agreement) and (not key_use_result.others):
                    score += 5
            elif pub_key_type.__class__ == ec._EllipticCurvePublicKey:
                if (not key_use_result.key_encipherment) and (not key_use_result.data_encipherment) and (not key_use_result.others):
                    score += 5
        else:
            score += 5
        
        # CRL
        crl_result = findExtensionResultByClass(self.extention_alanysis_result, CRLResult)
        crl_url_list = []
        if crl_result:
            if crl_result.has_crl_url:
                crl_url_list = crl_result.crl_url_list
                score += 4
        else:
            score += 4

        # CAA records
        caa_record = {}
        for cn in subject_cns:
            if cn is None: continue
            if "*." in cn:
                issue_ca, issue_wildcard_ca = get_dns_caa_records(cn[2:])
            else:
                issue_ca, issue_wildcard_ca = get_dns_caa_records(cn)
            caa_record[cn] = issue_ca + issue_wildcard_ca

        return X509SingleLeafCertResult(
            result_base.cert_type,
            result_base.ca_bit,
            result_base.sha256_hex,
            result_base.subject_cn,
            subject_cns,
            result_base.subject_org,
            result_base.subject_country,
            result_base.issuer_cn,
            result_base.issuer_org,
            result_base.issuer_country,
            result_base.not_valid_before,
            result_base.validation_period,
            result_base.pub_key,
            result_base.subject_pub_key_type,
            result_base.subject_pub_key_size,
            result_base.cert_signature_hash_algorithm,
            result_base.raw_str,
            result_base.has_lint_error,
            result_base.lint_error_list,
            leaf_cert_type,
            caa_record
        )


class X509IntermediateCertAnalyzer(X509SingleCertAnalyzer):

    def __init__(
            self,
            host_name: str,
            cert_type: X509CertType,
            cert: Certificate,
            issuer_cert: Optional[Certificate],
            extension_result : List[ExtensionResult],
            lint_analyzer : LintAnalyzer
        ) -> None:
        super().__init__(host_name, cert_type, cert, issuer_cert, extension_result, lint_analyzer)

    def analyzeSingleCert(self) -> X509SingleIntermediateCACertResult:

        if not self.cert_type == X509CertType.INTERMEDIATECERT:
            my_logger.dumpLog(ERROR, f"Why you pass a non-intermediate cert into intermediate cert analyzer?")
            return None

        result_base = self.analyzeSingleCertBase()
        return X509SingleIntermediateCACertResult(
            result_base.cert_type,
            result_base.ca_bit,
            result_base.sha256_hex,
            result_base.subject_cn,
            result_base.subject_cns,
            result_base.subject_org,
            result_base.subject_country,
            result_base.issuer_cn,
            result_base.issuer_org,
            result_base.issuer_country,
            result_base.not_valid_before,
            result_base.validation_period,
            result_base.pub_key,
            result_base.subject_pub_key_type,
            result_base.subject_pub_key_size,
            result_base.cert_signature_hash_algorithm,
            result_base.raw_str,
            result_base.has_lint_error,
            result_base.lint_error_list
        )


class X509RootCertAnalyzer(X509SingleCertAnalyzer):

    def __init__(
            self,
            host_name: str,
            cert_type: X509CertType,
            cert: Certificate,
            issuer_cert: Optional[Certificate],
            extension_result : List[ExtensionResult],
            lint_analyzer : LintAnalyzer
        ) -> None:
        super().__init__(host_name, cert_type, cert, issuer_cert, extension_result, lint_analyzer)

    def analyzeSingleCert(self) -> X509SingleRootCACertResult:

        if not self.cert_type == X509CertType.ROOTCERT:
            my_logger.dumpLog(ERROR, f"Why you pass a non-root cert into root cert analyzer?")
            return None

        result_base = self.analyzeSingleCertBase()
        return X509SingleRootCACertResult(
            result_base.cert_type,
            result_base.ca_bit,
            result_base.sha256_hex,
            result_base.subject_cn,
            result_base.subject_cns,
            result_base.subject_org,
            result_base.subject_country,
            result_base.issuer_cn,
            result_base.issuer_org,
            result_base.issuer_country,
            result_base.not_valid_before,
            result_base.validation_period,
            result_base.pub_key,
            result_base.subject_pub_key_type,
            result_base.subject_pub_key_size,
            result_base.cert_signature_hash_algorithm,
            result_base.raw_str,
            result_base.has_lint_error,
            result_base.lint_error_list
        )


CERT_TYPE_TO_ANALYZER_MAP : Dict[X509CertType, Union[
            X509LeafCertAnalyzer,
            X509IntermediateCertAnalyzer,
            X509RootCertAnalyzer]]= {
    X509CertType.LEAFCERT : X509LeafCertAnalyzer,
    X509CertType.INTERMEDIATECERT : X509IntermediateCertAnalyzer,
    X509CertType.ROOTCERT : X509RootCertAnalyzer
}

'''
    class X509CertScanAnalyzer is the first entry point of the system
    It reads the output scan directly from the certScanner
'''
class X509CertScanAnalyzer():

    def __init__(
            self,
            scan_input_dir : str,
            scan_time : str,
            config_data : Configuration = Configuration(),
        ) -> None:

        self.scan_input_dir = scan_input_dir
        self.scan_time = scan_time
        self.cert_lint_analyzer = LintAnalyzer()

        trusted_root_store_path = convertRelativePathToAbsPath(__file__, "root")
        self.trusted_root_store_path = os.path.join(trusted_root_store_path, config_data.trusted_root_store)

        # Build trusted root store
        with open(self.trusted_root_store_path, "r") as root_store_file:
            trusted_root_list = load_pem_x509_certificates(root_store_file.read().encode('utf-8'))
            trusted_root_analysis_result = self.analyzeTrustedRootStore(trusted_root_list)

        self.trusted_root_store = X509CertStore(
            X509CertType.ROOTCERT,
            True,
            scan_time,
            trusted_root_analysis_result
        )

        # Analyze scan result certs
        self.scanned_leaf_cert_store = X509CertStore(X509CertType.LEAFCERT, False, scan_time, [])
        self.scanned_intermediate_cert_store = X509CertStore(X509CertType.INTERMEDIATECERT, False, scan_time, [])
        self.scanned_root_cert_store = X509CertStore(X509CertType.ROOTCERT, False, scan_time, [])
        self.analyzeCertScanResult()


    def analyzeTrustedRootStore(self, trusted_root_list : List[Certificate]) -> List[X509SingleRootCACertResult]:
        result = []
        for root in trusted_root_list:
            single_cert_analyzer = X509RootCertAnalyzer("", X509CertType.ROOTCERT, root, root, [], self.cert_lint_analyzer)
            result.append(single_cert_analyzer.analyzeSingleCert())
        return result


    def analyzeCertScanResult(self) -> None:

        my_logger.dumpLog(INFO, f"Starting {self.scan_input_dir} scan analysis...")

        for f in os.listdir(self.scan_input_dir):
            input_file_name = os.path.join(self.scan_input_dir, f)
            if os.path.isfile(input_file_name):
                with open(input_file_name, "r") as input_file:
                    input_data = json.load(input_file)

                for object in input_data:
                    host_name = object["host"]
                    certs_as_pem = object["cert"]

                    for cert_as_pem in certs_as_pem:
                        try:
                            cert = load_pem_x509_certificate(cert_as_pem.encode("utf-8"), default_backend())
                        except:
                            my_logger.dumpLog(WARNING, "Meet cert ASN.1 format violation")
                            continue

                        # Get extension results for further analysis
                        try:
                            extension_analyzer = X509CertExtensionAnalyzer(cert.extensions)
                            extention_alanysis_result = extension_analyzer.analyzeExtensions()
                        except ValueError:
                            '''
                                \cryptography\x509\base.py:551: CryptographyDeprecationWarning: 
                                Parsed a negative serial number, which is disallowed by RFC 5280.
                                TODO: handle this when loading certificates
                            '''
                            extention_alanysis_result = []

                        # Check cert type
                        cert_type = X509CertType.LEAFCERT
                        target_cert_store = self.scanned_leaf_cert_store
                        basic_constraints_result = findExtensionResultByClass(extention_alanysis_result, BasicConstraintsResult)

                        if basic_constraints_result:
                            if basic_constraints_result.ca_bit:
                                if cert.subject == cert.issuer:
                                    cert_type = X509CertType.ROOTCERT
                                    target_cert_store = self.scanned_root_cert_store
                                else:
                                    cert_type = X509CertType.INTERMEDIATECERT
                                    target_cert_store = self.scanned_intermediate_cert_store

                        cert_analysis_result = self.analyzeSingleCertBasedOnCertType(host_name, cert, cert_type, extention_alanysis_result)
                        target_cert_store.addCert(cert_analysis_result)

        my_logger.dumpLog(INFO, "Cert scan analysis completed")


    def analyzeSingleCertBasedOnCertType(
            self,
            host_name : str,
            cert : Certificate,
            cert_type : X509CertType,
            extension_result : List[ExtensionResult]
        ):

        single_cert_analyzer = CERT_TYPE_TO_ANALYZER_MAP[cert_type](host_name, cert_type, cert, cert, extension_result, self.cert_lint_analyzer)
        return single_cert_analyzer.analyzeSingleCert()


class X509CertListAnalyzer():

    def __init__(
            self,
            type : X509CertType,
            cert_list : List[Certificate]
        ) -> None:

        self.type = type
        self.cert_analyzer_class = CERT_TYPE_TO_ANALYZER_MAP[self.type]
        self.cert_list = cert_list
        self.analyze_result = []


    def switchCertList(self, new_type : X509CertType, new_list : List[Certificate]):
        self.type = new_type
        self.cert_analyzer_class = CERT_TYPE_TO_ANALYZER_MAP[self.type]
        self.cert_list = new_list


    def analyzeCertList(self):

        for cert in self.cert_list:
            try:
                extension_analyzer = X509CertExtensionAnalyzer(cert.extensions)
                extention_alanysis_result = extension_analyzer.analyzeExtensions()
            except ValueError:
                '''
                    \cryptography\x509\base.py:551: CryptographyDeprecationWarning: 
                    Parsed a negative serial number, which is disallowed by RFC 5280.
                    TODO: handle this when loading certificates
                '''
                extention_alanysis_result = []

            cert_analyzer = self.cert_analyzer_class("", self.type, cert, cert, extention_alanysis_result)
            self.analyze_result.append(cert_analyzer.analyzeSingleCert())


    # def analyzeCertChain(
    #         self,
    #         host : str,
    #         input_cert_chain : List[bytes]
    #     ) -> X509CertAnalysisResult:
        
    #     '''
    #         TODO:
    #         1. build the complete chain
    #         currently, we only analyze leaf cert when cert chain length is greater than 1
    #         2. verify the chain with certain root store
    #     '''

    #     chain_length = len(input_cert_chain)

    #     if chain_length == 0:
    #         return X509CertAnalysisResult(host, 1, [])
        
    #     if chain_length == 1:
    #         # Only endpoint cert here...
    #         # Temp implementation...
    #         result = X509CertAnalysisResult(host, 1, [])
    #         result.chain_result_list.append(X509CertAnalysisResult.X509CertChainResult(1, {}, False, "NA", []))
    #         single_cert_analyzer = X509LeafCertAnalyzer(host, X509CertType.LEAFCERT, input_cert_chain[0], None)
    #         single_result = single_cert_analyzer.analyzeSingleCert()
    #         result.chain_result_list[-1].cert_result_list.append(single_result)
    #         return result
        
    #     # TODO: check full chain received
    #     hasfull_chain = True

    #     '''
    #         If the chain is not complete, we need to make sure that we rebuild it
    #         1. we use Mozilla certificate bundle
    #         2. we use OCSP response (may not work as well, depends on the OCSP server config)
    #     '''
    #     # import requests

    #     # url = "https://curl.se/ca/cacert.pem"
    #     # response = requests.get(url)
    #     # with open("mozilla_cert_bundle.pem", "wb") as file:
    #     #     file.write(response.content)
    #     # from cryptography import x509
    #     # from cryptography.hazmat.backends import default_backend

    #     # with open("mozilla_cert_bundle.pem", "rb") as file:
    #     #     bundle_data = file.read()

    #     # # 解析证书 bundle 文件
    #     # bundle = x509.load_pem_x509_certificates(bundle_data, default_backend())

    #     # # 提取中间证书
    #     # intermediate_certs = [cert for cert in bundle if not cert.is_signature_valid(root_certificates=bundle)]

    #     complete_cert_chains = [input_cert_chain]

    #     # TODO: check chain verified
    #     verified = True

    #     result = X509CertAnalysisResult(host, len(complete_cert_chains), [])
    #     self.total_cert += chain_length
    #     self.total_leaf_cert += 1


    #     return result

