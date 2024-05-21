
'''
    Created 11/05/23
    Parser for x509 cert extensions
'''

from cryptography.x509 import (
    Version,
    Name,
    DNSName,
    IPAddress,
    Certificate,
    ObjectIdentifier,
    Extension,
    Extensions,
    KeyUsage,
    ExtendedKeyUsage,
    CRLDistributionPoints,
    AuthorityInformationAccess,
    BasicConstraints,
    SubjectAlternativeName,
    CertificatePolicies,
    SubjectKeyIdentifier,
    AuthorityKeyIdentifier,
    PrecertificateSignedCertificateTimestamps
)

from cryptography.x509.oid import (
    NameOID,
    ExtensionOID,
    SignatureAlgorithmOID,
    CertificatePoliciesOID,
    ExtendedKeyUsageOID,
    AuthorityInformationAccessOID
)

from ..utils.type import LeafCertType
from ..utils.cert import (
    domain_extract,
    is_domain_match,
    utc_time_diff_in_days,
    get_name_attribute,
    check_local_domain,
    check_local_ip
)

import binascii
from typing import Optional, Dict, Union, List
from abc import ABC, abstractmethod
from dataclasses import dataclass


'''
    Extension Analysis Result
'''
@dataclass
class ExtensionResult():
    is_critical : bool

@dataclass
class AIAResult(ExtensionResult):
    has_ocsp_server_url : bool
    ocsp_url_list : List[str]
    issuer_url_list : List[str]

@dataclass
class BasicConstraintsResult(ExtensionResult):
    ca_bit : bool
    path_len_constraint : Optional[int]

@dataclass
class ExtendedKeyUsageResult(ExtensionResult):
    ext_usage_list : List[ExtendedKeyUsageOID]

@dataclass
class KeyUsageResult(ExtensionResult):
    # key_type : types.CERTIFICATE_PUBLIC_KEY_TYPES
    digital_sig : bool
    key_encipherment : bool
    data_encipherment : bool
    key_agreement : bool
    others : bool

@dataclass
class CRLResult(ExtensionResult):
    has_crl_url : bool
    crl_url_list : List[str]

@dataclass
class SANResult(ExtensionResult):
    name_list : List[str]
    ip_list : List[str]
    has_other_name_type : bool
    has_local_domain : bool
    has_local_ip : bool

@dataclass
class CertPoliciesResult(ExtensionResult):
    issuer_policy : str

@dataclass
class SubjectKeyIdentifierResult(ExtensionResult):
    key_identifier : str

@dataclass
class AuthorityKeyIdentifierResult(ExtensionResult):
    key_identifier : str

@dataclass
class PrecertificateSignedCertificateTimestampsResult(ExtensionResult):
    sct_length : int

class ExtensionResultWarpper():
    def __init__(self, extension_result_list : List[ExtensionResult]) -> None:
        self.ext_result_list = extension_result_list

    def get_result_by_type(self, result_type):
        for result in self.ext_result_list:
            if type(result) == result_type:
                return result
        return None

# TODO: Apply this new result class to the system

class X509CertExtensionParser():

    def __init__(self, input_extensions : Extensions) -> None:
        self.extensions = input_extensions

    def analyzeExtensions(self) -> List[ExtensionResult]:
        self.ext_result_list = []
        for extension in self.extensions:
            # do not want static method here right now...
            if extension.value.__class__ in EXTENSIONTOEXTENSIONPARSER.keys():
                result = EXTENSIONTOEXTENSIONPARSER[extension.value.__class__]().analyze(extension)
                self.ext_result_list.append(result)
        # TODO: Change the return result to ExtensionResultWarpper
        return self.ext_result_list

    def get_result_by_type(self, result_type):
        for result in self.ext_result_list:
            if type(result) == result_type:
                return result
        return None

'''
    Extension Parser derived from an abstract class
'''
class SingleExtensionParser(ABC):
    @abstractmethod
    def analyze(self, extension : Extension):
        pass


class AIAParser(SingleExtensionParser):

    def analyze(self, extension : Extension) -> AIAResult:
        has_ocsp_server = False
        ocsp_server_url = []
        issuer_server_url = []
        value = extension.value
        if isinstance(value, AuthorityInformationAccess):
            for access_description in value:
                if (access_description.access_method == AuthorityInformationAccessOID.OCSP) \
                    and (access_description.access_location is not None):
                    has_ocsp_server = True
                    ocsp_server_url.append(access_description.access_location.value)
                if (access_description.access_method == AuthorityInformationAccessOID.CA_ISSUERS) \
                    and (access_description.access_location is not None):
                    issuer_server_url.append(access_description.access_location.value)
            return AIAResult(extension.critical, has_ocsp_server, ocsp_server_url, issuer_server_url)
        return None


class BasicConstraintParser(SingleExtensionParser):

    def analyze(self, extension : Extension) -> BasicConstraints:
        value = extension.value
        if isinstance(value, BasicConstraints):
            return BasicConstraintsResult(
                extension.critical,
                value.ca,
                value.path_length
            )
        return None


class ExtendedKeyUsageParser(SingleExtensionParser):

    def analyze(self, extension : Extension) -> ExtendedKeyUsageResult:
        value = extension.value
        if isinstance(value, ExtendedKeyUsage):
            return ExtendedKeyUsageResult(extension.critical, value._usages)
        return None
    

class KeyUsageParser(SingleExtensionParser):

    def analyze(self, extension : Extension) -> KeyUsageResult:
        others = False
        value = extension.value
        if isinstance(value, KeyUsage):
            if value.content_commitment or value.crl_sign or value.key_cert_sign:
                others = True
            if value.key_agreement and (value.decipher_only or value.encipher_only):
                others = True
            return KeyUsageResult(
                extension.critical,
                value.digital_signature,
                value.key_encipherment,
                value.data_encipherment,
                value.key_agreement,
                others
            )
        return None
    

class CRLParser(SingleExtensionParser):

    def analyze(self, extension: Extension) -> CRLResult:
        has_crl = False
        crl_url_list = []
        value = extension.value
        if isinstance(value, CRLDistributionPoints):
            for distribution_point in value:
                if len(distribution_point.full_name) > 0:
                    has_crl = True
                    for name in distribution_point.full_name:
                        if type(name.value) != str:
                            print(name.value)
                            continue
                        crl_url_list.append(name.value)
            return CRLResult(extension.critical, has_crl, crl_url_list)
        return None


class SANParser(SingleExtensionParser):

    def analyze(self, extension: Extension) -> SANResult:
        dns_names = []
        ip_names = []
        has_other_name_type = False
        has_local_domain = False
        has_local_ip = False
        value = extension.value
        if isinstance(value, SubjectAlternativeName):
            for name in value._general_names:
                if isinstance(name, DNSName):
                    dns_names.append(name.value)
                    if check_local_domain(name.value):
                        has_local_domain = True
                elif isinstance(name, IPAddress):
                    ip_names.append(str(name.value))
                    if check_local_ip(name.value):
                        has_local_ip = True
                else:
                    has_other_name_type = True
            return SANResult(
                extension.critical,
                dns_names,
                ip_names,
                has_other_name_type,
                has_local_domain,
                has_local_ip
            )
        return None
    

class CertPoliciesParser(SingleExtensionParser):

    def analyze(self, extension: Extension) -> CertPoliciesResult:
        value = extension.value
        if isinstance(value, CertificatePolicies):
            for policy in value:
                policy_oid = policy.policy_identifier.dotted_string
                if policy_oid in LEAFCERTTYPEMAPPING.keys():
                    return CertPoliciesResult(extension.critical, policy_oid)
        return None


class SubjectKeyIdentifierParser(SingleExtensionParser):

    def analyze(self, extension: Extension) -> SubjectKeyIdentifierResult:
        value = extension.value
        if isinstance(value, SubjectKeyIdentifier):
            kid = value.key_identifier
            if kid:
                return SubjectKeyIdentifierResult(extension.critical, binascii.hexlify(kid).decode('utf-8'))
        return None


class AuthorityKeyIdentifierParser(SingleExtensionParser):

    def analyze(self, extension: Extension) -> AuthorityKeyIdentifierResult:
        value = extension.value
        if isinstance(value, AuthorityKeyIdentifier):
            kid = value.key_identifier
            if kid:
                return AuthorityKeyIdentifierResult(extension.critical, binascii.hexlify(kid).decode('utf-8'))
        return None


class PrecertificateSignedCertificateTimestampsParser(SingleExtensionParser):

    def analyze(self, extension: Extension) -> PrecertificateSignedCertificateTimestampsResult:
        value = extension.value
        if isinstance(value, PrecertificateSignedCertificateTimestamps):
            list_scts = value._signed_certificate_timestamps
            return PrecertificateSignedCertificateTimestampsResult(extension.critical, len(list_scts))
        return None


EXTENSIONTOEXTENSIONPARSER : Dict[Extension, SingleExtensionParser] = {
    AuthorityInformationAccess : AIAParser,
    BasicConstraints : BasicConstraintParser,
    ExtendedKeyUsage : ExtendedKeyUsageParser,
    KeyUsage : KeyUsageParser,
    CRLDistributionPoints : CRLParser,
    SubjectAlternativeName : SANParser,
    CertificatePolicies : CertPoliciesParser,
    SubjectKeyIdentifier : SubjectKeyIdentifierParser,
    AuthorityKeyIdentifier : AuthorityKeyIdentifierParser,
    PrecertificateSignedCertificateTimestamps : PrecertificateSignedCertificateTimestampsParser
}

LEAFCERTTYPEMAPPING : Dict[str, LeafCertType] = {
    "2.23.140.1.2.1" : LeafCertType.DV,
    "2.23.140.1.2.3" : LeafCertType.IV,
    "2.23.140.1.2.2" : LeafCertType.OV,
    "2.23.140.1.1" : LeafCertType.EV
}

