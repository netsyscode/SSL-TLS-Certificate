
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
    CertificatePolicies    
)

from cryptography.x509.oid import (
    NameOID,
    ExtensionOID,
    SignatureAlgorithmOID,
    CertificatePoliciesOID,
    ExtendedKeyUsageOID,
    AuthorityInformationAccessOID
)

from ..utils.cert import (
    CertType,
    LeafCertType,
    requestCRLResponse,
    requestOCSPResponse,
    extractDomain,
    isDomainMatch,
    utcTimeDifferenceInDays,
    getNameAttribute,
    checkLocalDomain,
    checkLocalIP
)

from webPKIScanner.logger.logger import (
    DEBUG,
    INFO,
    WARNING,
    ERROR,
    my_logger
)

from typing import Optional, Dict, Union
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
    ocsp_url_list : list[str]

@dataclass
class BasicConstraintsResult(ExtensionResult):
    ca_bit : bool
    path_len_constraint : Optional[int]

@dataclass
class ExtendedKeyUsageResult(ExtensionResult):
    ext_usage_list : list[ExtendedKeyUsageOID]

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
    crl_url_list : list[str]

@dataclass
class SANResult(ExtensionResult):
    name_list : list[str]
    ip_list : list[str]
    has_other_name_type : bool
    has_local_domain : bool
    has_local_ip : bool

@dataclass
class CertPoliciesResult(ExtensionResult):
    issuer_policy : str


class X509CertExtensionParser():

    def __init__(self, input_extensions : Extensions) -> None:
        self.extensions = input_extensions

    def analyzeExtensions(self) -> list[ExtensionResult]:
        output_list = []
        for extension in self.extensions:
            # do not want static method here right now...
            if extension.value.__class__ in EXTENSIONTOEXTENSIONParser.keys():
                result = EXTENSIONTOEXTENSIONParser[extension.value.__class__]().analyze(extension)
                output_list.append(result)
        return output_list


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
        value = extension.value
        if isinstance(value, AuthorityInformationAccess):
            for access_description in value:
                if (access_description.access_method == AuthorityInformationAccessOID.OCSP) \
                    and (access_description.access_location is not None):
                    has_ocsp_server = True
                    ocsp_server_url.append(access_description.access_location.value)
            return AIAResult(extension.critical, has_ocsp_server, ocsp_server_url)
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
                    if checkLocalDomain(name.value):
                        has_local_domain = True
                elif isinstance(name, IPAddress):
                    ip_names.append(name.value)
                    if checkLocalIP(name.value):
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


EXTENSIONTOEXTENSIONParser : Dict[Extension, SingleExtensionParser] = {
    AuthorityInformationAccess : AIAParser,
    BasicConstraints : BasicConstraintParser,
    ExtendedKeyUsage : ExtendedKeyUsageParser,
    KeyUsage : KeyUsageParser,
    CRLDistributionPoints : CRLParser,
    SubjectAlternativeName : SANParser,
    CertificatePolicies : CertPoliciesParser
}

LEAFCERTTYPEMAPPING : Dict[str, LeafCertType] = {
    "2.23.140.1.2.1" : LeafCertType.DV,
    "2.23.140.1.2.3" : LeafCertType.IV,
    "2.23.140.1.2.2" : LeafCertType.OV,
    "2.23.140.1.1" : LeafCertType.EV
}

