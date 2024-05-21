
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
class CryptoInfrus:
    id : int
    cn: str
    org: str
    country: str

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

    issuing_cert_storage : List[str] = field(default_factory=list)
    issuing_key_storage : Dict[str, List[str]] = field(default_factory=dict)


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
