


from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
# from cryptography.hazmat.backends.openssl import rsa, ec
from cryptography.hazmat.primitives.asymmetric import dsa as primitive_dsa, rsa as primitive_rsa, ec as primitive_ec, dh as primitive_dh
from cryptography.hazmat.primitives.asymmetric import types, padding
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
import cryptography.hazmat.bindings
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
from cryptography.x509 import Extensions

from ..utils.cert import (
    domain_extract,
    is_domain_match,
    utc_time_diff_in_days,
    get_name_attribute,
    get_cert_sha256_hex_from_object,
    get_cert_sha256_hex_from_str
)

from ..logger.logger import my_logger
from ..utils.type import CertType
from ..utils.exception import ParseError

from abc import ABC, abstractmethod
from datetime import datetime, timezone
from dataclasses import dataclass, asdict
from typing import Optional, Dict, List, Union, Tuple
from queue import Queue
import hashlib
import jsonlines
import json
import os


from sqlalchemy.exc import IntegrityError
from sqlalchemy import Table
from sqlalchemy.dialects.mysql import insert
from ..models import CertAnalysisStats, CertStoreContent, CertStoreRaw, CaCertStore, CertChainRelation
from ..parser.cert_parser_base import X509ParsedInfo
from app import app, db
from threading import Lock
import threading
import time

from OpenSSL import crypto


class CertScanChainAnalyzer():

    def __init__(
            self,
            scan_id : str,
            scan_input_table : Table,
        ) -> None:

        self.scan_id = scan_id
        self.scan_input_table = scan_input_table
        self.save_scan_chunk_size = 10000
        self.cert_store = crypto.X509Store()


    def analyze_cert_chain(self):
        my_logger.info(f"Starting {self.scan_input_table.name} chain analysis...")
        
        with app.app_context():
            # Prepare root store
            ca_certs = CaCertStore.query.filter()
            ca_certs = [cert.get_raw() for cert in ca_certs]

            for cert in ca_certs:
                root_cert = crypto.load_certificate(crypto.FILETYPE_PEM, cert)
                self.cert_store.add_cert(root_cert)

            # Analyze
            query = self.scan_input_table.select()
            result_proxy = db.session.execute(query)
            
            while True:
                rows = result_proxy.fetchmany(self.save_scan_chunk_size)
                if not rows:
                    # self.sync_update_info()
                    break

                for row in rows:
                    try:
                        cert = crypto.load_certificate(crypto.FILETYPE_PEM, row[1])
                        issuer = self.get_issuer(cert)
                        self.sync_update_info(cert, issuer)
                    except ValueError:
                        continue

        my_logger.info("Cert chain analysis completed")


    def get_issuer(self, cert):
        try:
            store_ctx = crypto.X509StoreContext(self.cert_store, cert)
            chain = store_ctx.get_verified_chain()
            if len(chain) == 1:
                return chain[0]
            else:
                return chain[1]
        
        except crypto.X509StoreContextError as e:
            # my_logger.error(f"Cert chain analysis failed for cert {get_cert_sha256_hex_from_object(e.certificate.to_cryptography())}...")
            return None


    def sync_update_info(self, cert : crypto.X509, issuer : crypto.X509):
        # with app.app_context():
            if issuer:
                cert_parent_id = get_cert_sha256_hex_from_object(issuer.to_cryptography())
            else:
                cert_parent_id = "Not Found Yet"

            cert_chain_data_to_insert = {
                'CERT_ID' : get_cert_sha256_hex_from_object(cert.to_cryptography()),
                'CERT_PARENT_ID' : cert_parent_id
            }
            insert_cert_store_statement = insert(CertChainRelation).values(cert_chain_data_to_insert).prefix_with('IGNORE')
            db.session.execute(insert_cert_store_statement)
            db.session.commit()


    # do not use now
    def verifySignature(self) -> bool:
        sig_verified = False

        if self.issuer_cert is not None:
            issuer_pub_key = self.issuer_cert.public_key()
            try:
                if issuer_pub_key.__class__ == primitive_rsa.RSAPublicKey:
                    issuer_pub_key.verify(
                        self.cert.signature,
                        self.cert.tbs_certificate_bytes,
                        # Depends on the algorithm used to create the certificate
                        padding.PKCS1v15(),
                        self.cert.signature_hash_algorithm
                    )
                elif issuer_pub_key.__class__ == primitive_ec.EllipticCurvePublicKey:
                    issuer_pub_key.verify(
                        self.cert.signature,
                        self.cert.tbs_certificate_bytes,
                        primitive_ec.ECDSA(hashes.SHA256())
                    )
                else:
                    issuer_pub_key.verify(
                        self.cert.signature,
                        self.cert.tbs_certificate_bytes
                    )
                sig_verified = True
            except InvalidSignature:
                my_logger.warn(f"Cert {self.cert.serial_number} signature checking failed")
                sig_verified = False
        else:
            my_logger.warn(f"Cert {self.cert.serial_number} has no issuer cert avaliable")

        return sig_verified

