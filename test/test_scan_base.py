

import sys
sys.path.append(r"E:\global_ca_monitor")

import socket
from datetime import datetime
from app import app
from app.scanner.scan_by_domain import DomainScanner
from app.config.scan_config import DomainScanConfig

domain = "www.google.com"
with app.app_context():
    scanner = DomainScanner("", datetime.now(), DomainScanConfig(), "20220127")
    scanner.fetch_raw_cert_chain(domain, socket.gethostbyname(domain))
    scanner.fetch_raw_cert_chain(domain, "")
    scanner.fetch_raw_cert_chain(domain, None)
