

import sys
sys.path.append(r"E:\global_ca_monitor")

import socket
from datetime import datetime
from app import app
from app.scanner.scan_by_domain import DomainScanner
from app.config.scan_config import DomainScanConfig

# domain = "0-courier.push.apple.com"
# domain = "platform.hicloud.com"
# domain = "cisco.com"
domain = "www.google.com"
domain = "google.com"

with app.app_context():
    scanner = DomainScanner("", datetime.now(), DomainScanConfig(), "cert_store_test")
    # scanner.fetch_raw_cert_chain(domain, socket.gethostbyname(domain))
    print(scanner.fetch_raw_cert_chain(domain, None))
