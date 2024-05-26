

import sys
sys.path.append(r"E:\global_ca_monitor")

import socket
from datetime import datetime, timezone
from app import app
from app.scanner.scan_by_domain import DomainScanner
from app.config.scan_config import DomainScanConfig

# domain = "0-courier.push.apple.com"
# domain = "platform.hicloud.com"
# domain = "www.cisco.com"
# domain = "www.google.com"
# domain = "google.com"
domain = "www.baidu.cn"

with app.app_context():
    scanner = DomainScanner("", datetime.now(timezone.utc), DomainScanConfig(), "cert_store_test")
    # scanner.fetch_raw_cert_chain(domain, socket.gethostbyname(domain))
    # print(scanner.fetch_raw_cert_chain(domain, None))
    print(scanner.fetch_raw_cert_chain(domain, None, proxy_host=None, proxy_port=None))
