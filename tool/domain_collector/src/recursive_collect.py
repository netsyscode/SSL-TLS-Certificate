
from app.scanner.scan_by_domain import DomainScanner
from app.config.scan_config import DomainScanConfig
from app.parser.cert_parser_base import X509CertParser
from app.parser.cert_parser_extension import SANResult
from .retrieve_ca_domain_from_cert import get_domain

import re
from typing import List
from threading import Lock
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed

ipv6_pattern = r"^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$"
ipv4_pattern = r"^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"

def retrieve_domain(org : str, domain_list : set):

    # The following three orgs contains too many non-ca domains
    if org == "Apple Inc." or org == "Cloudflare, Inc." or org == "Microsoft Corporation":
        return domain_list
            
    lock = Lock()
    visited = set()
    scanner = DomainScanner("", datetime.now(timezone.utc), DomainScanConfig(), "cert_store_test")

    def recursive_retrieve_domain(base_domain : str, base_ip : str, visited : set):
        if base_domain and base_domain in visited: return
        if base_ip and base_ip in visited: return

        with lock:
            if base_domain:
                visited.add(base_domain)
                if base_domain.startswith("*."):
                    base_domain = base_domain[2:]
            if base_ip:
                visited.add(base_ip)

        cert_pem, e, remote_ip, tls_version, tls_cipher = scanner.fetch_raw_cert_chain(base_domain, base_ip)
        if cert_pem and len(cert_pem) > 0:
            single_cert_parser = X509CertParser(cert_pem[0])
            cert_parse_result = single_cert_parser.parse_cert_base()

            # Skip all thrid party hosting provider certs
            regex_pattern = cert_parse_result.subject_cn.replace(".", "\.").replace("*", ".*")
            print(regex_pattern)
            # TODO: 还是有问题，这样排除的逻辑不对，会多排除在SAN里面的域名获得的证书
            if not re.match(regex_pattern, base_domain): return

            san : SANResult = single_cert_parser.extension_parser.get_result_by_type(SANResult)
            if san:
                for domain_name in san.name_list:
                    print(domain_name)
                    recursive_retrieve_domain(get_domain(domain_name), None, visited)
                for ip in san.ip_list:
                    recursive_retrieve_domain(None, ip, visited)

    with ThreadPoolExecutor(max_workers=10) as executor:
        for domain in domain_list:
            if re.match(ipv6_pattern, domain) or re.match(ipv4_pattern, domain):
                executor.submit(recursive_retrieve_domain, None, domain, visited).result()
            else:
                executor.submit(recursive_retrieve_domain, domain, None, visited).result()

        executor.shutdown(wait=True)
        return visited
