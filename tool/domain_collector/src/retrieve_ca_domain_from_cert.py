
from app import app, db
from typing import List, Dict
from threading import Lock
from sqlalchemy import MetaData, Table
from concurrent.futures import ThreadPoolExecutor, as_completed
from app.utils.exception import ParseError, UnknownTableError
from app.parser.cert_parser_base import X509CertParser
from app.parser.cert_parser_extension import SANResult
from app.utils.type import CertType
from urllib.parse import urlparse

result_list_lock = Lock()
result : Dict[str, set] = {}
save_scan_chunk_size = 10000
max_threads = 10

def get_domain(url : str):
    parsed_url = urlparse(url)
    if not parsed_url.scheme:
        url = "http://" + url
        parsed_url = urlparse(url)
    return parsed_url.netloc

def parse_domain(rows):
    for row in rows:
        try:
            single_cert_parser = X509CertParser(row[1])
            cert_parse_result = single_cert_parser.parse_cert_base()

            # Skip CA certs
            if cert_parse_result.cert_type != CertType.LEAF:
                continue

            if cert_parse_result.subject_org in result:
                with result_list_lock:
                    if "." in cert_parse_result.subject_cn:
                        result[cert_parse_result.subject_org].add(get_domain(cert_parse_result.subject_cn))

                san : SANResult = single_cert_parser.extension_parser.get_result_by_type(SANResult)
                if san:
                    for domain_name in san.name_list:
                        result[cert_parse_result.subject_org].add(get_domain(domain_name))
                    for ip in san.ip_list:
                        result[cert_parse_result.subject_org].add(ip)
        except ParseError:
            pass

def retrieve_ca_owned_domains_from_cert(scan_input_table : Table, org_name_list : List[str]):

    for org_name in org_name_list:
        result[org_name] = set()

    query = scan_input_table.select()
    result_proxy = db.session.execute(query)
    
    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        while True:
            rows = result_proxy.fetchmany(save_scan_chunk_size)
            if not rows:
                break
            executor.submit(parse_domain, rows)
        executor.shutdown(wait=True)
        return result

