
'''
    Created on 11/11/23
    Web Crawler for Top 1M websites

    11/19/23
    Add concurrent scanning mechansim with multi-processors
'''

from webPKIScanner.logger.logger import *

import os
import sys
import json
from socket import socket
from datetime import datetime
from OpenSSL import SSL
from OpenSSL.crypto import dump_certificate, FILETYPE_PEM
from func_timeout import func_set_timeout, FunctionTimedOut, dafunc
from concurrent.futures import ProcessPoolExecutor, Future


def create_cert_mapping_json(url_cert_mapping, json_filename):
    with open(json_filename, 'w') as json_file:
        json.dump(url_cert_mapping, json_file, indent=4)
    json_file.close()


# Naive way to get cert chain
@func_set_timeout(5)
def get_certificate_chain(hostname : str, port=443, timeout=2) -> list[str]:

    try:
        sock = socket()
        sock.settimeout(timeout)
        sock.setblocking(True)  # 关键
        sock.connect((hostname, port), )

        ctx = SSL.Context(SSL.SSLv23_METHOD)
        ctx.set_verify(SSL.VERIFY_NONE)

        sock_ssl = SSL.Connection(ctx, sock)
        sock_ssl.set_tlsext_host_name(hostname.encode())  # 关键: 对应不同域名的证书
        sock_ssl.set_connect_state()
        sock_ssl.do_handshake()

        # self.cert = sock_ssl.get_peer_certificate()
        certs = sock_ssl.get_peer_cert_chain()  # 下载证书
        # print("OK")
        sock_ssl.close()
        sock.close()
        cert_pem = [dump_certificate(FILETYPE_PEM, cert).decode('utf-8') for cert in certs]
        return cert_pem
    except Exception as e:
        my_logger.dumpLog(ERROR, f"Error fetching certificate for {hostname}: {e}")
        return []

    # try:
    #     context = SSL.Context(SSL.SSLv23_METHOD)
    #     s = socket.create_connection((hostname, port), timeout=timeout)
    #     s = SSL.Connection(context, s)
    #     # connection = SSL.Connection(context, socket.socket(socket.AF_INET, socket.SOCK_STREAM))
    #     s.set_connect_state()
    #     s.set_tlsext_host_name(hostname.encode('utf-8'))
    #     # s.connect()
        
    #     s.sendall('HEAD / HTTP/1.0\n\n')
    #     s.recv(16)

    #     certs = s.get_peer_cert_chain()
    #     print(certs)
    #     cert_pem = [dump_certificate(FILETYPE_PEM, cert).decode('utf-8') for cert in certs]
    #     # conn.close()
    #     return cert_pem
    # except TimeoutError as e:
    #     print(f"Error fetching certificate for {url}: {e}")
    #     return []


def concurrentScanner(url_list : list[str], start_index : int):

    timestamp = datetime.now().strftime("%Y%m%d")
    output_directory = "output"
    output_directory = os.path.join(output_directory, f"{timestamp}")
    os.makedirs(output_directory, exist_ok=True)

    max_certs_per_batch = 2000
    url_cert_mapping = []
    cert_counter = 0

    for url in url_list:
        try:
            cert_chain_as_pem_str = get_certificate_chain(url)
        except (FunctionTimedOut, dafunc.FunctionTimedOut) as e:
            # print(f"Fetching certificate for {url} time out")
            cert_chain_as_pem_str = []
        except Exception as e:
            # print(f"Error fetching certificate for {url}: {e}")
            cert_chain_as_pem_str = []

        # print(cert_counter)
        dict_cert = {
            "host" : url,
            "cert" : cert_chain_as_pem_str
        }
        url_cert_mapping.append(dict_cert)
        cert_counter += 1

        if cert_counter >= max_certs_per_batch:
            json_filename = os.path.join(output_directory, f"cert_mapping_{timestamp}_{start_index}.json")
            create_cert_mapping_json(url_cert_mapping, json_filename)

            url_cert_mapping = []
            cert_counter = 0
            start_index += max_certs_per_batch

    if cert_counter > 0:
        json_filename = os.path.join(output_directory, f"cert_mapping_{timestamp}_{start_index}.json")
        create_cert_mapping_json(url_cert_mapping, json_filename)


if __name__ == "__main__":

    url_list_filename = "input\\top-1m.csv"
    with open(url_list_filename, 'r') as url_file:
        url_list = [line.strip().split(',')[1] for line in url_file.readlines()]

    start = 0
    end = 100000
    group_size = 10000
    url_list = url_list[start:end]

    start_time = datetime.now()
    with ProcessPoolExecutor(max_workers=10) as executor:

        futures : list[Future] = []
        while start < end:
            futures.append(executor.submit(concurrentScanner, url_list[start:start+group_size], start))
            start += group_size

        results = [future.result() for future in futures]

    end_time = datetime.now()
    execution_time = end_time - start_time
    my_logger.dumpLog(INFO, f"Execution time for {end - start} certificates: {execution_time.total_seconds()}")
    print("All certificates processed.")
