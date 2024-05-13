
import time
import hashlib
import select
import socket
import http.client

from abc import ABC, abstractmethod
from threading import Lock
from rich.progress import Progress, BarColumn, TextColumn, TimeRemainingColumn, TaskID
from rich.console import Console

from datetime import datetime, timezone
from OpenSSL import SSL
from OpenSSL.crypto import dump_certificate, FILETYPE_PEM
from dataclasses import dataclass

from ..config.scan_config import ScanConfig
from ..utils.type import ScanType, ScanStatusType
from ..utils.exception import RetriveError
from ..logger.logger import my_logger
from ..models import ScanStatus, generate_cert_data_table


@dataclass
class ScanStatusData():

    '''
        Scan Status Data contains all info for ScanStatus db model
        use this soly for updating ScanStatus model
    '''

    start_time : datetime = datetime.now(timezone.utc)
    end_time : datetime = None
    status : ScanStatusType = ScanStatusType.RUNNING

    scanned_domains : int = 0
    scanned_ips : int = 0
    scanned_entries : int = 0
    scanned_certs : int = 0

    success_count : int = 0
    error_count : int = 0


tls_version_map = {
    SSL.SSL3_VERSION : 0,
    SSL.TLS1_1_VERSION : 1,
    SSL.TLS1_2_VERSION : 2,
    SSL.TLS1_3_VERSION : 3
}

class Scanner(ABC):

    def __init__(
            self,
            scan_id : str,
            start_time : datetime,
            scan_config : ScanConfig,
            cert_data_table_name : str,
        ) -> None:

        # scan settings from scan config
        self.scan_id = scan_id
        self.max_threads = scan_config.MAX_THREADS_ALLOC
        self.save_threshold = scan_config.SAVE_CHUNK_SIZE

        self.proxy_host = scan_config.PROXY_HOST
        self.proxy_port = scan_config.PROXY_PORT
        self.timeout = scan_config.SCAN_TIMEOUT
        self.max_retries = scan_config.MAX_RETRY

        self.cached_results_lock = Lock()
        self.cached_results = []

        self.scan_status_data_lock = Lock()
        self.scan_status_data = ScanStatusData(start_time=start_time)
        self.scan_status_entry : ScanStatus = ScanStatus.query.filter_by(ID=scan_id).first()

        # Console
        # @Debug only
        self.progress = Progress()
        self.progress_task = TaskID(-1)
        self.console = Console()

        # Create Tables
        self.cert_data_table_name = cert_data_table_name
        self.cert_data_table = generate_cert_data_table(cert_data_table_name)

        self.analyze_cert = scan_config.IS_ANALYZE

    '''
        @Methods used for IP and Domain scan
        @provide both host and ip to get the certificate
        @as we need to deal with CDN and SNI in the future

        Some server can be connected using the IP address resolved from DNS records
        Some server cannot directly with IP, but can with Host specfied in the HTTP header
        Some server cannot be connected with both methods
        TODO: solve this problem
        TODO: understand how Zmap or Masscan handle scanning and change my project directly based on that
    '''
    def fetch_raw_cert_chain(self, host : str, host_ip : str, port=443, proxy_host="127.0.0.1", proxy_port=33210):

        try:

            # import requests
            # headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/98.0.4758.102 Safari/537.36'}

            # if proxy_host and proxy_port:
            #     proxies = {
            #         'http': f'http://{proxy_host}:{proxy_port}',
            #         'https': f'http://{proxy_host}:{proxy_port}'
            #     }
            # else:
            #     proxies = None

            # try:
            #     url = f'https://{host}:{port}'
            #     print(url)
            #     response = requests.get(url, headers=headers, proxies=proxies, stream=True)
            #     # response = requests.get(url)
            #     response : requests.Response

            #     # print(response.raw)
            #     # print("Response:", response.headers)

            #     import urllib3
            #     raw : urllib3.response.HTTPResponse = response.raw

            #     # print(raw._fp.getheaders())
            #     raw_socket = response.raw._fp.fp.raw._sock
            #     remote_ip = raw_socket.getpeername()[0]
            #     print("Remote IP address:", remote_ip)
                
            # except requests.exceptions.RequestException as e:
            #     print("Error:", e)


            '''
                Well, OPENSSL.SSL.Connection only accepts socket.socket,
                we can not use socks.socksocket() from "socks" PySocks to set up proxy
                Instead, we use http.client.HTTPConnection and set_tunnel to
                use the CONNECT method to initiate a tunnelled connection

                TODO: better to construct raw packets for connection to avoid such restrictions
                need to do in the future

                TODO: well, now connects host with ip in the header,
                in the future, we better do it reversely
            '''
            if proxy_host and proxy_port:
                headers = {
                    "Host" : f"{host_ip}:443",
                    "Authorization": "Bearer YourAccessToken",  # 如果需要认证的话
                }
                proxy_conn = http.client.HTTPConnection(proxy_host, proxy_port, timeout=self.timeout)
                proxy_conn.set_tunnel(host, port, headers=headers)
            else:
                proxy_conn = http.client.HTTPConnection(host, port, timeout=self.timeout)

            proxy_conn.connect()
            proxy_socket = proxy_conn.sock
            remote_ip = proxy_conn.sock.getpeername()[0]

            '''
                TODO: handle various SSL/TLS context types
            '''
            ctx = SSL.Context(SSL.TLS_CLIENT_METHOD)
            ctx.set_verify(SSL.VERIFY_NONE)
            ctx.set_options(SSL.OP_NO_RENEGOTIATION)
            ctx.set_options(SSL.OP_IGNORE_UNEXPECTED_EOF)
            ctx.set_max_proto_version(SSL.TLS1_3_VERSION)
            ctx.set_min_proto_version(SSL.SSL3_VERSION)

            # my_logger.info(f"Getting certs from {host}...")
            sock_ssl = SSL.Connection(ctx, proxy_socket)
            sock_ssl.set_tlsext_host_name(host.encode())  # 关键: 对应不同域名的证书
            sock_ssl.set_connect_state()

            retry_count = 0
            last_error = None
            while True:
                if retry_count >= self.max_retries:
                    raise RetriveError
                try:
                    sock_ssl.do_handshake()
                    break
                except SSL.WantReadError as e:
                    # 等待套接字可读
                    readable, _, _ = select.select([sock_ssl], [], [], self.timeout)
                    # Timeout occurs
                    if not readable:
                        last_error = e
                        retry_count += 1
                        continue
                except SSL.SysCallError as e:
                    last_error = e
                    retry_count += 1
                    time.sleep(0.5)
                    continue
                # except SSL.Error as e:
                #     time.sleep(5)
                #     if 'tlsv1 alert protocol version' in str(e):
                #         my_logger.warning("TLS版本不兼容")
                #         return self.tls_connection(host, proxy_socket, SSL.TLSv1_1_METHOD)
                #     else:
                #         my_logger.error(f"Error fetching certificate for {host}: {e} {e.__class__}")
                #         return self.tls_connection(host, proxy_socket, SSL.TLSv1_METHOD)

            # Retrieve the peer certificate
            certs = sock_ssl.get_peer_cert_chain()
            cert_pem = [dump_certificate(FILETYPE_PEM, cert).decode('utf-8') for cert in certs]
            # my_logger.info(f"Success fetching certificate for {host} : {len(certs)}")

            tls_version = tls_version_map[sock_ssl.get_protocol_version()]
            tls_cipher = sock_ssl.get_cipher_name()
            proxy_socket.close()
            return cert_pem, None, remote_ip, tls_version, tls_cipher
        
        except RetriveError as e:
            # my_logger.error(f"Error fetching certificate for {host}: {last_error} {last_error.__class__}")
            proxy_socket.close()
            # print("ERROR")
            return [], f"{last_error} {last_error.__class__}", "", None, None

        except Exception as e:
            # my_logger.error(f"Error fetching certificate for {host}: {e} {e.__class__}")
            # proxy_socket.close()
            return [], f"{e} {e.__class__}", "", None, None


    '''
        @Methods for all types of scans
        @Use abstract methods here
    '''
    @abstractmethod
    def start(self):
        pass
    @abstractmethod
    def terminate(self):
        pass
    @abstractmethod
    def pause(self):
        pass
    @abstractmethod
    def resume(self):
        pass
    @abstractmethod
    def async_update_scan_process_info(self):
        pass
    @abstractmethod
    def sync_update_scan_process_info(self):
        pass
    @abstractmethod
    def save_results(self):
        pass
