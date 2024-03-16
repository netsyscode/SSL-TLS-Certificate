
import time
import hashlib
import select
import socket
import http.client

from abc import ABC, abstractmethod
from threading import Lock
from rich.progress import Progress, BarColumn, TextColumn, TimeRemainingColumn, TaskID
from rich.console import Console

from datetime import datetime
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

    start_time : datetime = datetime.utcnow()
    end_time : datetime = None
    status : ScanStatusType = ScanStatusType.RUNNING

    scanned_domains : int = 0
    scanned_ips : int = 0
    scanned_entries : int = 0
    scanned_certs : int = 0

    success_count : int = 0
    error_count : int = 0


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

            '''
                TODO: handle various SSL/TLS context types
            '''
            ctx = SSL.Context(SSL.TLS_CLIENT_METHOD)
            ctx.set_verify(SSL.VERIFY_NONE)

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

            # Retrieve the peer certificate
            certs = sock_ssl.get_peer_cert_chain()
            cert_pem = [dump_certificate(FILETYPE_PEM, cert).decode('utf-8') for cert in certs]
            # my_logger.info(f"Success fetching certificate for {host} : {len(certs)}")
            proxy_socket.close()
            return cert_pem, None
        
        except RetriveError as e:
            # my_logger.error(f"Error fetching certificate for {host}: {last_error} {last_error.__class__}")
            proxy_socket.close()
            # print("ERROR")
            return [], f"{last_error} {last_error.__class__}"

        except Exception as e:
            # my_logger.error(f"Error fetching certificate for {host}: {e} {e.__class__}")
            # proxy_socket.close()
            return [], f"{e} {e.__class__}"


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
