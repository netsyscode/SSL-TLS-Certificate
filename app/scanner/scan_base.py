
import csv
import time
import hashlib
import select
import threading
import http.client

from threading import Lock
from queue import PriorityQueue
from rich.progress import Progress, BarColumn, TextColumn, TimeRemainingColumn
from rich.console import Console
from concurrent.futures import ThreadPoolExecutor, as_completed
from concurrent.futures import ProcessPoolExecutor, Future
from sqlalchemy import insert
from sqlalchemy.exc import IntegrityError

from datetime import datetime
from OpenSSL import SSL
from OpenSSL.crypto import dump_certificate, FILETYPE_PEM
from dataclasses import dataclass

from app import db, app
from .scan_manager import ScanConfig, ScanType, ScanStatusType
from ..logger.logger import my_logger
from ..analyzer.scan_cert_analyze import ScanCertAnalyzer
from ..models import (
    ScanStatus, ScanData, CertData, generate_cert_data_table, generate_scan_data_table,
    CertScanMeta, CertStoreContent, CertStoreRaw
)

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
    scanned_certs : int = 0
    scanned_unique_certs : int = 0

    success_count : int = 0
    error_count : int = 0


class Scanner:

    def __init__(
            self,
            scan_id : str,
            start_time : datetime,
            scan_config : ScanConfig,
            cert_data_table_name : str,
            begin_num=0,
        ) -> None:

        # scan settings from scan config
        self.scan_id = scan_id
        self.input_csv_file = scan_config.input_csv_file
        self.out_put_dir = scan_config.output_dir
        self.max_threads = scan_config.max_threads
        self.save_threshold = scan_config.save_threshold

        self.proxy_host = scan_config.proxy_host
        self.proxy_port = scan_config.proxy_port
        self.timeout = scan_config.timeout
        self.max_retries = 3
        
        self.begin_num = begin_num
        self.end_num = scan_config.scan_domain_num
        self.task_queue = PriorityQueue()
        self.load_tasks_into_queue()

        self.cached_results_lock = Lock()
        self.cached_results = []

        self.scan_status_data_lock = Lock()
        self.scan_status_data = ScanStatusData(start_time=start_time)
        self.scan_status_entry : ScanStatus = ScanStatus.query.filter_by(ID=scan_id).first()

        # Console
        self.progress = Progress()
        self.console = Console()

        # Create Tables
        self.cert_data_table_name = cert_data_table_name
        self.cert_data_table = generate_cert_data_table(cert_data_table_name)


    def load_tasks_into_queue(self):
        self.current_index = self.begin_num
        with open(self.input_csv_file, 'r') as file:
            reader = csv.reader(file)

            for row in reader:
                if self.current_index > self.end_num:
                    break

                rank, host = int(row[0]), row[1]
                self.task_queue.put((rank, host))
                self.current_index += 1


    # Answer request from frontend pages
    # @deprecated, currently do not use
    def get_status_info(self):

        if self.scan_status_data.status == ScanStatusType.RUNNING:
            scan_time = (datetime.now() - self.scan_status_data.start_time).seconds
        elif self.scan_status_data.status == ScanStatusType.COMPLETED:
            scan_time = (self.scan_status_data.end_time - self.scan_status_data.start_time).seconds
        elif self.scan_status_data.status == ScanStatusType.STOP:
            scan_time = (self.scan_status_data.end_time - self.scan_status_data.start_time).seconds
        else:
            scan_time = -1

        with self.scan_status_data_lock:
            return {
                "scan_status" : self.scan_status_data.status,
                "scan_time" : scan_time,
                "scanned_domains" : self.scan_status_data.scanned_domains,
                "successes" : self.scan_status_data.success_count,
                "errors" : self.scan_status_data.error_count,
                "scanned_certs" : self.scan_status_data.scanned_certs,
                "scanned_unique_certs" : self.scan_status_data.scanned_unique_certs
            }


    def save_results(self):

        with app.app_context():
            my_logger.info(f"Saving {len(self.cached_results)} results...")

            scan_status_data_to_insert = []
            cert_data_to_insert = {}
            cert_metadata_to_insert = []

            for result in self.cached_results:
                scan_status_data_to_insert.append(
                    ScanData(
                        SCAN_TIME = self.scan_status_data.start_time,
                        DOMAIN = result['host'],
                        ERROR_MSG = result['error'],
                        RECEIVED_CERTS = result['sha256']
                    )
                )

                for i in range(len(result['sha256'])):
                    cert_data_to_insert[result['sha256'][i]] = result['certificate'][i]
                    cert_metadata_to_insert.append(
                        {
                            'CERT_ID' : result['sha256'][i],
                            'SCAN_DATE' : self.scan_status_data.start_time,
                            'SCAN_DOMAIN' : result['host']
                        }
                    )
            
            cert_data_to_insert = [{'CERT_ID' : key, 'CERT_RAW' : value} for key, value in cert_data_to_insert.items()]
            with db.session.begin():
                db.session.expunge_all()
                db.session.add_all(scan_status_data_to_insert)

                # only template model, can not use insert(Model) here
                insert_cert_data_statement = insert(self.cert_data_table).values(cert_data_to_insert).prefix_with('IGNORE')
                db.session.execute(insert_cert_data_statement)

                # many many primary key dupliates...
                # need to deal with Integrity Error with duplicate primary key pair with bulk_insert_mappings
                insert_cert_raw_statement = insert(CertStoreRaw).values(cert_data_to_insert).prefix_with('IGNORE')
                db.session.execute(insert_cert_raw_statement)

                # db.session.bulk_insert_mappings(CertScanMeta, cert_metadata_to_insert)
                insert_cert_scan_metadata_statement = insert(CertScanMeta).values(cert_metadata_to_insert).prefix_with('IGNORE')
                db.session.execute(insert_cert_scan_metadata_statement)

        self.cached_results = []


    def fetch_raw_cert_chain(self, hostname : str, port=443):

        try:
            # proxy_socket = socks.create_connection((host, port), proxy_type=socks.SOCKS5, proxy_addr=(proxy_host, proxy_port))
            # proxy_socket = socks.socksocket()
            # proxy_socket.set_proxy(socks.SOCKS5, self.proxy_host, self.proxy_port)
            # proxy_socket.settimeout(self.timeout)
            # proxy_socket.connect((hostname, port))

            proxy_conn = http.client.HTTPConnection(self.proxy_host, self.proxy_port, timeout=self.timeout)
            proxy_conn.set_tunnel(hostname, port)
            proxy_conn.connect()
            proxy_socket = proxy_conn.sock

            ctx = SSL.Context(SSL.TLS_CLIENT_METHOD)
            ctx.set_verify(SSL.VERIFY_NONE)

            # my_logger.info(f"Getting certs from {hostname}...")
            sock_ssl = SSL.Connection(ctx, proxy_socket)
            sock_ssl.set_tlsext_host_name(hostname.encode())  # 关键: 对应不同域名的证书
            sock_ssl.set_connect_state()

            retry_count = 0
            last_error = None
            while True:
                if retry_count >= self.max_retries:
                    raise Exception
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
            # my_logger.info(f"Success fetching certificate for {hostname} : {len(certs)}")
            proxy_socket.close()
            return cert_pem, None

        except Exception as e:
            # my_logger.error(f"Error fetching certificate for {hostname}: {last_error} {last_error.__class__}")
            proxy_socket.close()
            return [], f"{last_error} {last_error.__class__}"


    def scan_thread(self, rank : int, host : str):
            
        cert_chain, e = self.fetch_raw_cert_chain(host)
        cert_chain_sha256_hex = [hashlib.sha256(cert.encode()).hexdigest() for cert in cert_chain]
        result = {'rank': rank, 'host': host, 'error': e, 'certificate': cert_chain, 'sha256' : cert_chain_sha256_hex}

        with self.scan_status_data_lock:
            self.scan_status_data.scanned_domains += 1
            self.scan_status_data.scanned_certs += len(cert_chain)
            self.scan_status_data.scanned_unique_certs += len(cert_chain)

            if e is not None:
                self.scan_status_data.error_count += 1
            else:
                self.scan_status_data.success_count += 1

        with self.cached_results_lock:
            self.cached_results.append(result)
            # self.cached_results.sort(key=lambda x: x['rank'])
            if len(self.cached_results) >= self.save_threshold:
                self.save_results()

        self.progress.update(self.progress_task, description=f"[green]Completed: {self.scan_status_data.success_count}, [red]Errors: {self.scan_status_data.error_count}")
        self.progress.advance(self.progress_task)


    def start(self):
        with Progress(
            TextColumn("[bold blue]{task.description}", justify="right"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TimeRemainingColumn(),  # 添加预计剩余时间列
            transient=True  # 进度条完成后隐藏
        ) as self.progress:
            self.progress_task = self.progress.add_task("[Waiting]", total=self.end_num - self.begin_num)

            # asyncio.create_task(self.async_update_scan_process_info())
            timer_thread = threading.Thread(target=self.async_update_scan_process_info)
            timer_thread.daemon = True  # 设置为守护线程，以便主线程退出时自动退出定时器线程
            timer_thread.start()

            my_logger.info(f"Scanning...")
            with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
                futures : list[Future] = []
                while not self.task_queue.empty():
                    index, host = self.task_queue.get()
                    future = executor.submit(self.scan_thread, index, host)
                    futures.append(future)

                # 等待所有线程完成
                for future in as_completed(futures):
                    pass  # 可以在此处处理每个future的结果，如果需要

        # 确保所有线程完成后再保存剩余结果
        if self.cached_results:
            self.save_results()
        
        my_logger.info(f"Scan Completed")
        with self.scan_status_data_lock:
            self.scan_status_data.end_time = datetime.utcnow()
            self.scan_status_data.status = ScanStatusType.COMPLETED
        self.sync_update_scan_process_info()

        # 
        # Run analysis in background after scanning
        # 
        with app.app_context():
            self.analyzer = ScanCertAnalyzer(self.scan_id, self.cert_data_table_name)
            self.analyzer.analyzeCertScanResult()


    def async_update_scan_process_info(self):

        while not self.progress.finished:
            # await asyncio.get_event_loop().run_in_executor(None, self.sync_update_scan_process_info)
            # await asyncio.sleep(5)
            self.sync_update_scan_process_info()
            time.sleep(5)


    def sync_update_scan_process_info(self):

        my_logger.info(f"Updating...")
        if self.scan_status_data.status == ScanStatusType.RUNNING:
            scan_time = (datetime.utcnow() - self.scan_status_data.start_time).seconds
        elif self.scan_status_data.status == ScanStatusType.COMPLETED:
            scan_time = (self.scan_status_data.end_time - self.scan_status_data.start_time).seconds
        elif self.scan_status_data.status == ScanStatusType.STOP:
            scan_time = (self.scan_status_data.end_time - self.scan_status_data.start_time).seconds
        else:
            scan_time = -1

        with app.app_context():
            self.scan_status_entry.SCAN_TIME_IN_SECONDS = scan_time
            self.scan_status_entry.END_TIME = self.scan_status_data.end_time
            self.scan_status_entry.STATUS = self.scan_status_data.status.value
            self.scan_status_entry.SCANNED_DOMIANS = self.scan_status_data.scanned_domains
            self.scan_status_entry.SCANNED_CERTS = self.scan_status_data.scanned_certs
            self.scan_status_entry.SUCCESSES = self.scan_status_data.success_count
            self.scan_status_entry.ERRORS = self.scan_status_data.error_count
            db.session.add(self.scan_status_entry)
            db.session.commit()


    async def stop(self):
        pass
