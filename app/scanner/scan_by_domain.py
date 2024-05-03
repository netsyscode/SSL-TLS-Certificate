
import csv
import time
import hashlib
import threading

from datetime import datetime, timezone
from queue import PriorityQueue
from rich.progress import Progress, BarColumn, TextColumn, TimeRemainingColumn
from concurrent.futures import ThreadPoolExecutor, as_completed
from sqlalchemy import insert

from app import db, app
from .scan_base import Scanner, ScanStatusData
from ..config.scan_config import DomainScanConfig
from ..utils.type import ScanType, ScanStatusType
from ..logger.logger import my_logger
from ..models import (
    ScanStatus, ScanData, CertScanMeta, CertStoreContent, CertStoreRaw
)


class DomainScanner(Scanner):

    def __init__(
            self,
            scan_id : str,
            start_time : datetime,
            scan_config : DomainScanConfig,
            cert_data_table_name : str,
        ) -> None:

        super().__init__(scan_id, start_time, scan_config, cert_data_table_name)

        # scan settings from scan config
        self.input_csv_file = scan_config.INPUT_DOMAIN_LIST_FILE
        self.begin_num = scan_config.DOMAIN_RANK_START
        self.end_num = scan_config.NUM_DOMAIN_SCAN - 1
        self.task_queue = PriorityQueue()
        self.load_tasks_into_queue()


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


    def scan_thread(self, rank : int, host : str):
        
        '''
            To save VPN data, we first retrieve cert without VPN
            if this fails, we use VPN instead
            if both fail, we treat it as exact failure
            
            TODO: connect with different VPN nodes to see the data difference
        '''
        # ipv4, ipv6 = resolve_host_dns(host)
        ipv4 = []
        '''
            When we resolve DNS records, there might be many as CDN deploys
            TODO: for domain scan, try all ipv4 and ipv6 in the future
        '''
        if len(ipv4) > 0:
            host_ip = ipv4[0]
        else:
            host_ip = ""
        cert_chain, e, remote_ip, tls_version, tls_cipher = self.fetch_raw_cert_chain(host, host_ip, proxy_host=None, proxy_port=None)

        # print(len(cert_chain), e)
        if len(cert_chain) == 0:
            # my_logger.warning(f"{host} using VPN proxy data...")
            cert_chain, e, remote_ip, tls_version, tls_cipher = self.fetch_raw_cert_chain(host, host_ip, proxy_host=self.proxy_host, proxy_port=self.proxy_port)
        cert_chain_sha256_hex = [hashlib.sha256(cert.encode()).hexdigest() for cert in cert_chain]

        '''
            Right now, the IP address may not be right as we do not connect to IP address directly
            TODO: solve this problem and make sure the certificate matches IP address
        '''
        result = {'rank': rank, 'host': host, 'ip': remote_ip, 'error': e, 'certificate': cert_chain, 'sha256' : cert_chain_sha256_hex,
                  'tls_version' : tls_version, 'tls_cipher' : tls_cipher, 'scan_time' : datetime.now(timezone.utc)}

        with self.scan_status_data_lock:
            self.scan_status_data.scanned_domains += 1
            self.scan_status_data.scanned_certs += len(cert_chain)

            if e is not None:
                self.scan_status_data.error_count += 1
            else:
                self.scan_status_data.success_count += 1

        with self.cached_results_lock:
            self.cached_results.append(result)
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
                while not self.task_queue.empty():
                    index, host = self.task_queue.get()
                    executor.submit(self.scan_thread, index, host)
                # 等待所有线程完成
                executor.shutdown(wait=True)
                my_logger.info("All threads finished.")

        self.save_results()
        my_logger.info(f"Scan Completed")
        with self.scan_status_data_lock:
            self.scan_status_data.end_time = datetime.utcnow()
            self.scan_status_data.status = ScanStatusType.COMPLETED
        self.sync_update_scan_process_info()


    def terminate(self):
        pass
    def pause(self):
        pass
    def resume(self):
        pass


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
        elif self.scan_status_data.status == ScanStatusType.KILLED:
            scan_time = (self.scan_status_data.end_time - self.scan_status_data.start_time).seconds
        else:
            scan_time = -1

        with app.app_context():
            self.scan_status_entry.SCAN_TIME_IN_SECONDS = scan_time
            self.scan_status_entry.END_TIME = self.scan_status_data.end_time
            self.scan_status_entry.STATUS = self.scan_status_data.status.value
            self.scan_status_entry.SCANNED_DOMAINS = self.scan_status_data.scanned_domains
            self.scan_status_entry.SCANNED_CERTS = self.scan_status_data.scanned_certs
            self.scan_status_entry.SUCCESSES = self.scan_status_data.success_count
            self.scan_status_entry.ERRORS = self.scan_status_data.error_count
            db.session.add(self.scan_status_entry)
            db.session.commit()


    def save_results(self):
        with self.cached_results_lock:
            with app.app_context():
                my_logger.info(f"Saving {len(self.cached_results)} results...")

                scan_status_data_to_insert = []
                cert_data_to_insert = {}
                cert_metadata_to_insert = []

                for result in self.cached_results:
                    scan_status_data_to_insert.append(
                        ScanData(
                            SCAN_TIME = result['scan_time'],
                            DOMAIN = result['host'],
                            IP = result['ip'],
                            ERROR_MSG = result['error'],
                            RECEIVED_CERTS = result['sha256'],
                            TLS_VERSION = result['tls_version'],
                            TLS_CIPHER = result['tls_cipher']
                        )
                    )

                    for i in range(len(result['sha256'])):
                        cert_data_to_insert[result['sha256'][i]] = result['certificate'][i]
                        cert_metadata_to_insert.append(
                            {
                                'CERT_ID' : result['sha256'][i],
                                'SCAN_DATE' : result['scan_time'],
                                'SCAN_DOMAIN' : result['host'],
                                'SCAN_IP' : result['ip']
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

