
'''
    Created on 01/17/24
    Collect CT log entries and parse the certificates
'''

import json
import time
import base64
import requests
import threading

from OpenSSL import crypto
from cryptography.hazmat.primitives.serialization import Encoding
from datetime import datetime
from urllib3.exceptions import SSLError
from rich.progress import Progress, BarColumn, TextColumn, TimeRemainingColumn
from concurrent.futures import ThreadPoolExecutor, as_completed
from concurrent.futures import ProcessPoolExecutor, Future
from sqlalchemy import insert
from sqlalchemy.exc import IntegrityError

from app import db, app
from ..parser.ct_parser import *
from .scan_base import Scanner, ScanStatusData
from ..config.scan_config import CTScanConfig
from ..utils.type import ScanType, ScanStatusType
from ..utils.cert import get_cert_sha256_hex_from_str
from ..logger.logger import my_logger
from ..analyzer.cert_analyze_base import CertScanAnalyzer
from ..models import (
    ScanStatus, ScanData, CertScanMeta, CertStoreContent, CertStoreRaw
)

class CTScanner(Scanner):

    def __init__(
            self,
            scan_id : str,
            start_time : datetime,
            scan_config : CTScanConfig,
            cert_data_table_name : str,
        ) -> None:

        super().__init__(scan_id, start_time, scan_config, cert_data_table_name)

        # scan settings from scan config
        self.log_server = scan_config.CT_LOG_ADDRESS
        self.begin_entry = scan_config.ENTRY_START
        self.end_entry = scan_config.ENTRY_END
        self.window_size = scan_config.WINDOW_SIZE


    def scan_thread(self, start, end):
        log_server_request = f'https://{self.log_server}/ct/v1/get-entries'
        params = {'start': start, 'end': end}

        entries = []
        retry_times = 0
        while retry_times < self.max_retries:
            try:
                response = requests.get(log_server_request, params=params, verify=True, timeout=self.timeout)
            except Exception as e:
                # my_logger.warning(f"Exception {e} when requesting CT entries from {start} to {end}")
                retry_times += 1
                continue

            if response.status_code == 200:
                entries = json.loads(response.text)['entries']
                break
            else:
                # my_logger.warning(f"Requesting CT entries from {start} to {end} failed.")
                retry_times += 1
                continue

        result = []
        for entry in entries:

            leaf_cert = merkle_tree_header.parse(base64.b64decode(entry['leaf_input']))
            if leaf_cert.LogEntryType == "X509LogEntryType":
                # We have a normal x509 entry
                cert_data_string = certificate.parse(leaf_cert.Entry).CertData
                result.append(crypto.load_certificate(crypto.FILETYPE_ASN1, cert_data_string).to_cryptography().public_bytes(Encoding.PEM).decode('utf-8'))

                # Parse the `extra_data` structure for the rest of the chain
                extra_data = certificate_chain.parse(base64.b64decode(entry['extra_data']))
                for cert in extra_data.Chain:
                    result.append(crypto.load_certificate(crypto.FILETYPE_ASN1, cert.CertData).to_cryptography().public_bytes(Encoding.PEM).decode('utf-8'))

            else:
                # We have a precert entry
                extra_data = pre_cert_entry.parse(base64.b64decode(entry['extra_data']))
                result.append(crypto.load_certificate(crypto.FILETYPE_ASN1, extra_data.LeafCert.CertData).to_cryptography().public_bytes(Encoding.PEM).decode('utf-8'))

                for cert in extra_data.CertChain.Chain:
                    result.append(crypto.load_certificate(crypto.FILETYPE_ASN1, cert.CertData).to_cryptography().public_bytes(Encoding.PEM).decode('utf-8'))

        with self.scan_status_data_lock:
            self.scan_status_data.scanned_entries += self.window_size
            self.scan_status_data.scanned_certs += len(result)
            self.scan_status_data.success_count += len(entries)
            self.scan_status_data.error_count += self.window_size - len(entries)

        with self.cached_results_lock:
            self.cached_results += result
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
            total = (self.end_entry - self.begin_entry) / self.window_size
            self.progress_task = self.progress.add_task("[Waiting]", total=total)

            timer_thread = threading.Thread(target=self.async_update_scan_process_info)
            timer_thread.daemon = True  # 设置为守护线程，以便主线程退出时自动退出定时器线程
            timer_thread.start()

            my_logger.info(f"Scanning...")
            with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
                start = self.begin_entry
                while start < self.end_entry:
                    end = start + self.window_size
                    if end < self.end_entry:
                        executor.submit(self.scan_thread, start, end - 1)
                    else:
                        executor.submit(self.scan_thread, start, self.end_entry - 1)
                    start = end

                executor.shutdown(wait=True)
                my_logger.info("All threads finished.")

        if self.cached_results:
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
            self.scan_status_entry.SCANNED_RNTRIES = self.scan_status_data.scanned_entries
            self.scan_status_entry.SCANNED_CERTS = self.scan_status_data.scanned_certs
            self.scan_status_entry.SUCCESSES = self.scan_status_data.success_count
            self.scan_status_entry.ERRORS = self.scan_status_data.error_count
            db.session.add(self.scan_status_entry)
            db.session.commit()


    def save_results(self):

        with app.app_context():
            my_logger.info(f"Saving {len(self.cached_results)} results...")

            cert_data_to_insert = []
            for result in self.cached_results:
                cert_data_to_insert.append(
                    {
                        'CERT_ID' : get_cert_sha256_hex_from_str(result),
                        'CERT_RAW' : result
                    }
                )

            with db.session.begin():
                # only template model, can not use insert(Model) here
                insert_cert_data_statement = insert(self.cert_data_table).values(cert_data_to_insert).prefix_with('IGNORE')
                db.session.execute(insert_cert_data_statement)

                # many many primary key dupliates...
                # need to deal with Integrity Error with duplicate primary key pair with bulk_insert_mappings
                # insert_cert_raw_statement = insert(CertStoreRaw).values(cert_data_to_insert).prefix_with('IGNORE')
                # db.session.execute(insert_cert_raw_statement)

        self.cached_results = []
