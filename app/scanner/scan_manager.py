
'''
    Created on 01/24/24
    Certificate scan manager and register
'''

import uuid
from datetime import datetime
from typing import Optional, Dict, Union

from app import db, app
from .scan_by_domain import DomainScanner
from .scan_by_ip import IPScanner
from .scan_by_ct import CTScanner
from ..logger.logger import my_logger
from ..models import ScanStatus, ScanData, CertAnalysisStats
from ..config.scan_config import DomainScanConfig, IPScanConfig, CTScanConfig
from ..utils.type import ScanType, ScanStatusType

from ..manager import Manager
from ..manager.task import Task

class ScanManager(Manager):

    scan_config_to_type = {
        DomainScanConfig : ScanType.SCAN_BY_DOMAIN.value,
        IPScanConfig : ScanType.SCAN_BY_IP.value,
        CTScanConfig : ScanType.SCAN_BY_CT.value
    }
    
    scan_config_to_scanner = {
        DomainScanConfig : DomainScanner,
        IPScanConfig : IPScanner,
        CTScanConfig : CTScanner
    }

    def __init__(self) -> None:
        super().__init__()
        self.registry : Dict[int, Union[DomainScanner, IPScanner, CTScanner]] = {}

    def register_task(self, task : Task):

        '''
            TODO: handle how to make these register events into task with blocking
            use join() or is_alive()???
        '''
        # register entry in ScanStatus db model
        scan_process = ScanStatus()
        scan_process.ID = str(task.task_id)
        scan_process.NAME = task.task_config.SCAN_PROCESS_NAME
        scan_process.TYPE = self.scan_config_to_type.get(task.task_config.__class__)
        scan_process.START_TIME = datetime.utcnow()
        scan_process.STATUS = ScanStatusType.RUNNING.value
        scan_process.NUM_THREADS = task.task_config.MAX_THREADS_ALLOC

        time_to_str = scan_process.START_TIME.strftime("%Y%m%d%H%M%S")
        scan_process.CERT_STORE_TABLE = f"cert_store_{time_to_str}"
        if task.task_config.__class__ == CTScanConfig:
            scan_process.CT_LOG_ADDRESS = task.task_config.CT_LOG_ADDRESS

        db.session.add(scan_process)
        db.session.commit()

        self.registry[task.task_id] = self.scan_config_to_scanner.get(task.task_config.__class__)(
            scan_process.ID, scan_process.START_TIME, task.task_config, scan_process.CERT_STORE_TABLE
        )

        r = scan_process.ID
        db.session.expunge(scan_process)
        my_logger.info(f"New scan process registered")
        return r

    def start_task(self, task_id : int):
        my_logger.info(f"Starting scan {task_id}...")
        self.registry[task_id].start()

    def kill_task(self, task_id : int):
        my_logger.info(f"Killing scan {task_id}...")
        self.registry[task_id].terminate()

    def pause_task(self, task_id : int):
        my_logger.info(f"Pausing scan {task_id}...")
        self.registry[task_id].pause()

    def resume_task(self, task_id : int):
        my_logger.info(f"Resuming scan {task_id}...")
        self.registry[task_id].resume()

