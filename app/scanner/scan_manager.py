
'''
    Created on 01/24/24
    Certificate scan manager and register
'''

import uuid
from datetime import datetime
from typing import Optional, Dict, Union

from app import db, app
from .scan_base import Scanner
from ..logger.logger import my_logger
from ..models import ScanStatus, ScanData, CertAnalysisStats
from ..config.scan_config import ScanConfig
from ..utils.type import ScanType, ScanStatusType

class ScanManager():

    def __init__(self) -> None:
        self.registry : Dict[str, Union[Scanner, None]] = {}

    def register(self, scan_config : ScanConfig):

        # register entry in ScanStatus db model
        scan_process = ScanStatus()
        scan_process.ID = str(uuid.uuid4())
        scan_process.NAME = scan_config.SCAN_NAME
        scan_process.TYPE = scan_config.SCAN_TYPE.value
        scan_process.START_TIME = datetime.utcnow()
        scan_process.STATUS = ScanStatusType.RUNNING.value
        scan_process.NUM_THREADS = scan_config.THREADS_ALLOC

        time_to_str = scan_process.START_TIME.strftime("%Y%m%d%H%M%S")
        scan_process.CERT_STORE_TABLE = f"cert_store_{time_to_str}"

        db.session.add(scan_process)
        db.session.commit()

        # register entry in CertAnalysisStats db model
        cert_analysis_store = CertAnalysisStats()
        cert_analysis_store.SCAN_ID = scan_process.ID
        cert_analysis_store.SCAN_TIME = scan_process.START_TIME
        cert_analysis_store.SCAN_TYPE = scan_process.TYPE
        cert_analysis_store.SCANNED_CERT_NUM = 0
        cert_analysis_store.ISSUER_ORG_COUNT = {}
        cert_analysis_store.KEY_SIZE_COUNT = {}
        cert_analysis_store.KEY_TYPE_COUNT = {}
        cert_analysis_store.SIG_ALG_COUNT = {}
        cert_analysis_store.VALIDATION_PERIOD_COUNT = {}
        cert_analysis_store.EXPIRED_PERCENT = 0

        db.session.add(cert_analysis_store)
        db.session.commit()

        # register entry in CaAnalysis db model
        '''
        '''

        my_logger.info(f"New scan process registered")
        self.registry[scan_process.ID] = Scanner(scan_process.ID, scan_process.START_TIME, scan_config, scan_process.CERT_STORE_TABLE)
        r = scan_process.ID
        db.session.expunge(scan_process)
        db.session.expunge(cert_analysis_store)
        return r

    def start(self, task_id : str):
        my_logger.info(f"Starting new scan...")
        self.registry[task_id].start()
        # asyncio.run(self.registry[task_id].start())

    def kill(self, task_id : str):
        self.registry[task_id].stop()

    # Old version, deprecated
    def get_status(self, task_id : str):
        return self.registry[task_id].get_status_info()
    
    # Old version, deprecated
    def get_all_status(self):
        data = {}
        for id in self.registry:
            data[id] = self.registry[id].get_status_info()
            # my_logger.info(f"{data[id]}")
            # return data[id]
        return data

manager = ScanManager()
