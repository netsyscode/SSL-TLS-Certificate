
'''
    Created on 01/24/24
    Certificate scan manager and register
'''

import os
from typing import Optional, Dict, Union
from dataclasses import dataclass
from datetime import datetime
import time
from .scan_base import Scanner, ScanConfig
from ..logger.logger import my_logger
from ..models import ScanProcess
from .. import db
import uuid
import asyncio


class ScanManager():

    def __init__(self) -> None:
        self.registry : Dict[str, Union[Scanner, None]] = {}

    def register(self, scan_config : ScanConfig):

        scan_process = ScanProcess()
        scan_process.ID = str(uuid.uuid4())
        scan_process.CREATEDATETIME = datetime.now()
        time_to_str = scan_process.CREATEDATETIME.strftime("%Y%m%d%H%M%S")
        scan_process.TYPE = "Scan By Domain"
        scan_process.NAME = "test_scan"
        scan_process.SCAN_DATA_TABLE = f"scan_data_{time_to_str}"
        scan_process.CERT_STORE_TABLE = f"cert_store_{time_to_str}"
        scan_process.STATUS = "Pending"

        db.session.add(scan_process)
        db.session.commit()
        my_logger.info(f"New scan process registered")

        self.registry[scan_process.ID] = Scanner(scan_process.ID, scan_config, scan_process.SCAN_DATA_TABLE, scan_process.CERT_STORE_TABLE, begin_num=0, end_num=100)
        return scan_process.ID

    def start(self, task_id : str):
        my_logger.info(f"Starting new scan...")
        self.registry[task_id].start()
        # asyncio.run(self.registry[task_id].start())

    def kill(self, task_id : str):
        self.registry[task_id].stop()

    def get_status(self, task_id : str):
        return self.registry[task_id].get_status_info()
    
    def get_all_status(self):
        data = {}
        for id in self.registry:
            data[id] = self.registry[id].get_status_info()
            my_logger.info(f"{data[id]}")
            # return data[id]
        return data

manager = ScanManager()
