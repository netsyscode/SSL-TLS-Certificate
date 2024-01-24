
'''
    Created on 01/24/24
    Certificate scan manager and register
'''

import os
from enum import Enum
from typing import Optional, Dict, Union
from dataclasses import dataclass
from datetime import datetime
import time
from scan_base import Scanner

class ScanType(Enum):
    SCAN_BY_DOMAIN = 0
    SCAN_BY_IP = 1
    SCAN_BY_CT = 2

@dataclass
class ScanConfig():
    scan_type : ScanType = ScanType.SCAN_BY_DOMAIN
    input_csv_file : str = os.path.join(os.path.dirname(__file__), r"..\data\top-1m.csv")
    proxy_host : str = '127.0.0.1'
    proxy_port : int = 33211
    timeout : int = 5

    max_threads : int = 100
    save_threshold : int = 200

class ScanManager():

    def __init__(self) -> None:
        self.registry : Dict[str, Union[Scanner, None]] = {}

    def register(self, scan_config : ScanConfig):
        task_id = str(time.time)
        self.registry[task_id] = Scanner(scan_config, begin_num=0, end_num=100)
        return task_id

    def run(self, task_id : str):
        self.registry[task_id].start()

    def kill(self, task_id : str):
        self.registry[task_id].stop()

    def get_status(self, task_id : str):
        return self.registry[task_id].get_status_info()

manager = ScanManager()
