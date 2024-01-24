
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
from scan_by_domain import Crawler

class ScanType(Enum):
    SCAN_BY_DOMAIN = 0
    SCAN_BY_IP = 1
    SCAN_BY_CT = 2

@dataclass
class ScanConfig():
    scan_type : ScanType = ScanType.SCAN_BY_DOMAIN
    input_file : str = os.path.join(os.path.dirname(__file__), r"..\data\top-1m.csv")
    proxy_host : str = '127.0.0.1'
    proxy_port : int = 33211
    timeout : int = 5


@dataclass
class ScanData():
    status : str
    start_time : datetime
    end_time : datetime

    scanned_domains : int
    scanned_certs : int
    scanned_unique_certs : int




class ScanManager():

    def __init__(self) -> None:
        self.registry : Dict[str, Union[Crawler, None]] = {}

    def register(self, scan_config : ScanConfig):
        task_id = str(time.time)
        self.registry[task_id] = Crawler(csv_file='top-1m.csv', max_threads=100, save_threshold=200, begin_num=0, end_num=100000)
        return task_id

    def run(self, task_id : str):
        crawler = 
        self.registry[task_id]
        crawler.start()

    def kill(self, task_id):
        stop
        

    def get_status(self, task_id : str):
        return self.registry[task_id].status

manager = ScanManager()
