
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


class ScanManager():

    def __init__(self) -> None:
        self.registry : Dict[str, Union[Scanner, None]] = {}

    def register(self, scan_config : ScanConfig):
        task_id = str(time.time())
        self.registry[task_id] = Scanner(scan_config, begin_num=0, end_num=100000)
        return task_id

    def run(self, task_id : str):
        self.registry[task_id].start()

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
