import os
from dataclasses import dataclass
from ..utils.type import ScanType


@dataclass
class ScanConfig():
    '''
        Scan Config represents all user-controlled parameters, passing from frontend
    '''
    SCAN_NAME : str = ""
    SCAN_TYPE : ScanType = ScanType.SCAN_BY_DOMAIN
    INPUT_FILE : str = os.path.join(os.path.dirname(__file__), r"../data/top-1m.csv")
    OUTPUT_DIR : str = os.path.join(os.path.dirname(__file__), r"../data")

    PROXY_HOST : str = '127.0.0.1'
    PROXY_PORT : int = 33210
    TIMEOUT : int = 5
    RETRY : int = 3

    THREADS_ALLOC : int = 100
    SAVE_CHUNK_SIZE : int = 2000
    DOMAIN_RANK_START : int = 0
    NUM_DOMAIN_SCAN : int = 100

