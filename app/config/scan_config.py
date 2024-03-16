import os
from flask import Request
from ..utils.type import ScanType


class ScanConfig:
    def __init__(self, **kwargs):
        self.SCAN_PROCESS_NAME = kwargs.get('SCAN_PROCESS_NAME', '')
        self.MAX_THREADS_ALLOC = kwargs.get('MAX_THREADS_ALLOC', 100)
        self.SAVE_CHUNK_SIZE = kwargs.get('SAVE_CHUNK_SIZE', 2000)
        self.PROXY_HOST = kwargs.get('PROXY_HOST', '127.0.0.1')
        self.PROXY_PORT = kwargs.get('PROXY_PORT', 33210)
        self.SCAN_TIMEOUT = kwargs.get('SCAN_TIMEOUT', 5)
        self.MAX_RETRY = kwargs.get('MAX_RETRY', 3)


class DomainScanConfig(ScanConfig):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.INPUT_DOMAIN_LIST_FILE = kwargs.get('INPUT_DOMAIN_LIST_FILE', os.path.join(os.path.dirname(__file__), r"../data/top-1m.csv"))
        self.DOMAIN_RANK_START = kwargs.get('DOMAIN_RANK_START', 0)
        self.NUM_DOMAIN_SCAN = kwargs.get('NUM_DOMAIN_SCAN', 100)


class IPScanConfig(ScanConfig):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.INPUT_IP_LIST_FILE = kwargs.get('INPUT_IP_LIST_FILE', "")


class CTScanConfig(ScanConfig):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.CT_LOG_ADDRESS = kwargs.get('CT_LOG_ADDRESS', "")
        self.ENTRY_START = kwargs.get('ENTRY_START', 0)
        self.ENTRY_END = kwargs.get('ENTRY_END', 1000)


def create_scan_config(request : Request, scan_type : ScanType):

    common_args = {
        'SCAN_PROCESS_NAME': request.json.get('scanName'),
        'MAX_THREADS_ALLOC': int(request.json.get('scanThreadNum')),
        'SCAN_TIMEOUT': int(request.json.get('timeout')),
        'MAX_RETRY': int(request.json.get('retryTimes')),
    }

    if request.json.get('proxyAddress'):
        common_args['PROXY_HOST'] = request.json.get('proxyAddress')
    if request.json.get('proxyPort'):
        common_args['PROXY_PORT'] = request.json.get('proxyPort')
    if request.json.get('scanDomainFile'):
        common_args['INPUT_DOMAIN_LIST_FILE'] = request.json.get('scanDomainFile')
    if request.json.get('scanDomainNum'):
        common_args['NUM_DOMAIN_SCAN'] = request.json.get('scanDomainNum')
    if request.json.get('scanIpFile'):
        common_args['INPUT_IP_LIST_FILE'] = request.json.get('scanIpFile')
    if request.json.get('ctLog'):
        common_args['CT_LOG_ADDRESS'] = request.json.get('ctLog')
    if request.json.get('startValue'):
        common_args['ENTRY_START'] = request.json.get('startValue')
    if request.json.get('endValue'):
        common_args['ENTRY_END'] = request.json.get('endValue')

    config_class_mapping = {
        ScanType.SCAN_BY_DOMAIN: DomainScanConfig,
        ScanType.SCAN_BY_IP: IPScanConfig,
        ScanType.SCAN_BY_CT: CTScanConfig,
    }

    config_class = config_class_mapping.get(scan_type)
    config = config_class(**common_args)
    return config

