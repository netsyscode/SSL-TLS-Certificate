
from flask import Request

class CertAnalysisConfig:

    PARSE_SUBTASK = 0b0001
    CHAIN_SUBTASK = 0b0010
    REVOKE_SUBTASK = 0b0100
    CA_SUBTASK = 0b1000

    def __init__(self, **kwargs):
        '''
            SCAN_ID determines the cert_store table
            when the value is None, we use cert_store_raw table to analyze all unique certificates
        '''
        self.SCAN_ID  = kwargs.get('SCAN_ID', None)

        '''
            FLAG decides which subtasks to be launched
            we can OR the class constants above to catch the flag
        '''
        self.SUBTASK_FLAG = kwargs.get('SUBTASK_FLAG', 0b0001)
        self.SAVE_CHUNK_SIZE = kwargs.get('SAVE_CHUNK_SIZE', 2000)
        self.MAX_THREADS_ALLOC = kwargs.get('MAX_THREADS_ALLOC', 100)


class CaAnalysisConfig:

    PARSE_SUBTASK = 0b0001
    CLUSTERING_SUBTASK = 0b0010

    def __init__(self, **kwargs):

        self.SCAN_ID  = kwargs.get('SCAN_ID', None)
        self.SUBTASK_FLAG = kwargs.get('SUBTASK_FLAG', 0b0001)
        self.SAVE_CHUNK_SIZE = kwargs.get('SAVE_CHUNK_SIZE', 2000)
        self.MAX_THREADS_ALLOC = kwargs.get('MAX_THREADS_ALLOC', 100)


def create_analyze_config(request : Request, analyze_type : int):

    common_args = {
        'SCAN_ID': request.json.get('scanId'),
        'SUBTASK_FLAG': int(request.json.get('flag')),
        'SAVE_CHUNK_SIZE': int(request.json.get('saveChunkSize')),
        'MAX_THREADS_ALLOC': int(request.json.get('scanThreadNum')),
    }

    if analyze_type == 0:
        return CertAnalysisConfig(**common_args)
    else:
        return None
