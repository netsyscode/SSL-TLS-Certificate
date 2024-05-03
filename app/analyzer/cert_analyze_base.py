
from app import app, db
from sqlalchemy import insert, MetaData, Table
from concurrent.futures import ThreadPoolExecutor, as_completed

from ..manager import g_thread_executor
from ..logger.logger import my_logger
from ..utils.exception import ParseError, UnknownTableError
from ..config.analysis_config import CertAnalysisConfig

from .cert_analyze_chain import CertScanChainAnalyzer
from .cert_analyze_revocation import CertRevocationAnalyzer
from .cert_analyze_parse import CertParseAnalyzer

class CertScanAnalyzer():

    def __init__(
            self,
            analysis_config : CertAnalysisConfig,
            scan_input_table_name : str,
        ) -> None:

        '''
            Get the input table model
            Use this model to retrieve cert data with certain chunk size at a time
        '''
        metadata = MetaData()
        metadata.reflect(bind=db.engine)
        reflected_tables = metadata.tables
        if scan_input_table_name in reflected_tables:
            self.scan_input_table = reflected_tables[scan_input_table_name]
        else:
            raise UnknownTableError(scan_input_table_name)
        self.save_scan_chunk_size = analysis_config.SAVE_CHUNK_SIZE
        self.max_threads = analysis_config.MAX_THREADS_ALLOC

        # Parse analysis flag to choose to build analyzer
        self.parse_analyzer = CertParseAnalyzer(analysis_config.SCAN_ID, self.save_scan_chunk_size) if analysis_config.SUBTASK_FLAG & CertAnalysisConfig.PARSE_SUBTASK else None
        self.chain_analyzer = CertScanChainAnalyzer() if analysis_config.SUBTASK_FLAG & CertAnalysisConfig.CHAIN_SUBTASK else None
        self.revoke_analyzer = CertRevocationAnalyzer() if analysis_config.SUBTASK_FLAG & CertAnalysisConfig.REVOKE_SUBTASK else None
        self.ca_analyzer = None if analysis_config.SUBTASK_FLAG & CertAnalysisConfig.CA_SUBTASK else None


    def start(self):
        my_logger.info(f"Starting {self.scan_input_table.name} scan analysis...")
        
        with app.app_context():
            query = self.scan_input_table.select()
            result_proxy = db.session.execute(query)
            
            with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
                while True:
                    rows = result_proxy.fetchmany(self.save_scan_chunk_size)
                    if not rows:
                        break

                    from threading import Thread
                    if self.parse_analyzer:
                        print(len(rows))
                        my_logger.info("Allocate one thread for parse analyzer")
                        executor.submit(self.parse_analyzer.analyze_cert_parse, rows).result()
                        # g_thread_executor.submit(self.parse_analyzer.analyze_cert_parse, rows).result()
                        # _thread = Thread(target=self.parse_analyzer.analyze_cert_parse, args=(rows,))
                        # _thread.start()

                    if self.chain_analyzer:
                        my_logger.info("Allocate one thread for chain analyzer")
                        pass

                    if self.revoke_analyzer:
                        my_logger.info("Allocate one thread for revocation analyzer")
                        pass
                    
                    if self.ca_analyzer:
                        my_logger.info("Allocate one thread for ca analyzer")
                        pass
                executor.shutdown(wait=True)
