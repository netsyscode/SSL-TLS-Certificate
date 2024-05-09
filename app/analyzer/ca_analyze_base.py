
from app import app, db
from sqlalchemy import MetaData
from concurrent.futures import ThreadPoolExecutor, as_completed

from ..manager import g_thread_executor
from ..logger.logger import my_logger
from ..utils.exception import ParseError, UnknownTableError
from ..config.analysis_config import CaAnalysisConfig
from .ca_analyze_parse import CaParseAnalyzer

class CaMetricAnalyzer():

    def __init__(
            self,
            analysis_config : CaAnalysisConfig,
            scan_input_table_name : str,
        ) -> None:

        metadata = MetaData()
        metadata.reflect(bind=db.engine)
        reflected_tables = metadata.tables
        if scan_input_table_name in reflected_tables:
            self.scan_input_table = reflected_tables[scan_input_table_name]
        else:
            raise UnknownTableError(scan_input_table_name)
        self.save_scan_chunk_size = analysis_config.SAVE_CHUNK_SIZE
        self.max_threads = analysis_config.MAX_THREADS_ALLOC
        self.parse_analyzer = CaParseAnalyzer(analysis_config.SCAN_ID)


    def start(self):
        my_logger.info(f"Starting {self.scan_input_table.name} CA analysis...")
        
        with app.app_context():
            query = self.scan_input_table.select()
            result_proxy = db.session.execute(query)
            
            with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
                while True:
                    rows = result_proxy.fetchmany(self.save_scan_chunk_size)
                    if not rows:
                        break

                    if self.parse_analyzer:
                        my_logger.info("Allocate one thread for ca parse analyzer")
                        # use .result() to show exception info
                        # but will become single thread
                        executor.submit(self.parse_analyzer.analyze_ca_parse, rows)

                executor.shutdown(wait=True)
