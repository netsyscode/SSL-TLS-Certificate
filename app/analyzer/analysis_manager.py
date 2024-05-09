
from typing import Optional, Dict, Union
from .cert_analyze_base import CertScanAnalyzer
from .ca_analyze_base import CaMetricAnalyzer

from ..logger.logger import my_logger
from ..models import ScanStatus, CertAnalysisStats
from ..config.analysis_config import CertAnalysisConfig, CaAnalysisConfig
from ..manager import Manager
from ..manager.task import Task
from ..utils.exception import RegisterError, UnknownTableError

class AnalysisManager(Manager):

    analyze_config_to_analyzer = {
        CertAnalysisConfig : CertScanAnalyzer,
        CaAnalysisConfig : CaMetricAnalyzer
    }

    def __init__(self) -> None:
        super().__init__()
        self.registry : Dict[int, Union[CertScanAnalyzer, CaMetricAnalyzer]] = {}

    def register_task(self, task : Task):

        # search for cert store info
        try:
            scan_process : ScanStatus = ScanStatus.query.filter_by(ID=task.task_config.SCAN_ID).first()
            self.registry[task.task_id] = self.analyze_config_to_analyzer.get(task.task_config.__class__)(
                task.task_config, scan_process.CERT_STORE_TABLE
            )
        except UnknownTableError:
            raise RegisterError(task.task_id)

        my_logger.info(f"New analysis process registered")

    def start_task(self, task_id : int):
        my_logger.info(f"Starting analysis {task_id}...")
        self.registry[task_id].start()

    def kill_task(self, task_id : int):
        my_logger.info(f"Killing analysis {task_id}...")
        self.registry[task_id].terminate()

    def pause_task(self, task_id : int):
        my_logger.info(f"Pausing analysis {task_id}...")
        self.registry[task_id].pause()

    def resume_task(self, task_id : int):
        my_logger.info(f"Resuming analysis {task_id}...")
        self.registry[task_id].resume()
