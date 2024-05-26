
import sys
sys.path.append(r"E:\global_ca_monitor")

import socket
import threading
from datetime import datetime, timezone
from app import app
from app.scanner.scan_by_domain import DomainScanner
from app.config.scan_config import DomainScanConfig
from app.utils.type import ScanType
from app.manager import g_manager
from app.manager.task import TaskBatchTemplate

with app.app_context():
    scan_type = ScanType(ScanType.SCAN_BY_DOMAIN)
    scan_args = {
        'SCAN_PROCESS_NAME': "20240521 0-1M",
        'SCAN_TIMEOUT' : 2,
        'MAX_RETRY' : 2,
        'NUM_DOMAIN_SCAN' : 1000000
    }

    config = DomainScanConfig(**scan_args)
    task_id = g_manager.submit_task([TaskBatchTemplate.create_scan_task_without_analysis(config)])
    g_manager.start_submitted_tasks()
