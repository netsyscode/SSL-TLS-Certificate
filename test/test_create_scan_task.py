

import sys
sys.path.append(r"E:\global_ca_monitor")

from app import app, db
from app.manager import g_manager
from app.manager.task import TaskBatchTemplate
from app.config.scan_config import DomainScanConfig


with app.app_context:
    scan_args = {'SCAN_PROCESS_NAME': "test_scan"}
    scan_task = TaskBatchTemplate.create_scan_task(DomainScanConfig(**scan_args))
    g_manager.submit_task([scan_task])

