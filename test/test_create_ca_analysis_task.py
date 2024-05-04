
import sys
sys.path.append(r"E:\global_ca_monitor")

import multiprocessing
from threading import Thread
from app import app, db
from app.manager import g_manager
from app.manager.task import TaskBatchTemplate
from app.config.analysis_config import CaAnalysisConfig

with app.app_context():
    analyze_args = {
        # 'SCAN_ID' : '62b10ef7-ef79-442f-8b6e-0599de728ebb',
        # 'SCAN_ID' : 'e323cab1-567b-489e-8bac-0789690150ca',
        'SCAN_ID' : '95dc7748-7490-4d84-8d67-4b2193953ffb',
        'SAVE_CHUNK_SIZE': 10000,
        'MAX_THREADS_ALLOC': 5
    }
    analyze_task = TaskBatchTemplate.create_analysis_task(CaAnalysisConfig(**analyze_args))
    g_manager.submit_task([analyze_task])
    g_manager.start_submitted_tasks()
