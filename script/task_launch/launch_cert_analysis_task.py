
import sys
sys.path.append(r"E:\global_ca_monitor")

import multiprocessing
from threading import Thread
from app import app, db
from app.manager import g_manager
from app.manager.task import TaskBatchTemplate
from app.config.analysis_config import CertAnalysisConfig

if __name__ == "__main__":
    # multiprocessing.freeze_support()

    '''
        An idle thread to continously check and start submitted tasks
    '''
    # task_scheduler_thread = Thread(target=g_manager.task_scheduler, args=())
    # task_scheduler_thread.start()
    # p = multiprocessing.Process(target=g_manager.task_scheduler)
    # p.start()

    with app.app_context():
        analyze_args = {
            'SCAN_ID' : '0',
            # 'SCAN_ID' : '19e938d4-a6e2-4924-a9d7-0e1184e2bc58',
            # 'SCAN_ID' : '09a97bc9-a03f-46ad-ab2f-1763701d64c1',
            # 'SCAN_ID' : '94904b17-8b2a-436c-a83e-f4fbb75b0de7',
            # 'SCAN_ID' : '2846a9c8-5b6e-486c-8974-97b8f5ed85f6',
            'SUBTASK_FLAG': 0b0001,
            'SAVE_CHUNK_SIZE': 20000,
            'MAX_THREADS_ALLOC': 50
        }
        analyze_task = TaskBatchTemplate.create_analysis_task(CertAnalysisConfig(**analyze_args))
        g_manager.submit_task([analyze_task])
        g_manager.start_submitted_tasks()
