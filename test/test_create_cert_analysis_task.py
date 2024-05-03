
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
            'SCAN_ID' : 'e323cab1-567b-489e-8bac-0789690150ca',
            'SUBTASK_FLAG': 0b0001,
            'SAVE_CHUNK_SIZE': 10000,
            'MAX_THREADS_ALLOC': 5
        }
        analyze_task = TaskBatchTemplate.create_analysis_task(CertAnalysisConfig(**analyze_args))
        g_manager.submit_task([analyze_task])
        g_manager.start_submitted_tasks()
