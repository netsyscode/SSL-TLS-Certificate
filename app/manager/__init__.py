
'''
    Manager base class
'''
from abc import ABC, abstractmethod
from .task import Task

class Manager(ABC):

    def __init__(self) -> None:
        super().__init__()

    @abstractmethod
    def register_task(self, task : Task):
        pass

    @abstractmethod
    def start_task(self, task_id : int):
        pass

    @abstractmethod
    def pause_task(self, task_id : int):
        pass

    @abstractmethod
    def resume_task(self, task_id : int):
        pass

    @abstractmethod
    def kill_task(self, task_id : int):
        pass

# Global thread pool, covers all the tasks thread allocation
from concurrent.futures import ProcessPoolExecutor
GLOBAL_MAX_PROCESSES = 20
g_process_executor = ProcessPoolExecutor(max_workers=GLOBAL_MAX_PROCESSES)

# Global thread pool, covers all the tasks thread allocation
from concurrent.futures import ThreadPoolExecutor
GLOBAL_MAX_THREADS = 1000
g_thread_executor = ThreadPoolExecutor(max_workers=GLOBAL_MAX_THREADS)

'''
    The thing is: we cannot call ThreadPoolExecutor.submit in any child thread
    nor ProcessPoolExecutor.submit not in main process
    (though I have no idea why, but it cannot)
    TODO: There are two ways:
    1. Delete the thread/process for manager task_scheduler and run start_submitted_task manually
    This will ensure that the start_task function runs in the main process
    2. Need to think a way to implement ProcessPool and ThreadPool by myself
    This can skip the constraints implemented in concurrent library
'''

# global task manager
import multiprocessing
from .task_manager import GlobalTaskManager
g_manager = GlobalTaskManager()
# self.task_scheduler_thread = Thread(target=self.task_scheduler, args=())
# self.task_scheduler_thread.start()
# multiprocessing.freeze_support()
# p = multiprocessing.Process(target=g_manager.task_scheduler)
# p.start()
