
'''
    Backend process manager
    Created on 03/27/24
'''

from time import sleep
from threading import Thread, Lock, RLock
from typing import List, Dict

from .task import Task
from ..io.sql_io_manager import SqlIoManager
from ..scanner.scan_manager import ScanManager
from ..analyzer.analysis_manager import AnalysisManager
from ..utils.type import TaskType
from ..utils.exception import RegisterError, ResourceInsufficientError
from ..logger.logger import my_logger

class GlobalTaskManager():

    def __init__(self) -> None:
        self.scan_manager = ScanManager()
        self.analysis_manager = AnalysisManager()
        self.sql_io_manager = SqlIoManager()
        self.manager_map = {
            TaskType.TASK_SCAN : self.scan_manager,
            TaskType.TASK_ANALYSIS : self.analysis_manager,
            TaskType.TASK_READ_SQL : self.sql_io_manager,
            TaskType.TASK_WRITE_SQL : self.sql_io_manager
        }
        '''
            Hierarchical manager arrangment
        '''

        # TODO: change lock type to Rlock
        self.task_lock = RLock()
        self.submitted_task : Dict[int, Task] = {}
        self.running_task : Dict[int, Task] = {}
        self.suspended_task : Dict[int, Task] = {}
        '''
            These task dicts contain tree structure tasks, with unique task_id as dict keys
            submitted_task and suspended_task may have tasks whose parents are cuurently in running_task
            e.g.
                    Task1
                    /   \
                Task2   Task3
                self.submitted_task = Task2
                self.running_task = Task1
                self.suspended_task = Task3

            In this example, Task1 is running and Task2 has not started, while Task3 is suspended
            As Task1 is the parent, this senario is acceptable
            When parent task finishes, the manager tries to kills all suspended child tasks

            There are two corner cases we need to take care of:
            1. The parent task is about to finish, it needs one last data chunk from it child;
                however, that child is currently suspended for some reason.
                Solve: In this case, put the parent into the suspended queue
            2. Suspended child task accepts data from its parent. The parent is running and generate data;
                however, the data is too much and goes beyond the cache limit.
                Solve: In this case, we let the child tell its parent not to send data anymore.
                When the child resumes, it initiates new tasks to read from database.
        '''

        self.max_running_task = 100
        self.task_scheduler_thread = Thread(target=self.task_scheduler, args=())
        self.task_scheduler_thread.start()
        '''
            An idle thread to continously check and start submitted tasks
        '''


    def task_scheduler(self):
        while True:
            try:
                sleep(5)
                self.start_submitted_tasks()
            except:
                continue


    def submit_task(self, task_queue : List[Task]):
        with self.task_lock:
            for task in task_queue:
                try:
                    self.manager_map[task.task_type].register_task(task)    # Register task to certain manager
                    self.submitted_task[task.task_id] = task
                except RegisterError as e:
                    my_logger.error(e.message)


    def start_submitted_tasks(self):
        if len(self.running_task.keys()) >= self.max_running_task:
            my_logger.warning("Full task running slots, please wait for some running task finishes")
            return

        for task_id in list(self.submitted_task.keys()):
            # if the task has parent, check its parent's status
            try:
                parent = self.submitted_task.get(task_id).parent_task
                if not parent or parent.task_id in self.running_task:
                    self.start_task(task_id)
                else:
                    my_logger.warning(f"Task {task_id} parent is not running, cannot start it.")
            except AttributeError:
                my_logger.warning(f"Trying to start task {task_id} that has been killed manually")


    def start_task(self, task_id : int):
        if len(self.running_task.keys()) >= self.max_running_task:
            my_logger.warning("Full task running slots, please wait for some running task finishes")
            return
        
        with self.task_lock:
            try:
                my_logger.info(f"Staring task {task_id}...")
                self.manager_map[self.submitted_task.get(task_id).task_type].start_task(task_id)
                self.running_task[task_id] = self.submitted_task.get(task_id)
                self.submitted_task.pop(task_id)
            except ResourceInsufficientError as e:
                my_logger.error(e.message)
    

    def suspend_task(self, task_id : int):
        '''
            Warning: this action will suspend a task
            If the task has children, they will also be suspended
        '''
        # suspend child first, then parent
        if task_id not in self.running_task:
            my_logger.warning(f"Trying to suspend non-running task {task_id}")
            return
        
        with self.task_lock:
            child_list = self.running_task.get(task_id).child_task
            for child in child_list:
                self.suspend_task(child.task_id)

            my_logger.info(f"Suspending task {task_id}...")
            self.manager_map[self.running_task.get(task_id).task_type].suspend_task(task_id)
            self.suspended_task[task_id] = self.running_task.get(task_id)
            self.running_task.pop(task_id)


    def resume_task(self, task_id : int, resume_child : bool):
        '''
            Resume the sepicified task
            Do pass a flag to tell the manager if resume all child tasks
            If the task's parent is suspended, this method will return an error
        '''
        if len(self.running_task.keys()) >= self.max_running_task:
            my_logger.warning("Full task running slots, please wait for some running task finishes")
            return
        
        # resume parent first, then child
        if task_id not in self.suspended_task:
            my_logger.warning(f"Trying to resume non-suspend task {task_id}")
            return
        
        with self.task_lock:
            parent_task_id = self.suspended_task.get(task_id).parent_task.task_id
            if parent_task_id in self.suspended_task:
                my_logger.warning(f"Trying to resume task {task_id} while its parent is currently suspended")
                return

            try:
                my_logger.info(f"Resuming task {task_id}...")
                self.manager_map[self.suspended_task.get(task_id).task_type].resume_task(task_id)
                self.running_task[task_id] = self.suspended_task.get(task_id)
                self.suspended_task.pop(task_id)

                if resume_child:
                    for child in self.running_task.get(task_id).child_task:
                        self.resume_task(child.task_id)
            except ResourceInsufficientError as e:
                my_logger.error(e.message)


    def kill_task(self, task_id : int):
        '''
            Warning: killed task cannot be resumed anymore
            If the task has children, they will also be killed
            DO think twice before making any actions
            The current context will be archived
        '''
        # kill child first, then parent
        with self.task_lock:
            if task_id in self.submitted_task:
                task = self.submitted_task.get(task_id)
            elif task_id in self.running_task:
                task = self.running_task.get(task_id)
            elif task_id in self.suspended_task:
                task = self.suspended_task.get(task_id)
        
            for child in task.child_task:
                self.kill_task(child.task_id)

            my_logger.info(f"Killing task {task_id}...")
            self.manager_map[task.task_type].kill_task(task_id)

            if task_id in self.submitted_task:
                self.submitted_task.pop(task_id)
            elif task_id in self.running_task:
                self.running_task.pop(task_id)
            elif task_id in self.suspended_task:
                self.suspended_task.pop(task_id)

