
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

from .task_manager import GlobalTaskManager
g_manager = GlobalTaskManager()
