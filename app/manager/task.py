
'''
    User submitted task specifics
    Created on 03/27/24
'''

import uuid
from threading import Thread
from typing import Union, List
from dataclasses import dataclass
from ..config.scan_config import DomainScanConfig, IPScanConfig, CTScanConfig
from ..config.analysis_config import CertAnalysisConfig, CaAnalysisConfig
from ..config.sql_io_config import SqlReadConfig, SqlWriteConfig
from ..utils.type import TaskType, ScanType

@dataclass
class Task():

    task_type : TaskType
    '''
        Current system has four task types:
        1. Scan: scan certs from internet (handled by scan manager)
        2. Analyze: analyze certs with user-specified input (handled by analysis manager, inputs either from SQL table, or from scan cache)
        
        The following two tasks need heavy I/O from external place: MySQL database schema, handled by sql_io_manager
        3. Store SQL: store data to certain table (args passed in config)
        4. Read SQL: read data from certain table (args passed in config)
    '''

    task_config : Union[
        DomainScanConfig,
        IPScanConfig,
        CTScanConfig,
        CertAnalysisConfig,
        CaAnalysisConfig,
        SqlReadConfig,
        SqlWriteConfig
    ]

    task_id = uuid.uuid4()
    '''
        Random generated 128 bit id
    '''

    parent_task : 'Task' = None
    child_task = []
    '''
        parent_task and child_task correspond to task tree relationships, stored as pointers
        The parent task can initiate multiple child tasks. For each child task, the parent may or may not count data onto it.
        Normally, parent and child run asynchronously, speeding up the task process. However, child_task cannot self-exist without its parent
        To enhance robustness, parent_task can run with its children suspended or killed.
    '''


class TaskBatchTemplate():
    '''
        Template for creating one to multiple tasks to submit to task manager
    '''
    @staticmethod
    def create_scan_task(scan_config):
        return Task(
            task_type=TaskType.TASK_SCAN,
            task_config=scan_config
        )

    @staticmethod
    def create_analysis_task(analysis_config):
        return Task(
            task_type=TaskType.TASK_ANALYSIS,
            task_config=analysis_config
        )
    
    @staticmethod
    def create_sql_read_task(read_config):
        return Task(
            task_type=TaskType.TASK_READ_SQL,
            task_config=read_config
        )
    
    @staticmethod
    def create_sql_write_task(write_config):
        return Task(
            task_type=TaskType.TASK_WRITE_SQL,
            task_config=write_config
        )

    @staticmethod
    def create_scan_task_with_analysis(scan_config, analysis_config):
        scan_task = TaskBatchTemplate.create_scan_task(scan_config)
        analysis_task = TaskBatchTemplate.create_analysis_task(analysis_config)
        scan_task.child_task.append(analysis_task)
        analysis_task.parent_task = scan_task
        return [scan_task, analysis_task]

    @staticmethod
    def create_scan_task_without_analysis(scan_config):
        return TaskBatchTemplate.create_scan_task(scan_config)

