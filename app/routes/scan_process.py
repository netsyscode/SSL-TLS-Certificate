
from ..base import base
from ..models import ScanStatus
from flask import Blueprint, jsonify, request
from flask_login import login_required, current_user

from ..scanner.scan_base import ScanConfig, ScanType
from ..scanner.scan_manager import manager
from ..logger.logger import my_logger
import threading

import asyncio

from .. import db
from datetime import datetime
import uuid


@base.route('/system/scan_process/list', methods=['GET'])
@login_required
def scan_process_list():
    # my_logger.info(f"{request.args}")
    filters = []
    if 'name' in request.args:
        filters.append(ScanStatus.NAME.like('%' + request.args['name'] + '%'))

    scan_processes = ScanStatus.query.filter(*filters)
    # my_logger.info(f"{[scan_process.to_json() for scan_process in scan_processes]}")

    return jsonify({'msg': '操作成功', 'code': 200, "data": [scan_process.to_json() for scan_process in scan_processes]})


@base.route('/system/scan_process', methods=['POST'])
@login_required
def scan_process_start():

    config = ScanConfig(
        request.json['scanTypeOptions'],
        scan_domain_num=request.json['scanDomainNum'],
        max_threads=request.json['scanThreadNum'],
    )

    task_id = manager.register(config)
    threading.Thread(target=manager.start, args=(task_id,)).start()
    # manager.start(task_id)
    # my_logger.info("Test")

    return jsonify({'code': 200, 'msg': '操作成功'})
