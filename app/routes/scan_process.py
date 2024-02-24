
from ..base import base
from ..models import ScanStatus
from flask import Blueprint, jsonify, request
from flask_login import login_required, current_user

import threading
from datetime import datetime
from ..scanner.scan_manager import manager, ScanConfig, ScanType
from ..logger.logger import my_logger


@base.route('/system/scan_process/list', methods=['GET'])
@login_required
def scan_process_list():
    # my_logger.info(f"{request.args}")
    filters = []
    if 'scanProcessName' in request.args:
        filters.append(ScanStatus.NAME.like('%' + request.args['scanProcessName'] + '%'))
    if 'scanStatus' in request.args:
        filters.append(ScanStatus.STATUS == request.args['scanStatus'])

    scan_processes = ScanStatus.query.filter(*filters)
    return jsonify({'msg': '操作成功', 'code': 200, "data": [scan_process.to_json() for scan_process in scan_processes]})


@base.route('/system/scan_process', methods=['POST'])
@login_required
def scan_process_start():

    config = ScanConfig(
        scan_name=request.json['scanName'],
        scan_type=ScanType(int(request.json['scanTypeOptions'])),
        scan_domain_num=int(request.json['scanDomainNum']),
        max_threads=int(request.json['scanThreadNum'])
    )

    task_id = manager.register(config)
    threading.Thread(target=manager.start, args=(task_id,)).start()
    # manager.start(task_id)
    # my_logger.info("Test")

    return jsonify({'code': 200, 'msg': '操作成功'})
