
from ..base import base
from ..models import ScanProcess
from flask import Blueprint, jsonify, request
from flask_login import login_required, current_user

from ..scanner.scan_base import ScanConfig, ScanType
from ..scanner.scan_manager import manager
from ..logger.logger import my_logger
import threading


from .. import db
from datetime import datetime
import uuid


@base.route('/system/scan_process/list', methods=['GET'])
@login_required
def scan_process_list():
    my_logger.info(f"{request.args}")
    filters = []
    if 'name' in request.args:
        filters.append(ScanProcess.NAME.like('%' + request.args['name'] + '%'))

    scan_processes = ScanProcess.query.filter(*filters)
    my_logger.info(f"{[scan_process.to_json() for scan_process in scan_processes]}")

    return jsonify({'msg': '操作成功', 'code': 200, "data": [scan_process.to_json() for scan_process in scan_processes]})




@base.route('/system/scan_process', methods=['POST'])
@login_required
def scan_process_start():

    my_logger.info(f"Registering scan with type SCAN_BY_DOMAIN...")
    scan_process = ScanProcess()
    scan_process.ID = str(uuid.uuid4())

    # if 'name' in request.data:
    #     scan_process.NAME = request.data['name']
    # if 'type' in request.data:
    #     scan_process.TYPE = request.data['type']


    db.session.add(scan_process)

    my_logger.info(f"Registering scan with type SCAN_BY_DOMAIN...")
    config = ScanConfig(ScanType.SCAN_BY_DOMAIN)
    task_id = manager.register(config)
    threading.Thread(target=manager.run, args=(task_id,)).start()

    return jsonify({'code': 200, 'msg': '操作成功'})
