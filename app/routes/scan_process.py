
from ..blueprint import base
from ..models import ScanStatus
from flask import Blueprint, jsonify, request
from flask_login import login_required, current_user

import threading
from ..scanner.scan_manager import manager
from ..config.scan_config import create_scan_config
from ..utils.type import ScanType


@base.route('/system/scan_process/list', methods=['GET'])
@login_required
def scan_process_list():
    # build db select filter from search options
    # note options might not exist, so do check for any exceptions
    filters = []
    if 'scanProcessName' in request.args:
        filters.append(ScanStatus.NAME.like('%' + request.args['scanProcessName'] + '%'))
    if 'scanStatus' in request.args:
        filters.append(ScanStatus.STATUS == request.args['scanStatus'])
    if 'params[beginTime]' in request.args:
        filters.append(ScanStatus.START_TIME >= request.args['params[beginTime]'])
    if 'params[endTime]' in request.args:
        filters.append(ScanStatus.START_TIME <= request.args['params[endTime]'])
        # both are ok
        # scan_date = datetime.strptime(request.args['params[endTime]'], '%Y-%m-%d')
        # filters.append(func.DATE(ScanStatus.START_TIME) <= scan_date.date())

    data = {}
    total = {}
    filters.append(None)
    for value in ScanType.__members__.values():
        data[value.value] = []
        total[value.value] = 0

    for value in ScanType.__members__.values():
        page = request.args.get(f'pageNum[{value.value}]', 1, type=int)
        rows = request.args.get('pageSize', 10, type=int)
        filters[-1] = ScanStatus.TYPE == value.value
        pagination = ScanStatus.query.filter(*filters).paginate(
            page=page, per_page=rows, error_out=False)

        scan_processes = pagination.items
        for scan_process in scan_processes:
            data[value.value].append(scan_process.to_json())
            total[value.value] += 1

    return jsonify({'msg': '操作成功', 'code': 200, "data": data, 'total': total})


@base.route('/system/scan_process', methods=['POST'])
@login_required
def scan_process_start():

    scan_type = ScanType(int(request.json['scanType']))
    config = create_scan_config(request, scan_type)
    task_id = manager.register(config)
    # threading.Thread(target=manager.start, args=(task_id,)).start()
    return jsonify({'code': 200, 'msg': '操作成功'})
