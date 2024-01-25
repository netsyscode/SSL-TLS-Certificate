
from ..base import base
from flask import render_template
from flask_login import login_user, logout_user, login_required, \
    current_user
from flask import g, jsonify
from ..models import Resource, Organization, ResourceType
from ..scanner.scan_base import ScanConfig, ScanType
from ..scanner.scan_manager import manager
from ..logger.logger import my_logger
import threading
import time

@base.route('/system/scan', methods=['POST'])
def start_scan():
    my_logger.info(f"Registering scan with type SCAN_BY_DOMAIN...")
    config = ScanConfig(ScanType.SCAN_BY_DOMAIN)
    task_id = manager.register(config)
    threading.Thread(target=manager.run, args=(task_id,)).start()
    return jsonify({'taskId': task_id})

@base.route('/system/scan_status', methods=['GET'])
def scan_status():
    return render_template("scan_status.html")

# @base.route('/system/scan_status/<task_id>', methods=['POST'])
# def scan_status_per_task(task_id):
#     status = manager.get_status(task_id)
#     return status

@base.route('/system/scan_status', methods=['POST'])
def scan_status_per_task():
    status = manager.get_all_status()
    my_logger.info(f"{status}")
    return jsonify(status)
