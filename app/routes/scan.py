
from ..base import base
from flask import render_template
from flask_login import login_user, logout_user, login_required, \
    current_user
from flask import g, jsonify
from ..models import Resource, Organization, ResourceType
from ..scanner.scan_manager import ScanConfig, ScanType, manager
import threading
import time

@base.route('/scan', methods=['POST'])
def start_scan():
    config = ScanConfig(ScanType.SCAN_BY_DOMAIN)
    task_id = manager.register(config)
    threading.Thread(target=manager.run, args=(task_id,)).start()
    return jsonify({'taskId': task_id})

@base.route('/scan_status/<task_id>')
def scan_status(task_id):
    status = manager.get_status(task_id)
    return jsonify({'status': status})
