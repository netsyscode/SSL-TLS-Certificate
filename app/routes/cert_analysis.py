
from ..blueprint import base
from ..models import CertAnalysisStats

from flask import Blueprint, jsonify, request
from flask_login import login_required, current_user

from ..analyzer.cert_analyze_base import ScanCertAnalyzer
from ..logger.logger import my_logger

from .. import db
from datetime import datetime
import uuid
from sqlalchemy import select


@base.route('/system/cert_analysis/list', methods=['GET'])
@login_required
def cert_analysis_list():

    # my_logger.info(f"{request.args}")
    filters = []
    if 'name' in request.args:
        filters.append(CertAnalysisStats.SCAN_ID.like('%' + request.args['name'] + '%'))
    cert_analysis_stats = CertAnalysisStats.query.filter(*filters)

    return jsonify({'msg': '操作成功', 'code': 200, "data": [cert_analysis_stat.metadata_to_json() for cert_analysis_stat in cert_analysis_stats]})
