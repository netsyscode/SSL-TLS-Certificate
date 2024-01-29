
from ..base import base
from ..models import CertAnalysisStore

from flask import Blueprint, jsonify, request
from flask_login import login_required, current_user

from ..analyzer.analyze import X509CertScanAnalyzer
from ..logger.logger import my_logger

from .. import db
from datetime import datetime
import uuid
from sqlalchemy import select


@base.route('/system/cert_analysis/list', methods=['GET'])
@login_required
def cert_analysis_list():

    my_logger.info(f"{request.args}")
    filters = []
    if 'name' in request.args:
        filters.append(CertAnalysisStore.SCAN_ID.like('%' + request.args['name'] + '%'))
    cert_analysises = CertAnalysisStore.query.filter(*filters)

    my_logger.info(f"{[cert_analysis.to_json() for cert_analysis in cert_analysises]}")
    return jsonify({'msg': '操作成功', 'code': 200, "data": [cert_analysis.to_json() for cert_analysis in cert_analysises]})

