

from ..base import base
from flask import render_template
from flask_login import login_user, logout_user, login_required, \
    current_user
from flask import g, jsonify
from ..models import Resource, Organization, ResourceType
from ..analyzer.cert_analyze import CertScanAnalyzer
from ..logger.logger import my_logger

@base.route('/cert')
def cert_result():
    return render_template('cert.html')

@base.route('/cert/result')
def cert_result_retrive():
    analyzer = CertScanAnalyzer()
    result, error = analyzer.analyzeCertScanResult()
    return jsonify({
        "cert_result" : result,
        "error_result" : error
    })
