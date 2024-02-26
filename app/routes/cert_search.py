
from ..base import base
from ..models import CertStoreContent, CertScanMeta, CertStoreRaw
from flask import Blueprint, jsonify, request
from flask_login import login_required, current_user
from sqlalchemy import func, union
from flask_sqlalchemy.model import Query

import threading
from datetime import datetime
from ..scanner.scan_manager import manager, ScanConfig, ScanType
from ..logger.logger import my_logger


@base.route('/system/cert_search/list', methods=['GET'])
@login_required
def cert_search_list():
    my_logger.info(f"{request.args}")

    filters = []
    if 'certID' in request.args:
        filters.append(CertStoreContent.CERT_ID == request.args['certID'])
    if 'certDomain' in request.args:
        # filters.append(CertStoreContent.SUBJECT_DOMAIN == request.args['certDomain'])
        filters.append(CertStoreContent.SUBJECT_DOMAIN.like('%' + request.args['certDomain'] + '%'))

    if 'params[beginNotValidBefore]' in request.args and 'params[endNotValidBefore]' in request.args:
        filters.append(CertStoreContent.NOT_VALID_BEFORE >= request.args['params[beginNotValidBefore]'])
        filters.append(CertStoreContent.NOT_VALID_BEFORE <= request.args['params[endNotValidBefore]'])
    if 'params[beginNotValidAfter]' in request.args and 'params[beginNotValidAfter]' in request.args:
        filters.append(CertStoreContent.NOT_VALID_AFTER >= request.args['params[beginNotValidAfter]'])
        filters.append(CertStoreContent.NOT_VALID_AFTER <= request.args['params[beginNotValidAfter]'])

    # combined_query : Query
    # combined_query = union(cert_store_query, cert_scan_query)

    page = request.args.get('pageNum', 1, type=int)
    rows = request.args.get('pageSize', 30, type=int)
    pagination = CertStoreContent.query.filter(*filters).paginate(
        page=page, per_page=rows, error_out=False)
    search_certs = pagination.items

    return jsonify({'msg': '操作成功', 'code': 200, "data": [search_cert.to_json() for search_cert in search_certs], "total" : pagination.total})


@base.route('/system/cert_view/<cert_id>', methods=['GET'])
@login_required
def get_cert_info(cert_id):

    cert_raw = CertStoreRaw.query.get(cert_id).get_raw()

    filters = []
    filters.append(CertScanMeta.CERT_ID == cert_id)
    scan_metas = CertStoreContent.query.filter(*filters)

    return jsonify({'code': 200, 'msg': '操作成功', "cert_raw" : cert_raw, "scan_info" : [scan_meta.to_json() for scan_meta in scan_metas]})
