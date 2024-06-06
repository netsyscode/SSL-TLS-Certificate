
import sys
sys.path.append(r"E:\global_ca_monitor")

import json
from app import app, db
from sqlalchemy import MetaData
# from app.utils.exception import UnknownTableError
from datetime import datetime, timezone

import numpy as np
from sklearn.cluster import DBSCAN
from sklearn import metrics
import seaborn as sns
import pandas as pd
# from sklearn.datasets.samples_generator import make_blobs
from sklearn.preprocessing import StandardScaler
from sklearn.cluster import KMeans, MiniBatchKMeans
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Lock
import numpy as np
import matplotlib.pyplot as plt
from mpl_toolkits.mplot3d import Axes3D
import matplotlib.pyplot as plt
import pandas as pd
from app.utils.exception import UnknownTableError
from app.parser.cert_parser_base import X509CertParser
from app.parser.cert_parser_extension import SubjectKeyIdentifier
from collections import Counter

lock_crl = Lock()
lock_ocsp = Lock()
ca_revoke_result_crl = {}
ca_revoke_result_ocsp = {}

def merge_dict(d1, d2):
    merged_dict = dict(Counter(d1) + Counter(d2))
    return merged_dict

def analyze_crl(rows):
    with app.app_context():
        print(len(rows))
        for row in rows:
            cert_id = row[0]
            status = row[3]

            q = cert_table.select().where(cert_table.c.CERT_ID == cert_id)
            result_proxy = db.session.execute(q)
            result = result_proxy.fetchone()
            ca = result[4]

            with lock_crl:
                if ca not in ca_revoke_result_crl:
                    ca_revoke_result_crl[ca] = {}

                if (cert_id not in ca_revoke_result_crl[ca]) or (status and status > ca_revoke_result_crl[ca][cert_id]):
                    ca_revoke_result_crl[ca][cert_id] = status


def analyze_ocsp(rows):
    with app.app_context():
        print(len(rows))
        for row in rows:
            cert_id = row[0]
            status = row[4]

            q = cert_table.select().where(cert_table.c.CERT_ID == cert_id)
            result = db.session.execute(q).fetchone()
            ca = result[4]

            with lock_ocsp:
                if ca not in ca_revoke_result_ocsp:
                    ca_revoke_result_ocsp[ca] = {}

                if (cert_id not in ca_revoke_result_ocsp[ca]) or (status and status < ca_revoke_result_ocsp[ca][cert_id]):
                    ca_revoke_result_ocsp[ca][cert_id] = status


cert_crl_table_name = "cert_revocation_status_crl"
cert_ocsp_table_name = "cert_revocation_status_ocsp"
cert_table_name = "cert_store_content"

with app.app_context():
    metadata = MetaData()
    metadata.reflect(bind=db.engine)
    reflected_tables = metadata.tables

    if cert_crl_table_name in reflected_tables:
        cert_crl_table = reflected_tables[cert_crl_table_name]
    else:
        raise UnknownTableError(cert_crl_table_name)

    if cert_ocsp_table_name in reflected_tables:
        cert_ocsp_table = reflected_tables[cert_ocsp_table_name]
    else:
        raise UnknownTableError(cert_ocsp_table_name)

    if cert_table_name in reflected_tables:
        cert_table = reflected_tables[cert_table_name]
    else:
        raise UnknownTableError(cert_table_name)
    

    query = cert_crl_table.select()
    result_proxy = db.session.execute(query)

    with ThreadPoolExecutor(max_workers=10) as executor:
        while True:
            rows = result_proxy.fetchmany(10000)
            if not rows:
                break
            executor.submit(analyze_crl, rows)
        executor.shutdown(wait=True)

# #######################################

    query = cert_ocsp_table.select()
    result_proxy = db.session.execute(query)

    with ThreadPoolExecutor(max_workers=10) as executor:
        while True:
            rows = result_proxy.fetchmany(10000)
            if not rows:
                break
            executor.submit(analyze_ocsp, rows)
        executor.shutdown(wait=True)


    def draw(data):
        # 获取所有状态
        all_statuses = set(status for ca_status in data.values() for status in ca_status.values())
        all_statuses = sorted(all_statuses)

        # 初始化状态累加字典
        status_accumulation = {status: 0 for status in all_statuses}

        # 累加每个状态的比例
        for ca_status in data.values():
            for status, count in ca_status.items():
                status_accumulation[status] += count

        # 计算状态比例
        total_certificates = sum(status_accumulation.values())
        status_proportions = {status: count / total_certificates for status, count in status_accumulation.items()}

        # 绘制柱状图
        plt.figure(figsize=(10, 6))
        plt.bar(range(len(status_proportions)), status_proportions.values(), align='center', alpha=0.7)

        # 设置横坐标标签
        plt.xticks(range(len(status_proportions)), status_proportions.keys())

        # 设置图形标题和标签
        plt.title('Proportion of Certificate Status by CA')
        plt.xlabel('Status')
        plt.ylabel('Proportion')

        # 显示图例
        plt.legend(['Proportion'])

        # 显示图形
        plt.show()


    draw(ca_revoke_result_crl)
    draw(ca_revoke_result_ocsp)
