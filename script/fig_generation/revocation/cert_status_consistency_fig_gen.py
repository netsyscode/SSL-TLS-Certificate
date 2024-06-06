
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

lock = Lock()
cert_status_track = {}

def merge_dict(d1, d2):
    merged_dict = dict(Counter(d1) + Counter(d2))
    return merged_dict

cert_crl_table_name = "cert_revocation_status_crl"
cert_ocsp_table_name = "cert_revocation_status_ocsp"

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

    query = cert_crl_table.select()
    result_proxy = db.session.execute(query)

    # while True:
    rows = result_proxy.fetchmany(10000)
        # if not rows:
        #     break
    for row in rows:
        cert_id = row[0]
        status = row[3]

        if cert_id not in cert_status_track:
            cert_status_track[cert_id] = {
                "crl" : [],
                "ocsp" : []
            }

        cert_status_track[cert_id]["crl"].append(status)

    query = cert_ocsp_table.select()
    result_proxy = db.session.execute(query)

    # while True:
    rows = result_proxy.fetchmany(10000)
        # if not rows:
        #     break
    for row in rows:
        cert_id = row[0]
        status = row[4]

        if cert_id not in cert_status_track:
            cert_status_track[cert_id] = {
                "crl" : [],
                "ocsp" : []
            }

        cert_status_track[cert_id]["ocsp"].append(status)

    import matplotlib.pyplot as plt
    import numpy as np
    from collections import Counter

    # 计算每个 cert 的 CRL 和 OCSP 状态变化次数
    cert_changes = []
    for cert_status in cert_status_track.values():
        crl_changes = sum([1 for i in range(1, len(cert_status['crl'])) if cert_status['crl'][i] != cert_status['crl'][i - 1]])
        ocsp_changes = sum([1 for i in range(1, len(cert_status['ocsp'])) if cert_status['ocsp'][i] != cert_status['ocsp'][i - 1]])
        cert_changes.append((crl_changes, ocsp_changes))

    # 统计每个 cert 的变化次数的出现次数
    crl_changes_counter = Counter([change[0] for change in cert_changes])
    ocsp_changes_counter = Counter([change[1] for change in cert_changes])

    # 计算 CDF
    total_certs = len(cert_changes)
    crl_cdf = np.cumsum(sorted(list(crl_changes_counter.items())))
    ocsp_cdf = np.cumsum(sorted(list(ocsp_changes_counter.items())))

    # 绘制 CDF 曲线
    plt.plot(crl_cdf[:, 0], crl_cdf[:, 1] / total_certs, label='CRL', marker='o', linestyle='-')
    plt.plot(ocsp_cdf[:, 0], ocsp_cdf[:, 1] / total_certs, label='OCSP', marker='o', linestyle='-')

    # 设置图例、标题和标签
    plt.legend()
    plt.title('CDF of Changes in CRL and OCSP Statuses')
    plt.xlabel('Number of Changes')
    plt.ylabel('CDF')

    # 显示图形
    plt.grid(True)
    plt.show()
