


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

import numpy as np
import matplotlib.pyplot as plt
from mpl_toolkits.mplot3d import Axes3D
import matplotlib.pyplot as plt
import pandas as pd
from app.utils.exception import UnknownTableError, ParseError
from collections import Counter
import math
from app.parser.cert_parser_base import X509CertParser
from app.parser.cert_parser_extension import SubjectKeyIdentifier, SubjectKeyIdentifierResult

def merge_dict(d1, d2):
    merged_dict = dict(Counter(d1) + Counter(d2))
    return merged_dict

ca_market_table = {}
top_10_ca = ["Let's Encrypt", 'DigiCert Inc', 'Amazon', 'Google Trust Services LLC', 'Sectigo Limited', 'Cloudflare, Inc.', 'GoDaddy.com, Inc.', 'GlobalSign nv-sa', 'Entrust, Inc.', 'Microsoft Corporation']
with app.app_context():
    scan_input_table_name = "cert_store_content"
    metadata = MetaData()
    metadata.reflect(bind=db.engine)
    reflected_tables = metadata.tables
    if scan_input_table_name in reflected_tables:
        scan_input_table = reflected_tables[scan_input_table_name]
    else:
        raise UnknownTableError(scan_input_table_name)

    query = scan_input_table.select()
    result_proxy = db.session.execute(query)
    rows = result_proxy.fetchall()
    print(len(rows))

    for row in rows:
        ca_org = row[4]
        start_date : datetime = row[8]
        if not start_date: continue

        if start_date.year > 2023 or (start_date.year >= 2023 and start_date.month >= 4):
            start_date = start_date.strftime("%Y%m%d")

            if start_date not in ca_market_table:
                ca_market_table[start_date] = {}

            # if ca_org in top_10_ca:
            # print(ca_org)
            if ca_org not in ca_market_table[start_date]:
                ca_market_table[start_date][ca_org] = 0
            # print(row[8])
            # print(ca_region_table[time][ca_org])
            ca_market_table[start_date][ca_org] += 1
            # print(ca_region_table[time][ca_org])

    # 将数据转换为适合绘图的 DataFrame
    def transform_data(data):
        df = pd.DataFrame(data).T
        df.index = pd.to_datetime(df.index)
        return df

    # 聚合数据，保留前10个CA，其他合并为 "Other"
    def aggregate_data(df : pd.DataFrame, top_n=10):
        # 计算前10个CA
        top_cas = df.sum().nlargest(top_n).index
        # 将其他CA合并为 "Other"
        df['Other'] = df.drop(columns=top_cas).sum(axis=1)
        # 只保留前10个CA和 "Other"
        df = df[top_cas.to_list() + ['Other']]
        return df

    # 变换和聚合数据
    df = transform_data(ca_market_table)
    df = aggregate_data(df)

    # 计算比例
    df_ratio = df.divide(df.sum(axis=1), axis=0)

    # 绘制堆叠面积图
    ax = df_ratio.plot.area()

    # 设置图表标题和标签
    ax.set_title('Proportion of Certificates Issued by CA Over Time')
    ax.set_xlabel('Date')
    ax.set_ylabel('Proportion')
    ax.legend(bbox_to_anchor=(1.5, 0.5), loc='center right', title='CA')
    plt.tight_layout()

    # 显示图表
    plt.show()
