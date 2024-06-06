
import sys
sys.path.append(r"E:\global_ca_monitor")

import json
from app import app, db
from sqlalchemy import MetaData, select
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
from app.utils.exception import UnknownTableError
from collections import Counter
from app.utils.exception import UnknownTableError, ParseError
from app.utils.cert import get_cert_sha256_hex_from_str
from app.parser.cert_parser_base import X509CertParser
from app.parser.cert_parser_extension import SubjectKeyIdentifier, SubjectKeyIdentifierResult

def merge_dict(d1, d2):
    merged_dict = dict(Counter(d1) + Counter(d2))
    return merged_dict

# 将数据转换为适合绘图的 DataFrame
def transform_data(data):
    dfs = []
    for date, ca_data in data.items():
        df = pd.DataFrame(ca_data).T
        df['Date'] = date
        dfs.append(df)
    return pd.concat(dfs)

top_10_ca = ["Let's Encrypt", 'DigiCert Inc', 'Amazon', 'Google Trust Services LLC', 'Sectigo Limited', 'Cloudflare, Inc.', 'GoDaddy.com, Inc.', 'GlobalSign nv-sa', 'Entrust, Inc.', 'Microsoft Corporation']
ca_region_table = {}

with app.app_context():
    cert_input_table_name = "cert_store_raw"

    metadata = MetaData()
    metadata.reflect(bind=db.engine)
    reflected_tables = metadata.tables

    if cert_input_table_name in reflected_tables:
        cert_input_table = reflected_tables[cert_input_table_name]
    else:
        raise UnknownTableError(cert_input_table_name)

    query = cert_input_table.select()
    result_proxy = db.session.execute(query)


    
    rows = result_proxy.fetchall()
    print(len(rows))

    for row in rows:
        try:
            single_cert_analyzer = X509CertParser(row[1])
            cert_parse_result = single_cert_analyzer.parse_cert_base()
        except ParseError:
            continue

        start_date = cert_parse_result.not_valid_before_utc
        if not (start_date.year > 2023 or (start_date.year >= 2023 and start_date.month >= 4)):
            continue

        start_time = start_date.strftime("%Y%m%d")
        country = cert_parse_result.subject_country
        ca_org = cert_parse_result.issuer_org

        if start_time not in ca_region_table:
            ca_region_table[start_time] = {"Others" : {}}

        if ca_org not in top_10_ca:
            ca_org = "Others"
        # print(ca_org)
        if ca_org not in ca_region_table[start_time]:
            ca_region_table[start_time][ca_org] = {}
        # print(row[8])
        # print(ca_region_table[time][ca_org])
        if country not in ca_region_table[start_time][ca_org]:
            ca_region_table[start_time][ca_org][country] = 0

        ca_region_table[start_time][ca_org][country] += 1
        # print(ca_region_table[time][ca_org])

    print(ca_region_table["20240413"])
    # 变换数据
    df = transform_data(ca_region_table)
    
    # 将日期转换为日期时间格式
    df['Date'] = pd.to_datetime(df['Date'])

    # 按 CA 分组绘制图表
    for ca in df.index.unique():
        if ca in top_10_ca:
            ca_df = df.loc[ca]
            print(ca_df)

            ca_df.set_index('Date', inplace=True)
            ca_df = ca_df.divide(ca_df.sum(axis=1), axis=0)  # 计算比例
            print(ca_df)
            
            # 绘制堆叠面积图
            ca_df.plot.area()
            
            # 设置标题和标签
            plt.title(f'Proportion of Certificates Issued by {ca} Over Time')
            plt.xlabel('Date')
            plt.ylabel('Proportion')
            plt.legend(title='Region')
            
            # 显示图表
            plt.show()
