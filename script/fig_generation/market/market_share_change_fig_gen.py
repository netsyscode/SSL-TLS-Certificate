
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

def merge_dict(d1, d2):
    merged_dict = dict(Counter(d1) + Counter(d2))
    return merged_dict

top_10_ca = ["Let's Encrypt", 'DigiCert Inc', 'Amazon', 'Google Trust Services LLC', 'Sectigo Limited', 'Cloudflare, Inc.', 'GoDaddy.com, Inc.', 'GlobalSign nv-sa', 'Entrust, Inc.', 'Microsoft Corporation']
market_share_table = {}

with app.app_context():
    input_table_names = ["ca_parse_20240413155158",
                         "ca_parse_20240423173449",
                         "ca_parse_20240513161811",
                         "ca_parse_20240520155953"]

    metadata = MetaData()
    metadata.reflect(bind=db.engine)
    reflected_tables = metadata.tables

    for input_table_name in input_table_names:
        if input_table_name in reflected_tables:
            input_table = reflected_tables[input_table_name]
        else:
            raise UnknownTableError(input_table_name)

        query = input_table.select()
        result_proxy = db.session.execute(query)
        rows = result_proxy.fetchall()
        print(len(rows))

        time = input_table_name[9:17]
        market_share_table[time] = {}
        for row in rows:
            ca_org = row[2]
            if ca_org not in market_share_table[time]:
                market_share_table[time][ca_org] = 0
            market_share_table[time][ca_org] += row[4]

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

    print(market_share_table["20240513"])
    # 变换和聚合数据
    df = transform_data(market_share_table)
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
