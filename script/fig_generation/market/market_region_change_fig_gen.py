
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
        ca_region_table[time] = {}
        for row in rows:
            ca_org = row[2]
            if ca_org in top_10_ca:
                # print(ca_org)
                if ca_org not in ca_region_table[time]:
                    ca_region_table[time][ca_org] = {}
                # print(row[8])
                # print(ca_region_table[time][ca_org])
                ca_region_table[time][ca_org] = merge_dict(ca_region_table[time][ca_org], row[8])
                # print(ca_region_table[time][ca_org])

    # print(ca_region_table["20240413"])
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
