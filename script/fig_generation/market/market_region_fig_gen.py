
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
with app.app_context():
    scan_input_table_name = "ca_parse_20000101000000"
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

    ca_region_table = {}
    for row in rows:
        ca_org = row[2]
        if ca_org not in top_10_ca:
            continue
        if ca_org not in ca_region_table:
            ca_region_table[ca_org] = {}

        ca_region_table[ca_org] = merge_dict(ca_region_table[ca_org], row[8])

    # 转换为 DataFrame
    df = pd.DataFrame(ca_region_table)
    print(df)

    # 计算每个CA的总数
    total = df.sum()

    # 计算比例
    df_ratio = df.divide(total, axis=1)

    # 排除列名为None的列
    # df_ratio = df_ratio.drop(columns=[None])

    # 按字母顺序排序CA
    df_ratio = df_ratio.reindex(sorted(df_ratio.columns), axis=1)

    # 绘制堆叠柱状图
    df_ratio.T.plot(kind='bar', stacked=True, legend=False)

    # 添加标题和标签
    # plt.title('Proportion of Certificates Issued by CA')
    plt.xlabel('CA')
    # plt.xticks(rotation=45)  # 旋转横坐标标签

    plt.ylabel('Proportion')
    # plt.legend(title='Region')
    plt.tight_layout()

    # 显示图表
    plt.show()

