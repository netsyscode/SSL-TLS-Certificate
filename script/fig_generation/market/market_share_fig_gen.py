
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
from app.utils.exception import UnknownTableError
from collections import Counter
import math

def merge_dict(d1, d2):
    merged_dict = dict(Counter(d1) + Counter(d2))
    return merged_dict

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

    ca_market_table = {}
    for row in rows:
        ca_org = row[2]
        if ca_org not in ca_market_table:
            ca_market_table[ca_org] = 0

        ca_market_table[ca_org] += row[4]

    # 中文显示设置
    plt.rcParams['font.sans-serif'] = ['SimHei']  # 设置中文显示的字体为黑体
    plt.rcParams['axes.unicode_minus'] = False  # 解决负号'-'显示为方块的问题

    # 排序并提取前10个CA
    sorted_ca = sorted(ca_market_table.items(), key=lambda x: x[1], reverse=True)
    top_10 = sorted_ca[:10]
    others = sorted_ca[10:]

    # 计算“Others”的数量
    others_sum = sum([item[1] for item in others])

    # 前10个CA和“Others”的数据
    labels = [item[0] for item in top_10] + ["Others"]
    sizes = [item[1] for item in top_10] + [others_sum]

    # 调整饼图大小
    plt.figure(figsize=(10, 8))

    # 生成饼图
    explode = (0, 0, 0, 0, 0, 0, 0.1, 0.2, 0.3, 0.4, 0.2)
    wedges, texts, autotexts = plt.pie(sizes, labels=labels, autopct='%1.1f%%', startangle=140, pctdistance=0.85, textprops={'fontsize': 10}, explode=explode)

    # 添加标题
    plt.suptitle('前10个CA签发证书的市场占比', fontsize=16, y=-0.92)

    # 创建图例
    plt.legend(wedges, labels, title="标签", loc="center left", bbox_to_anchor=(1, 0, 0.5, 1))

    # 显示图表
    plt.show()
    print(top_10)