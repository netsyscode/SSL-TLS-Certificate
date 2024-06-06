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

with app.app_context():

    scan_input_table_name = "fp_letsencrypt"
    scan_input_table_name = "fp_sectigolimited"
    scan_input_table_name = "fp_wotruscalimited"
    scan_input_table_name = "fp_digicertinc"
    # scan_input_table_name = "fp_digicert,inc."
    scan_input_table_name = "fp_appleinc."
    scan_input_table_name = "fp_cloudflare,inc."
    scan_input_table_name = "fp_googletrustservicesllc"
    scan_input_table_name = "fp_internet2"
    # scan_input_table_name = "fp_swisssignag"
    # scan_input_table_name = "fp_microsoftcorporation"
    # scan_input_table_name = "fp_amazon"
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

    query_result = []
    for row in rows:
        time : datetime = row[4]
        if time.year > 2023 or (time.year >= 2023 and time.month >= 4):
            time = time.strftime("%Y%m")
            for fp in row[5]:
                fp[3] = int(fp[3] / 100)
                query_result.append((time, str(fp)))

    # 将数据转换为 DataFrame
    data = pd.DataFrame([(item[0], item[1]) for item in query_result], columns=['timestamp', 'value'])

    # 对数据进行处理，计算占比
    data['count'] = 1  # 添加一列，用于计数
    data = data.groupby(['timestamp', 'value']).count().reset_index()  # 根据时间和值进行分组统计
    data['total'] = data.groupby('timestamp')['count'].transform('sum')  # 计算每个时间点的总数
    data['percentage'] = data['count'] / data['total']  # 计算占比

    # 创建包含所有时间点的完整日期范围
    start_date = datetime(2023,4,1)
    end_date = datetime(2024,6,1)
    all_dates = pd.date_range(start_date, end_date, freq='M').strftime('%Y%m')

    # 创建一个包含所有可能值的 DataFrame
    all_data = pd.DataFrame([(date, value) for date in all_dates for value in data['value'].unique()], columns=['timestamp', 'value'])

    # 将原始数据与完整日期范围的数据合并
    data = pd.merge(all_data, data, on=['timestamp', 'value'], how='left')

    # 将缺失的百分比填充为0
    data['percentage'].fillna(0, inplace=True)

    # 聚合小占比类别
    threshold = 0.01  # 定义最小占比阈值
    data['value'] = np.where(data['percentage'] < threshold, 'Other', data['value'])

    # 使用 pivot_table 将数据转换为矩阵形式
    pivot_data = data.pivot_table(index='timestamp', columns='value', values='percentage', fill_value=0)

    # 绘制累计面积图
    fig, ax = plt.subplots(figsize=(10, 5))  # 放大图像尺寸
    labels = [f'fp{i+1}' for i in range(len(pivot_data.columns))]
    ax.stackplot(pivot_data.index, pivot_data.T, labels=labels, alpha=0.8)
    ax.legend(loc='upper right')
    plt.xlabel('Timestamp')
    plt.ylabel('Percentage')
    plt.ylim(0, 1)  # 确保纵轴范围是0到1
    plt.xticks(rotation=45)
    plt.title(f'{scan_input_table_name} FP Percentage Change Over Time')
    plt.tight_layout()  # 调整布局，使图例不会超出图的边界
    plt.show()
