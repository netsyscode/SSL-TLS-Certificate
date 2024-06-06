
import sys
sys.path.append(r"E:\global_ca_monitor")

import json
from app import app, db
from sqlalchemy import MetaData
# from app.utils.exception import UnknownTableError

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

ca_table_name = "profiling_digicert,inc."
# ca_table_name = "profiling_let'sencrypt"
# ca_table_name = "profiling_gandi"
# ca_table_name = "profiling_wotruscalimited"
# ca_table_name = "profiling_cloudflare,inc."
# ca_table_name = "profiling_swisssignag"

if __name__ ==  "__main__":
    with app.app_context():
        metadata = MetaData()
        metadata.reflect(bind=db.engine)
        reflected_tables = metadata.tables

        if ca_table_name in reflected_tables:
            ca_table = reflected_tables[ca_table_name]
            query = ca_table.select()
            result_proxy = db.session.execute(query)
            rows = result_proxy.fetchall()

            data = {}
            def update_dict(dict, key):
                if key in dict:
                    dict[key] += 1
                else:
                    dict[key] = 1
            
            for row in rows:
                # update_dict(data, (row[1], row[2], row[3]))
                update_dict(data, row[4])

            # x = [t[0] for t in data]
            # y = [t[1] for t in data]
            # z = [t[2] for t in data]
            # sizes = [data[t] for t in data]
            # print(sizes)

            # # 创建图形和三维坐标系
            # fig = plt.figure()
            # ax = fig.add_subplot(111, projection='3d')

            # # 绘制散点图
            # ax.scatter(x, y, z, s=sizes)

            # # 设置坐标轴标签
            # ax.set_xlabel('X Label')
            # ax.set_ylabel('Y Label')
            # ax.set_zlabel('Z Label')

            # plt.show()

            print(data)

            db = DBSCAN(eps=1, min_samples=5).fit(data) #DBSCAN聚类方法 还有参数，matric = ""距离计算方法
            data['labels'] = db.labels_ #和X同一个维度，labels对应索引序号的值 为她所在簇的序号。若簇编号为-1，表示为噪声，我们把标签放回到data数据集中方便画图
            labels = db.labels_
            raito = data.loc[data['labels']==-1].x.count()/data.x.count() #labels=-1的个数除以总数，计算噪声点个数占总数的比例
            print('噪声比:', format(raito, '.2%'))
            n_clusters_ = len(set(labels)) - (1 if -1 in labels else 0) # 获取分簇的数目
            print('分簇的数目: %d' % n_clusters_)
            print("轮廓系数: %0.3f" % metrics.silhouette_score(data, labels)) #轮廓系数评价聚类的好坏
            sns.relplot(x="x",y="y", hue="labels",data=data)


# def kMedoidsWithKMeansPP(self, distance_matrix):
#     m, n = distance_matrix.shape
#     if self.num_medoids > n:
#         raise Exception('too many medoids')

#     # Use K-Means++ initialization to select initial medoids
#     kmeans = MiniBatchKMeans(n_clusters=self.num_medoids, init='k-means++', n_init=1)
#     kmeans.fit(distance_matrix)

#     return kmeans.labels_

#     M = kmeans.cluster_centers_
#     print(kmeans.cluster_centers_, kmeans.labels_)
#     print(kmeans.inertia_, kmeans.n_features_in_, kmeans.n_iter_)

#     # Rest of the K-Medoids algorithm remains the same
#     # C = {}
#     # for t in range(self.num_iter):
#     #     J = np.argmin(distance_matrix[:, M], axis=1)
#     #     for kappa in range(self.num_medoids):
#     #         C[kappa] = np.where(J == kappa)[0]

#     #     Mnew = np.copy(M)
#     #     for kappa in range(self.num_medoids):
#     #         J = np.mean(distance_matrix[np.ix_(C[kappa], C[kappa])], axis=1)
#     #         j = np.argmin(J)
#     #         Mnew[kappa] = C[kappa][j]
#     #     Mnew.sort()

#     #     if np.array_equal(M, Mnew):
#     #         break
#     #     M = np.copy(Mnew)
#     # else:
#     #     J = np.argmin(distance_matrix[:, M], axis=1)
#     #     for kappa in range(self.num_medoids):
#     #         C[kappa] = np.where(J == kappa)[0]

#     # return M, C
