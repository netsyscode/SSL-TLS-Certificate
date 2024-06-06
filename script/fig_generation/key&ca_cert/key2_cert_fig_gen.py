
import sys
sys.path.append(r"E:\global_ca_monitor")

from app import app, db
from sqlalchemy import MetaData
import numpy as np
import matplotlib.pyplot as plt
from app.utils.exception import UnknownTableError, ParseError
from app.utils.cert import get_cert_sha256_hex_from_str
from app.parser.cert_parser_base import X509CertParser
from app.parser.cert_parser_extension import SubjectKeyIdentifier, SubjectKeyIdentifierResult
from collections import Counter

def merge_dict(d1, d2):
    merged_dict = dict(Counter(d1) + Counter(d2))
    return merged_dict


ca_key_table = {}
with app.app_context():
    ca_cert_input_table_name = "ca_cert_store"
    key_input_table_name = "ca_key_store"
    cert_input_table_name = "cert_store_raw"

    metadata = MetaData()
    metadata.reflect(bind=db.engine)
    reflected_tables = metadata.tables

    if ca_cert_input_table_name in reflected_tables:
        ca_cert_input_table = reflected_tables[ca_cert_input_table_name]
    else:
        raise UnknownTableError(ca_cert_input_table_name)

    if key_input_table_name in reflected_tables:
        key_input_table = reflected_tables[key_input_table_name]
    else:
        raise UnknownTableError(key_input_table_name)

    query = key_input_table.select()
    result_proxy = db.session.execute(query)
    rows = result_proxy.fetchall()
    print(len(rows))

    for row in rows:
        key_id = row[0]
        ca_org = row[4]
        if ca_org not in ca_key_table:
            ca_key_table[ca_org] = {}

        if key_id:
            ca_key_table[ca_org][key_id] = 0

    query = ca_cert_input_table.select()
    result_proxy = db.session.execute(query)
    rows = result_proxy.fetchall()
    print(len(rows))

    for row in rows:
        try:
            single_cert_analyzer = X509CertParser(row[1])
            cert_parse_result = single_cert_analyzer.parse_cert_base()
        except ParseError:
            continue

        key_id : SubjectKeyIdentifierResult = single_cert_analyzer.extension_parser.get_result_by_type(SubjectKeyIdentifierResult)
        if key_id:
            key_id = key_id.key_identifier
            ca_key_table[row[4]][key_id] += 1
        else:
            key_id = get_cert_sha256_hex_from_str(cert_parse_result.pub_key_raw)
            ca_key_table[row[4]][key_id] += 1

    # print(ca_key_table)
    # 提取所有密钥的使用次数
    usage_counts = []
    for ca, keys in ca_key_table.items():
        usage_counts.extend(keys.values())

    # 转换为 NumPy 数组并排序
    usage_counts = np.array(usage_counts)
    usage_counts.sort()
    print(usage_counts)

    # 计算CDF
    cdf = np.arange(1, len(usage_counts)+1) / len(usage_counts)

    # 绘制图形
    plt.figure(figsize=(10, 6))
    plt.plot(usage_counts, cdf, linestyle='-', color='r')

    # 设置对数坐标
    plt.xscale('log')

    # 设置图形标题和标签
    plt.title('CDF of Key Usage Counts')
    plt.xlabel('Key Usage Counts (log scale)')
    plt.ylabel('CDF')

    # 显示网格
    plt.grid(True)

    # 显示图形
    plt.show()
    