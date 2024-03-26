
import sys
sys.path.append(r"E:\global_ca_monitor")

from app import app, db
from app.analyzer.cert_analyze_base import CertScanAnalyzer
from sqlalchemy import create_engine, MetaData, Table

with app.app_context():

    # 创建一个MetaData对象
    metadata = MetaData()

    # 使用reflect()方法从数据库中读取表结构
    metadata.reflect(bind=db.engine)

    # 获取反射后的表对象
    reflected_tables = metadata.tables

    # 根据特定的表名找到表对象
    # scan_input_table_name = 'cert_store_20240314042813'
    scan_input_table_name = 'cert_store_20240314043706'
    if scan_input_table_name in reflected_tables:
        scan_input_table = reflected_tables[scan_input_table_name]
        analyzer = CertScanAnalyzer("d3c5f601-c8b2-40c2-9479-1809dd1171c2", scan_input_table)
        # analyzer = CertScanAnalyzer("2b60c365-0fa4-492d-bb75-be2130ffb3bc", scan_input_table)
        analyzer.analyze_cert_scan_result()
    else:
        print(f"Table '{scan_input_table_name}' not found in the database.")

