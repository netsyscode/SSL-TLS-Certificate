
import sys
sys.path.append(r"E:\global_ca_monitor")

from app import app, db
from sqlalchemy import MetaData
from app.utils.exception import UnknownTableError

ca_org_name_list = set()
ca_org_issued_cert_dict = {}

with app.app_context():
    table_name = "ca_parse_20240429171346"
    metadata = MetaData()
    metadata.reflect(bind=db.engine)
    reflected_tables = metadata.tables
    if table_name in reflected_tables:
        scan_input_table = reflected_tables[table_name]
    else:
        raise UnknownTableError(table_name)

    query = scan_input_table.select()
    result_proxy = db.session.execute(query)
    cas = result_proxy.fetchall()

    for ca in cas:
        if ca[2] in ca_org_issued_cert_dict:
            ca_org_issued_cert_dict[ca[2]] += ca[4]
        else:
            ca_org_issued_cert_dict[ca[2]] = ca[4]

    for ca_org in ca_org_issued_cert_dict:
        if ca_org_issued_cert_dict[ca_org] >= 100 and ca_org:
            ca_org_name_list.add(ca_org)

    print(ca_org_name_list)
    with open(r"../data/seed_ca_org_name", "w", encoding="utf-8") as file:
        for org_name in sorted(ca_org_name_list):
            if org_name:
                file.write(org_name + "\n")
