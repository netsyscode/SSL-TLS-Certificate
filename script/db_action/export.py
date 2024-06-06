
import csv
import sys
sys.path.append(r"E:\global_ca_monitor")

from app import app, db
from sqlalchemy import MetaData

with app.app_context():
    cert_input_table_name = "cert_store_raw"
    metadata = MetaData()
    metadata.reflect(bind=db.engine)
    reflected_tables = metadata.tables
    cert_input_table = reflected_tables[cert_input_table_name]

    query = cert_input_table.select()
    result_proxy = db.session.execute(query)
    rows = result_proxy.fetchall()
    print(len(rows))

    with open("cert_pem_data.csv", "a", newline='') as file:
        writer = csv.writer(file)
        for row in rows:
            writer.writerow([row[0], row[1]])
