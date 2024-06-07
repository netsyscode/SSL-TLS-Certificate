
import csv
import sys
sys.path.append(r"E:\global_ca_monitor")

from app import app, db
from sqlalchemy import MetaData

cert_input_table_name = "cert_store_raw"
cert_input_table_name = sys.argv[1]
output_file = "cert_content.csv"
output_file = sys.argv[2]

with app.app_context():
    metadata = MetaData()
    metadata.reflect(bind=db.engine)
    reflected_tables = metadata.tables
    cert_input_table = reflected_tables[cert_input_table_name]

    query = cert_input_table.select()
    result_proxy = db.session.execute(query)
    rows = result_proxy.fetchall()
    print(len(rows))

    with open(output_file, "w", newline='', encoding='utf-8') as file:
        writer = csv.writer(file)
        for row in rows:
            writer.writerow(row)
