
import sys
sys.path.append(r"E:\global_ca_monitor")

import json
from app import app, db
from sqlalchemy import MetaData
from app.utils.exception import UnknownTableError
from src.retrieve_ca_domain_from_cert import retrieve_ca_owned_domains_from_cert, get_domain
from src.recursive_collect import retrieve_domain

cert_table_name = "cert_store_raw"
ca_table_name = "ca_parse_20240429171346"
ca_org_list = []

if __name__ ==  "__main__":
    with app.app_context():
        metadata = MetaData()
        metadata.reflect(bind=db.engine)
        reflected_tables = metadata.tables

        # Read CA Org Name from file
        with open(r"data/seed_ca_org_name", "r", encoding='utf-8') as file:
            for line in file:
                ca_org_list.append(line.strip())

        # Retrieve domain from cert by Org Name
        if cert_table_name in reflected_tables:
            result = retrieve_ca_owned_domains_from_cert(reflected_tables[cert_table_name], ca_org_list)
        else:
            raise UnknownTableError(cert_table_name)

        # Add seed domains from human crawl
        with open(r"data/seed_ca_domain", "r", encoding='utf-8') as file:
            ca_org = None
            for line in file:
                if line.startswith("//"):
                    ca_org = line[2:].strip()
                else:
                    domain = get_domain(line.strip())
                    result[ca_org].add(domain)

        # Add crl/ocsp/issuer domain from ca_analysis
        if ca_table_name in reflected_tables:
            ca_table = reflected_tables[ca_table_name]
            query = ca_table.select()
            result_proxy = db.session.execute(query)
            cas = result_proxy.fetchall()

            for ca in cas:
                if ca[2] in ca_org_list:
                    for url in ca[-1] + ca[-2] + ca[-3]:
                        domain = get_domain(url)
                        result[ca[2]].add(domain)
        else:
            raise UnknownTableError(ca_table_name)

        # Try to collect cert with current domain set
        for ca in result:
            result[ca] = retrieve_domain(ca, result[ca])

        # dump result
        for key in result:
            result[key] = list(result[key])
            if "" in result[key]:
                result[key].remove("")

        with open(r"data/one_turn/result.json", "w", encoding='utf-8') as file:
            json.dump(result, file, indent=4)
