
from app import db, app
from ..parser.cert_parser_base import X509CertParser, X509ParsedInfo
from ..parser.cert_parser_extension import (
    AIAResult,
    KeyUsageResult,
    CertPoliciesResult,
    BasicConstraintsResult,
    ExtendedKeyUsageResult,
    CRLResult,
    AuthorityKeyIdentifierResult,
    SubjectKeyIdentifierResult,
    PrecertificateSignedCertificateTimestampsResult
)

from ..utils.exception import ParseError, UnknownTableError
from ..models.CaProfiling import generate_ca_fp_table
from ..parser.cert_parser_base import X509ParsedInfo
from ..logger.logger import my_logger

from typing import Dict, List, Tuple
from threading import Lock
from sqlalchemy import MetaData, Table
from sqlalchemy.dialects.mysql import insert
from sklearn.preprocessing import LabelEncoder

ca_org_list = []
# Read CA Org Name from file
with open(r"E:/global_ca_monitor/tool/domain_collector/data/seed_ca_org_name", "r", encoding='utf-8') as file:
    for line in file:
        ca_org_list.append(line.strip())
print(ca_org_list)

class CaSignedCertProfilingAnalyzer:

    def __init__(self) -> None:
        self.fp_dict_lock= Lock()
        self.fp_dict_by_ca_and_time : Dict[Tuple[str, str, str], List[int]]= {}
        for ca_org in ca_org_list:
            generate_ca_fp_table(ca_org)

    def analyze_ca_fp_track(self, rows):
        for row in rows:
            # Get CA and issuing time
            ca_org = row[4]
            issuer = (row[3], row[4], row[5])
            issuing_time = row[8]
            fp = row[-1]

            with self.fp_dict_lock:
                if issuer not in self.fp_dict_by_ca_and_time:
                    self.fp_dict_by_ca_and_time[issuer] = {}
                if issuing_time not in self.fp_dict_by_ca_and_time[issuer]:
                    self.fp_dict_by_ca_and_time[issuer][issuing_time] = []
                self.fp_dict_by_ca_and_time[issuer][issuing_time].append(fp)
        self.sync_update_info()

    def sync_update_info(self):
        with app.app_context():
            with self.fp_dict_lock:
                metadata = MetaData()
                metadata.reflect(bind=db.engine)

                for ca_org in self.fp_dict_by_ca_and_time:
                    if ca_org[1] not in ca_org_list: continue
                    ca_org_name = ca_org[1].replace(" ", "").replace("'","").lower()
                    table_name = f"fp_{ca_org_name}"

                    if table_name in metadata.tables:
                        table = metadata.tables[table_name]
                    else:
                        table = generate_ca_fp_table(ca_org[1])

                    fp_data = []
                    for time, fp in self.fp_dict_by_ca_and_time[ca_org].items():
                        fp_data.append({
                            'ISSUER_CN' : ca_org[0],
                            'ISSUER_ORG' : ca_org[1],
                            'ISSUER_COUNTRY' : ca_org[2],
                            'ISSUING_TIME' : time,
                            'FINGERPRINT' : fp
                        })
                    insert_ca_fp_data_statement = insert(table).values(fp_data).prefix_with('IGNORE')
                    db.session.execute(insert_ca_fp_data_statement)
                    db.session.commit()

                print("Done")
                self.fp_dict_by_ca_and_time = {}
