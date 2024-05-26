
from app import db
from sqlalchemy import MetaData

def generate_ca_analysis_table(table_name):

    class CaData(db.Model):
        __tablename__ = table_name
        __table_args__ = {'extend_existing': True}

        CA_ID = db.Column(db.Integer, primary_key=True)
        CA_COMMON_NAME = db.Column(db.String(128, collation='utf8mb4_unicode_ci'), index=True, default=None)
        CA_ORG_NAME = db.Column(db.String(128, collation='utf8mb4_unicode_ci'), index=True, default=None)
        CA_COUNTRY_NAME = db.Column(db.String(16, collation='utf8mb4_unicode_ci'), index=True, default=None)

        # Below are all for issued certificates
        ISSUED_CERT_NUM = db.Column(db.Integer, default=0)
        ISSUED_EXPIRED_NUM = db.Column(db.Integer, default=0)

        ISSUED_SERIAL_LEN_COUNT = db.Column(db.JSON, default={})
        ISSUED_SIG_TYPE_COUNT = db.Column(db.JSON, default={})
        ISSUED_SUBJECT_COUNTRY_COUNT = db.Column(db.JSON, default={})
        ISSUED_CERT_DAY_COUNT = db.Column(db.JSON, default={})
        ISSUED_VALIDITY_PERIOD_COUNT = db.Column(db.JSON, default={})
        ISSUED_KEY_TYPE_COUNT = db.Column(db.JSON, default={})
        ISSUED_KEY_SIZE_COUNT = db.Column(db.JSON, default={})
        ISSUED_BASIC_CONSTRAINTS_COUNT = db.Column(db.JSON, default={})
        ISSUED_KEY_USAGE_COUNT = db.Column(db.JSON, default={})
        ISSUED_EKU_COUNT = db.Column(db.JSON, default={})
        ISSUED_POLICY_COUNT = db.Column(db.JSON, default={})
        
        CRL_POINTS = db.Column(db.JSON, default={})
        OCSP_SERVER = db.Column(db.JSON, default={})
        CA_CERT_SERVER = db.Column(db.JSON, default={})

        def to_json(self):
            return {
                'ca_id': self.CA_ID,
                'ca_common_name': self.CA_COMMON_NAME,
                'ca_org_name': self.CA_ORG_NAME,
                'ca_country_name': self.CA_COUNTRY_NAME,
                'issued_cert_num': self.ISSUED_CERT_NUM,
                'expired_cert_num': self.ISSUED_EXPIRED_NUM,
                'issued_cert_day_count': self.ISSUED_CERT_DAY_COUNT,
                'validation_period_count': self.ISSUED_VALIDITY_PERIOD_COUNT,
                'key_size_count': self.ISSUED_KEY_SIZE_COUNT,
                'key_type_count': self.ISSUED_KEY_TYPE_COUNT,
                'sig_type_count': self.ISSUED_SIG_TYPE_COUNT,
            }
        
        def get_id(self):
            return str(self.__tablename__)

        def __repr__(self):
            return f"<CaAnalysis {self.CA_ID}>"

    metadata = MetaData()
    metadata.reflect(bind=db.engine)

    # Drop table if exists
    if table_name in metadata.tables:
        table = metadata.tables[table_name]
        table.drop(db.engine)

    CaData.__table__.create(db.engine)
    metadata.reflect(bind=db.engine)

    return metadata.tables[table_name]

