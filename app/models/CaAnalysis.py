
from app import db
from datetime import datetime

def generate_ca_analysis_table(table_name):

    class CaAnalysis(db.Model):
        __tablename__ = table_name
        __table_args__ = {'extend_existing': True}

        CA_ID = db.Column(db.Integer, primary_key=True, autoincrement=True)
        CA_SIGNING_CERT = db.Column(db.JSON, default={})

        CA_ISSUER_INFO = db.Column(db.JSON, default={})
        CA_ISSUER_CERT = db.Column(db.JSON, default={})

        CA_COMMON_NAME = db.Column(db.String(128, collation='gbk_chinese_ci'), index=True, default=None)
        CA_ORG_NAME = db.Column(db.String(128, collation='gbk_chinese_ci'), index=True, default=None)
        CA_COUNTRY_NAME = db.Column(db.String(4, collation='gbk_chinese_ci'), index=True, default=None)

        # Below are all for issued certificates
        ISSUED_CERT_NUM = db.Column(db.Integer, default=0)
        EXPIRED_CERT_NUM = db.Column(db.Integer, default=0)

        ISSUED_CERT_DAY_COUNT = db.Column(db.JSON, default={})
        VALIDATION_PERIOD_COUNT = db.Column(db.JSON, default={})

        KEY_SIZE_COUNT = db.Column(db.JSON, default={})
        KEY_TYPE_COUNT = db.Column(db.JSON, default={})
        HASH_TYPE_COUNT = db.Column(db.JSON, default={})


        def to_json(self):
            return {
                'ca_id': self.CA_ID,
                'ca_signing_cert': self.CA_SIGNING_CERT,
                'ca_issuer_info': self.CA_ISSUER_INFO,
                'ca_issuer_cert': self.CA_ISSUER_CERT,
                'ca_common_name': self.CA_COMMON_NAME,
                'ca_org_name': self.CA_ORG_NAME,
                'ca_country_name': self.CA_COUNTRY_NAME,
                'issued_cert_num': self.ISSUED_CERT_NUM,
                'expired_cert_num': self.EXPIRED_CERT_NUM,
                'issued_cert_day_count': self.ISSUED_CERT_DAY_COUNT,
                'validation_period_count': self.VALIDATION_PERIOD_COUNT,
                'key_size_count': self.KEY_SIZE_COUNT,
                'key_type_count': self.KEY_TYPE_COUNT,
                'hash_type_count': self.HASH_TYPE_COUNT,
            }
        
        def get_id(self):
            return str(self.__tablename__)

        def __repr__(self):
            return f"<CaAnalysis {self.CA_ID}>"

    CertAnalysis.__table__.create(db.engine)
    return db.Model.metadata.tables[table_name]
