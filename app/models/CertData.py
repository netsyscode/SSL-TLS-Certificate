
from app import db
from datetime import datetime, timezone
from sqlalchemy import MetaData

def generate_cert_data_table(table_name):

    class CertData(db.Model):
        __tablename__ = table_name
        __table_args__ = {'extend_existing': True}
        
        CERT_ID = db.Column(db.String(64, collation='gbk_chinese_ci'), primary_key=True, nullable=False, unique=True, index=True)
        CERT_RAW = db.Column(db.Text, nullable=False)

        def to_json(self):
            return {
                'sha256_id': self.CERT_ID,
                'raw': self.CERT_RAW,
            }
        
        def get_id(self):
            return str(self.__tablename__)

        def __repr__(self):
            return f"<CertData {self.CERT_ID}>"


    metadata = MetaData()
    metadata.reflect(bind=db.engine)

    if table_name not in metadata.tables:
        CertData.__table__.create(db.engine)
        metadata.reflect(bind=db.engine)

    return metadata.tables[table_name]


class CertStoreRaw(db.Model):
    __tablename__ = "CERT_STORE_RAW"
    
    CERT_ID = db.Column(db.String(64, collation='gbk_chinese_ci'), primary_key=True, nullable=False, unique=True, index=True)
    CERT_RAW = db.Column(db.Text, nullable=False)

    def to_json(self):
        return {
            'cert_id': self.CERT_ID,
            'raw': self.CERT_RAW
        }
    
    def get_id(self):
        return str(self.CERT_ID)
    
    def get_raw(self):
        return str(self.CERT_RAW)

    def __repr__(self):
        return f"<CertStoreRaw {self.CERT_ID}>"


class CertStoreContent(db.Model):
    __tablename__ = "CERT_STORE_CONTENT"
    
    CERT_ID = db.Column(db.String(64, collation='gbk_chinese_ci'), db.ForeignKey('CERT_STORE_RAW.CERT_ID'), primary_key=True, nullable=False, unique=True, index=True)
    CERT_TYPE = db.Column(db.Integer, default=0, nullable=False, comment="leaf")
    SUBJECT_CN = db.Column(db.String(512, collation='utf8mb4_unicode_ci'))
    ISSUER_CN = db.Column(db.String(128, collation='utf8mb4_unicode_ci'))
    ISSUER_ORG = db.Column(db.String(128, collation='utf8mb4_unicode_ci'), comment="use issuer org name")
    ISSUER_COUNTRY = db.Column(db.String(16, collation='utf8mb4_unicode_ci'))
    KEY_SIZE = db.Column(db.Integer, nullable=False)
    KEY_TYPE = db.Column(db.Integer, nullable=False)
    NOT_VALID_BEFORE = db.Column(db.DateTime, nullable=False)
    NOT_VALID_AFTER = db.Column(db.DateTime, nullable=False)
    VALIDATION_PERIOD = db.Column(db.Integer, nullable=False)
    FINGERPRINT = db.Column(db.JSON, nullable=False)

    def to_json(self):
        return {
            'cert_id': self.CERT_ID,
            'cert_type': self.CERT_TYPE,
            'subject_cn': self.SUBJECT_CN,
            'issuer_cn': self.ISSUER_CN,
            'issuer_org': self.ISSUER_ORG,
            'issuer_country': self.ISSUER_COUNTRY,
            'key_size': self.KEY_SIZE,
            'key_type': self.KEY_TYPE,
            'not_valid_before_utc': self.NOT_VALID_BEFORE,
            'not_valid_after_utc': self.NOT_VALID_AFTER,
            'validation_period': self.VALIDATION_PERIOD,
            'fingerprint': self.FINGERPRINT
        }

    # def get_raw(self):
    #     return {
    #         'cert_id': self.CERT_ID,
    #         'raw': self.CERT_RAW
    #     }
    
    def get_id(self):
        return str(self.CERT_ID)

    def __repr__(self):
        return f"<CertStoreContent {self.CERT_ID}>"


class CertScanMeta(db.Model):
    __tablename__ = "CERT_SCAN_METADATA"

    CERT_ID = db.Column(db.String(64, collation='gbk_chinese_ci'), db.ForeignKey('CERT_STORE_RAW.CERT_ID'), primary_key=True, nullable=False, index=True)
    SCAN_DATE = db.Column(db.DateTime, primary_key=True, nullable=False, index=True)
    SCAN_DOMAIN = db.Column(db.Text, primary_key=True, index=True)
    SCAN_IP = db.Column(db.Text, primary_key=True, index=True)

    def to_json(self):
        return {
            'cert_id': self.CERT_ID,
            'scan_date': self.SCAN_DATE,
            'scan_domain': self.SCAN_DOMAIN,
            'scan_ip': self.SCAN_IP
        }
    
    def get_id(self):
        return str(self.CERT_ID)

    def __repr__(self):
        return f"<CertScanMeta {self.CERT_ID}>"


class CaCertStore(db.Model):
    __tablename__ = "CA_CERT_STORE"
    
    CERT_ID = db.Column(db.String(64, collation='gbk_chinese_ci'), db.ForeignKey('CERT_STORE_RAW.CERT_ID'), primary_key=True, nullable=False, index=True)
    CERT_RAW = db.Column(db.Text, nullable=False)
    CERT_TYPE = db.Column(db.Integer, default=1, nullable=False)
    CA_COMMON_NAME = db.Column(db.String(128, collation='utf8mb4_unicode_ci'))
    CA_ORG_NAME = db.Column(db.String(128, collation='utf8mb4_unicode_ci'))
    CA_COUNTRY_NAME = db.Column(db.String(16, collation='utf8mb4_unicode_ci'))
    
    def to_json(self):
        return {
            'cert_id': self.CERT_ID,
            'raw': self.CERT_RAW,
            'cert_type' : self.CERT_TYPE,
            'ca_common_name': self.CA_COMMON_NAME,
            'ca_org_name': self.CA_ORG_NAME,
            'ca_country_name': self.CA_COUNTRY_NAME
        }
    
    def get_id(self):
        return str(self.CERT_ID)
    
    def get_raw(self):
        return str(self.CERT_RAW)

    def __repr__(self):
        return f"<CaCertStore {self.CERT_ID}>"


class CaKeyStore(db.Model):
    __tablename__ = "CA_KEY_STORE"
    
    KEY_ID = db.Column(db.String(64, collation='gbk_chinese_ci'), primary_key=True, nullable=False)
    KEY_RAW = db.Column(db.Text, nullable=False)
    KEY_TYPE = db.Column(db.String(32, collation='gbk_chinese_ci'), nullable=False)
    CA_COMMON_NAME = db.Column(db.String(128, collation='utf8mb4_unicode_ci'))
    CA_ORG_NAME = db.Column(db.String(128, collation='utf8mb4_unicode_ci'))
    CA_COUNTRY_NAME = db.Column(db.String(16, collation='utf8mb4_unicode_ci'))
    
    def to_json(self):
        return {
            'key_id': self.KEY_ID,
            'raw': self.KEY_RAW,
            'key_type': self.KEY_TYPE,
            'ca_common_name': self.CA_COMMON_NAME,
            'ca_org_name': self.CA_ORG_NAME,
            'ca_country_name': self.CA_COUNTRY_NAME
        }
    
    def get_id(self):
        return str(self.KEY_ID)
    
    def get_raw(self):
        return str(self.KEY_RAW)

    def __repr__(self):
        return f"<CaKeyStore {self.KEY_ID}>"
