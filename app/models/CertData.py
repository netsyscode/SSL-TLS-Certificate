
from app import db
from datetime import datetime

def generate_cert_data_table(table_name):

    class CertData(db.Model):
        __tablename__ = table_name
        __table_args__ = {'extend_existing': True}
        
        SHA256_ID = db.Column(db.String(64, collation='gbk_chinese_ci'), primary_key=True, nullable=False, unique=True, index=True, default=None)
        RAW_PEM = db.Column(db.Text, nullable=False)
        # 0 : Leaf
        # 1 : Inter
        # 2 : Root
        # TYPE = db.Column(db.Integer, default=0)
        # ISSUER = db.Column(db.String(128, collation='gbk_chinese_ci'))
        # ISSUER_CERT_ID = db.Column(db.String(36, collation='gbk_chinese_ci'))
        # KEY_SIZE = db.Column(db.Integer, nullable=False)
        # KEY_TYPE = db.Column(db.String(8, collation='gbk_chinese_ci'), nullable=False)
        # NOT_VALID_BEFORE = db.Column(db.DateTime)
        # NOT_VALID_AFTER = db.Column(db.DateTime)
        # VALIDATION_PERIOD = db.Column(db.Integer, nullable=False)
        # EXPIRED = db.Column(db.Bool)

        def to_json(self):
            return {
                'sha256_id': self.SHA256_ID,
                'raw': self.RAW_PEM,
                # 'type': self.TYPE,
                # 'issuer': self.ISSUER,
                # 'issuer_cert_id': self.ISSUER_CERT_ID,
                # 'key_size': self.KEY_SIZE,
                # 'key_type': self.KEY_TYPE,
                # 'not_valid_before': self.NOT_VALID_BEFORE,
                # 'not_valid_after': self.NOT_VALID_AFTER,
                # 'validation_period': self.VALIDATION_PERIOD,
                # 'expired': self.EXPIRED,
            }
        
        def get_id(self):
            return str(self.__tablename__)

        def __repr__(self):
            return f"<CertData {self.SHA256_ID}>"

    CertData.__table__.create(db.engine)
    return db.Model.metadata.tables[table_name]
