
from app import db
from datetime import datetime


class CaAnalysisStore(db.Model):
    __tablename__ = "CA_ANALYSIS_STORE"

    SCAN_ID = db.Column(db.String(36), primary_key=True, nullable=False, unique=True, index=True)
    # SCANCREATEDATETIME = db.Column(db.DateTime, index=True)
    # SCANCREATEDATETIME = db.Column(db.String(16, primary_key=True, nullable=False, unique=True, index=True, default=""))
    SCANNED_CA_NUM = db.Column(db.Integer, default=0)
    CA_DATA_TABLE = db.Column(db.String(32, collation='gbk_chinese_ci'))

    def to_json(self):
        return {
            'scan_id': self.SCAN_ID,
            'scanned_ca_num': self.SCANNED_CA_NUM,
            'ca_data_table': self.CA_DATA_TABLE,
        }
    
    def get_id(self):
        return str(self.SCAN_ID)

    def __repr__(self):
        return f"<CertAnalysisStore {self.SCAN_ID}>"
