
'''
    MySQL Model for Scan Process
'''

from app import db
from datetime import datetime


class ScanProcess(db.Model):
    __tablename__ = 'SCAN_PROCESS'

    ID = db.Column(db.String(36), primary_key=True, nullable=False, unique=True, index=True)
    CREATEDATETIME = db.Column(db.DateTime, index=True, default=datetime.now)
    TYPE = db.Column(db.String(20, collation='gbk_chinese_ci'))
    NAME = db.Column(db.String(20, collation='gbk_chinese_ci'), nullable=False)
    START_TIME = db.Column(db.DateTime, index=True, default=datetime.now)
    END_TIME = db.Column(db.DateTime)
    SCAN_DATA_TABLE = db.Column(db.String(32, collation='gbk_chinese_ci'))
    CERT_STORE_TABLE = db.Column(db.String(32, collation='gbk_chinese_ci'))
    STATUS = db.Column(db.String(10, collation='gbk_chinese_ci'))
    SCAN_TIME = db.Column(db.Integer, default=0)
    SCANNED_DOMIANS = db.Column(db.Integer, default=0)
    SUCCESSES = db.Column(db.Integer, default=0)
    ERRORS = db.Column(db.Integer, default=0)
    SCANNED_CERTS = db.Column(db.Integer, default=0)

    def to_json(self):
        return {
            # 'scanProcessID': self.ID,
            # 'scanType' : self.TYPE,
            # 'createTime': self.CREATEDATETIME,
            'name' : self.NAME,
            'startTime' : self.START_TIME,
            "scan_time" : self.SCAN_TIME,
            'endTime': self.END_TIME,
            # 'scanDataTable' : self.SCAN_DATA_TABLE,
            # 'certStoreTable' : self.CERT_STORE_TABLE,
            'status': self.STATUS,
            "scanned_domains" : self.SCANNED_DOMIANS,
            "successes" : self.SUCCESSES,
            "errors" : self.ERRORS,
            "scanned_certs" : self.SCANNED_CERTS
        }
    
    def get_id(self):
        return str(self.ID)

    def __repr__(self):
        return f"<ScanProcess {self.NAME}>"
