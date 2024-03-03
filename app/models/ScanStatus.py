
'''
    MySQL Model for Scan Status
'''

from app import db
from datetime import datetime

class ScanStatus(db.Model):
    __tablename__ = 'SCAN_STATUS'
    # __table_args__ = (
    #     db.PrimaryKeyConstraint('ID', 'START_TIME'),
    # )

    ID = db.Column(db.String(36), primary_key=True, nullable=False, unique=True, index=True)
    NAME = db.Column(db.String(20, collation='gbk_chinese_ci'), nullable=False)
    TYPE = db.Column(db.Integer, default=0, comment="see SYS_DICT_DATA")
    START_TIME = db.Column(db.DateTime, index=True, default=datetime.now)
    END_TIME = db.Column(db.DateTime, default=None)
    STATUS = db.Column(db.Integer, default=0, comment="see SYS_DICT_DATA")
    SCAN_TIME_IN_SECONDS = db.Column(db.Integer, default=0)
    SCANNED_DOMIANS = db.Column(db.Integer, default=0)
    SUCCESSES = db.Column(db.Integer, default=0)
    ERRORS = db.Column(db.Integer, default=0)
    SCANNED_CERTS = db.Column(db.Integer, default=0)
    NUM_THREADS = db.Column(db.Integer, default=0)
    CERT_STORE_TABLE = db.Column(db.String(32, collation='gbk_chinese_ci'))

    def to_json(self):
        return {
            'id': self.ID,
            'name' : self.NAME,
            'scanType' : self.TYPE,
            'startTime' : self.START_TIME,
            'endTime': self.END_TIME,
            "scan_time_in_seconds" : self.SCAN_TIME_IN_SECONDS,
            'status': self.STATUS,
            "scanned_domains" : self.SCANNED_DOMIANS,
            "successes" : self.SUCCESSES,
            "errors" : self.ERRORS,
            "scanned_certs" : self.SCANNED_CERTS,
            "num_threads" : self.NUM_THREADS
        }

    def get_id(self):
        return str(self.ID)

    def __repr__(self):
        return f"<ScanStatus {self.NAME}>"
    