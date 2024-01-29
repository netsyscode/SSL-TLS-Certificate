
from app import db
from datetime import datetime

def generate_scan_data_table(table_name):

    class ScanData(db.Model):
        __tablename__ = table_name
        __table_args__ = {'extend_existing': True}

        # RANK = db.Column(db.Integer, primary_key=True, nullable=False, unique=True, index=True)
        RANK = db.Column(db.Integer, primary_key=True, nullable=False, index=True)
        DOMAIN = db.Column(db.String(128, collation='gbk_chinese_ci'), nullable=False)
        ERROR_MSG = db.Column(db.Text, default=None)
        RECEIVED_CERTS = db.Column(db.JSON, default=[])

        def to_json(self):
            return {
                'rank' : self.RANK,
                "domain" : self.DOMAIN,
                "error_msg" : self.ERROR_MSG,
                "received_certs" : self.RECEIVED_CERTS
            }
        
        def get_id(self):
            return str(self.__tablename__)

        def __repr__(self):
            return f"<ScanData {self.RANK}>"

    ScanData.__table__.create(db.engine)
    return db.Model.metadata.tables[table_name]
