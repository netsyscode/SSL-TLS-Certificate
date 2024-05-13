
from app import db
from datetime import datetime, timezone

def generate_scan_data_table(table_name):

    class ScanData(db.Model):
        __tablename__ = table_name
        __table_args__ = {'extend_existing': True}

        # SCAN_TIME = db.Column(db.DateTime, db.ForeignKey('SCAN_STATUS.START_TIME'), index=True, primary_key=True, nullable=False)
        SCAN_TIME = db.Column(db.DateTime, index=True, primary_key=True, nullable=False)
        DOMAIN = db.Column(db.Text, primary_key=True, index=True)
        IP = db.Column(db.String(128), primary_key=True, index=True, nullable=True)
        ERROR_MSG = db.Column(db.Text, default=None)
        RECEIVED_CERTS = db.Column(db.JSON, default=[])
        TLS_VERSION = db.Column(db.Integer)
        TLS_CIPHER = db.Column(db.String(128))

        def to_json(self):
            return {
                'scan_time' : self.SCAN_TIME,
                "domain" : self.DOMAIN,
                "ip" : self.IP,
                "error_msg" : self.ERROR_MSG,
                "received_certs" : self.RECEIVED_CERTS
            }
        
        def get_id(self):
            return str(self.__tablename__)

        def __repr__(self):
            return f"<ScanData {self.SCAN_TIME}>"

    ScanData.__table__.create(db.engine)
    return db.Model.metadata.tables[table_name]

class ScanData(db.Model):
    __tablename__ = 'SCAN_DATA'
    __table_args__ = {'extend_existing': True}

    # SCAN_TIME = db.Column(db.DateTime, db.ForeignKey('SCAN_STATUS.START_TIME'), index=True, primary_key=True, nullable=False)
    SCAN_TIME = db.Column(db.DateTime, index=True, primary_key=True, nullable=False)
    DOMAIN = db.Column(db.Text, primary_key=True, index=True)
    IP = db.Column(db.String(128), primary_key=True, index=True, nullable=True)
    ERROR_MSG = db.Column(db.Text, default=None)
    RECEIVED_CERTS = db.Column(db.JSON, default=[])
    TLS_VERSION = db.Column(db.Integer)
    TLS_CIPHER = db.Column(db.String(128))

    def to_json(self):
        return {
            'scan_time' : self.SCAN_TIME,
            "domain" : self.DOMAIN,
            "ip" : self.IP,
            "error_msg" : self.ERROR_MSG,
            "received_certs" : self.RECEIVED_CERTS,
            "tls_version" : self.TLS_VERSION,
            "tls_cipher" : self.TLS_CIPHER
        }
    
    def get_id(self):
        return str(self.__tablename__)

    def __repr__(self):
        return f"<ScanData {self.SCAN_TIME}>"
