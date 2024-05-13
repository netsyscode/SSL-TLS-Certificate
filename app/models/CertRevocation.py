
from app import db
from datetime import datetime, timezone


class CertRevocationStatusOCSP(db.Model):
    __tablename__ = "CERT_REVOCATION_STATUS_OCSP"

    CERT_ID = db.Column(db.String(64, collation='gbk_chinese_ci'), db.ForeignKey('CERT_STORE_RAW.CERT_ID'), primary_key=True, nullable=False, index=True)
    CHECK_TIME = db.Column(db.DateTime, primary_key=True, nullable=False)
    AIA_LOCATION = db.Column(db.Text)
    REVOCATION_STATUS = db.Column(db.Integer, default=0, nullable=False)

    def to_json(self):
        return {
            'cert_id': self.CERT_ID,
            'check_time': self.CHECK_TIME,
            'aia_location': self.AIA_LOCATION,
            'revocation_status' : self.REVOCATION_STATUS
        }
    
    def get_id(self):
        return str(self.CERT_ID)

    def __repr__(self):
        return f"<CertRevocationStatusOCSP {self.CERT_ID}>"

