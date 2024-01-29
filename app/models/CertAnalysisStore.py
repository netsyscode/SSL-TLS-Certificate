
from app import db
from datetime import datetime


class CertAnalysisStore(db.Model):
    __tablename__ = "CERT_ANALYSIS_STORE"

    SCAN_ID = db.Column(db.String(36), primary_key=True, nullable=False, unique=True, index=True)
    # SCANCREATEDATETIME = db.Column(db.DateTime, index=True)
    # SCANCREATEDATETIME = db.Column(db.String(16, primary_key=True, nullable=False, unique=True, index=True, default=""))
    SCANNED_CERT_NUM = db.Column(db.Integer, default=0)
    ISSUER_COUNT = db.Column(db.JSON, default={})
    KEY_SIZE_COUNT =  db.Column(db.JSON, default={})
    KEY_TYPE_COUNT =  db.Column(db.JSON, default={})
    VALIDATION_PERIOD_COUNT = db.Column(db.JSON, default={})
    EXPIRED_PERCENT = db.Column(db.Float, default=0)

    def to_json(self):
        return {
            "scan_id": self.SCAN_ID,
            # "scan_created_datetime": self.SCANCREATEDATETIME,
            "scanned_cert_num": self.SCANNED_CERT_NUM,
            "issuer_count": self.ISSUER_COUNT,
            "key_size_count": self.KEY_SIZE_COUNT,
            "key_type_count": self.KEY_TYPE_COUNT,
            "validation_period_count": self.VALIDATION_PERIOD_COUNT,
            "expired_percent": f"{self.EXPIRED_PERCENT*100}%",
        }
    
    def get_id(self):
        return str(self.SCAN_ID)

    def __repr__(self):
        return f"<CertAnalysisStore {self.SCAN_ID}>"
