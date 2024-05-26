
from app import db
from datetime import datetime, timezone

class CertAnalysisStats(db.Model):
    __tablename__ = "CERT_STAT_RESULT"

    SCAN_ID = db.Column(db.String(64), primary_key=True, nullable=False, unique=True, index=True)
    SCAN_TIME = db.Column(db.DateTime, primary_key=True, nullable=False, unique=True, index=True)
    SCAN_TYPE = db.Column(db.Integer, default=0)
    SCANNED_CERT_NUM = db.Column(db.Integer, default=0)
    ISSUER_ORG_COUNT = db.Column(db.JSON, default={})
    KEY_SIZE_COUNT =  db.Column(db.JSON, default={})
    KEY_TYPE_COUNT =  db.Column(db.JSON, default={})
    SIG_ALG_COUNT =  db.Column(db.JSON, default={})
    VALIDATION_PERIOD_COUNT = db.Column(db.JSON, default={})
    EXPIRED_PERCENT = db.Column(db.Float, default=0)

    def metadata_to_json(self):
        return {
            "scan_id": self.SCAN_ID,
            "scan_time": self.SCAN_TIME,
            "scan_type": self.SCAN_TYPE,
            "scanned_cert_num": self.SCANNED_CERT_NUM
        }
    
    def to_json(self):
        return {
            "scan_id": self.SCAN_ID,
            "scan_time": self.SCAN_TIME,
            "scan_type": self.SCAN_TYPE,
            "scanned_cert_num": self.SCANNED_CERT_NUM,
            "issuer_org_count": self.ISSUER_ORG_COUNT,
            "key_size_count": self.KEY_SIZE_COUNT,
            "key_type_count": self.KEY_TYPE_COUNT,
            "sig_alg_count" : self.SIG_ALG_COUNT,
            "validation_period_count": self.VALIDATION_PERIOD_COUNT,
            "expired_percent": f"{self.EXPIRED_PERCENT*100}%",
        }
    
    def get_id(self):
        return str(self.SCAN_ID)

    def __repr__(self):
        return f"<CertAnalysisStats {self.SCAN_ID}>"


class CertChainRelation(db.Model):
    __tablename__ = "CERT_CHAIN_RELATION"

    CERT_ID = db.Column(db.String(64), db.ForeignKey('CERT_STORE_RAW.CERT_ID'), primary_key=True, nullable=False, index=True)
    CERT_PARENT_ID = db.Column(db.String(64), db.ForeignKey('CA_CERT_STORE.CERT_ID'), primary_key=True, nullable=False, index=True)

    def to_json(self):
        return {
            "cert_id": self.CERT_ID,
            "cert_parent_id": self.CERT_PARENT_ID
        }
    
    def get_id(self):
        return str(self.CERT_ID)

    def __repr__(self):
        return f"<CertChainRelation {self.CERT_ID}>"
