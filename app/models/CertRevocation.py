
from app import db
from datetime import datetime, timezone


class CertRevocationStatusOCSP(db.Model):
    __tablename__ = "CERT_REVOCATION_STATUS_OCSP"

    CERT_ID = db.Column(db.String(64, collation='gbk_chinese_ci'), db.ForeignKey('CERT_STORE_RAW.CERT_ID'), primary_key=True, nullable=False, index=True)
    CHECK_TIME = db.Column(db.DateTime, primary_key=True, nullable=False)
    AIA_LOCATION = db.Column(db.Text, nullable=False)
    ISSUER_ID = db.Column(db.String(64, collation='gbk_chinese_ci'), nullable=False)
    REVOCATION_STATUS = db.Column(db.Integer)
    REVOCATION_TIME = db.Column(db.DateTime, nullable=True)
    REVOCATION_REASON = db.Column(db.Integer, nullable=True)

    def to_json(self):
        return {
            'cert_id': self.CERT_ID,
            'check_time': self.CHECK_TIME,
            'aia_location': self.AIA_LOCATION,
            'issuer_id' : self.ISSUER_ID,
            'revocation_status' : self.REVOCATION_STATUS,
            'revocation_time' : self.REVOCATION_TIME,
            'revocation_reason' : self.REVOCATION_REASON
        }
    
    def get_id(self):
        return str(self.CERT_ID)

    def __repr__(self):
        return f"<CertRevocationStatusOCSP {self.CERT_ID}>"


class CertRevocationStatusCRL(db.Model):
    __tablename__ = "CERT_REVOCATION_STATUS_CRL"

    CERT_ID = db.Column(db.String(64, collation='gbk_chinese_ci'), db.ForeignKey('CERT_STORE_RAW.CERT_ID'), primary_key=True, nullable=False, index=True)
    CHECK_TIME = db.Column(db.DateTime, primary_key=True, nullable=False)
    CRL_POSITION = db.Column(db.Text, nullable=False)
    REVOCATION_STATUS = db.Column(db.Integer)
    REVOCATION_TIME = db.Column(db.DateTime, nullable=True)
    REVOCATION_REASON = db.Column(db.Integer, nullable=True)

    def to_json(self):
        return {
            'cert_id': self.CERT_ID,
            'check_time': self.CHECK_TIME,
            'crl_position': self.CRL_POSITION,
            'revocation_status' : self.REVOCATION_STATUS,
            'revocation_time' : self.REVOCATION_TIME,
            'revocation_reason' : self.REVOCATION_REASON
        }
    
    def get_id(self):
        return str(self.CERT_ID)

    def __repr__(self):
        return f"<CertRevocationStatusCRL {self.CERT_ID}>"


class CRLArchive(db.Model):
    __tablename__ = "CRL_ARCHIVE"

    CRL_POSITION = db.Column(db.Text, primary_key=True, nullable=False)
    STORE_TIME = db.Column(db.DateTime, primary_key=True, nullable=False)
    FINGERPRINT = db.Column(db.String(64, collation='gbk_chinese_ci'), nullable=False)
    CRL_DATA = db.Column(db.LargeBinary, nullable=False)

    def to_json(self):
        return {
            'crl_position': self.CRL_POSITION,
            'store_time': self.STORE_TIME,
            'fingerprint': self.FINGERPRINT,
            'crl_data': self.CRL_DATA.hex()  # 返回十六进制字符串表示的二进制数据
        }
    
    def get_id(self):
        return str(self.FINGERPRINT)

    def __repr__(self):
        return f"<CRLArchive CRL Position: {self.CRL_POSITION}, Store Time: {self.STORE_TIME}, Fingerprint: {self.FINGERPRINT}>"
