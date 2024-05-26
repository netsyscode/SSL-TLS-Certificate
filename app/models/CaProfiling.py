
from app import db
from sqlalchemy import MetaData, PrimaryKeyConstraint

def generate_ca_fp_table(ca_org : str):

    # My MySql only accepts lowercase table names
    ca_org = ca_org.replace(" ", "").replace("'","").lower()
    table_name = f"fp_{ca_org}"

    class CaFpData(db.Model):
        __tablename__ = table_name

        ID = db.Column(db.Integer, primary_key=True, autoincrement=True)
        ISSUER_CN = db.Column(db.String(128, collation='utf8mb4_unicode_ci'))
        ISSUER_ORG = db.Column(db.String(128, collation='utf8mb4_unicode_ci'))
        ISSUER_COUNTRY = db.Column(db.String(16, collation='utf8mb4_unicode_ci'))
        ISSUING_TIME = db.Column(db.DateTime, nullable=False)
        FINGERPRINT = db.Column(db.JSON, nullable=False)

        __table_args__ = {
            'extend_existing': True,
            'primary_key': PrimaryKeyConstraint('ISSUER_CN', 'ISSUER_ORG', 'ISSUER_COUNTRY')
        }

        def to_json(self):
            return {
                'id' : self.ID,
                'issuer_cn': self.ISSUER_CN,
                'issuer_org': self.ISSUER_ORG,
                'issuer_country': self.ISSUER_COUNTRY,
                'time' : self.ISSUING_TIME,
                'fingerprint' : self.FINGERPRINT
            }
        
        def get_id(self):
            return str(self.__tablename__)

        def __repr__(self):
            return f"<CaFp {self.ISSUING_TIME}>"

    metadata = MetaData()
    metadata.reflect(bind=db.engine)

    # Drop table if exists
    if table_name in metadata.tables:
        table = metadata.tables[table_name]
        table.drop(db.engine)

    CaFpData.__table__.create(db.engine)
    metadata.reflect(bind=db.engine)

    return metadata.tables[table_name]
