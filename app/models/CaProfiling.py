
from app import db
from sqlalchemy import MetaData

def generate_ca_profiling_table(ca_org : str):

    # My MySql only accepts lowercase table names
    ca_org = ca_org.replace(" ", "").lower()
    table_name = f"profiling_{ca_org}"

    class CaProfilingData(db.Model):
        __tablename__ = table_name
        __table_args__ = {'extend_existing': True}

        ID = db.Column(db.Integer, autoincrement=True, primary_key=True)
        HIGH_FEATURE_VALUE = db.Column(db.Float, default=0)
        MEDIUM_FEATURE_VALUE = db.Column(db.Float, default=0)
        LOW_FEATURE_VALUE = db.Column(db.Float, default=0)

        def to_json(self):
            return {
                'id' : self.ID,
                'high': self.HIGH_FEATURE_VALUE,
                'medium': self.MEDIUM_FEATURE_VALUE,
                'low': self.LOW_FEATURE_VALUE
            }
        
        def get_id(self):
            return str(self.__tablename__)

        def __repr__(self):
            return f"<CaProfiling {self.ID}>"

    metadata = MetaData()
    metadata.reflect(bind=db.engine)

    # Drop table if exists
    if table_name in metadata.tables:
        table = metadata.tables[table_name]
        table.drop(db.engine)

    CaProfilingData.__table__.create(db.engine)
    metadata.reflect(bind=db.engine)

    return metadata.tables[table_name]
