from app import db
from flask_login import UserMixin, AnonymousUserMixin
from datetime import datetime, timezone

organization_resource_table = db.Table('SYORGANIZATION_SYRESOURCE', db.metadata,
                                       db.Column('SYRESOURCE_ID', db.String, db.ForeignKey('SYRESOURCE.ID')),
                                       db.Column('SYORGANIZATION_ID', db.String, db.ForeignKey('SYORGANIZATION.ID')))


class Organization(db.Model, UserMixin):
    __tablename__ = 'SYORGANIZATION'
    ID = db.Column(db.String(36), primary_key=True)
    CREATEDATETIME = db.Column(db.DateTime, index=True, default=datetime.now(timezone.utc))
    UPDATEDATETIME = db.Column(db.DateTime, index=True, default=datetime.now(timezone.utc))
    NAME = db.Column(db.String(200))
    ADDRESS = db.Column(db.String(200))
    CODE = db.Column(db.String(200))
    ICONCLS = db.Column(db.String(100))
    SEQ = db.Column(db.Integer)
    LEADER = db.Column(db.String(20))
    PHONE = db.Column(db.String(11))
    EMAIL = db.Column(db.String(50))
    STATUS = db.Column(db.String(10))

    '''
        resources 属性的定义表明 Organization 模型与 Resource 模型之间存在多对多的关系，并且这个关系是通过 organization_resource_table 中间表来维护的。这样的设计使得一个组织可以拥有多个资源，而一个资源也可以被多个组织拥有。

        你可以利用这个关系来进行一些操作，比如添加资源给组织、获取某个组织拥有的资源等。

        以下是一些可能的用法：

        添加资源给组织：

        python
        Copy code
        # 创建一个组织
        organization = Organization(...)

        # 创建一个资源
        resource = Resource(...)

        # 将资源添加给组织
        organization.resources.append(resource)

        # 提交到数据库
        db.session.add(organization)
        db.session.commit()
        这将在 organization_resource_table 中添加一行，表示这个组织拥有了这个资源。

        获取某个组织拥有的资源：

        python
        Copy code
        # 获取某个组织
        organization = Organization.query.get(organization_id)

        # 获取该组织拥有的所有资源
        resources = organization.resources.all()
    '''
    resources = db.relationship('Resource',
                                secondary=organization_resource_table,
                                backref=db.backref('organizations', lazy='dynamic'))

    SYORGANIZATION_ID = db.Column(db.String, db.ForeignKey('SYORGANIZATION.ID'))

    # "Show the parent-child relationship explicitly."
    parent = db.relationship('Organization', remote_side=[ID], backref='children', uselist=False)
    # children = db.relationship('Organization', remote_side=[ID], backref='parent', uselist=True)

    def to_json(self):
        return {
            'deptId': self.ID,
            'createTime': self.CREATEDATETIME,
            'updateTime': self.UPDATEDATETIME,
            'deptName': self.NAME,
            'address': self.ADDRESS,
            'code': self.CODE,
            'iconCls': self.ICONCLS,
            'orderNum': self.SEQ,
            'parentId': self.get_pid(),
            'leader': self.LEADER,
            'phone': self.PHONE,
            'email': self.EMAIL,
            'status': self.STATUS,
            'children': [
                org.to_json() for org in self.children
            ]
        }
    
    def to_tree_select_json(self):
        return {
            'id': self.ID,
            'label': self.NAME,
            'children': [org.to_tree_select_json() for org in self.children]
        }

    def get_pid(self):
        if self.parent:
            return self.parent.ID
        return ''

    def get_id(self):
        return str(self.ID)

    def __repr__(self):
        return '<Organization %r>\n' %(self.NAME)