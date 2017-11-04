from app import db, app
from sqlalchemy.dialects.postgresql import JSON
from itsdangerous import (TimedJSONWebSignatureSerializer as
                          Serializer, BadSignature,
                          SignatureExpired)


class Users(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    user_name = db.Column(db.String(100), unique=True)
    user_username = db.Column(db.String(100), unique=True)
    user_password = db.Column(db.String(100))

    def __init__(self, username, password, name=None):
        self.user_name = name
        self.user_username = username
        self.user_password = password

    def add(self):
        db.session.add(self)
        db.session.commit()

    @staticmethod
    def update():
        db.session.commit()

    def delete(self):
        db.session.delete(self)
        db.session.commit()

    def generate_auth_token(self, expiration=600):
        try:
            s = Serializer(app.config['SECRET_KEY'],
                           expires_in = expiration)
            return s.dumps({'user_id': self.id})
        except Exception as ex:
            return str(ex)

    @staticmethod
    def decode_token(token):
        s = Serializer(app.config['SECRET_KEY'])
        try:
            data = s.loads(token)
        except SignatureExpired:
            return None
        except BadSignature:
            return None
        user = Users.query.get(data['user_id'])
        return user

    def __repr__(self):
        return '<Admin: %s>' % self.admin_username

    # flask login properties
    @property
    def is_authenticated(self):
        return True

    @property
    def is_active(self):
        return True

    @property
    def is_anonymous(self):
        return False

    def get_id(self):
        return str(self.id)
