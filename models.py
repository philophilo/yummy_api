from app import db, app
import jwt
from sqlalchemy.dialects.postgresql import JSON
from itsdangerous import (TimedJSONWebSignatureSerializer as
                          Serializer, BadSignature,
                          SignatureExpired)
from datetime import datetime, timedelta
import traceback


class Users(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    user_name = db.Column(db.String(100))
    user_username = db.Column(db.String(100), unique=True)
    user_password = db.Column(db.String(100))
    user_cats = db.relationship('Category',
                                order_by='Category.cat_id',
                                cascade='delete, all')

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

    def generate_auth_token(self, expiration=60000):
        try:
            payload = {
                'exp': datetime.utcnow() + timedelta(minutes=expiration),
                'iat': datetime.utcnow(),
                'sub': self.id
            }
            # create the byte string token using the payload and the SECRET key
            print(app.config['SECRET_KEY'])
            jwt_string = jwt.encode(
                payload,
                app.config['SECRET_KEY'],
                algorithm='HS256'
            )
            return jwt_string
        except Exception as ex:
            traceback.print_exc()
            print(self.id)
            return str(ex)

    @staticmethod
    def decode_token(token):
        try:
            payload = jwt.decode(token, app.config['SECRET_KEY'])
            #print(">>>", payload)
            return payload['sub']
        except jwt.ExpiredSignatureError:
            return "The token is expired"
        except jwt.InvalidTokenError:
            return "Invalid token"


    def __repr__(self):
        return '<Users %s>' % self.user_username

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
        return str(self.user_username)


class Category(db.Model):
    __tablename__ = 'category'
    cat_id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey(Users.id))
    cat_name = db.Column(db.String(100), nullable=False)
    cat_recipes = db.relationship('Recipes',
                                  order_by='Recipes.rec_id',
                                  cascade='delete, all')

    def __init__(self, cat_name, user_id):
        self.cat_name = cat_name
        self.user_id = user_id

    def add(self):
        db.session.add(self)
        db.session.commit()

    @staticmethod
    def update():
        db.session.commit()

    def delete(self):
        db.session.delete(self)
        db.session.commit()

    def __repr__(self):
        return '<Category: %s>' % self.cat_name


class Recipes(db.Model):
    __tablename__ = 'recipes'
    rec_id = db.Column(db.Integer, primary_key=True)
    rec_name = db.Column(db.String(100), nullable=False, unique=True)
    rec_cat = db.Column(db.Integer, db.ForeignKey(Category.cat_id))
    rec_ingredients = db.Column(db.String(500), nullable=False)
    rec_date = db.Column(db.DateTime, nullable=False)

    def __init__(self, name, category, ingredients, date):
        self.rec_name = name
        self.rec_cat = category
        self.rec_date = date
        self.rec_ingredients = ingredients

    def add(self):
        db.session.add(self)
        db.session.commit()

    @staticmethod
    def update():
        db.session.commit()

    def delete(self):
        db.session.delete(self)
        db.session.commit()

    def __repr__(self):
        return '<Recipes %s>' % self.rec_name
