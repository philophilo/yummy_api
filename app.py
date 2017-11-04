from flask import Flask
from flask_sqlalchemy import SQLAlchemy
import os
from config import DevelopingConfig
from flask_login import LoginManager


app = Flask(__name__)
APP_ROOT = os.path.dirname(os.path.abspath(__file__))
app.config.from_object(DevelopingConfig)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# set up login manager for the api
login_manager = LoginManager()
login_manager.init_app(app)

from views import *

if __name__ == '__main__':
    app.run()
