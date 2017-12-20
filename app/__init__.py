from flask import Flask
from flask_sqlalchemy import SQLAlchemy
import os
from app.config import DevelopingConfig
from flasgger import Swagger


app = Flask(__name__)
swagger = Swagger(app)
APP_ROOT = os.path.dirname(os.path.abspath(__file__))
app.config.from_object(DevelopingConfig)
db = SQLAlchemy(app)


from app.views import *
