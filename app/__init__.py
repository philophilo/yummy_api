from flask import Flask
from flask_sqlalchemy import SQLAlchemy
import os
from app.config import DevelopingConfig
from flasgger import Swagger


app = Flask(__name__)
swagger = Swagger(app,
                  template={
                    "info": {
                        "title": "Yummy Recipes API",
                        "description": "Ymmy recipes helps many individuals "+
                            "who love to cook and aet food keep track of "+
                            "those awesome food recipes. Yummy recipes allows "+
                            "them to remember recipes and share with others."
                    },
                    "securityDefinitions":{
                        "TokenHeader": {
                            "type": "apiKey",
                            "name": "Authorization",
                            "in": "header"
                        }
                    },
                    "Consumes": "Application/json"
                  })
APP_ROOT = os.path.dirname(os.path.abspath(__file__))
app.config.from_object(DevelopingConfig)
db = SQLAlchemy(app)


from app.views import *
