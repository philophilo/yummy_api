import os

basedir = os.path.abspath(os.path.dirname(__file__))


class Config(object):
    DEBUG = False
    TESTING = False
    CSRF_ENABLED = True
    SECRET_KEY = 'this is the secrete'
    SQLALCHEMY_TRACK_MODIFICATIONS = False


class ProductionConfig(Config):
    DEBUG = False


class StagingConfig(Config):
    DEVELOPMENT = True
    DEBUG = True


class DevelopingConfig(Config):
    SQLALCHEMY_DATABASE_URI = "postgresql://philophilo:philophilo@localhost/yummy"
    DEVELOPING = True
    DEBUG = True


class TestingConfig(Config):
    SQLALCHEMY_DATABASE_URI = "postgresql://philophilo:philophilo@localhost/test_yummy"
    TESTING = True
