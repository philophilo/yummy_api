import os

basedir = os.path.abspath(os.path.dirname(__file__))


class Config(object):
    DEBUG = False
    TESTING = False
    CSRF_ENABLED = True
    SECRETE_KEY = 'this is the secrete'
    SQLALCHEMY_DATABASE_URI = "postgresql://philophilo:philophilo@localhost/eagle_eye"


class ProductionConfig(Config):
    DEBUG = False


class StagingConfig(Config):
    DEVELOPMENT = True
    DEBUG = True


class DevelopingConfig(Config):
    DEVELOPING = True
    DEBUG = True


class TestingConfig(Config):
    TESTING = True
