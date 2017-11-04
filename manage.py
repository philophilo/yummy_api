import os
from flask.ext.script import Manager
from flask.ext.migrate import Migrate, MigrateCommand
from config import DevelopingConfig


from app import app, db

app.config.from_object(DevelopingConfig())

migrate = Migrate(app, db)
manager = Manager(app)

manager.add_command('db', MigrateCommand)


if __name__ == '__main__':
    manager.run()
