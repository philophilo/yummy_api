[![Build Status](https://travis-ci.org/philophilo/yummy_api.svg?branch=master)](https://travis-ci.org/philophilo/yummy_api) [![Coverage Status](https://coveralls.io/repos/github/philophilo/yummy_api/badge.svg)](https://coveralls.io/github/philophilo/yummy_api) [![Maintainability](https://api.codeclimate.com/v1/badges/5e39cd477a45d4144b68/maintainability)](https://codeclimate.com/github/philophilo/yummy_api/maintainability)


Yummy Recipes is an application that allow users to keep track of their owesome food recipes. It helps individuals who love to cook and eat good food to remember recipes and also share with others.

# Features
* A user creates an account, logs in, logs out, updates password and deletes his/her account
* A user creates, views, updates and deletes his/her recipes categories
* A user creates, views, updates and deletes his/her recipes of existing categories

# Pre-requisites
* Python 3.6.X
* Python 2.7.3
* Flask
* Postman
* Flasgger
* Postgres

# Installations

* Create a new folder  ``webapp``
* ``cd Desktop/project``
* Install virtualenv ``$pip install virtualenv``
* Create a virtual environment ``virtualenv -p python3 venv``
* Clone the repo ``https://github.com/philophilo/yummy_api.git``
* Activate your virtual environment `source venv/bin/activate`
* Install project requirements ``pip install -r requirements.txt``
* Setup the postgres database ``yummy`` and test database ``test_yummy``
* Update the configuration files
* Create database and tables ``python manage.py db init`` ``python manage.py db migrate`` ``python manage.py db upgrade``
* Run the application ``python run.py``

# Running tests
You can test the application using two libraries nose2 or nosetests: ``nose2 --with-coverage` or `nosetests --with-coverage --cover-package=apps``
