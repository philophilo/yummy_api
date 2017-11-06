import os
from app import app, login_manager, APP_ROOT
from flask import g, request, abort, jsonify
from models import Users
from sqlalchemy.exc import IntegrityError
from werkzeug.security import (generate_password_hash,
                               check_password_hash)
from flask_login import (login_user, login_required,
                         logout_user, current_user)
from datetime import datetime
import random
import string
import requests
import traceback
import pdb


login_manager.login_view = '/'
@login_manager.user_loader
def load_user(user_username):
    return Users.query.filter_by(user_username=user_username).first()

def check_crap(val):
    split_val = val.split(" ")
    splits = len(split_val)
    zeros = 0
    for i in split_val:
        if len(i) == 0:
            zeros+=1
    if zeros == splits:
        return False
    return True

def check_values(names):
    for key, name in enumerate(names):
        if(isinstance(name, str)):
            if not check_crap(name): return [False, key, 'empty']
        else:
            return [False, key, 'not a string']
    return [True]

@app.route('/auth/register', methods=['POST'])
def user_register():
    if request.headers.get('content-type') == 'application/json':
        info = request.json
        try:
            user_details = {
                'username': info['username'],
                'password': info['password'],
                'name': info['name']
            }
            if (len(user_details['username']) and
                len(user_details['password'])):
                val = check_values(user_details.values())
                if val[0]:
                    user = Users(user_details['username'],
                                 generate_password_hash(
                                     user_details['password']),
                                 user_details['name'])
                    user.add()
                    return jsonify({'username': user.user_username,
                                   'status': 'pass',
                                   'message': 'Account created'}), 201
                else:
                    return jsonify({'status':'fail', 'message':
                                    list(user_details.keys())[val[1]]+" "+val[2]
                                    })

            return jsonify({'status': 'fail',
                            'message':
                            'Username and Password cannot be empty'
                            }), 400

        except IntegrityError:
            return jsonify({'status': 'fail', 'message':
                            'The username is not available exits'}
                            ), 500

        except Exception as ex:
            return jsonify({'status': 'fail',
                            'message': ex.message}), 500
    return jsonify({'status': 'pass',
                    'message': 'User registration'}), 201


@app.route("/auth/login", methods=['POST', 'GET'])
def login():
    if request.headers.get('content-type') == 'application/json':
        info = request.json
        try:
            user_details = {
                'username': info['username'],
                'password': info['password']
            }
            if (len(user_details['username']) and
                len(user_details['password'])):
                val = check_values(user_details.values())

                if val[0]:
                    user = Users.query.filter_by(user_username=
                                                 info['username']
                                                 ).first()
                    # authenticate user
                    if (user and check_password_hash(
                        user.user_password,
                        user_details['password'])):
                        # generate token
                        token = user.generate_auth_token()
                        login_user(user)
                        if token:
                            print(current_user)
                            g.user = current_user
                            pdb.set_trace()

                            return jsonify(
                                {'token':token.decode('ascii'),
                                 'status': 'pass',
                                 'message': 'login was successful'}
                            ), 201

                    if user.user_username:
                        return jsonify({'status': 'fail',
                                        'message':
                                        'The password is incorrect'}
                                       ), 400
                    else:
                            return jsonify({'status': 'fail',
                                        'message':
                                        'Username does not exits'}
                                       ), 400
                else:
                    return jsonify({'status':'fail',
                                    'message':
                                    list(user_details.keys())[val[1]]+" "+val[2]
                                    }
                                   ), 400
            return jsonify({'status': 'fail',
                            'message':
                            'Username and password cannot be empty'}
                           ), 400

        except Exception as ex:
            print(ex)
            traceback.print_exc()
            # return jsonify({'status': 'fail',
            #                'message': ex}), 500
    return jsonify({'status': 'fail', 'message':
                    'content-type not specified as application/json'}
                   ), 400


@app.route('/')
def home():
    print(current_user)
    return jsonify({'status':'pass'})

@app.route('/auth/logout', methods=['POST'])

@login_required
def logout():
    pdb.set_trace()
    logout_user()
    return jsonify({'status': 'pass', 'message':
                    'logout was successful'}), 200


@app.route('/create/category', methods=['POST'])
@login_required
def create_category():
    pdb.set_trace()
    token = None
    try:
        auth_header = request.headers.get('Authorization')
        token = auth_header.split(" ")[1]
    except Exception as ex:
        print(ex.message)

    if token:
        print(token)
    else:
        print("Nara")
