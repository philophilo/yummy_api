from app import app, login_manager
from flask import request, jsonify
from flasgger import swag_from
from app.models.blacklist import Blacklist
from app.models.users import Users
from werkzeug.security import (generate_password_hash,
                               check_password_hash)
from flask_login import (login_user, login_required,
                         logout_user)
from datetime import datetime
from werkzeug.exceptions import BadRequest
from app.serializer import (check_data_keys, check_values,
                            valid_data, validate_username, validate_name,
                            validate_password, error, validate_email,
                            check_token, handle_exceptions, validation)


login_manager.login_view = '/'


# login_manager's user loader from the users' object
@login_manager.user_loader
def load_user(user_username):
    return Users.query.filter_by(user_username=user_username).first()


class UserView():
    """The class views for user account"""
    @app.route('/auth/register', methods=['POST'])
    @swag_from('/app/docs/userregister.yml')
    def user_register():
        """The function registers a new user"""
        try:
            data = request.json
            if validation(data, ['username', 'name', 'password', 'email']):
                if validate_username(valid_data['username']) and validate_name(
                    valid_data['name']) and validate_password(valid_data[
                        'password']) and validate_email(valid_data['email']):
                    check_user = Users.query.filter_by(
                        user_username=valid_data['username']).first()
                    if check_user is None:
                        user = Users(valid_data['username'],
                                     generate_password_hash(
                                        valid_data['password']),
                                     valid_data['name'], valid_data['email'])
                        user.add()
                        return jsonify({'username': user.user_username}), 201
                    return jsonify({'Error': 'Username already exists'}), 409
            return jsonify(error), 400
        except Exception as ex:
            excepts = {'KeyError': {'Error': str(ex).strip('\'')+' key is ' +
                                    'missing'}, 'IntegrityError':
                       {'Error': 'Email already exists'},
                       'BadRequest': {'Error': 'All fields keys are required'},
                       'ValueError': {'Error': str(ex)}
                       }
            return jsonify(handle_exceptions(type(ex).__name__, excepts))

    @app.route("/auth/login", methods=['POST'])
    @swag_from('/app/docs/userlogin.yml')
    def login():
        """The function logs in a new user"""
        try:
            data = request.json
            # check that expected data is present
            expected_data = check_data_keys(data, ['username', 'password'])
            # check that credentials are strings and not empty
            check_response = check_values(data)
            if check_response and expected_data:
                # check if user exists
                user = Users.query.filter_by(
                    user_username=valid_data['username']).first()
                if user is not None:
                    # check password
                    if check_password_hash(
                            user.user_password,
                            valid_data['password']):
                        # generate token
                        token = user.generate_auth_token()
                        # login in user with floask_login
                        login_user(user)
                        return jsonify(
                            {'token': token.decode('ascii'),
                             'message': 'login was successful'}
                        ), 200
                    return jsonify({'Error': 'Incorrect password'}), 403
                return jsonify({'Error': 'User not found'}), 403
            else:
                return jsonify(error), 400
        except BadRequest:
            return jsonify({'Error': 'Please ensure that all ' +
                            'fields are correctly specified'}), 400
        except Exception as ex:
            return jsonify({'Error': str(ex)}), 400

    @app.route('/auth/reset-password', methods=['PUT'])
    @login_required
    @swag_from('/app/docs/userresetpassword.yml')
    def reset_password():
        """The function updates a user's password"""
        token = check_token()
        if token:
            try:
                # get user id
                user_id = Users.decode_token(token)
                # get data
                data = request.json
                # check for expected data
                expected_data = check_data_keys(data,
                                                ['password', 'new_password',
                                                 'confirm_password'])
                # check whether values are strings and not empty
                check_response = check_values(data)
                if check_response and expected_data:
                    # get the user object based on authenticated user id
                    user = Users.query.filter_by(
                                    id=user_id).first()
                    # check if password matches the user's
                    if check_password_hash(user.user_password,
                                           valid_data['password']):
                        # delete current password from the dictionary
                        del valid_data['password']
                        # TODO check empty values for passwords
                        if valid_data['new_password'] \
                                == valid_data['confirm_password']:
                            # set password to new value
                            user.user_password = generate_password_hash(
                                valid_data['new_password'])
                            # update the pasword
                            user.update()
                            return jsonify({'message':
                                            'Your password was ' +
                                            'successfully reset'}), 201
                        return jsonify({'message':
                                        'Passwords do not ' +
                                        'match'})
                    return jsonify({'message': 'Incorrect password'}), 403
                return jsonify(error)
            except BadRequest:
                return jsonify({'Error': 'All fields must be parsed'}), 400
            except AttributeError as ex:
                return jsonify({'Error': 'All attributes are expected'}), 400
            except Exception as ex:
                return jsonify({'Error': str(ex)}), 400
        return jsonify(error), 401

    @app.route('/auth/delete-account', methods=['DELETE'])
    @login_required
    @swag_from('/app/docs/userdeleteaccount.yml')
    def delete_account():
        """The function deletes a user's account"""
        token = check_token()
        if token:
            try:
                user_id = Users.decode_token(token)
                data = request.json
                # check that data was sent
                expected_data = check_data_keys(data, ['password'])
                # check if password value is string and not empty
                check_response = check_values(data)
                if check_response and expected_data:
                    user = Users.query.filter_by(
                        id=user_id).first()
                    # check if the password provided matches the known
                    if check_password_hash(user.user_password,
                                           valid_data['password']):
                        user.delete()
                        return '', 204
                    return jsonify({'Error': 'Incorrect password'}), 403
                return jsonify(error), 400
            except TypeError:
                return jsonify({'Error': 'Please provide a ' +
                                'password key and value'}), 400
            except BadRequest:
                return jsonify({'Error': 'Please create a password key ' +
                                'and value'}), 400
            except Exception as ex:
                return jsonify({'Error': str(ex)}), 400
        return jsonify(error), 401

    @app.route('/auth/logout', methods=['POST'])
    @login_required
    @swag_from('/app/docs/userlogout.yml')
    def logout():
        """The function ends a user's session and blacklists the token"""
        try:
            token = check_token()
            if token:
                blacklist = Blacklist(token=token,
                                      date=datetime.now())
                blacklist.add()
                logout_user()
                return jsonify({'Error':
                                'logout was successful'}), 200
            else:
                return jsonify(error), 401
        except Exception as ex:
            return jsonify(ex), 400
