from app import app
from flask import request, abort, jsonify
from app.models import Users, Category, Recipes
from sqlalchemy.exc import IntegrityError
from sqlalchemy import and_
from werkzeug.security import (generate_password_hash,
                               check_password_hash)
from datetime import datetime
import re
from werkzeug.exceptions import BadRequest
import traceback
# import pdb

error = {}

def check_empty_spaces(string):
    """ Check if a string still has any empty spaces"""
	# split the string into chuncks
    split_string = string.split(" ")
    # get the length of chunks extructed
    number_of_splits = len(split_string)
    # keep track of the empty chunks
    empty_chunks = 0
    # for each of the chuncks get the length
    for i in split_string:
        if len(i) == 0:
            empty_chunks+=1
    # if the string is completely empty return False
    if empty_chunks == number_of_splits:
        return False
    return True

def check_values(details):
    """check that the value is strictly a string"""
    for key, value in enumerate(details):
        if(isinstance(value, str)):
            if not value.strip() and not check_empty_spaces(value):
                return [False, key, 'empty']
        else:
            return [False, key, 'not a string']
    return [True]

def check_token():
    """check token validity"""
    token = None
    try:
        auth_header = request.headers.get('Authorization')
        token = auth_header.split(" ")[1]
        return token
    except Exception:
        return None

def check_string(value):
    """check that the value is strictly a string"""
    if isinstance(value, str):
        return True
    return False

def check_fullname(name):
    """ Check firstname and lastname seperated by space"""
    if re.match("([a-zA-Z]+) ([a-zA-Z]+)$", name):
        return True
    return False

def check_upper_limit_fullname(name):
    """ checks maximum length of name """
    print('.....',len(name))
    if len(name) <= 50:
        return True
    return False

def check_lower_limit_fullname(name):
    """ checks minimum length of name """
    if len(name) >= 4:
        return True
    return False


def check_username(username):
    """check valid username"""
    if re.match("^[a-zA-Z0-9_-]+$", username):
        return True
    return False

def check_username_upper_limit(username):
    """check the upper limit of the username"""
    if len(username) <= 20:
        return True
    return False

def check_username_lower_limit(username):
    """check the lower limit of the username"""
    if len(username) >= 4:
        return True
    return False

def check_password(password):
    """check that the password has numbers, symbols and minimum"""
    state = True
    while state:
        if not re.search("[a-z]", password):
            break
        elif not re.search("[0-9]", password):
            break
        elif not re.search("[A-Z]", password):
            break
        elif not re.search("[!\(\)\[\]@#$%^&*+]", password):
            break
        else:
            state = False
            return True
    return False

def check_password_upper_limit(password):
    """check the upper limit of password"""
    if len(password) <= 50:
        return True
    return False

def check_password_lower_limit(password):
    """check the lower mimit of the password"""
    if len(password) >= 6:
        return True
    return False

def check_item_name_alphabet(name):
    """check whether name is alphabetical"""
    if name.isalpha():
        return True
    return False

def check_item_name_upper_limit(name):
    """check the upper limit of a name"""
    if len(name) <= 20:
        return True
    return False

def check_item_name_lower_limit(name):
    """ check the lower limit of a name"""
    if len(name) >= 4:
        return True
    return False

#def check_id_as_integer(id):
#    """check that an id parsed is an intger"""
#    if isinstance(int(id), int):
#        return True
#    return False

def validate_username(username):
    """ Validate username constraints """
    global error
    if check_username(username):
        if check_username_upper_limit(username):
            if check_username_lower_limit(username):
                return True
            else:
                error = {'Error':'Username cannot '+
                         'be less than 4'}
        else:
            error = {'Error':'Username must be '+
                     'less than 20'}
    else:
        error = {'Error': 'username can have '+
                 'alphabets, numbers'+
                 ' and selected symbols(\'_ and -\')'}

def validate_name(fullname):
    """Validate full name constraints"""
    global error
    if check_fullname(fullname):
        if check_upper_limit_fullname(fullname):
            if check_lower_limit_fullname(fullname):
                return True
            else:
                error = {'Error': 'Firstname and Lastname cannot be '+
                         'less than 4 characters'}
        else:
            error = {'Error': 'Firstname and lastname cannot be more '+
                     'than 50 characters'}
    else:
        error = {'Error': 'Your firstname and lastname must '+
                 'be seperated by a space'}
    return False

def validate_password(password):
    """Validate password constraints"""
    global error
    if check_password(password):
        if check_password_upper_limit(password):
            if check_password_lower_limit(password):
                return True
            else:
                error = {'Error': 'Password cannot be less than 6 characters'}
        else:
            error = {'Error': 'Password cannot be more than 50 characters'}
    else:
        error = {'Error': 'Password must have atleast one Block letter, '+
                 'a number and a symbol'}
    return False


def validate_item_names(name):
    """Validate item names"""
    global error
    if check_string(name):
        if check_item_name_alphabet(name):
            if check_item_name_upper_limit(name):
                if check_item_name_lower_limit(name):
                    return True
                else:
                    error = {'Error': 'The name cannot have less than '+
                             '4 characters'}
            else:
                error = {'Error': 'The name cannot be more than 6'+
                         '6 characters'}
        else:
            error = {'Error': 'The name must be from alphabetical letters'}
    else:
        error = {'Error': 'The name must be a string'}

def check_data_keys(data, expected_keys):
    for key in expected_keys:
        if key not in data:
            return False, key
    return True,

@app.route('/auth/register', methods=['POST'])
def user_register():
    """
    Register a user
    This resource registers new users
    ---
    tags:
      - Authentication
    parameters:
      - name: body
        in: body
        type: string
        required: true
        schema:
            id: registration_input
            properties:
                username:
                    type: string
                    decription: user's nick name
                name:
                    type: string
                    description: user's full name, firstname and last name
                password:
                    type: string
                    description: user' password for authentication
    responses:
      201:
        description: A user's account created
        content: application/json
        schema:
          id: registration_output
          properties:
            username:
              type: string
              description: The username
              default: some_username

    """
    if request.headers.get('content-type') == 'application/json':
        try:
            data = request.json
            # check if values are strings and not empty
            check_response = check_values(data.values())
            if check_response[0]:
                # validate the username, name and password
                if validate_username(data['username']) and \
                        validate_name(data['name']) and \
                        validate_password(data['password']):
                    # parse data to Users model
                    user = Users(data['username'],
                                    generate_password_hash(data['password']),
                                    data['name'])
                    # add and commit to the database
                    user.add()
                    return jsonify({'username': user.user_username}), 201
                else:
                    return jsonify(error)
            else:
                return jsonify({'message':
                                list(data.keys())[check_response[1]]+' is '+
                                check_response[2]
                                })
        except KeyError as ex:
            return jsonify({'message':
                            str(ex)+' key is missing'})
        except IntegrityError:
            return jsonify({'message':
                            'The username already exits'}), 500
        except ValueError as ex:
            return jsonify({'message', str(ex)}), 400
        except BadRequest:
            return jsonify({'message': 'Please ensure that all '+
                            'fields are specied'})
        except Exception as ex:
            traceback.print_exc()
            return jsonify({'message': str(ex)}), 500
    else:
        return jsonify({'message': 'Please specify json data'})
    return jsonify({'message': 'User registration'}), 201


@app.route("/auth/login", methods=['POST'])
def login():
    """
    Login
    This resource Logs in registered users
    ---
    tags:
      - Authentication
    parameters:
      - name: body
        in: body
        type: string
        required: true
        schema:
            id: login_input
            properties:
                username:
                    type: string
                    decription: user's nick name
                password:
                    type: string
                    description: user' password for authentication
    responses:
      200:
        description: Login successful
        content: application/json
        schema:
          id: login_output
          properties:
            token:
              type: string
              description: Authentication token
              default: eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJleHAiOjE1MTczODIxMjEsImlhdCI6MTUxMzc4MjEyMSwic3ViIjoxfQ.i-IF_S78cYIkrJpCj0ykeq2Of52BWMaEpYeDNvJnlwc
    """

    if request.headers.get('content-type') == 'application/json':
        try:
            data = request.json
            # check that expected data is present
            expected_data = check_data_keys(data, ['username', 'password'])
            if expected_data[0]:
                # check that credentials are strings and not empty
                check_response = check_values(data.values())
                if check_response[0]:
                    # check if user exists
                    user = Users.query.filter_by(
                        user_username=data['username']).first()
                    if user is not None:
                        # check password
                        if check_password_hash(
                                user.user_password,
                                data['password']):
                            # generate token
                            token = user.generate_auth_token()
                            if token:
                                return jsonify(
                                    {'token': token.decode('ascii'),
                                    'message': 'login was successful'}
                                ), 200
                        return jsonify({'message': 'Incorrect password'})
                    return jsonify({'message': 'User not found'})
                else:
                    return jsonify({'message':
                                    list(data.keys())[check_response[1]]+
                                    " is "+check_response[2]
                                    }
                                    ), 400
            else:
                return jsonify({'message': expected_data[1]+' key missing'})

        except Exception as ex:
            traceback.print_exc()
            return jsonify({'message': str(ex)})

    return jsonify({'message':
                    'content-type not specified as application/json'}
                   ), 400


@app.route('/auth/reset-password', methods=['PUT'])
def reset_password():
    """
    Reset password
    This resource resets a registered user's password
    ---
    tags:
      - Authentication
    parameters:
      - name: body
        in: body
        type: string
        required: true
        schema:
            id: reset_password_input
            properties:
                password:
                    type: string
                    decription: user's authentication password
                new_password:
                    type: string
                    description: user's new authentication password
                confirm_password:
                    type: string
                    description: user's matching new authentication password
    responses:
      200:
        description: Login successful
        content: application/json
        schema:
          id: reset_password_output
          properties:
            message:
              type: string
              description: Success message
              default: Your password was successfully reset
    """

    token = check_token()
    if token:
        user_id = Users.decode_token(token)
        print('----')
        # check username is an integer
        if isinstance(int(user_id), int):
            data = request.json
            # check for original password in data
            try:
                expected_data = check_data_keys(data,
                                                    ['password', 'new_password',
                                                     'confirm_password'])
                if expected_data[0]:
                    check_response = check_values(data.values())
                    if check_response[0]:
                        # get the user object based on authenticated user id
                        user = Users.query.filter_by(
                                        id=user_id).first()
                        # check if password matches the user's
                        if check_password_hash(user.user_password,
                                            data['password']):
                            # delete current password from the dictionary
                            del data['password']
                            # TODO check empty values for passwords
                            if data['new_password'] \
                                    == data['confirm_password']:
                                # set password to new value
                                user.user_password = generate_password_hash(
                                    data['new_password'])
                                # update the pasword
                                user.update()
                                return jsonify({'message':
                                                'Your password was '+
                                                'successfully reset'})
                            else:
                                return jsonify({'message':
                                                'Passwords do not '+
                                                'match'})
                        else:
                            return jsonify({'message':'Incorrect password'})
                    else:
                        return jsonify({'message':
                                        list(data.keys())[check_response[1]]+
                                        " is "+check_response[2]
                                        }
                                        ), 400
                else:
                    return jsonify({'message': expected_data[1]+
                                    ' key missing'})

            except BadRequest:
                return jsonify({'Error': 'All fields must be parsed'})
            except AttributeError as ex:
                return jsonify({'Error': 'All attributes are expected'})
            except Exception as ex:
                return jsonify({'message':str(ex)})
    return jsonify({'message':'reset password'})

@app.route('/auth/delete-account', methods=['DELETE'])
def delete_account():
    """
    Delete an account
    This resource a registered user's account
    ---
    tags:
      - Authentication
    parameters:
      - name: body
        in: body
        type: string
        required: true
        schema:
            id: delete_account_input
            properties:
                password:
                    type: string
                    decription: user's authentication password
    security:
        - TokenHeader: []
    responses:
      200:
        description: Login successful
        content: application/json
        schema:
          id: delete_account_output
          properties:
            message:
              type: string
              description: Success message
              default: Your account was successfully deleted
    """

    token = check_token()
    if token:
        user_id = Users.decode_token(token)
        if isinstance(int(user_id), int):

            try:
                data = request.json
                # check that data was sent
                expected_data = check_data_keys(data, ['password'])
                if expected_data[0]:
                    # check if password value is string and not empty
                    check_response = check_values([data['password']])
                    if check_response[0]:
                        user = Users.query.filter_by(
                            id=user_id).first()
                        # check if the password provided matches the known
                        if check_password_hash(user.user_password,
                                            data['password']):
                            # TODO implement revocation of tokens
                            # user.delete()
                            return jsonify({'message': 'Your account '+
                                            'was successfully deleted'})
                        else:
                            return jsonify({'Error': 'Incorrect password'})
                    else:
                        return jsonify({'Error':
                                        list(data.keys())[check_response[1]]+
                                        " is "+check_response[2]
                                        }
                                        ), 400

                else:
                    return jsonify({'Error': expected_data[1]+
                                    ' key missing'})
            except TypeError:
                return jsonify({'Error': 'Please provide a '+
                                'password key and value'})
            except BadRequest:
                return jsonify({'Error': 'Please create a password key '+
                                'and value'})
            except Exception as ex:
                traceback.print_exc()
                return jsonify({'message': str(ex)})

@app.route('/category', methods=['POST'])
def create_category():
    """
    Create a category
    This resource a registered user's account
    ---
    tags:
      - Categories
    parameters:
      - name: body
        in: body
        type: string
        required: true
        schema:
            id: create_category_input
            properties:
                category_name:
                    type: string
                    description: A user defined category
    security:
        - TokenHeader: []
    responses:
      200:
        description: Login successful
        content: application/json
        schema:
          id: create_category_output
          properties:
            message:
              type: string
              description: Success message
              default: category created
            id:
              type: integer
              description: The id of the created category
            category_name:
              type: string
              description: The name of the created category
    """

    # pdb.set_trace()
    token = check_token()

    if token:
        user_id = Users.decode_token(token)
        if isinstance(int(user_id), int):
            # cre
            try:
                data = request.json
                # check for expected data
                expected_data = check_data_keys(data, ['category_name'])
                if expected_data[0]:
                    # check that the expected data are strings and not empty
                    check_response = check_values(data.values())
                    if check_response[0]:
                        # create a the category object
                        category = Category(user_id=int(user_id),
                                            cat_name=data['category_name']
                                            )
                        # add the object to the database
                        category.add()
                        # create response
                        response = jsonify({'id': category.cat_id,
                                            'category_name': category.cat_name,
                                            'message': 'category created'})
                        # return response
                        return response, 201
                    else:
                        return jsonify({'message':
                                        list(data.keys())[check_response[1]]+
                                        " is "+check_response[2]
                                        }
                                        ), 400

                else:
                    return jsonify({'Error': expected_data[1]+
                                    ' key missing'})
            except TypeError:
                return jsonify({'Error': 'Please provide a '+
                                'password key and value'})
            except BadRequest:
                return jsonify({'Error': 'Please create a category name key '+
                                'and value'})
            except Exception as ex:
                return jsonify({'message': ex
                                }), 500

    else:
        return jsonify({'message': 'no access token'}), 400


@app.route('/category/', methods=['GET'])
def view_all_categories():
    """
    View allo categories
    This resource shows all categories created by a user
    ---
    tags:
      - Categories
    parameters:
      - name: page
        in: path
        type: integer
        required: false
        default: 1
      - name: per_page
        in: path
        type: integer
        default: 5
    security:
        - TokenHeader: []
    responses:
      200:
        description: Login successful
        content: application/json
        schema:
          id: view_categories_output
          properties:
            message:
              type: string
              description: Success message
              default: categories found
            categories:
              type: array
              items:
                  type: object
                  properties:
                    id:
                      type: integer
                      description: The id of the retrieved category
                    category_name:
                      type: string
                      description: The category name of the retrieved category
              description: A list of retrieved categories
            current_page:
              type: integer
              description: The current page retrieved
            next_page:
              type: integer
              description: The next page value if it exists
            count:
              type: integer
              description: Number of categories retrieved
            previous_page:
              type: integer
              description: The previous page retrived if it existed
    """
    token = check_token()
    if token:
        try:
            user_id = Users.decode_token(token)
            # page to retieve
            page = int(request.args.get('page', 1))
            # number of pages on the retrieved page
            per_page = int(request.args.get('per_page', 5))
            # check that user_id is an interger
            if isinstance(int(user_id), int):
                # get a paginated categories object
                user_categories = Category.query.filter_by(
                    user_id=user_id).paginate(page, per_page, False)
                # check if the object is not None
                if user_categories is not None:
                    # list to store dictionaries of categories
                    results = []
                    # ----set pagination values----
                    current_page = user_categories.page
                    number_of_pages = user_categories.pages
                    next_page = user_categories.next_num
                    previous_page = user_categories.prev_num
                    # ---end
                    # loop through the object retrieve all categories
                    # and store in results
                    for category in user_categories.items:
                        # get single category
                        result = {
                            'id': category.cat_id,
                            'category_name': category.cat_name,
                        }
                        # append category in results list
                        results.append(result)
                    # return response with list of found categories attached
                    return jsonify({'categories': results,
                                    'count': str(len(results)),
                                    'current_page': current_page,
                                    'number_of_pages': number_of_pages,
                                    'next_page': next_page,
                                    'previous_page': previous_page,
                                    'message': 'categories found'}), 200
                return jsonify({'count': '0',
                                'message': 'no categories found'
                                }), 404
            abort(401)
        except Exception as ex:
            return jsonify({'message': str(ex)}), 500

    return jsonify({'message': 'no access token'}), 500


@app.route('/category/<category_id>', methods=['GET'])
def view_a_category(category_id):
    """
    View one category
    This resource retrieves a particular category specified by a category id
    ---
    tags:
      - Categories
    parameters:
      - name: category_id
        in: path
        type: integer
        required: true
    security:
        - TokenHeader: []
    responses:
      200:
        description: Login successful
        content: application/json
        schema:
          id: view_a_category_output
          properties:
            message:
              type: string
              description: Success message
              default: category found
            id:
              type: integer
              description: The id of the category retrieved
            category_name:
              type: string
              description: The name of the category retrieved
    """
    token = check_token()
    if token:
        try:
            user_id = Users.decode_token(token)
            # check that user is an integer
            if isinstance(int(user_id), int):
                # get the category object with category
                user_category = Category.query.filter_by(
                    cat_id=category_id, user_id=user_id).first()
                # check the category object is not empty
                if user_category is not None:
                    # create response
                    response = jsonify(
                        {'id': user_category.cat_id,
                        'category_name': user_category.cat_name,
                        'message': 'category found'})
                    # return response
                    return response, 200
                return jsonify({'count': '0',
                                'message': 'category not found'}), 404
            abort(401)
        # capture value error
        except ValueError as ex:
            traceback.print_exc()
            return jsonify({'Error': 'Invalid entry for category id'})
        # capture bad request
        except BadRequest:
                return jsonify({'Error': 'Please parse a category id'})
        # get any other exception
        except Exception as ex:
            traceback.print_exc()
            return jsonify({'message': str(ex)}), 500
    return jsonify({'message': 'no access token'}), 401


@app.route('/category/<int:category_id>', methods=['PUT'])
def update_category(category_id):
    """
    Update a category
    This resource updates a particular category specified by a category id
    ---
    tags:
      - Categories
    parameters:
      - name: category_id
        in: path
        type: integer
        required: true
    security:
        - TokenHeader: []
    responses:
      200:
        description: Login successful
        content: application/json
        schema:
          id: update_category_output
          properties:
            message:
              type: string
              description: Success message
              default: category updated
            id:
              type: integer
              description: The id of the updated category
            category_name:
              type: string
              description: The updated category name
    """
    # check token
    token = check_token()
    if token:
        try:
            data = request.json
            user_id = Users.decode_token(token)
            if isinstance(int(user_id), int):
                # check for expected data
                expected_data = check_data_keys(data, ['category_name'])
                if expected_data[0]:
                    # check that the data is a string and not empty
                    check_response = check_values(data.values())
                    if check_response[0]:
                        # get category object
                        user_category = Category.query.filter_by(
                            cat_id=category_id, user_id=user_id).first()
                        # check that the category object is not empty
                        if user_category is not None:
                            # update the the category name in the object
                            user_category.cat_name = data["category_name"]
                            # commit the update to the database
                            user_category.update()
                            # create response
                            response = jsonify({
                                'id': user_category.cat_id,
                                'category_name': user_category.cat_name,
                                'message': 'category updated'})
                            # return the response
                            return response, 201
                        return jsonify({'message': 'category not found'
                                        })
                    else:
                        return jsonify({'message':
                                        list(data.keys())[check_response[1]]+
                                        " is "+check_response[2]
                                        }
                                        ), 400

                else:
                    return jsonify({'Error': expected_data[1]+
                                    ' key missing'})

            abort(401)
        # capture value error
        except ValueError as ex:
            traceback.print_exc()
            return jsonify({'Error': 'Invalid entry, please provide the '+
                            'category id as integer and catgory name as '+
                            'string'})
        # capture bad request
        except BadRequest:
                return jsonify({'Error': 'Please parse both category id '+
                                'and category name'})
        # get any other exception
        except Exception as ex:
            return jsonify({'message': str(ex)})
    return jsonify({'message': 'category not found'})


@app.route('/category/<int:category_id>', methods=['DELETE'])
def delete_category(category_id):
    """
    Delete a category
    This resource deletes a particular category specified by a category id
    ---
    tags:
      - Categories
    parameters:
      - name: category_id
        in: path
        type: integer
        required: true
        description: The id of the category to be deleted
    security:
        - TokenHeader: []
    responses:
      200:
        description: Login successful
        content: application/json
        schema:
          id: delete_category_output
          properties:
            message:
              type: string
              description: Success message
              default: category deleted
    """

    token = check_token()
    if token:
        try:
            # get user id from token
            user_id = Users.decode_token(token)
            # check user_id is integer
            if isinstance(int(user_id), int):
                # get the object of the specified category
                user_category = Category.query.filter_by(
                    cat_id=category_id, user_id=user_id).first()
                # check the object is not None
                if user_category is not None:
                    # delete the category and commit
                    user_category.delete()
                    # return response
                    return jsonify({'message': 'category deleted'}), 200
                return jsonify({'message': 'category not found'})
            abort(401)
        # capture value error
        except ValueError as ex:
            traceback.print_exc()
            return jsonify({'Error': 'Invalid entry for category id'})
        # capture bad request
        except BadRequest:
                return jsonify({'Error': 'Please parse a category id'})
        # get any other exception
        except Exception as ex:
            return jsonify({'message': str(ex)})
    return jsonify({'message': 'no access token'})

# TODO change the name of the method to create_recipe
# TODO change the route to /recipes/<int: category_id>
@app.route('/category/recipes/<int:category_id>', methods=['POST'])
def add_recipe(category_id):
    """
    Add a recipe
    This resource a registered user's account
    ---
    tags:
      - Recipes
    parameters:
      - name: category_id
        in: path
        type: integer
        required: true
      - name: body
        in: body
        type: string
        required: true
        schema:
            id: create_recipe_input
            properties:
                recipe_name:
                    type: string
                    description: A user defined recipe in a category
                ingredients:
                    type: string
                    description: A set of ingredients in a recipes seperated by ','
    security:
        - TokenHeader: []
    responses:
      200:
        description: Recipe created
        content: application/json
        schema:
          id: create_recipe_output
          properties:
            message:
              type: string
              description: Success message
              default: Recipe created
            recipe_id:
              type: integer
              description: The id of the created recipe
            category_name:
              type: string
              description: The name of the category underwhich the recipe was recipe
            recipe_name:
              type: string
              description: The name of the recipe created
            ingredients:
              type: array
              items:
                  type: string
              description: A list of ingredients in the recipe
    """

    token = check_token()
    if token:
        try:
            user_id = Users.decode_token(token)
            if isinstance(int(user_id), int):
                data = request.json
                # check for expected data
                expected_data = check_data_keys(data,
                                                ['recipe_name', 'ingredients'])
                if expected_data[0]:
                    # check that the expected data is string and not empty
                    check_responses = check_values(data.values())
                    if check_responses[0]:
                        # get object of categiry with parsed category id
                        user_category = Category.query.filter_by(
                            cat_id=category_id, user_id=user_id).first()
                        # check that the category id not None
                        if user_category is not None:
                            # create a recipe object
                            recipe = Recipes(name=data['recipe_name'],
                                                category=category_id,
                                                ingredients=data['ingredients'],
                                                date=datetime.now())
                            # recipe under category id commited to database
                            recipe.add()
                            # return response
                            return jsonify({'recipe_id': recipe.rec_id,
                                            'recipe_name': recipe.rec_name,
                                            'category_name': recipe.rec_cat,
                                            'ingredients':
                                                recipe.rec_ingredients.split(','),
                                            'message': 'Recipe created'}), 201
                        return jsonify({'message': 'category not found'})
                    else:
                        return jsonify({'message':
                                        list(data.keys())[check_response[1]]+
                                        " is "+check_response[2]
                                        }
                                        ), 400

                else:
                    return jsonify({'Error': expected_data[1]+
                                    ' key missing'})
            abort(401)
        # capture value error
        except ValueError as ex:
            traceback.print_exc()
            return jsonify({'Error': 'Invalid entry, please provide the '+
                            'category id as integer while recipe name '+
                            'and ingredients as string'})
        # capture bad request
        except BadRequest:
                return jsonify({'Error': 'Please parse category id, '+
                                'recipe name and ingredients'})
        # get any other exception
        except Exception as ex:
            return jsonify({'message': str(ex)})
    return jsonify({'message': 'no access token'})


# TODO remove the <int: category> parameter
@app.route('/category/recipes/<int:category_id>/<int:recipe_id>',
           methods=['PUT'])
def update_recipe(category_id, recipe_id):
    """
    Update a recipe
    This resource a registered user's account
    ---
    tags:
      - Recipes
    parameters:
      - name: category_id
        in: path
        required: true
        type:integer
        description: The category under which the recipes recipe is registered
      - name: recipe_id
        in: path
        required: true
        type: integer
        description: The identifier of the recipe to be updated
      - name: body
        in: body
        type: string
        required: true
        description: updated recipes details
        schema:
            id: update_recipe_input
            properties:
                recipe_name:
                    type: string
                    description: The updated recipe name
                ingredients:
                    type: string
                    description: Updated set of ingredients  seperated by ','
                recipe_category_id:
                    type: integer
                    decription: The updated category id of the recipe
    security:
        - TokenHeader: []
    responses:
      200:
        description: Recipe created
        content: application/json
        schema:
          id: update_recipe_output
          properties:
            message:
              type: string
              description: Success message
              default: Recipe updated
            recipe_id:
              type: integer
              description: The id of the updated recipe
            category:
              type: integer
              description: The updated category id of the recipe
            recipe_name:
              type: string
              description: The name of the recipe created
            recipe_ingredients:
              type: array
              items:
                  type: string
              description: A list of ingredients in the recipe
    """

    token = check_token()
    if token:
        try:
            user_id = Users.decode_token(token)
            if isinstance(int(user_id), int):
                data = request.json
                # check that the expected data is present
                expected_data = check_data_keys(data,
                                                ['recipe_name',
                                                 'recipe_category_id',
                                                 'ingredients'])
                if expected_data[0]:
                    # check that the data are strings and are not empty
                    check_response = check_values([data['recipe_name'],
                                                   data['ingredients']])
                    if check_response[0]:
                        # get category object of category id
                        user_category = Category.query.filter_by(
                            cat_id=category_id, user_id=user_id).first()
                        # check that the category is not none
                        if user_category is not None:
                            # get recipes object
                            user_recipe = Recipes.query.filter_by(
                                rec_cat=category_id, rec_id=recipe_id).first()
                            if user_recipe is not None:
                                # TODO include rec_category_id in tests
                                # ---update the recipes object
                                user_recipe.rec_name = data[
                                    'recipe_name']
                                user_recipe.rec_cat = category_id
                                user_recipe.rec_ingredients = data[
                                    'ingredients']
                                user_recipe.rec_cat = data[
                                    'recipe_category_id']
                                # -------
                                # commit the updates
                                user_recipe.update()
                                # return response
                                return jsonify(
                                    {'recipe_id': user_recipe.rec_id,
                                        'recipe_name': user_recipe.rec_name,
                                        'category': user_recipe.rec_cat,
                                        'recipe_ingredients':
                                        user_recipe.rec_ingredients.split(','),
                                        'message': 'Recipe updated'}), 200
                            return jsonify({'message': 'Recipe not found'})
                        return jsonify({'message': 'category not found'})
                    else:
                        return jsonify({'Error':
                                        list(data.keys())[check_response[1]]+
                                        " is "+check_response[2]
                                        }
                                        ), 400

                else:
                    return jsonify({'Error': expected_data[1]+
                                    ' key missing'})
            abort(401)
        # capture value error
        except ValueError as ex:
            traceback.print_exc()
            return jsonify({'Error': 'Invalid entry, please provide the '+
                            'category id as integer while recipe name '+
                            'and ingredients as string'})
        # capture bad request
        except BadRequest:
                return jsonify({'Error': 'Please parse category id, '+
                                'recipe name and ingredients'})
        # get any other exception
        except Exception as ex:
            traceback.print_exc()
            return jsonify({'message': str(ex)})
    return jsonify({'message': 'no access token'})


# TODO remove the category_id from the route
@app.route('/category/recipes/<int:category_id>/<int:recipe_id>',
           methods=['DELETE'])
def delete_recipe(category_id, recipe_id):
    """
    Delete a recipe
    This resource deletes a particular recipe specified by a recipe id
    ---
    tags:
      - Recipes
    parameters:
      - name: category_id
        in: path
        type: integer
        required: true
        description: The category id of the recipe to be deleted
      - name: recipe_id
        in: path
        type: integer
        required: true
        description: The id of the recipe to be deleted
    security:
        - TokenHeader: []
    responses:
      200:
        description: Login successful
        content: application/json
        schema:
          id: delete_recipe_output
          properties:
            message:
              type: string
              description: Success message
              default: Recipe deleted
    """

    token = check_token()
    if token:
        try:
            # get the user id from the token
            user_id = Users.decode_token(token)
            # check user is an integer
            if isinstance(int(user_id), int):
                # get category object of parsed category and logged in user
                user_category = Category.query.filter_by(
                    cat_id=category_id, user_id=user_id).first()
                # check the category object is not empty
                if user_category is not None:
                    # get the recipes object
                    user_recipe = Recipes.query.filter_by(
                        rec_cat=category_id, rec_id=recipe_id).first()
                    # check the recipes object is not None
                    if user_recipe is not None:
                        # delete and commit changes to the database
                        user_recipe.delete()
                        # return response
                        return jsonify({'message': 'Recipe deleted'}), 200
                    return jsonify({'message': 'Recipe not found'}), 404
                return jsonify({'message': 'Category not found'}), 404
            abort(401)
        # capture value error
        except ValueError as ex:
            traceback.print_exc()
            return jsonify({'Error': 'Invalid entry, please provide the '+
                            'category id and recipe id as integers'})
        # capture bad request
        except BadRequest:
                return jsonify({'Error': 'Please parse the recipe id '+
                                'and category id'})
        # get any other exception
        except Exception as ex:
            return jsonify({'message': str(ex)})
    return jsonify({'message': 'no access token'})


@app.route('/category/recipes/<int:category_id>', methods=['GET'])
def view_category_recipes(category_id):
    """
    View recipes in a category
    This resource shows all recipes in a specifies category id
    ---
    tags:
      - Recipes
    parameters:
      - name: page
        in: path
        type: integer
        required: false
        default: 1
      - name: per_page
        in: path
        type: integer
        default: 5
      - name: category_id
        in: path
        type: integer
        required: true
        description: The category from which to extract recipes
    security:
        - TokenHeader: []
    responses:
      200:
        description: Recipes found
        content: application/json
        schema:
          id: view_category_recipes_output
          properties:
            message:
              type: string
              description: Success message
              default: recipes found
            recipes:
              type: array
              items:
                  type:string
              description: A list of retrieved recipes
            current_page:
              type: integer
              description: The current page retrieved
            next_page:
              type: integer
              description: The next page value if it exists
            count:
              type: integer
              description: Number of recipes retrieved
            previous_page:
              type: integer
              description: The previous page retrived if it existed
    """

    token = check_token()
    if token:
        try:
            # get user id from the token
            user_id = Users.decode_token(token)
            # page number to go to
            page = int(request.args.get('page', 1))
            # number of items per page
            per_page = int(request.args.get('per_page', 5))
            # check user id is an integer
            if isinstance(int(user_id), int):
                # get user category object based on user
                user_categories = Category.query.filter_by(
                    cat_id=category_id, user_id=user_id).first()
                # check user categories object is not None
                if user_categories is not None:
                    # get recipe object
                    user_recipes = Recipes.query.filter_by(
                        rec_cat=category_id).paginate(page, per_page, False)
                    # check recipes object is not None
                    if user_recipes is not None:
                        # -----pagination properties----
                        current_page = user_recipes.page
                        number_of_pages = user_recipes.pages
                        next_page = user_recipes.next_num
                        previous_page = user_recipes.prev_num
                        # -----
                        # a list of all recipe dictionary
                        results = []
                        # loop through the paginated recipes object
                        for recipe in user_recipes.items:
                            # for each recipe store in dictionary
                            result = {
                                'id': recipe.rec_id,
                                'recipe_name': recipe.rec_name,
                                'ingredients': recipe.rec_ingredients.split(",")
                            }
                            # append the dictionary to list
                            results.append(result)
                        # return the response with list of recipes
                        return jsonify({'recipes': results,
                                        'count': str(len(results)),
                                        'current_page': current_page,
                                        'number_of_pages': number_of_pages,
                                        'next_page': next_page,
                                        'previous_page': previous_page,
                                        'messages': 'recipes found'}), 200
                    return jsonify({'message': 'no recipes found'}), 404
                return jsonify({'message': 'category not found'}), 404
            abort(401)
        # capture value error
        except ValueError as ex:
            traceback.print_exc()
            return jsonify({'Error': 'Invalid entry, please provide the '+
                            'category id as integer while recipe name '+
                            'and ingredients as string'})
        # capture bad request
        except BadRequest:
                return jsonify({'Error': 'Please parse the recipe id'})
        # get any other exception
        except Exception as ex:
            return jsonify({'message': str(ex)}), 500
    return jsonify({'message': 'no access token'}), 500


@app.route('/category/recipes/one/<int:category_id>/<int:recipe_id>',
           methods=['GET'])
def view_one_recipe(category_id, recipe_id):
    """
    View one recipe
    This resource retrieves a particular recipe specified by a recipe id
    ---
    tags:
      - Recipes
    parameters:
      - name: recipe_id
        in: path
        type: integer
        required: true
    security:
        - TokenHeader: []
    responses:
      200:
        description: Login successful
        content: application/json
        schema:
          id: view_one_recipe_output
          properties:
            message:
              type: string
              description: Success message
              default: recipe found
            id:
              type: integer
              description: The id of the recipe retrieved
            recipe_name:
              type: string
              description: The name of the recipe retrieved
            ingredients:
              type: string
              description: The ingredients of the recipe
    """
    # check token
    token = check_token()
    # continue if present
    if token:
        try:
            user_id = Users.decode_token(token)
            if isinstance(int(user_id), int):
                # get user category object based on user
                user_categories = Category.query.filter_by(
                    cat_id=category_id, user_id=user_id).first()
                # check user categories object is not None
                if user_categories is not None:
                    # get recipe object
                    user_recipes = Recipes.query.filter_by(
                        rec_cat=category_id, rec_id=recipe_id)
                    #user_recipes = Recipes.query.filter_by(rec_id=recipe_id)
                    # if the recipes is not None
                    if user_recipes is not None:
                        # list in which dictionaries of recipes will be stored
                        results = []
                        # loop though the recipes
                        for recipe in user_recipes:
                            result = {
                                'id': recipe.rec_id,
                                'recipe_name': recipe.rec_name,
                                'ingredients': recipe.rec_ingredients.split(","),
                                'message': 'recipe found'
                            }
                            results.append(result)
                        return jsonify({'recipes': results,
                                        'count': str(len(results))}), 200
                    return jsonify({'message': 'no recipes found'}), 404
            abort(401)
        # capture value error
        except ValueError as ex:
            traceback.print_exc()
            return jsonify({'Error': 'Invalid entry, please provide the '+
                            'category id and recipe id as integers'})
        # capture bad request
        except BadRequest:
                return jsonify({'Error': 'Please parse the recipe id and '+
                                'category id'})
        # get any other exception
        except Exception as ex:
            return jsonify({'message': str(ex)}), 500
    return jsonify({'message': 'no access token'}), 500


@app.route('/category/search/', methods=['GET'])
def search_categories():
    """
    Search categories
    This resource retrieves categories by search parameter q
    ---
    tags:
      - Categories
    parameters:
      - name: q
        in: path
        type: string
        required: true
        description: String, typically a category name being searched
      - name: page
        in: path
        type: integer
        required: false
        default: 1
        decription: The page number to visit
      - name: per_page
        in: path
        type: integer
        default: 5
        descrption: Limit number of records per page

    security:
        - TokenHeader: []
    responses:
      200:
        description: Success
        content: application/json
        schema:
          id: search_category_output
          properties:
            message:
              type: string
              description: Success message
              default: Categories found
            categories:
              type: array
              items:
                  type: object
                  properties:
                    id:
                      type: integer
                      description: The id of the retrieved category
                    category_name:
                      type: string
                      description: The category name of the retrieved category

    """

    token = check_token()
    if token:
        try:
            # TODO validate the search parameters
            q = str(request.args.get('q', '')).title()
            page = int(request.args.get('page', 1))
            per_page = int(request.args.get('per_page', 5))
            user_id = Users.decode_token(token)
            # check if q is a string and not empty
            check_response = check_values([q])
            if check_response[0]:
                if isinstance(int(user_id), int):
                    # get category object
                    user_categories = Category.query.filter(and_(
                        Category.user_id == user_id,
                        Category.cat_name.like('%'+q+'%'))).paginate(
                            page, per_page, False)
                    # check the object id not None
                    if user_categories is not None:
                        # -----pagination properties----
                        current_page = user_categories.page
                        number_of_pages = user_categories.pages
                        next_page = user_categories.next_num
                        previous_page = user_categories.prev_num
                        # ----
                        results = []
                        for category in user_categories.items:
                            result = {
                                'id': category.cat_id,
                                'category_name': category.cat_name,
                            }
                            results.append(result)
                    return jsonify({'categories': results,
                                    'current_page': current_page,
                                    'number_of_pages': number_of_pages,
                                    'next_page': next_page,
                                    'previous_page': previous_page,
                                    'message': 'Categories found'})
            else:
                return jsonify({'message':
                                list(data.keys())[check_response[1]]+
                                " is "+check_response[2]
                                }
                                ), 400

        # capture value error
        except ValueError as ex:
            traceback.print_exc()
            return jsonify({'Error': 'Invalid entry, please provide '+
                            'q as a string'})
        # capture bad request
        except BadRequest:
                return jsonify({'Error': 'Please parse the q parameter'})
        # get any other exception
        except Exception as ex:
            return jsonify({'message': str(ex)})
    return jsonify({'message': 'no access token'}), 500


@app.route('/recipes/search/', methods=['GET'])
def search_recipes():
    """
    Search recipes
    This resource retrieves categories by search parameter q
    ---
    tags:
      - Recipes
    parameters:
      - name: q
        in: path
        type: string
        required: true
        description: String, typically a recipe name being searched
      - name: page
        in: path
        type: integer
        required: false
        default: 1
        decription: The page number to visit
      - name: per_page
        in: path
        type: integer
        default: 5
        descrption: Limit number of records per page
    security:
        - TokenHeader: []
    responses:
      200:
        description: Success
        content: application/json
        schema:
          id: search_recipe_output
          properties:
            message:
              type: string
              description: Success message
              default: Categories found
            recipes:
              type: array
              items:
                  type: object
                  properties:
                    recipe_id:
                      type: integer
                      description: The id of the retrieved recipe
                    recipe_name:
                      type: string
                      description: The recipe name of the retrieved recipe
                    recipe_ingredients:
                      type: string
                      description: The ingredients of the recipe
                    category_id:
                      type: string
                      description: The category id of the recipes
                    category_name:
                      type: string
                      description: The category name underwhich the recipe falls

    """

    token = check_token()
    if token:
        try:
            # TODO validate the search parameters
            q = str(request.args.get('q', '')).title()
            page = int(request.args.get('page', 1))
            per_page = int(request.args.get('per_page', 5))
            user_id = Users.decode_token(token)
            # check if q is a string and not empty
            check_response = check_values([q])
            if check_response[0]:
                # check if user_id is an integer
                if isinstance(int(user_id), int):
                    found_recipes = Category.query.join(
                        Recipes, Category.cat_id==Recipes.rec_cat).add_columns(
                            Category.cat_id, Category.user_id,
                            Category.cat_name, Recipes.rec_id, Recipes.rec_name,
                            Recipes.rec_ingredients).filter(
                                Category.user_id == user_id).filter(
                                    Recipes.rec_name.like('%'+q+'%')).paginate(
                                        page, per_page, False)
                    current_page = found_recipes.page
                    number_of_pages = found_recipes.pages
                    next_page = found_recipes.next_num
                    previous_page = found_recipes.prev_num
                    print(">>>>>", found_recipes)
                    results = []
                    for recipe in found_recipes.items:
                        result = {
                            'category_id':recipe.cat_id,
                            'category_name': recipe.cat_name,
                            'recipe_id':recipe.rec_id,
                            'recipe_name':recipe.rec_name,
                            'recipes_ingredients':recipe.rec_ingredients
                        }
                        results.append(result)
                    return jsonify({'categories': results,
                                    'count': str(len(results)),
                                    'current_page': current_page,
                                    'number_of_pages': number_of_pages,
                                    'next_page': next_page,
                                    'previous_page': previous_page,
                                    'message': 'Recipes found'})
            else:
                return jsonify({'message':
                                "q is "+check_response[2]
                                }
                                ), 400
        # capture value error
        except ValueError as ex:
            traceback.print_exc()
            return jsonify({'Error': 'Invalid entry, please provide '+
                            'q as a string'})
        # capture bad request
        except BadRequest:
                return jsonify({'Error': 'Please parse the q parameter'})
        # get any other exception
        except Exception as ex:
            return jsonify({'message': str(ex)})
    return jsonify({'message': 'no access token'}), 500
