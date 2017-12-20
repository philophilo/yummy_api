from app import app
from flask import request, abort, jsonify
from app.models import Users, Category, Recipes
from sqlalchemy.exc import IntegrityError
from werkzeug.security import (generate_password_hash,
                               check_password_hash)
from datetime import datetime
import traceback
# import pdb


def check_crap(val):
    split_val = val.split(" ")
    splits = len(split_val)
    zeros = 0
    for i in split_val:
        if len(i) == 0:
            zeros += 1
    if zeros == splits:
        return False
    return True


def check_values(names):
    for key, name in enumerate(names):
        if(isinstance(name, str)):
            if not check_crap(name):
                return [False, key, 'empty']
        else:
            return [False, key, 'not a string']
    return [True]


def check_token():
    token = None
    try:
        auth_header = request.headers.get('Authorization')
        token = auth_header.split(" ")[1]
        return token
    except Exception:
        return None


@app.route('/auth/register', methods=['POST'])
def user_register():
    if request.headers.get('content-type') == 'application/json':
        print("there", "...")
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
                    return jsonify({'username': user.user_username}), 201
                else:
                    return jsonify({'message':
                                    list(user_details.keys())[val[1]]+" "+val[2]
                                    })

            return jsonify({'message':
                            'Username and Password cannot be empty'
                            }), 400

        except IntegrityError:
            return jsonify({'message':
                            'The username already exits'}), 500

        except ValueError as ex:
            return jsonify({'message', str(ex)}), 400

        except Exception as ex:
            return jsonify({'message': str(ex)}), 500
    else:
        return jsonify({'message', 'Please specify json data'})
    return jsonify({'message': 'User registration'}), 201


@app.route("/auth/login", methods=['POST'])
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
                    user = Users.query.filter_by(
                        user_username=user_details['username']).first()
                    # authenticate user
                    if (user and check_password_hash(
                            user.user_password,
                            user_details['password'])):
                        # generate token
                        token = user.generate_auth_token()
                        if token:
                            return jsonify(
                                {'token': token.decode('ascii'),
                                 'message': 'login was successful'}
                            ), 200
                    return jsonify({'message': 'Incorrect username \
                                     or password'})
                else:
                    return jsonify({'message':
                                    list(user_details.keys())[val[1]]+" "+val[2]
                                    }
                                   ), 400
            return jsonify({'message':
                            'Username and password cannot be empty'}
                           ), 400

        except Exception as ex:
            print(ex)
            traceback.print_exc()
    return jsonify({'message':
                    'content-type not specified as application/json'}
                   ), 400


@app.route('/category', methods=['POST'])
def create_category():
    # pdb.set_trace()
    token = check_token()

    if token:
        user_id = Users.decode_token(token)
        if isinstance(int(user_id), int):
            if request.headers.get('content-type') == 'application/json':
                data = request.json
                if 'category_name' in data:
                    try:
                        category = Category(user_id=int(user_id),
                                            cat_name=data['category_name']
                                            )
                        category.add()
                        response = jsonify({'id': category.cat_id,
                                            'category_name': category.cat_name,
                                            'message': 'category created'})
                        return response, 201
                    except Exception as ex:
                        return jsonify({'message': ex
                                        }), 500
                return jsonify({'message': 'category name not found'
                                }), 400
            return jsonify({'message': 'message not json format'
                            }), 400

    else:
        return jsonify({'message': 'no access token'}), 400


@app.route('/category/', methods=['GET'])
def view_all_categories():
    token = check_token()
    if token:
        try:
            user_id = Users.decode_token(token)
            if isinstance(int(user_id), int):
                user_categories = Category.query.filter_by(
                    user_id=user_id)

                if user_categories is not None:
                    results = []
                    for category in user_categories.items:
                        result = {
                            'id': category.cat_id,
                            'category_name': category.cat_name,
                        }
                        results.append(result)
                    return jsonify({'categories': results,
                                    'count': str(len(results)),
                                    'message': 'categories found'})
                return jsonify({'count': '0',
                                'message': 'no categories found'
                                }), 404
            abort(401)
        except Exception as ex:
            return jsonify({'message': str(ex)}), 500
    return jsonify({'message': 'no access token'}), 500


@app.route('/category/<category_id>', methods=['GET'])
def view_a_category(category_id):
    token = check_token()
    if token:
        try:
            user_id = Users.decode_token(token)
            if isinstance(int(user_id), int):
                user_category = Category.query.filter_by(
                    cat_id=category_id, user_id=user_id).first()

                if user_category is not None:
                    response = jsonify(
                        {'category': dict(id=user_category.cat_id,
                                          category_name=user_category.cat_name),
                         'count': '1',
                         'message': 'category found'})
                    return response, 200
                return jsonify({'count': '0',
                                'message': 'category not found'}), 404
            abort(401)
        except Exception as ex:
            return jsonify({'message': str(ex)}), 500
    return jsonify({'message': 'no access token'}), 401


@app.route('/category/<int:category_id>', methods=['PUT'])
def update_category(category_id):
    token = check_token()
    if token:
        try:
            user_id = Users.decode_token(token)
            if isinstance(int(user_id), int):
                user_category = Category.query.filter_by(
                    cat_id=category_id, user_id=user_id).first()
                if request.headers.get('content-type') == 'application/json':
                    data = request.json
                    if user_category is not None and 'category_name' in data:
                        user_category.cat_name = data["category_name"]
                        user_category.update()
                        response = jsonify({
                            'category': dict(
                                id=user_category.cat_id,
                                category_name=user_category.cat_name),
                            'message': 'category updated'})
                        return response, 201
                    return jsonify({'message': 'category not found'
                                    })
                return jsonify({'message': 'category not found'})
            abort(401)

        except Exception as ex:
            return jsonify({'message': str(ex)})
    return jsonify({'message': 'category not found'})


@app.route('/category/<int:category_id>', methods=['DELETE'])
def delete_category(category_id):
    token = check_token()
    if token:
        try:
            user_id = Users.decode_token(token)
            if isinstance(int(user_id), int):
                user_category = Category.query.filter_by(
                    cat_id=category_id, user_id=user_id).first()
                if user_category is not None:
                    user_category.delete()
                    return jsonify({'message': 'category deleted'}), 200
                return jsonify({'message': 'category not found'})
            abort(401)
        except Exception as ex:
            return jsonify({'message': str(ex)})
    return jsonify({'message': 'no access token'})


@app.route('/category/recipes/<int:category_id>', methods=['POST'])
def add_recipe(category_id):
    token = check_token()
    if token:
        try:
            user_id = Users.decode_token(token)
            if isinstance(int(user_id), int):
                if request.headers.get('content-type') == 'application/json':
                    data = request.json
                    user_category = Category.query.filter_by(
                        cat_id=category_id, user_id=user_id).first()
                    if user_category is not None and 'recipe_name' in data:
                        recipe = Recipes(name=data['recipe_name'],
                                         category=category_id,
                                         ingredients=data['ingredients'],
                                         date=datetime.now())
                        recipe.add()
                        return jsonify({'message': 'Recipe created'}), 201
                    return jsonify({'message': 'category not found'})
                return jsonify({'message': 'content should be json'})
            abort(401)
        except Exception as ex:
            return jsonify({'message': str(ex)})
    return jsonify({'message': 'no access token'})


@app.route('/category/recipes/<int:category_id>/<int:recipe_id>',
           methods=['PUT'])
def update_recipe(category_id, recipe_id):
    token = check_token()
    if token:
        try:
            user_id = Users.decode_token(token)
            if isinstance(int(user_id), int):
                user_category = Category.query.filter_by(
                    cat_id=category_id, user_id=user_id).first()
                if user_category is not None:
                    if request.headers.get('content-type') == \
                            'application/json':
                        user_recipe = Recipes.query.filter_by(
                            rec_cat=category_id, rec_id=recipe_id).first()
                        data = request.json
                        if user_recipe is not None and 'recipe_name' in data:
                            user_recipe.rec_name = data['recipe_name']
                            user_recipe.rec_cat = category_id
                            user_recipe.rec_ingredients = data['ingredients']
                            user_recipe.update()
                            return jsonify({'message': 'Recipe updated'}), 200
                        return jsonify({'message': 'Recipe not found'})
                    return jsonify({'message': 'content should be json'})
                return jsonify({'message': 'category not found'})
            abort(401)
        except Exception as ex:
            return jsonify({'message': str(ex)})
    return jsonify({'message': 'no access token'})


@app.route('/category/recipes/<int:category_id>/<int:recipe_id>',
           methods=['DELETE'])
def delete_recipe(category_id, recipe_id):
    token = check_token()
    if token:
        try:
            user_id = Users.decode_token(token)
            if isinstance(int(user_id), int):
                user_category = Category.query.filter_by(
                    cat_id=category_id, user_id=user_id).first()
                if user_category is not None:
                    user_recipe = Recipes.query.filter_by(
                        rec_cat=category_id, rec_id=recipe_id).first()
                    data = request.json
                    if user_recipe is not None and 'recipe_name' in data:
                        user_recipe.delete()
                        return jsonify({'message': 'Recipe deleted'}), 200
                    return jsonify({'message': 'Recipe not found'}), 404
                return jsonify({'message': 'Category not found'}), 404
            abort(401)
        except Exception as ex:
            return jsonify({'message': str(ex)})
    return jsonify({'message': 'no access token'})


@app.route('/category/recipes/<int:category_id>', methods=['GET'])
def view_category_recipes(category_id):
    token = check_token()
    if token:
        try:
            user_id = Users.decode_token(token)
            if isinstance(int(user_id), int):
                user_categories = Category.query.filter_by(
                    cat_id=category_id).first()
                if user_categories is not None:
                    user_recipes = Recipes.query.filter_by(rec_cat=category_id)
                    if user_recipes is not None:
                        results = []
                        for recipe in user_recipes:
                            result = {
                                'id': recipe.rec_id,
                                'recipe_name': recipe.rec_name,
                                'ingredients': recipe.rec_ingredients.split(",")
                            }
                            results.append(result)
                        return jsonify({'recipes': results,
                                        'count': str(len(results))}), 200
                    return jsonify({'message': 'no recipes found'}), 404
                return jsonify({'message': 'category not found'}), 404
            abort(401)
        except Exception as ex:
            return jsonify({'message': str(ex)}), 500
    return jsonify({'message': 'no access token'}), 500


@app.route('/category/recipes/one/<int:recipe_id>', methods=['GET'])
def view_one_recipe(recipe_id):
    token = check_token()
    if token:
        try:
            user_id = Users.decode_token(token)
            if isinstance(int(user_id), int):
                user_recipes = Recipes.query.filter_by(rec_id=recipe_id)
                if user_recipes is not None:
                    results = []
                    for recipe in user_recipes:
                        result = {
                            'id': recipe.rec_id,
                            'recipe_name': recipe.rec_name,
                            'ingredients': recipe.rec_ingredients.split(",")
                        }
                        results.append(result)
                    return jsonify({'recipes': results,
                                    'count': str(len(results))}), 200
                return jsonify({'message': 'no recipes found'}), 404
            abort(401)
        except Exception as ex:
            return jsonify({'message': str(ex)}), 500
    return jsonify({'message': 'no access token'}), 500
