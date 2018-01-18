from app import app
from flask import request, jsonify
from flasgger import swag_from
from app.models.category import Category
from app.models.recipes import Recipes
from app.models.users import Users
from sqlalchemy.exc import IntegrityError
from flask_login import login_required
from datetime import datetime
from werkzeug.exceptions import BadRequest
from app.serializer import (check_data_keys, check_values,
                            valid_data, validate_descriptions,
                            error, validate_item_names,
                            check_token)


class RecipesView():
    """The class has the views for recipes"""
    @app.route('/category/<int:category_id>/recipes/', methods=['POST'])
    @login_required
    @swag_from('/app/docs/recipesaddrecipe.yml')
    def add_recipe(category_id):
        """The function adds recipes to the database"""
        token = check_token()
        if token:
            try:
                user_id = Users.decode_token(token)
                data = request.json
                # get object of categiry with parsed category id
                user_category = Category.query.filter_by(
                    cat_id=category_id, user_id=user_id).first()
                # check that the category id not None
                if user_category is not None:
                    # check for expected data
                    expected_data = check_data_keys(data,
                                                    ['recipe_name',
                                                     'ingredients',
                                                     'description'])
                    # check that the expected data is string and not empty
                    check_responses = check_values(data)
                    if check_responses and expected_data and \
                            validate_item_names(valid_data['recipe_name']) and \
                            validate_descriptions(valid_data['description']):
                        # create a recipe object
                        recipe = Recipes(name=valid_data['recipe_name'],
                                         category=category_id,
                                         ingredients=valid_data[
                                             'ingredients'],
                                         description=valid_data[
                                             'description'],
                                         date=datetime.now())
                        # recipe under category id commited to database
                        recipe.add()
                        # return response
                        return jsonify({'recipe_id': recipe.rec_id,
                                        'recipe_name': recipe.rec_name,
                                        'category_name':
                                        user_category.cat_name,
                                        'ingredients':
                                        recipe.rec_ingredients.split(','),
                                        'message': 'Recipe created'}), 201
                    return jsonify(error), 400
                return jsonify({'Error': 'category not found'}), 404
            except IntegrityError:
                return jsonify({'Error': 'Recipe name already exists'}), 409
            # capture value error
            except ValueError as ex:
                return jsonify({'Error': 'Invalid entry, please provide the ' +
                                'category id as integer while recipe name ' +
                                'and ingredients as string'}), 400
            # capture bad request
            except BadRequest:
                    return jsonify({'Error': 'Please parse category id, ' +
                                    'recipe name and ingredients'}), 400
            # get any other exception
            except Exception as ex:
                import traceback
                traceback.print_exc()
                return jsonify({'Error': str(ex)}), 400
        return jsonify(error), 401

    # TODO remove the <int: category> parameter
    @app.route('/category/<int:category_id>/recipes/<int:recipe_id>',
               methods=['PUT'])
    @login_required
    @swag_from('/app/docs/recipesupdaterecipe.yml')
    def update_recipe(category_id, recipe_id):
        """The function updates a recipe"""
        token = check_token()
        if token:
            try:
                user_id = Users.decode_token(token)
                data = request.json
                # check that the expected data is present
                expected_data = check_data_keys(data,
                                                ['recipe_name',
                                                 'recipe_category_id',
                                                 'ingredients',
                                                 'description'
                                                 ])
                # check that the data are strings and are not empty
                check_response = check_values(
                    {'recipe_name': data['recipe_name'],
                     'ingredients': data['ingredients'],
                     'description': data['description']
                     })
                if check_response and expected_data:
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
                            user_recipe.rec_name = valid_data[
                                'recipe_name']
                            user_recipe.rec_cat = category_id
                            user_recipe.rec_ingredients = valid_data[
                                'ingredients'],
                            user_recipe.rec_description = valid_data[
                                'description']
                            user_recipe.rec_cat = data['recipe_category_id']
                            # -------
                            # commit the updates
                            user_recipe.update()
                            # return response
                            return jsonify(
                                {'recipe_id': user_recipe.rec_id,
                                    'recipe_name': user_recipe.rec_name,
                                    'category': user_recipe.rec_cat,
                                    'description': user_recipe.rec_description,
                                    'recipe_ingredients':
                                    user_recipe.rec_ingredients.split(','),
                                    'message': 'Recipe updated'}), 201
                        return jsonify({'Error': 'Recipe not found'}), 404
                    return jsonify({'Error': 'category not found'}), 404
                else:
                    return jsonify(error), 400

            except KeyError as ex:
                return jsonify({'Error': str(ex).strip('\'')+' key missing'}), 400
            except IntegrityError:
                return jsonify({'Error': 'Recipe name already exists'}), 409
            # capture value error
            except ValueError as ex:
                return jsonify({'Error': 'Invalid entry, please provide the ' +
                                'category id as integer while recipe name ' +
                                'and ingredients as string'}), 400
            # capture bad request
            except BadRequest:
                    return jsonify({'Error': 'Please parse category id, ' +
                                    'recipe name and ingredients'}), 400
            # get any other exception
            except Exception as ex:
                import traceback
                traceback.print_exc()
                return jsonify({'Error': str(ex)}), 400
        return jsonify(error), 401

    # TODO remove the category_id from the route
    @app.route('/category/<int:category_id>/recipes/<int:recipe_id>',
               methods=['DELETE'])
    @login_required
    @swag_from('/app/docs/recipesdeleterecipe.yml')
    def delete_recipe(category_id, recipe_id):
        """The function delete a recipe"""
        token = check_token()
        if token:
            try:
                # get the user id from the token
                user_id = Users.decode_token(token)
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
                        return jsonify({'message': 'recipe deleted'}), 200
                    return jsonify({'Error': 'Recipe not found'}), 404
                return jsonify({'message': 'Category not found'}), 404
            # capture value error
            except ValueError as ex:
                return jsonify({'Error': 'Invalid entry, please provide the ' +
                                'category id and recipe id as integers'}), 400
            # capture bad request
            except BadRequest:
                    return jsonify({'Error': 'Please parse the recipe id ' +
                                    'and category id'}), 400
            # get any other exception
            except Exception as ex:
                return jsonify({'Error': str(ex)}), 400
        return jsonify(error), 401

    @app.route('/category/<int:category_id>/recipes/', methods=['GET'])
    @login_required
    @swag_from('/app/docs/recipesviewcategoryrecipes.yml')
    def view_category_recipes(category_id):
        """The function return recipes in a category"""
        token = check_token()
        if token:
            try:
                # get user id from the token
                user_id = Users.decode_token(token)
                # page number to go to
                page = int(request.args.get('page', 1))
                # number of items per page
                per_page = int(request.args.get('per_page', 5))
                # get user category object based on user
                user_categories = Category.query.filter_by(
                    cat_id=category_id, user_id=user_id).first()
                # check user categories object is not None
                if user_categories is not None:
                    # get recipe object
                    user_recipes = Recipes.query.filter_by(
                        rec_cat=category_id).paginate(page, per_page, False)
                    # check recipes object is not None
                    if user_recipes.items:
                        # -----pagination properties----
                        current_page = user_recipes.page
                        number_of_pages = user_recipes.pages
                        next_page = user_recipes.next_num
                        previous_page = user_recipes.prev_num
                        # -----
                        if page <= number_of_pages:
                            # a list of all recipe dictionary
                            results = []
                            # loop through the paginated recipes object
                            for recipe in user_recipes.items:
                                # for each recipe store in dictionary
                                result = {
                                    'id': recipe.rec_id,
                                    'recipe_name': recipe.rec_name,
                                    'description': recipe.rec_description,
                                    'ingredients':
                                    recipe.rec_ingredients.split(",")
                                }
                                # append the dictionary to list
                                results.append(result)
                            # return the response with list of recipes
                            return jsonify({'recipes': results,
                                            'count': str(len(results)),
                                            'current_page': current_page,
                                            'number_of_pages': number_of_pages,
                                            'category_name':
                                            user_categories.cat_name,
                                            'next_page': next_page,
                                            'previous_page': previous_page,
                                            'message': 'recipes found'}), 200
                        return jsonify({'message': 'Page not found'}), 404
                    return jsonify({'message': 'no recipes found'}), 404
                return jsonify({'message': 'category not found'}), 404
            # capture value error
            except ValueError as ex:
                return jsonify({'Error': 'Invalid entry, please provide the ' +
                                'category id as integer while recipe name ' +
                                'and ingredients as string'}), 400
            # capture bad request
            except BadRequest:
                    return jsonify({'Error': 'Please parse the recipe id'}), 400
            # get any other exception
            except Exception as ex:
                import traceback
                traceback.print_exc()
                return jsonify({'Error': str(ex)}), 400
        return jsonify(error), 401

    @app.route('/category/<int:category_id>/recipes/<int:recipe_id>/one/',
               methods=['GET'])
    @login_required
    @swag_from('/app/docs/recipesviewonerecipe.yml')
    def view_one_recipe(category_id, recipe_id):
        """The function returns one recipe"""
        # check token
        token = check_token()
        # continue if present
        if token:
            try:
                user_id = Users.decode_token(token)
                # get user category object based on user
                user_categories = Category.query.filter_by(
                    cat_id=category_id, user_id=user_id).first()
                # check user categories object is not None
                if user_categories is not None:
                    # get recipe object
                    user_recipes = Recipes.query.filter_by(
                        rec_cat=category_id, rec_id=recipe_id)
                    # user_recipes = Recipes.query.filter_by(rec_id=recipe_id)
                    # if the recipes is not None
                    if user_recipes is not None:
                        # list in which dictionaries of recipes will be stored
                        results = []
                        # loop though the recipes
                        for recipe in user_recipes:
                            result = {
                                'id': recipe.rec_id,
                                'recipe_name': recipe.rec_name,
                                'description': recipe.rec_description,
                                'ingredients':
                                recipe.rec_ingredients.split(",")
                            }
                            results.append(result)
                        return jsonify({'recipes': results,
                                        'message': 'recipe found',
                                        'count': len(results)}), 200
                    return jsonify({'message': 'no recipes found'}), 404
            # capture value error
            except ValueError as ex:
                return jsonify({'Error': 'Invalid entry, please provide the ' +
                                'category id and recipe id as integers'}), 400
            # capture bad request
            except BadRequest:
                    return jsonify({'Error': 'Please parse the recipe id and ' +
                                    'category id'}), 400
            # get any other exception
            except Exception as ex:
                return jsonify({'Error': str(ex)}), 400
        return jsonify(error), 401

    @app.route('/recipes/search/', methods=['GET'])
    @login_required
    @swag_from('/app/docs/recipessearchrecipes.yml')
    def search_recipes():
        """The function searches and returns recipes in the database"""
        token = check_token()
        if token:
            try:
                # TODO validate the search parameters
                q = str(request.args.get('q', '')).title()
                page = int(request.args.get('page', 1))
                per_page = int(request.args.get('per_page', 5))
                user_id = Users.decode_token(token)
                # check if q is a string and not empty
                check_response = check_values({'q': q})
                if check_response:
                    # query for recipes that a closely related searched string
                    found_recipes = Category.query.join(
                        Recipes,
                        Category.cat_id == Recipes.rec_cat).add_columns(
                            Category.cat_id, Category.user_id,
                            Category.cat_name, Recipes.rec_id,
                            Recipes.rec_name, Recipes.rec_description,
                            Recipes.rec_ingredients).filter(
                                Category.user_id == user_id).filter(
                                    Recipes.rec_name.ilike('%'+q+'%')).paginate(
                                        page, per_page, False)
                    current_page = found_recipes.page
                    number_of_pages = found_recipes.pages
                    next_page = found_recipes.next_num
                    previous_page = found_recipes.prev_num
                    if page <= number_of_pages:
                        results = []
                        for recipe in found_recipes.items:
                            print('=====', recipe)
                            result = {
                                'category_id': recipe.cat_id,
                                'category_name': recipe.cat_name,
                                'recipe_id': recipe.rec_id,
                                'recipe_name': recipe.rec_name,
                                'description': recipe.rec_description,
                                'recipes_ingredients': recipe.rec_ingredients
                            }
                            results.append(result)
                        return jsonify({'categories': results,
                                        'count': str(len(results)),
                                        'current_page': current_page,
                                        'number_of_pages': number_of_pages,
                                        'next_page': next_page,
                                        'previous_page': previous_page,
                                        'message': 'Recipes found'}), 200
                    return jsonify({'Error': 'Page not found'}), 404
                return jsonify(error), 400
            # capture value error
            except ValueError as ex:
                return jsonify({'Error': 'Invalid entry, please provide ' +
                                'q as a string'}), 400
            # capture bad request
            except BadRequest:
                    return jsonify({'Error': 'Please parse the q ' +
                                    'parameter'}), 400
            # get any other exception
            except Exception as ex:
                import traceback
                traceback.print_exc()
                return jsonify({'Error': str(ex)}), 400
        return jsonify(error), 401
