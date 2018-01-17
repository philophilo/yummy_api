from app import app
from flask import request, jsonify
from flasgger import swag_from
from app.models.category import Category
from app.models.users import Users
from flask_login import login_required
from sqlalchemy import and_
from sqlalchemy.exc import IntegrityError
from datetime import datetime
from werkzeug.exceptions import BadRequest
from app.serializer import (check_data_keys, check_values,
                            valid_data, validate_descriptions,
                            error,
                            check_token)


class CategoryView():
    """The class has views for categories"""
    @app.route('/category', methods=['POST'])
    @swag_from('/app/docs/categorycreatecategory.yml')
    def create_category():
        """The function creates a new category"""
        token = check_token()

        if token:
            user_id = Users.decode_token(token)
            try:
                data = request.json
                # check for expected data
                expected_data = check_data_keys(data,
                                                ['category_name',
                                                 'category_description'])
                # check that the expected data are strings and not empty
                check_response = check_values(data)
                if check_response and expected_data and \
                        validate_descriptions(
                            valid_data['category_description']):
                    # check if category name already exists
                    check_category = Category.query.filter_by(
                        user_id=int(user_id),
                        cat_name=valid_data['category_name']
                    ).first()
                    if check_category is None:
                        # create a the category object
                        category = Category(
                            user_id=int(user_id),
                            cat_name=valid_data['category_name'],
                            description=valid_data['category_description'],
                            date=datetime.now()
                        )
                        # add the object to the database
                        category.add()
                        # create response
                        response = jsonify({
                            'id': category.cat_id,
                            'category_name': category.cat_name,
                            'category_description': category.cat_description,
                            'message': 'category created'})
                        # return response
                        return response, 201
                    return jsonify({'Error': 'Category name ' +
                                    'already exists'}), 409
                return jsonify(error), 400
            except BadRequest:
                return jsonify({'Error': 'Please create a category name key ' +
                                'and value'}), 400
            except ValueError as ex:
                return jsonify({'Error': "you sent an " + str(ex)}), 400
            except Exception as ex:
                import traceback
                traceback.print_exc()
                return jsonify({'Error': str(ex)
                                }), 400
        return jsonify(error), 401

    @app.route('/category/', methods=['GET'])
    @login_required
    @swag_from('/app/docs/categoryviewallcategories.yml')
    def view_all_categories():
        """The function returns all categories"""
        token = check_token()
        if token:
            try:
                user_id = Users.decode_token(token)
                # page to retieve
                page = int(request.args.get('page', 1))
                # number of pages on the retrieved page
                per_page = int(request.args.get('per_page', 5))
                # check that user_id is an interger
                user_categories = Category.query.filter_by(
                    user_id=user_id).paginate(page, per_page, False)
                # check if the object is not None
                if user_categories.items:
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
                            'category_description': category.cat_description
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
                return jsonify({'message': 'no categories found'}), 404
            # capture value error
            except ValueError as ex:
                return jsonify({'Error': 'Invalid entry'}), 400
            # capture bad request
            except BadRequest:
                    return jsonify({'Error': 'Please parse the q ' +
                                    'parameter'}), 400
            except Exception as ex:
                return jsonify({'Error': str(ex)}), 400
        return jsonify(error), 401

    @app.route('/category/<int:category_id>', methods=['GET'])
    @login_required
    @swag_from('/app/docs/categoryviewacategory.yml')
    def view_a_category(category_id):
        """The function returns one category"""
        token = check_token()
        if token:
            try:
                user_id = Users.decode_token(token)
                # get the category object with category
                user_category = Category.query.filter_by(
                    cat_id=category_id, user_id=user_id).first()
                # check the category object is not empty
                if user_category is not None:
                    # create response
                    response = jsonify(
                        {'id': user_category.cat_id,
                         'category_name': user_category.cat_name,
                         'category_description': user_category.cat_description,
                         'message': 'category found'})
                    # return response
                    return response, 200
                return jsonify({'message': 'category not found'}), 404
            # get any other exception
            except Exception as ex:
                return jsonify({'Error': str(ex)}), 400
        return jsonify(error), 401

    @app.route('/category/<int:category_id>', methods=['PUT'])
    @login_required
    @swag_from('/app/docs/categoryupdateacategory.yml')
    def update_category(category_id):
        """The function updates a category"""
        # check token
        token = check_token()
        if token:
            try:
                data = request.json
                user_id = Users.decode_token(token)
                # check for expected data
                expected_data = check_data_keys(data, ['category_name',
                                                       'category_description'])
                # check that the data is a string and not empty
                check_response = check_values(data)
                if check_response and expected_data:
                    # get category object
                    user_category = Category.query.filter_by(
                        cat_id=category_id, user_id=user_id).first()
                    # check that the category object is not empty
                    if user_category is not None:
                        # update the the category name in the object
                        user_category.cat_name = valid_data["category_name"]
                        user_category.cat_description = valid_data[
                            "category_description"]
                        # commit the update to the database
                        user_category.update()
                        # create response
                        response = jsonify({
                            'id': user_category.cat_id,
                            'category_name': user_category.cat_name,
                            'category_description':
                            user_category.cat_description,
                            'message': 'category updated'})
                        # return the response
                        return response, 201
                    return jsonify({'message': 'category not found'
                                    }), 404
                else:
                    return jsonify(error), 400
            except IntegrityError:
                return jsonify({'Error': 'Recipe name already exists'}), 409
            # capture value error
            except ValueError as ex:
                return jsonify({'Error': 'Invalid entry, please provide the ' +
                                'category id as integer and catgory name as ' +
                                'string'}), 400
            # capture bad request
            except BadRequest:
                    return jsonify({'Error': 'Please parse both category id ' +
                                    'and category name'}), 400
            # get any other exception
            except Exception as ex:
                return jsonify({'Error': str(ex)}), 400
        return jsonify(error), 401

    @app.route('/category/<int:category_id>', methods=['DELETE'])
    @login_required
    @swag_from('/app/docs/categorydeletecategory.yml')
    def delete_category(category_id):
        """The function deletes a category"""
        token = check_token()
        if token:
            try:
                # get user id from token
                user_id = Users.decode_token(token)
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
            # capture value error
            except ValueError as ex:
                return jsonify({'Error': 'Invalid entry for category id'}), 400
            # capture bad request
            except BadRequest:
                    return jsonify({'Error': 'Please parse a category id'}), 400
            # get any other exception
            except Exception as ex:
                return jsonify({'message': str(ex)}), 400
        return jsonify(error), 401

    @app.route('/category/search/', methods=['GET'])
    @login_required
    @swag_from('/app/docs/categorysearchcategories.yml')
    def search_categories():
        """The function searches and returns categories"""
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
                    # get category object
                    user_categories = Category.query.filter(and_(
                        Category.user_id == user_id,
                        Category.cat_name.ilike('%'+q+'%'))).paginate(
                            page, per_page, False)
                    # check the object id not None
                    if user_categories.items:
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
                                        'message': 'Categories found'}), 200
                    return jsonify({'Error': 'category not found'}), 404
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
