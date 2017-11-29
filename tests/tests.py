import unittest
from app import app, db, models
import json
from werkzeug.security import generate_password_hash
from datetime import datetime
from flask_testing import TestCase


class TestYummyApi(TestCase):
    test_user = "user"
    test_user_password = "pass"
    test_user_name = "name"
    test_category_name = "Meat"
    test_recipe = "local beef"
    test_recipe_ingredients = "onions, meat, tomatoes"

    # function required by flask-testing
    def create_app(self):
        return app

    # defined functions
    def create_user(self):
        user = models.Users(username=self.test_user,
                            name=self.test_user_name,
                            password=generate_password_hash(
                                self.test_user_password))
        user.add()

    def create_category(self):
        category = models.Category(user_id=1,
                                   cat_name=self.test_category_name)
        category.add()

    def create_recipe(self):
        recipe = models.Recipes(name=self.test_recipe,
                                category=1,
                                ingredients=self.test_recipe_ingredients,
                                date=datetime.now())
        recipe.add()

    def helper_login(self):
        response = self.client.post('/auth/login',
                                    content_type='application/json',
                                    data=json.dumps(
                                        dict(username='user',
                                             password="pass")))
        return response

    def helper_login_with_token(self):
        reply = json.loads(self.helper_login().data.decode())
        bearer = 'Bearer {}'.format(reply['token'])
        headers = {'Authorization': bearer}
        return headers

    def setUp(self):
        db.create_all()
        db.session.commit()

    def tearDown(self):
        db.session.remove()
        db.drop_all()

    # testing user registration
    def test_user_can_register(self):
        with self.client:
            response = self.client.post('/auth/register',
                                        content_type='application/json',
                                        data=json.dumps(
                                            dict(username="user",
                                                 name="name",
                                                 password="pass")))
            reply = json.loads(response.data.decode())
            self.assertEqual(reply['username'], "user", msg="username key fail")

    def test_existing_user_account(self):
        self.create_user()
        with self.client:
            response = self.client.post('/auth/register',
                                        content_type='application/json',
                                        data=json.dumps(dict(username='user',
                                                             name='name',
                                                             password='pass')))
            reply = json.loads(response.data.decode())
            self.assertEqual(reply['message'], 'The username already exits')

    def test_wrong_user_login_credentials(self):
        self.create_user()
        with self.client:
            response = self.client.post('/auth/login',
                                        content_type='application/json',
                                        data=json.dumps(
                                            dict(username='user1',
                                                 password='password')))
            reply = json.loads(response.data.decode())
            self.assertTrue(reply['message'], 'Incorrect username or password')

    def test_create_category(self):
        self.create_user()
        with self.client:
            headers = self.helper_login_with_token()
            response = self.client.post('/category',
                                        content_type='application/json',
                                        headers=headers,
                                        data=json.dumps(
                                            dict(category_name='Meat')))
            reply = json.loads(response.data.decode())
            self.assertEqual(reply['category_name'], "Meat")
            self.assertEqual(reply['message'], 'category created')
            self.assertTrue(reply['id'], msg='no id')

    def test_view_categories(self):
        self.create_user()
        self.create_category()
        with self.client:
            headers = self.helper_login_with_token()
            response = self.client.get('/category',
                                       content_type='application/json',
                                       headers=headers)
            reply = json.loads(response.data.decode())
            self.assertEqual(reply['count'], "1")
            self.assertEqual(reply['message'], 'categories found')
            self.assertTrue(reply['categories'], msg='no categories')

    def test_view_one_existing_category(self):
        self.create_user()
        self.create_category()
        with self.client:
            headers = self.helper_login_with_token()
            response = self.client.get('/category/1',
                                       content_type='application/json',
                                       headers=headers)
            reply = json.loads(response.data.decode())
            self.assertEqual(reply['count'], "1")
            self.assertEqual(reply['message'], 'category found')
            self.assertTrue(reply['category'], msg='no categories')

    def test_view_one_nonexisting_category(self):
        self.create_user()
        self.create_category()
        with self.client:
            headers = self.helper_login_with_token()
            response = self.client.get('/category/2',
                                       content_type='application/json',
                                       headers=headers)
            reply = json.loads(response.data.decode())
            self.assertEqual(reply['count'], "0")
            self.assertEqual(reply['message'], 'category not found')

    def test_updating_category(self):
        self.create_user()
        self.create_category()
        with self.client:
            headers = self.helper_login_with_token()
            response = self.client.put('/category/1',
                                       content_type='application/json',
                                       headers=headers,
                                       data=json.dumps(
                                           dict(category_name='local beef')))
            reply = json.loads(response.data.decode())
            self.assertEqual(reply['message'], 'category updated')
            self.assertTrue(reply['category'], msg='no categories')

    def test_updating_unknown_category(self):
        self.create_user()
        self.create_category()
        with self.client:
            headers = self.helper_login_with_token()
            response = self.client.put('/category/2',
                                       content_type='application/json',
                                       headers=headers,
                                       data=json.dumps(
                                           dict(category_name='local beef')))
            reply = json.loads(response.data.decode())
            self.assertEqual(reply['message'], 'category not found')

    def test_create_recipe(self):
        self.create_user()
        self.create_category()
        with self.client:
            headers = self.helper_login_with_token()
            response = self.client.post('/category/recipes/1',
                                        content_type='application/json',
                                        headers=headers,
                                        data=json.dumps(
                                            dict(recipe_name='ugandan meat',
                                                 ingredients="beef, onions")))
            reply = json.loads(response.data.decode())
            self.assertEqual(reply['message'], 'Recipe created')


if __name__ == "__main__":
    unittest.main()
