import unittest
from app import app, db, models
import json
from werkzeug.security import generate_password_hash
from datetime import datetime
from flask_testing import TestCase


class TestYummyApi(TestCase):
    test_user = "user"
    test_user_password = "pass"
    test_user_name = "user's name"
    test_category_name = "Meat"
    test_recipe = "local beef"
    test_recipe_ingredients = "onions, meat, tomatoes"

    def create_app(self):
        return app

    def create_user(self):
        user = models.User(name=self.test_user,
                           password=generate_password_hash(self.test_user_password))
        user.add()

    def create_category(self):
        category = models.Category(user_id=1,
                               cat_name=self.test_category_name)
        category.add()

    def create_recipe(self):
        recipe = models.Recipes(name=self.test_category,
                           category=1,
                           ingredients=self.test_recipe_ingredients)
        recipe.add()

    def setUp(self):
        db.create_all()
        db.session.commit()

    def tearDown(self):
        db.session.remove()
        db.drop_all()

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


    """
    def test_user_existing_account(self):
        self.create_user()
        with self.client:
            response = self.client.po
    """
if __name__ == "__main__":
    unittest.main()
