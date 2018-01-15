from tests.test_base import BaseTestCase
import json


class TestRecipes(BaseTestCase):
    # -----recipe tests
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
                                                 description=self.test_recipe_description,
                                                 ingredients="beef, onions")))
            reply = json.loads(response.data.decode())
            self.assertEqual(reply['message'], 'Recipe created')

    def test_view_recipe_in_category(self):
        """
        Test viewing recipes in a category with pagination
        """
        self.create_user()
        self.create_category()
        self.create_recipe()
        with self.client:
            headers = self.helper_login_with_token()
            response = self.client.get('/category/recipes/1',
                                       content_type='application/json',
                                       headers=headers)
            reply = json.loads(response.data.decode())
            self.assertEqual(reply['count'], '1')
            self.assertEqual(reply['number_of_pages'], 1)
            self.assertEqual(reply['current_page'], 1)
            self.assertEqual(reply['next_page'], None)
            self.assertEqual(reply['previous_page'], None)
            self.assertTrue(reply['recipes'], msg='no recipes')

    def test_view_recipe_from_unknown_category(self):
        """
        Test viewing recipe in a category that doesnot exits
        """
        self.create_user()
        self.create_category()
        self.create_recipe()
        with self.client:
            headers = self.helper_login_with_token()
            response = self.client.get('/category/recipes/2',
                                       content_type='application/json',
                                       headers=headers)
            reply = json.loads(response.data.decode())
            self.assertEqual(reply['message'], 'category not found')

    def test_updating_known_recipe(self):
        """
        Test updating recipe with a known id (key)
        """
        self.create_user()
        self.create_category()
        self.create_recipe()
        with self.client:
            headers = self.helper_login_with_token()
            response = self.client.put('/category/recipes/1/1',
                                       content_type='application/json',
                                       headers=headers,
                                       data=json.dumps(
                                           dict(recipe_name="Ugandan beef",
                                                recipe_category_id=1,
                                                description=self.test_recipe_description,
                                                ingredients="beef, onions")))
            reply = json.loads(response.data.decode())
            self.assertEqual(reply['message'], 'Recipe updated')

    def test_updating_unknown_recipe(self):
        self.create_user()
        self.create_category()
        self.create_recipe()
        with self.client:
            headers = self.helper_login_with_token()
            response = self.client.put('/category/recipes/1/1',
                                       content_type='application/json',
                                       headers=headers,
                                       data=json.dumps(
                                           dict(recipe_name="Ugandan beef",
                                                recipe_category_id=1,
                                                description=self.test_recipe_description,
                                                ingredients="beef, onions")))
            reply = json.loads(response.data.decode())
            print('----', reply)
            self.assertEqual(reply['message'], 'Recipe updated')

    def test_deleting_known_recipe(self):
        self.create_user()
        self.create_category()
        self.create_recipe()
        with self.client:
            headers = self.helper_login_with_token()
            response = self.client.delete('/category/recipes/1/1',
                                          content_type='application/json',
                                          headers=headers,
                                          data=json.dumps(
                                              dict(recipe_name="Ugandan beef")))
            self.assertEquals(response.status_code, 204)

    def test_deleting_unknown_recipe(self):
        self.create_user()
        self.create_category()
        self.create_recipe()
        with self.client:
            headers = self.helper_login_with_token()
            response = self.client.delete('/category/recipes/1/2',
                                          content_type='application/json',
                                          headers=headers,
                                          data=json.dumps(
                                              dict(recipe_name="Ugandan beef")))
            reply = json.loads(response.data.decode())
            self.assertEqual(reply['message'], 'Recipe not found')

    def test_deleting_recipe_from_unknown_category(self):
        self.create_user()
        self.create_category()
        self.create_recipe()
        with self.client:
            headers = self.helper_login_with_token()
            response = self.client.delete('/category/recipes/2/1',
                                          content_type='application/json',
                                          headers=headers,
                                          data=json.dumps(
                                              dict(recipe_name="Ugandan beef")))
            reply = json.loads(response.data.decode())
            self.assertEqual(reply['message'], 'Category not found')

    def test_deleting_unknown_category(self):
        self.create_user()
        self.create_category()
        self.create_recipe()
        with self.client:
            headers = self.helper_login_with_token()
            response = self.client.delete('/category/2',
                                          content_type='application/json',
                                          headers=headers,
                                          data=json.dumps(
                                              dict(category_name="Meat")))
            reply = json.loads(response.data.decode())
            self.assertEqual(reply['message'], 'category not found')

    def test_deleting_known_category(self):
        self.create_user()
        self.create_category()
        self.create_recipe()
        with self.client:
            headers = self.helper_login_with_token()
            response = self.client.delete('/category/1',
                                          content_type='application/json',
                                          headers=headers,
                                          data=json.dumps(
                                              dict(category_name="Meat")))
            self.assertEqual(response.status_code, 204)
