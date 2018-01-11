from tests.test_base import BaseTestCase
import json


class TestDeleteAccount(BaseTestCase):
    # ---delete account tests
    def test_deleting_account_without_password_key(self):
        self.create_user()
        self.create_category()
        self.create_recipe()
        with self.client:
            headers = self.helper_login_with_token()
            response = self.client.delete('/auth/delete-account',
                                          content_type='application/json',
                                          headers=headers)
            reply = json.loads(response.data.decode())
            self.assertEqual(reply['Error'], 'Please create a ' +
                             'password key and value')

    def test_deleting_account_with_empty_password_value(self):
        self.create_user()
        with self.client:
            headers = self.helper_login_with_token()
            response = self.client.delete('/auth/delete-account',
                                          content_type='application/json',
                                          headers=headers,
                                          data=json.dumps(
                                              dict(password='')))
            reply = json.loads(response.data.decode())
            self.assertEqual(reply['Error'], 'Please provide a password ' +
                             'key and value')

    def test_deleting_account_with_wrong_password(self):
        self.create_user()
        with self.client:
            headers = self.helper_login_with_token()
            response = self.client.delete('/auth/delete-account',
                                          content_type='application/json',
                                          headers=headers,
                                          data=json.dumps(
                                            dict(password='p')))
            reply = json.loads(response.data.decode())
            self.assertEqual(reply['Error'], 'Incorrect password')

    def test_deleting_account_successfully(self):
        self.create_user()
        with self.client:
            headers = self.helper_login_with_token()
            response = self.client.delete('/auth/delete-account',
                                          content_type='application/json',
                                          headers=headers,
                                          data=json.dumps(
                                              dict(password='pass')))
            self.assertEqual(response.status_code, 204)
