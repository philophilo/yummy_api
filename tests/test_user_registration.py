from tests.test_base import BaseTestCase
import json


class TestUserRegistration(BaseTestCase):
    # testing user registration
    def test_user_can_register(self):
        with self.client:
            response = self.client.post('/auth/register',
                                        content_type='application/json',
                                        data=json.dumps(
                                            dict(username="user",
                                                 name="fname lname",
                                                 password="Pass1!")))
            reply = json.loads(response.data.decode())
            self.assertEqual(reply['username'], "user", msg="username key fail")

    def test_existing_user_account(self):
        self.create_user()
        with self.client:
            response = self.client.post('/auth/register',
                                        content_type='application/json',
                                        data=json.dumps(dict(username='user',
                                                             name='fname lname',
                                                             password='Pass1!'
                                                             )))
            reply = json.loads(response.data.decode())
            self.assertEqual(reply['Error'], 'The username already exits')

    def test_wrong_user_login_credentials(self):
        self.create_user()
        with self.client:
            response = self.client.post('/auth/login',
                                        content_type='application/json',
                                        data=json.dumps(
                                            dict(username='user1',
                                                 password='password')))
            reply = json.loads(response.data.decode())
            self.assertTrue(reply['Error'], 'Incorrect username or password')
