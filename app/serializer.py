from flask import request
from app.models.users import Users
import re
from jwt import ExpiredSignatureError, InvalidTokenError

error = {}
valid_data = {}


def check_empty_spaces(string):
    """ Check if a string still has any empty spaces"""
    string = string.strip()
    split_string = string.split(" ")
    number_of_splits = len(split_string)
    empty_chunks = 0
    for i in split_string:
        if len(i) == 0:
            empty_chunks += 1
    if empty_chunks == number_of_splits:
        return False
    return string


def check_values(details):
    """check that the value is strictly a string"""
    for key, value in details.items():
        if(isinstance(value, str)):
            # strip strings of white spaces
            cleaned_value = check_empty_spaces(value)
            if not cleaned_value:
                error['Error'] = key+' is empty'
                return False
            valid_data[key] = cleaned_value
        else:
            error['Error'] = key+' is not a string'
            return False
    return True


def check_token():
    """check token validity"""
    token = None
    try:
        auth_header = request.headers.get('Authorization')
        token = auth_header.split(" ")[1]
        if Users.decode_token(token):
            return token
    except InvalidTokenError:
        error['Error'] = 'Invalid token'
    except ExpiredSignatureError as ex:
        error['Error'] = 'The token is expired'
    except AttributeError:
        error['Error'] = 'Please provide a token'


def handle_exceptions(ex, expected):
    if ex in expected:
        return expected[ex]
    return {'Error': str(ex)}


def check_fullname(name):
    """ Check firstname and lastname seperated by space"""
    if re.match("([a-zA-Z]+) ([a-zA-Z]+)$", name):
        return True


def check_upper_limit_fullname(name):
    """ checks maximum length of name """
    if len(name) <= 50:
        return True


def check_lower_limit_fullname(name):
    """ checks minimum length of name """
    if len(name) >= 4:
        return True


def check_username(username):
    """check valid username"""
    if re.match("^[a-zA-Z0-9_-]+$", username):
        return True


def check_username_upper_limit(username):
    """check the upper limit of the username"""
    if len(username) <= 20:
        return True


def check_username_lower_limit(username):
    """check the lower limit of the username"""
    if len(username) >= 4:
        return True


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


def check_password_upper_limit(password):
    """check the upper limit of password"""
    print(len(password), '.....')
    if len(password) <= 50:
        return True


def check_password_lower_limit(password):
    """check the lower mimit of the password"""
    if len(password) >= 6:
        return True


def check_item_name_alphabet(name):
    """check whether name is alphabetical"""
    if re.match("^[a-zA-Z ]+$", name):
        return True


def check_item_name_upper_limit(name):
    """check the upper limit of a name"""
    if len(name) <= 20:
        return True


def check_item_name_lower_limit(name):
    """ check the lower limit of a name"""
    if len(name) >= 4:
        return True


def validate_username(username):
    """ Validate username constraints """
    if check_username(username):
        if check_username_upper_limit(username) and \
                check_username_lower_limit(username):
            return True
        error['Error'] = 'Username can have between 4 and 20 characters'
        return False
    error['Error'] = 'username can have ' \
        'alphabets, numbers and selected symbols(\'_ and -\')'
    return False


def validate_name(fullname):
    """Validate full name constraints"""
    if check_fullname(fullname):
        if check_upper_limit_fullname(fullname) and \
                check_lower_limit_fullname(fullname):
            return True
        error['Error'] = 'Firstname and Lastname cannot be less than 4'
        return False
    error['Error'] = 'Your firstname and lastname must ' \
        'be alphabetical and seperated by a space'
    return False


def validate_email(email):
    """Validate user email addresses"""
    if re.match(r'[a-zA-Z0-9.-]+@[a-z]+\.[a-z]+', email):
        return True
    error['Error'] = 'Invalid email address'


def validate_descriptions(description):
    """Validate item description"""
    if len(description) <= 200:
        return True
    error['Error'] = 'Description is too long'


def validate_password(password):
    """Validate password constraints"""
    if check_password(password):
        if check_password_upper_limit(password) and \
                check_password_lower_limit(password):
            return True
        error['Error'] = 'Password can have between 6 and 50 characters'
        return False
    error['Error'] = 'Password must have atleast one Block letter, ' \
        'a number and a symbol'
    return False


def validate_item_names(name):
    """Validate item names"""
    print(name, '**********')
    if isinstance(name, str) and check_item_name_alphabet(name):
        if check_item_name_upper_limit(name) and \
                check_item_name_lower_limit(name):
            return True
        error['Error'] = 'The name should have between 4 and 20 characters'
        return False
    error['Error'] = 'The name must be from alphabetical letters'
    return False


def check_data_keys(data, expected_keys):
    """Check if expected are present in received data"""
    for key in expected_keys:
        if key not in data:
            error['Error'] = key+' key missing'
            return False
    return True


def validation(data, expected):
    """Checks for expected data values"""
    data_keys = check_data_keys(data, expected)
    if data_keys and check_values(data):
        return True

def valid_register():
    print(valid_data['password'], '========')
    if validate_username(valid_data['username']) and validate_name(
        valid_data['name']) and validate_password(valid_data[
            'password']) and validate_email(valid_data['email']):
        return True
