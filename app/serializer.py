from flask import request
from app.models.users import Users
import re
from jwt import ExpiredSignatureError, InvalidTokenError

error = {}
valid_data = {}


def check_empty_spaces(string):
    """ Check if a string still has any empty spaces"""
    # split the string into chuncks
    string = string.strip()
    split_string = string.split(" ")
    # get the length of chunks extructed
    number_of_splits = len(split_string)
    # keep track of the empty chunks
    empty_chunks = 0
    # for each of the chuncks get the length
    for i in split_string:
        if len(i) == 0:
            empty_chunks += 1
    # if the string is completely empty return False
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
        return False
    except ExpiredSignatureError as ex:
        error['Error'] = 'The token is expired'
        return False
    except AttributeError:
        error['Error'] = 'Please provide a token'
        return False
    except ValueError:
        error['Error'] = "you sent an invalid token"
        return False
    except Exception as ex:
        error['Error'] = str(ex)
        return False


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


def validate_username(username):
    """ Validate username constraints """
    if check_username(username):
        if check_username_upper_limit(username):
            if check_username_lower_limit(username):
                return True
            error['Error'] = 'Username cannot be less than 4'
        error['Error'] = 'Username must be ' \
            'less than 20'
    error['Error'] = 'username can have ' \
        'alphabets, numbers' \
        ' and selected symbols(\'_ and -\')'


def validate_name(fullname):
    """Validate full name constraints"""
    if check_fullname(fullname):
        if check_upper_limit_fullname(fullname):
            if check_lower_limit_fullname(fullname):
                return True
            error['Error'] = 'Firstname and Lastname cannot be ' \
                'less than 4 characters'
        error['Error'] = 'Firstname and lastname cannot be more ' \
            'than 50 characters'
    error['Error'] = 'Your firstname and lastname must ' \
        'be seperated by a space'
    return False


def validate_email(email):
    """Validate user email addresses"""
    if re.match(r'[a-zA-Z0-9.-]+@[a-z]+\.[a-z]+', email):
        return True
    error['Error'] = 'Invalid email address'
    return False


def validate_descriptions(description):
    """Validate item description"""
    if len(description) <= 200:
        return True
    error['Error'] = 'Description is too long'
    return False


def validate_password(password):
    """Validate password constraints"""
    if check_password(password):
        if check_password_upper_limit(password):
            if check_password_lower_limit(password):
                return True
            else:
                error['Error'] = 'Password cannot be less than 6 characters'
        else:
            error['Error'] = 'Password cannot be more than 50 characters'
    else:
        error['Error'] = 'Password must have atleast one Block letter, ' \
                 'a number and a symbol'
    return False


def validate_item_names(name):
    """Validate item names"""
    if check_string(name):
        if check_item_name_alphabet(name):
            if check_item_name_upper_limit(name):
                if check_item_name_lower_limit(name):
                    return True
                else:
                    error['Error'] = 'The name cannot have less than ' \
                             '4 characters'
            else:
                error['Error'] = 'The name cannot be more than 6' \
                         '6 characters'
        else:
            error['Error'] = 'The name must be from alphabetical letters'
    else:
        error['Error'] = 'The name must be a string'


def check_data_keys(data, expected_keys):
    """Check if expected are present in received data"""
    for key in expected_keys:
        if key not in data:
            error['Error'] = key+' key missing'
            return False
    return True
