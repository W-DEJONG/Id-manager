import functools

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from flask import request, current_app, abort
from flask_login import LoginManager, current_user
from flask_wtf import CSRFProtect

csrf = CSRFProtect()
hash_provider = PasswordHasher()
login_manager = LoginManager()
login_manager.login_view = "manager.routes.auth.login"


def hash_pwd(pwd):
    return hash_provider.hash(pwd)


def verify_pwd(stored_hash, pwd):
    try:
        hash_provider.verify(stored_hash, pwd)
        return True
    except VerifyMismatchError:
        return False


def roles_required(roles_str='', operator='AND'):
    def wrapper(f):
        @functools.wraps(f)
        def decorated(*args, **kwargs):
            if request.method in set(['OPTIONS']):
                return f(*args, **kwargs)
            elif not current_user.is_authenticated:
                return current_app.login_manager.unauthorized()
            elif not current_user.roles.validate_roles(roles_str, operator):
                abort(401)
            return f(*args, **kwargs)

        return decorated

    return wrapper
