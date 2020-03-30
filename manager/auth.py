from argon2.exceptions import VerifyMismatchError
from flask import Blueprint, request, render_template, flash, redirect, url_for, session
from argon2 import PasswordHasher
from uuid import uuid4
from .models import db, User

bp = Blueprint(__name__, 'accounts')

hash_provider = PasswordHasher()


def hash_pwd(pwd):
    return hash_provider.hash(pwd)


def verify_pwd(stored_hash, pwd):
    try:
        hash_provider.verify(stored_hash, pwd)
        return True
    except VerifyMismatchError:
        return False


def current_user():
    if 'id' in session:
        uid = session['id']
        return User.query.get(uid)
    return None




@bp.route('/auth/create-account', methods=('GET', 'POST'))
def create_account():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        if not username:
            error = 'Username is required.'
        elif not password:
            error = 'Password is required.'
        else:
            user = User.query.filter_by(username=username).first()
            if not user:
                user = User(
                    uuid=str(uuid4()),
                    username=username,
                    password=hash_pwd(password)
                )
                db.session.add(user)
                db.session.commit()
                return redirect(url_for('manager.auth.login'))
            error = 'User {} is already registered.'.format(username)
        flash(error)

    return render_template('auth/create_account.html')
