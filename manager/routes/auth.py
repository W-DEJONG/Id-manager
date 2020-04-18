import flask
from flask import Blueprint, request, render_template, flash, redirect, url_for, session
from uuid import uuid4
from flask_login import login_user, current_user, logout_user
from manager.auth import login_manager, verify_pwd, hash_pwd
from manager.models import db, User
from manager.auth import roles_required

bp = Blueprint(__name__, 'auth')


@login_manager.user_loader
def load_user(user_id):
    return User.query.filter_by(login_id=user_id).first()


@bp.route('/auth/login', methods=('GET', 'POST'))
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        remember_me = 'remember_me' in request.form
        if not username:
            error = 'Username is required.'
        elif not password:
            error = 'Password is required.'
        else:
            user = User.query.filter_by(username=username).first()
            if user:
                if verify_pwd(user.password, password):
                    login_user(user, remember=remember_me)
                    if 'next' in session:
                        next_uri = session['next']
                        del session['next']
                    else:
                        next_uri = '/'
                    return flask.redirect(next_uri)
            error = 'Invalid credentials'
        flash(error)
    return render_template('auth/login.html', user=current_user)


@bp.route('/auth/logout', methods=('GET', 'POST'))
def logout():
    user = current_user
    if user.is_authenticated:
        user.login_id = str(uuid4())
        db.session.commit()
    logout_user()
    return render_template('auth/logout.html')


@bp.route('/auth/create-account', methods=('GET', 'POST'))
@roles_required('admin')
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
