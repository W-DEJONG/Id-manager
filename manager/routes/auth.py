from flask import Blueprint, request, render_template, flash, redirect, url_for, session
from uuid import uuid4
from flask_login import login_user, current_user, logout_user, login_required
from flask_wtf import FlaskForm
from wtforms import StringField, BooleanField, PasswordField
from wtforms.fields.html5 import EmailField
from wtforms.validators import Length, InputRequired, Email
from manager.auth import login_manager, verify_pwd, hash_pwd
from manager.models import db, User
from manager.auth import roles_required

bp = Blueprint(__name__, 'auth', url_prefix='/auth')


@login_manager.user_loader
def load_user(user_id):
    return User.query.filter_by(login_id=user_id).first()


class LoginForm(FlaskForm):
    username = StringField('username', validators=[Length(min=2, max=200), InputRequired()])
    password = PasswordField('password', validators=[Length(min=5, max=200), InputRequired()])
    remember_me = BooleanField('remember_me')


class ProfileForm(FlaskForm):
    given_name = StringField('Given name', validators=[Length(min=0, max=255), InputRequired()])
    middle_name = StringField('middle_name', validators=[Length(min=0, max=255)])
    family_name = StringField('family_name', validators=[Length(min=0, max=255)])
    nickname = StringField('nickname', validators=[Length(min=0, max=255)])
    email = StringField('email', validators=[Length(min=0, max=255), Email(), InputRequired()])


@bp.route('/login', methods=('GET', 'POST'))
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if verify_pwd(user.password, form.password.data):
                login_user(user, remember=form.remember_me.data)
                if 'next' in session:
                    next_uri = session['next']
                    del session['next']
                else:
                    next_uri = url_for('.user_profile')
                return redirect(next_uri)
        error = 'Invalid credentials'
        flash(error)
    return render_template('auth/login.html', user=current_user, form=form)


@bp.route('/logout', methods=('GET', 'POST'))
def logout():
    user = current_user
    if user.is_authenticated:
        user.login_id = str(uuid4())
        db.session.commit()
    logout_user()
    return render_template('auth/logout.html')


class CreateAccountForm(FlaskForm):
    username = StringField('User name', validators=[Length(min=2, max=200), InputRequired()])
    email = EmailField('Email', validators=[Length(min=0, max=255), Email(), InputRequired()])
    password = PasswordField('Password', validators=[Length(min=5, max=200), InputRequired()])
    repeat_password = PasswordField('Repeat password', validators=[Length(min=5, max=200), InputRequired()])

    def validate_repeat_password(self, field):
        if self.password.data != field.data:
            raise ValueError("Passwords don't match!")

    def validate_username(self, field):
        user = User.query.filter_by(username=field.data).first()
        if user:
            raise ValueError("User already exists!")


@bp.route('/create-account', methods=('GET', 'POST'))
@roles_required('admin')
def create_account():
    form = CreateAccountForm()
    if form.validate_on_submit():
        user = User(
            uuid=str(uuid4()),
            login_id=str(uuid4()),
            username=form.username.data,
            password=hash_pwd(form.password.data),
            email=form.email.data,
            locale='NL',
            server_roles='connect'
        )
        db.session.add(user)
        db.session.commit()
        return redirect(url_for('.user_profile'))
    return render_template('auth/create_account.html', user=current_user, form=form)

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
                return redirect(url_for('.login'))
            error = 'User {} is already registered.'.format(username)
        flash(error)

    return render_template('auth/create_account.html')


@bp.route('/user-profile', methods=('GET', 'POST'))
@login_required
def user_profile():
    user = current_user
    form = ProfileForm(obj=user)
    if form.validate_on_submit():
        form.populate_obj(user)
        db.session.commit()
        flash('Changes saved!')
    return render_template('auth/edit_profile.html', user=user, form=form)
