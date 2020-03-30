from flask import Blueprint, request, session, redirect, flash, render_template
from .auth import current_user, verify_pwd
from .models import User, csrf
from .oauth2 import authorization

bp = Blueprint(__name__, 'accounts')


@bp.route('/oauth/authorize', methods=('GET', 'POST'))
def authorize():
    user = current_user()
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        if not username:
            error = 'Username is required.'
        elif not password:
            error = 'Password is required.'
        else:
            grant_user = User.query.filter_by(username=username).first()
            if grant_user:
                if verify_pwd(grant_user.password, password):
                    session['id'] = grant_user.id
                    return authorization.create_authorization_response(grant_user=grant_user)
            error = 'Invalid credentials'
        flash(error)

    if user is not None:
        return authorization.create_authorization_response(grant_user=user)

    grant = authorization.validate_consent_request(end_user=user)
    return render_template('oauth/authorize.html', user=user, grant=grant)


@bp.route('/oauth/token', methods=['POST'])
@csrf.exempt
def issue_token():
    return authorization.create_token_response()


@bp.route('/oauth/config')
def oauth_config():
    with open('/Users/wj/Developer/id-manager/instance/jwt.key.pub', 'r') as f:
        jwt = f.read()

    return {
        'jwt_key': str(jwt)
    }
