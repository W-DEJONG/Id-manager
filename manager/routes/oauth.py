from flask import Blueprint, request, session, flash, render_template, jsonify, current_app as app
from flask_login import current_user, login_required
from manager.auth import csrf
from manager.models import User, UserRole, OAuth2Client
from manager.oauth2 import authorization, require_oauth, generate_user_info
from authlib.integrations.flask_oauth2 import current_token

bp = Blueprint(__name__, 'accounts')


@bp.route('/oauth/authorize', methods=('GET', 'POST'))
@login_required
def authorize():
    user = current_user
    grant = authorization.validate_consent_request(end_user=user)
    #
    # if request.method == 'POST':
    #     username = request.form.get('username')
    #     password = request.form.get('password')
    #     if not username:
    #         error = 'Username is required.'
    #     elif not password:
    #         error = 'Password is required.'
    #     else:
    #         grant_user = User.query.filter_by(username=username).first()
    #         if grant_user:
    #             if verify_pwd(grant_user.password, password):
    #                 session['id'] = grant_user.id
    #                 return authorization.create_authorization_response(grant_user=grant_user)
    #         error = 'Invalid credentials'
    #     flash(error)

    if user is not None:
        return authorization.create_authorization_response(request=request, grant_user=user)

    # return render_template('oauth/authorize.html', user=user, grant=grant)


@bp.route('/oauth/token', methods=['POST'])
@csrf.exempt
def issue_token():
    return authorization.create_token_response()


@bp.route('/oauth/config')
def oauth_config():
    with open(app.instance_path + '/' + app.config['JWT_PUBLIC_FILE']) as f:
        jwt = f.read()

    return {
        'key': str(jwt),
        'alg': 'HS256',
        'iss': request.host_url,
        'exp': 3600,
    }


@bp.route('/user-info')
@require_oauth('profile email roles', 'OR')
def user_info():
    scope = current_token.scope
    user = current_token.user
    info = generate_user_info(user, scope)
    if 'roles' in scope:
        user_role = UserRole.query.join(OAuth2Client) \
            .filter(UserRole.user == user, OAuth2Client.client_id == current_token.client_id) \
            .first()
        info['roles'] = user_role.client_roles if user_role else ''
    return jsonify(info)
