from flask import Blueprint, request, current_app
from flask_login import current_user, login_required
from manager.auth import csrf
from manager.oauth2 import authorization, require_oauth, generate_user_info

bp = Blueprint(__name__, 'oauth')


@bp.route('/oauth/authorize', methods=('GET', 'POST'))
@login_required
def authorize():
    user = current_user
    grant = authorization.validate_consent_request(end_user=user)
    # TODO: Proper implementation with scope consents
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
    with open(current_app.instance_path + '/' + current_app.config['JWT_PUBLIC_FILE']) as f:
        jwt = f.read()

    return {
        'key': str(jwt),
        'alg': 'HS256',
        'iss': request.host_url,
        'exp': 3600,
    }
