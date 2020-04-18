from authlib.integrations.flask_oauth2 import current_token
from flask import Blueprint, jsonify

from manager.models import UserRole, OAuth2Client
from manager.oauth2 import require_oauth, generate_user_info

bp = Blueprint(__name__, 'api')


@bp.route('/api/user-info')
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
