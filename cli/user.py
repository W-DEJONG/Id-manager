from uuid import uuid4

import click
from flask import Blueprint
from flask.cli import with_appcontext

from manager import ALL_SERVER_ROLES
from manager.auth import hash_pwd
from manager.models import User, db, UserRole, OAuth2Client, UserConsent, OAuth2AuthorizationCode, OAuth2Token
from id_roles import Roles

bp = Blueprint('user', __name__)
bp.cli.help = 'Maintain users'


@bp.cli.command(name='create')
@click.option('-n', '--user-name', type=click.STRING, prompt=True, help='user name')
@click.option('-e', '--email', type=click.STRING, prompt=True, help='email')
@click.option('-g', '--given-name', type=click.STRING, prompt=True, help='given name')
@click.option('-f', '--family-name', type=click.STRING, prompt=True, default='', help='family name')
@click.option('-m', '--middle-name', type=click.STRING, prompt=True, default='', help='middle name')
@click.option('-k', '--nickname', type=click.STRING, prompt=True, default='', help='nickname')
@click.option('-l', '--locale', type=click.STRING, prompt=True, default='en_US', help='locale')
def create_user(user_name, email, given_name, family_name, middle_name, nickname, locale):
    """ Register a new user. """
    user = User(
        uuid=str(uuid4()),
        login_id=str(uuid4()),
        username=user_name,
        given_name=given_name,
        family_name=family_name,
        middle_name=middle_name,
        nickname=nickname,
        email=email,
        locale=locale,
        server_roles=''
    )
    db.session.add(user)
    db.session.commit()
    _show_user_details(user)


@bp.cli.command(name='modify')
@click.argument('user-id')
@click.option('-n', '--user-name', type=click.STRING, help='user name')
@click.option('-e', '--email', type=click.STRING, help='email')
@click.option('-g', '--given-name', type=click.STRING, help='given name')
@click.option('-f', '--family-name', type=click.STRING, help='family name')
@click.option('-m', '--middle-name', type=click.STRING, help='middle name')
@click.option('-k', '--nickname', type=click.STRING, help='nickname')
@click.option('-l', '--locale', type=click.STRING, help='locale')
def modify_user(user_id, **kwargs):
    """ Modify user information """
    user = _find_user(user_id)
    if user is None:
        return 1
    for key in kwargs.keys():
        if kwargs[key]:
            setattr(user, key, kwargs[key])
    db.session.commit()
    _show_user_details(user)


@bp.cli.command(name='show')
@click.argument('user-id')
def show_user(user_id):
    """ Show user details """
    user = _find_user(user_id)
    if user is None:
        return 1
    _show_user_details(user)


@bp.cli.command(name='list')
@click.option('-v', '--verbose', is_flag=True)
def list_users(verbose):
    """ List all registered users. """
    users = User.query.all()
    if len(users) == 0:
        click.echo('No users found')
        return

    if verbose:
        _show_line()
        for user in users:
            _show_user_details(user)
            _show_line()
        return

    click.echo('%-37s %-20s %s' % ('user id', 'user name', 'Server roles'))
    _show_line()
    for user in users:
        click.echo('%-37s %-20s %s' %
                   (user.uuid,
                    user.username,
                    user.server_roles))


@bp.cli.command(name='password')
@click.argument('user-id')
@click.password_option('-p', '--password')
def user_password(user_id, password):
    """ Change user password """
    user = _find_user(user_id)
    if user is None:
        return 1
    if len(password) < 5:
        click.echo('Failed: Password must be at least 5 characters!')
        return 1
    user.password = hash_pwd(password)
    user.login_id = str(uuid4())
    db.session.commit()
    click.echo('Password for user %s has been changed.' % user.username)


@bp.cli.command(name='enable')
@click.argument('user-id')
def enable_user(user_id):
    """ Activate user """
    user = _find_user(user_id)
    if user is None:
        return 1
    user.active = True
    db.session.commit()


@bp.cli.command(name='disable')
@click.argument('user-id')
def disable_user(user_id):
    """ Deactivate user """
    user = _find_user(user_id)
    if user is None:
        return 1
    user.active = False
    db.session.commit()


@bp.cli.command(name='delete')
@click.argument('user-id')
def delete_user(user_id):
    """ Delete user """
    user = _find_user(user_id)
    if user is None:
        return 1
    if user.active:
        click.echo('User must be disabled first!', err=True)
        return 1

    UserConsent.query.filter_by(user_id=user.id).delete()
    UserRole.query.filter_by(user_id=user.id).delete()
    OAuth2AuthorizationCode.query.filter_by(user_id=user.id).delete()
    OAuth2Token.query.filter_by(user_id=user.id).delete()
    User.query.filter_by(id=user.id).delete()
    db.session.commit()
    click.echo('User deleted.')


@bp.cli.group(name='roles', help='Modify user roles')
@click.argument('user-id')
@click.pass_context
def user_roles(ctx, user_id):
    ctx.ensure_object(dict)
    ctx.obj['user_id'] = user_id


@user_roles.command(name='list', help='List user role')
@click.pass_context
def user_roles_list(ctx):
    user = _find_user(ctx.obj['user_id'])
    if user is None:
        return 1
    ctx.obj['user'] = user
    click.echo('Server roles: ' + user.server_roles)
    client_roles = UserRole.query.join(OAuth2Client).filter(UserRole.user == user).all()
    for role in client_roles:
        click.echo('Client %s roles: %s' % (role.client.client_id, role.client_roles))


@user_roles.group(name='add', help='Add user role', invoke_without_command=True)
@click.argument('role')
@click.pass_context
@with_appcontext
def user_roles_add(ctx, role):
    if ctx.invoked_subcommand is not None:
        ctx.ensure_object(dict)
        ctx.obj['role'] = role
        return

    user = _find_user(ctx.obj['user_id'])
    if user is None:
        return 1
    new_roles = Roles(user.server_roles)
    new_roles.merge_roles(Roles(role))
    user.server_roles = str(new_roles)
    db.session.commit()
    click.echo('Server roles: %s' % user.server_roles)


@user_roles_add.group(name='for')
def user_roles_add_for():
    pass


@user_roles_add_for.command('client')
@click.argument('client_id')
@click.pass_context
def user_roles_add_for_client(ctx, client_id):
    user = _find_user(ctx.obj['user_id'])
    if user is None:
        return 1
    client = _find_client(client_id)
    if client is None:
        return 1
    new_roles = Roles(ctx.obj['role'])
    user_role = UserRole.query.join(OAuth2Client).filter(UserRole.user == user, UserRole.client == client).first()
    if not user_role:
        user_role = UserRole(user=user, client=client, client_roles=str(new_roles))
        db.session.add(user_role)
    else:
        old_roles = Roles(user_role.client_roles)
        old_roles.merge_roles(new_roles)
        user_role.client_roles = str(old_roles)
    db.session.commit()
    click.echo('User %s client %s roles: %s' % (user.uuid, client.client_id, user_role.client_roles))


@user_roles.group(name='remove', help='Remove user role', invoke_without_command=True)
@click.argument('role')
@click.pass_context
def user_roles_remove(ctx, role):
    if ctx.invoked_subcommand is not None:
        ctx.ensure_object(dict)
        ctx.obj['role'] = role
        return

    user = _find_user(ctx.obj['user_id'])
    if user is None:
        return 1
    new_roles = Roles(user.server_roles)
    new_roles.remove_roles(Roles(role))
    user.server_roles = str(new_roles)
    db.session.commit()
    click.echo('Server roles: %s' % user.server_roles)


@user_roles_remove.group(name='for')
def user_roles_remove_for():
    pass


@user_roles_remove_for.command('client')
@click.argument('client_id')
@click.pass_context
def user_roles_remove_for_client(ctx, client_id):
    user = _find_user(ctx.obj['user_id'])
    if user is None:
        return 1
    client = _find_client(client_id)
    if client is None:
        return 1
    user_role = UserRole.query.join(OAuth2Client).filter(UserRole.user == user, UserRole.client == client).first()
    if user_role:
        new_roles = Roles(user_role.client_roles)
        new_roles.remove_roles(Roles(ctx.obj['role']))
        user_role.client_roles = str(new_roles)
        db.session.commit()
    db.session.commit()
    if user_role is None or user_role.client_roles == '':
        click.echo('User %s has no roles for client %s' % (user.uuid, client.client_id))
    else:
        click.echo('User %s client %s roles: %s' % (user.uuid, client.client_id, user_role.client_roles))


@user_roles.group(name='all', help='Add all user roles for server', invoke_without_command=True)
@click.pass_context
@with_appcontext
def user_roles_all(ctx):
    if ctx.invoked_subcommand is not None:
        return

    user = _find_user(ctx.obj['user_id'])
    if user is None:
        return 1
    user.server_roles = ALL_SERVER_ROLES
    db.session.commit()
    click.echo('Server roles: %s' % user.server_roles)


@user_roles_all.group(name='for')
def user_roles_all_for():
    pass


@user_roles_all_for.command('client')
@click.argument('client_id')
@click.pass_context
def user_roles_all_for_client(ctx, client_id):
    user = _find_user(ctx.obj['user_id'])
    if user is None:
        return 1
    client = _find_client(client_id)
    if client is None:
        return 1
    user_role = UserRole.query.join(OAuth2Client).filter(UserRole.user == user, UserRole.client == client).first()
    if not user_role:
        user_role = UserRole(user=user, client=client, client_roles=client.supported_roles)
        db.session.add(user_role)
    else:
        user_role.client_roles = client.supported_roles
    db.session.commit()
    click.echo('User %s client %s roles: %s' % (user.uuid, client.client_id, user_role.client_roles))


@user_roles.group(name='clear', help='Clear all user roles for server', invoke_without_command=True)
@click.pass_context
@with_appcontext
def user_roles_clear(ctx):
    if ctx.invoked_subcommand is not None:
        return

    user = _find_user(ctx.obj['user_id'])
    if user is None:
        return 1
    user.server_roles = ''
    db.session.commit()
    click.echo('Server roles removed for user %s.' % user.uuid)


@user_roles_clear.group(name='for')
def user_roles_clear_for():
    pass


@user_roles_clear_for.command('client')
@click.argument('client_id')
@click.pass_context
def user_roles_clear_for_client(ctx, client_id):
    user = _find_user(ctx.obj['user_id'])
    if user is None:
        return 1
    client = _find_client(client_id)
    if client is None:
        return 1
    user_role = UserRole.query.join(OAuth2Client).filter(UserRole.user == user, UserRole.client == client).first()
    if user_role:
        UserRole.query.filter_by(user_id=user_role.user_id, client_id=user_role.client_id).delete()
    db.session.commit()
    click.echo('Cleared user %s roles for client %s' % (user.uuid, client.client_id))


def _find_user(user_id):
    user = User.query.filter_by(uuid=user_id).first()
    if user is None:
        user = User.query.filter_by(username=user_id).first()
    if user is None:
        click.echo('User not found.', err=True)
    return user


def _find_client(client_id):
    client = OAuth2Client.query.filter_by(client_id=client_id).first()
    if client is None:
        client = OAuth2Client.query.filter_by(client_tag=client_id).first()
    if client is None:
        click.echo('Client not found.', err=True)
    return client


def _show_line():
    click.echo(str().ljust(120, '-'))


def _show_user_details(user: User):
    click.echo('User id     : ' + user.uuid)
    click.echo('Active      : ' + ('Yes' if user.is_active else 'No'))
    click.echo('Username    : ' + user.username)
    click.echo('Password    : ' + ('*******' if user.username and len(user.username) is not None else '<not set>'))
    click.echo('Email       : ' + user.email)
    click.echo('Given name  : ' + user.given_name)
    click.echo('Family name : ' + user.family_name)
    click.echo('Middle name : ' + user.middle_name)
    click.echo('Nickname    : ' + user.nickname)
    click.echo('Locale      : ' + user.locale)
    click.echo('Server roles: ' + user.server_roles)
