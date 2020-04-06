import click
from flask import Blueprint

bp = Blueprint('user', __name__)
bp.cli.help = 'Maintain users'


@bp.cli.command(name='create')
@click.option('-n', '--user-name', type=click.STRING, prompt=True, help='user name')
@click.password_option('-p', '--password')
def create_user(user_name, password):
    """ Register a new user. """
    pass


@bp.cli.command(name='show')
@click.argument('user-id')
def show_user(user_id):
    """ Show user details. """
    pass


@bp.cli.command(name='list')
@click.option('-v', '--verbose', is_flag=True)
def list_users(verbose):
    """ List all registered users. """
    pass


@bp.cli.group(name='modify', help='Modify user')
@click.argument('user-id')
def user_modify(user_id):
    click.echo(user_id)


@user_modify.command('add')
def user_modify_add():
    click.echo('add')
