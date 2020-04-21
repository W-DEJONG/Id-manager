import time

import click
from flask import Blueprint
from uuid import uuid4

from werkzeug.security import gen_salt

from manager.models import OAuth2Client, db

bp = Blueprint('client', __name__)
bp.cli.help = 'Maintain oauth2 clients'


@bp.cli.command(name='create')
@click.option('-t', '--client-tag', type=click.STRING, prompt=True, help='client tag')
@click.option('-n', '--client-name', type=click.STRING, prompt=True, help='client name')
@click.option('-u', '--client-uri', type=click.STRING, prompt=True, default='https://example.com', help='client URI')
@click.option('-r', '--redirect-url', type=click.STRING, prompt=True, default='https://example.com',
              help='redirect URL(s), multiple separated by <space>')
@click.option('-s', '--scope', type=click.STRING, default='openid profile', help='client scope')
@click.option('-R', '--supported-roles', type=click.STRING, default='connect admin', help='Supported user roles')
def create_client(client_tag, client_name, client_uri, redirect_url, scope, supported_roles):
    """Create an oauth2 client."""

    redirects = [s.strip() for s in redirect_url.split()]

    client = OAuth2Client(client_tag=client_tag,
                          client_id=str(uuid4()),
                          client_secret=gen_salt(48),
                          client_id_issued_at=int(time.time()),
                          supported_roles=supported_roles)
    client_metadata = {
        "client_name": client_name,
        "client_uri": client_uri,
        "grant_types": ['authorization_code'],
        "redirect_uris": redirects,
        "response_types": ['code'],
        "scope": scope,
        "token_endpoint_auth_method": 'client_secret_basic'
    }

    click.echo('')
    click.echo('About to create client:')
    client.set_client_metadata(client_metadata)
    _show_line()
    _show_client_details(client)
    _show_line()
    click.confirm('Create client?', abort=True)
    db.session.add(client)
    db.session.commit()
    click.echo("Client created")


@bp.cli.command(name='list', help='List all oauth clients.')
@click.option('-v', '--verbose', is_flag=True)
def list_clients(verbose):
    clients = OAuth2Client.query.all()
    if len(clients) == 0:
        click.echo('No clients found')
        return

    if verbose:
        _show_line()
        for client in clients:
            _show_client_details(client)
            _show_line()
        return

    click.echo('%-37s %-20s %s' % ('client id', 'tag', 'client URI'))
    _show_line()
    for client in clients:
        click.echo('%-37s %-20s %s' %
                   (client.client_id,
                    client.client_tag if client.client_tag is not None else '<empty>',
                    client.client_uri))


@bp.cli.command(name='show', help='Display oauth client details.')
@click.argument('client-id')
def show_client(client_id):
    client = OAuth2Client.query.filter_by(client_id=client_id).first()
    if client is None:
        client = OAuth2Client.query.filter_by(client_tag=client_id).first()
    if client is None:
        click.echo('Client not found.', err=True)
        return 1
    _show_line()
    _show_client_details(client)
    _show_line()


def _show_line():
    click.echo(str().ljust(120, '-'))


def _show_client_details(client: OAuth2Client):
    click.echo('Client tag     : ' + (client.client_tag if client.client_tag is not None else '<empty>'))
    click.echo('Client name    : ' + client.client_name)
    click.echo('Client id      : ' + client.client_id)
    click.echo('  Issued at    : ' + time.ctime(client.client_id_issued_at))
    click.echo('Client secret  : ' + client.client_secret)
    click.echo('Client URI     : ' + client.client_uri)
    click.echo('Redirect URL(s): ' + ' '.join(client.redirect_uris))
    click.echo('scope          : ' + client.scope)
    click.echo('Supported roles: ' + client.supported_roles)
