import re
import time
import click

from click import BadArgumentUsage
from flask import Blueprint
from uuid import uuid4
from werkzeug.security import gen_salt
from manager.models import OAuth2Client, db

bp = Blueprint('client', __name__)
bp.cli.help = 'Maintain oauth2 clients'


def valid_uri(uri):
    regex = re.compile(
        r'^(?:http|ftp)s?://'  # http:// or https://
        r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)|'  # domain...
        r'localhost|'  # localhost...
        r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'  # ...or ip
        r'(?::\d+)?'  # optional port
        r'(?:/?|[/?]\S+)$', re.IGNORECASE)
    return re.match(regex, uri) is not None


def parse_uri_str(uri_str):
    url_list = []
    for uri in uri_str.split():
        if not valid_uri(uri):
            raise ValueError('Invalid uri: ' + uri)
        url_list.append(uri)
    return url_list


def validate_uri(ctx, param, value):
    try:
        if not valid_uri(value):
            raise ValueError('Invalid uri: ' + value)
        return value
    except ValueError as e:
        raise click.BadParameter(str(e))


def validate_uri_list(ctx, param, value):
    try:
        uri_list = parse_uri_str(value)
        return uri_list
    except ValueError as e:
        raise click.BadParameter(str(e))


@bp.cli.command(name='create')
@click.option('-t', '--client-tag', type=click.STRING, prompt=True, help='client tag')
@click.option('-n', '--client-name', type=click.STRING, prompt=True, help='client name')
@click.option('-u', '--client-uri', type=click.STRING, prompt=True, callback=validate_uri,
              default='https://example.com', help='client URI')
@click.option('-r', '--redirect-uri', type=click.STRING, prompt=True, default='https://example.com',
              callback=validate_uri_list, help='redirect URL(s), multiple separated by <space>')
@click.option('-s', '--scope', type=click.STRING, default='openid profile', help='client scope')
@click.option('-R', '--supported-roles', type=click.STRING, default='connect admin', help='Supported user roles')
def create_client(client_tag, client_name, client_uri, redirect_uri, scope, supported_roles):
    """Create an oauth2 client."""

    client = OAuth2Client(client_tag=client_tag,
                          client_id=str(uuid4()),
                          client_secret=gen_salt(48),
                          client_id_issued_at=int(time.time()),
                          supported_roles=supported_roles)
    client_metadata = {
        "client_name": client_name,
        "client_uri": client_uri,
        "grant_types": ['authorization_code'],
        "redirect_uris": redirect_uri,
        "response_types": ['code'],
        "scope": scope,
        "token_endpoint_auth_method": 'client_secret_basic'
    }

    click.echo('')
    click.echo('About to create client:')
    client.set_client_metadata(client_metadata)
    _show_client_details(client)
    click.confirm('Create client?', abort=True)
    db.session.add(client)
    db.session.commit()
    click.echo("Client created")


@bp.cli.command(name='modify')
@click.argument('client-id')
@click.option('-t', '--client-tag', type=click.STRING, help='client tag')
@click.option('-n', '--client-name', type=click.STRING, help='client name')
@click.option('-u', '--client-uri', type=click.STRING, callback=validate_uri, help='client URI')
@click.option('-r', '--redirect-uri', type=click.STRING, callback=validate_uri_list,
              help='redirect URI(s), multiple separated by <space>')
@click.option('-s', '--scope', type=click.STRING, help='client scope')
@click.option('-R', '--supported-roles', type=click.STRING, help='Supported user roles')
def modify_client(client_id, client_tag, client_name, client_uri, redirect_uri, scope, supported_roles):
    """Modify an oauth2 client."""
    client = _find_client(client_id)
    if client is None:
        return 1
    if client_tag:
        client.client_tag = client_tag
    if supported_roles:
        client.supported_roles = supported_roles
    metadata = client.client_metadata
    if client_name:
        metadata['client_name'] = client_name
        client.set_client_metadata(metadata)
    if client_uri:
        metadata['client_uri'] = client_uri
        client.set_client_metadata(metadata)
    if redirect_uri:
        metadata['redirect_uris'] = redirect_uri
        client.set_client_metadata(metadata)
    if scope:
        metadata['scope'] = scope
        client.set_client_metadata(metadata)

    db.session.commit()
    _show_client_details(client)


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
    client = _find_client(client_id)
    if client is None:
        return 1
    _show_client_details(client)


@bp.cli.group(name='redirect', help='Modify redirect uris')
@click.argument('client_id')
@click.pass_context
def client_redirect(ctx, client_id):
    ctx.ensure_object(dict)
    ctx.obj['client_id'] = client_id


@client_redirect.command(name='list', help='List redirect uri\'s')
@click.pass_context
def client_redirect_list(ctx):
    client = _find_client(ctx.obj['client_id'])
    if client is None:
        return 1
    for uri in client.redirect_uris:
        click.echo(uri)


@client_redirect.command(name='add', help='Add redirect uri')
@click.argument('redirect_uri', callback=validate_uri)
@click.pass_context
def client_redirect_add(ctx, redirect_uri):
    client = _find_client(ctx.obj['client_id'])
    if client is None:
        return 1

    uri_list = client.redirect_uris
    uri_list.append(redirect_uri)
    metadata = client.client_metadata
    metadata['redirect_uris'] = uri_list
    client.set_client_metadata(metadata)
    db.session.commit()
    click.echo('Added: ' + redirect_uri)


@client_redirect.command(name='remove', help='Remove redirect uri')
@click.argument('redirect_uri', callback=validate_uri)
@click.pass_context
def client_redirect_remove(ctx, redirect_uri):
    client = _find_client(ctx.obj['client_id'])
    if client is None:
        return 1

    uri_list = client.redirect_uris
    if redirect_uri not in uri_list:
        raise BadArgumentUsage('Uri not in list: ' + redirect_uri)

    uri_list.remove(redirect_uri)
    metadata = client.client_metadata
    metadata['redirect_uris'] = uri_list
    client.set_client_metadata(metadata)
    db.session.commit()
    click.echo('Removed: ' + redirect_uri)


def _find_client(client_id):
    client = OAuth2Client.query.filter_by(client_id=client_id).first()
    if client is None:
        client = OAuth2Client.query.filter_by(client_tag=client_id).first()
    if client is None:
        click.echo('Client not found.', err=True)
    return client


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
