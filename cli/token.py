import time

import click
from flask import Blueprint

from manager.models import OAuth2Token, OAuth2AuthorizationCode, db

bp = Blueprint('token', __name__)
bp.cli.help = 'Token maintenance'


@bp.cli.command(name='list')
def token_list():
    """ List access tokens """
    tokens = OAuth2Token.query.all()
    click.echo('%-37s %-20s %-20s %-8s %s' % ('client id', 'access token', 'scope', 'revoked', 'Expires'))
    _show_line()
    for token in tokens:
        click.echo('%-37s %-20s %-20s %-8s %s' %
                   (token.client_id,
                    token.access_token[0:20],
                    token.scope[0:20],
                    token.revoked,
                    time.ctime(token.issued_at+token.expires_in)))


@bp.cli.command(name='cleanup')
def token_cleanup():
    """ Cleanup outdated access tokens and authorization codes. """
    OAuth2Token.query.filter(OAuth2Token.issued_at+OAuth2Token.expires_in < time.time()).delete()
    OAuth2AuthorizationCode.query.filter(OAuth2AuthorizationCode.auth_time+600 < time.time()).delete()
    db.session.commit()


def _show_line():
    click.echo(str().ljust(120, '-'))
