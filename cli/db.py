from flask import Blueprint

bp = Blueprint('database', __name__)
bp.cli.help = 'Database routines'


@bp.cli.command(name='init')
def init_db():
    """ Initialise the database schema """
    from manager.models import db
    db.create_all()


@bp.cli.command(name='seed')
def seed_db():
    """ Seed the database with test data"""
    from manager.models import db
    from manager.models import OAuth2Client
    from manager.models import User, UserConsent, UserRole
    from manager.auth import hash_pwd
    import time

    client = OAuth2Client(client_tag='stock',
                          client_id='3MEZIcvlhMPiTEcy46spogzg',
                          client_secret='POac9Sd4h0mrHZeXN9MljGB6oQRVJenKRnltCyDU10pvfHiX',
                          supported_roles='connect admin warehouse',
                          client_id_issued_at=int(time.time()))
    client_metadata = {
        "client_name": 'Test client',
        "client_uri": 'http://stock.maxilia.cloud',
        "grant_types": ['authorization_code'],
        "redirect_uris": ['http://127.0.0.1:9031',
                          'http://127.0.0.1:9032',
                          'http://127.0.0.1:9035/authorize',
                          'http://stock.maxilia.cloud',
                          'http://warehouse.maxilia.cloud'],
        "response_types": ['code'],
        "scope": 'openid profile email roles',
        "token_endpoint_auth_method": 'client_secret_basic'
    }
    client.set_client_metadata(client_metadata)
    db.session.add(client)

    user = User(
        uuid='8c4205ba-85df-4708-87d4-28589bc7f5e9',
        login_id='53d205ba-85df-4708-87d4-28589bc7f5e3',
        username='wj',
        password=hash_pwd('secret'),
        given_name='Wouter A.',
        family_name='Jong',
        middle_name='de',
        nickname='Wouter',
        email='wouter@maxilia.nl',
        locale='NL',
        server_roles='connect admin'
    )
    db.session.add(user)

    scope = UserConsent(client=client, user=user, scope='openid profile email roles')
    db.session.add(scope)

    role = UserRole(client=client, user=user, client_roles='connect admin warehouse[CM]')
    db.session.add(role)
    db.session.commit()
