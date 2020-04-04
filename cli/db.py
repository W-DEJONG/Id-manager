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
    from manager.models import User
    from manager.auth import hash_pwd
    import time

    client = OAuth2Client(client_tag='test',
                          client_id='3MEZIcvlhMPiTEcy46spogzg',
                          client_secret='POac9Sd4h0mrHZeXN9MljGB6oQRVJenKRnltCyDU10pvfHiX',
                          client_id_issued_at=int(time.time()))
    client_metadata = {
        "client_name": 'Test client',
        "client_uri": 'http://localhost:8000',
        "grant_types": ['authorization_code'],
        "redirect_uris": ['http://127.0.0.1:8000'],
        "response_types": ['code'],
        "scope": 'openid profile',
        "token_endpoint_auth_method": 'client_secret_basic'
    }
    client.set_client_metadata(client_metadata)
    db.session.add(client)

    user = User(
        uuid='8c4205ba-85df-4708-87d4-28589bc7f5e9',
        username='wj',
        password=hash_pwd('secret')
    )
    db.session.add(user)

    db.session.commit()
