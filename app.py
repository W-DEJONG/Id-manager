from manager import create_app

app = create_app()


@app.cli.command(name='init-db')
def init_db():
    from manager.models import db
    db.create_all()


@app.cli.command(name='seed-db')
def seed_db():
    from manager.models import db
    from manager.models import OAuth2Client
    from manager.models import User
    from manager.auth import hash_pwd
    import time

    client = OAuth2Client(client_id='3MEZIcvlhMPiTEcy46spogzg',
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
