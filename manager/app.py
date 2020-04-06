from flask import Flask
from manager import config
from manager.models import db
from manager.oauth2 import config_oauth
from manager.routes import auth, oauth
from manager.auth import csrf, login_manager


def create_app(test_config=None):
    """
    create and configure the app
    :param test_config: dict() with test configuration
    :return:
    """
    app = Flask(__name__)

    app.config.from_object(config)
    if test_config is None:
        app.config.from_pyfile(app.instance_path + '/manager.conf', silent=True)
    else:
        app.config.from_mapping(test_config)

    db.init_app(app)
    csrf.init_app(app)
    login_manager.init_app(app)
    config_oauth(app)
    app.register_blueprint(auth.bp)
    app.register_blueprint(oauth.bp)

    @app.route('/_health')
    def health():
        return {'status': 'healthy'}

    return app