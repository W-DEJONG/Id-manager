import os

from flask import Flask
from manager import config
from manager.models import db
from manager.oauth2 import config_oauth
from manager.routes import auth, oauth, api
from manager.auth import csrf, login_manager

ALL_SERVER_ROLES = 'connect admin'


def create_app(test_config=None):
    """
    create and configure the app
    :param test_config: dict() with test configuration
    :return:
    """
    app = Flask(__name__,
                static_folder=None,
                instance_path=os.environ.get('MANAGER_INSTANCE_PATH'),
                instance_relative_config=True)

    app.config.from_object(config)
    if test_config is None:
        app.config.from_pyfile('manager.cfg', silent=True)
    else:
        app.config.from_mapping(test_config)

    db.init_app(app)
    csrf.init_app(app)
    login_manager.init_app(app)
    config_oauth(app)
    app.register_blueprint(auth.bp)
    app.register_blueprint(oauth.bp)
    app.register_blueprint(api.bp)

    @app.route('/_health')
    def health():
        return {'status': 'healthy'}

    return app
