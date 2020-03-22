from flask import Flask
from manager import config
from .models import db, csrf
from .oauth2 import config_oauth


def create_app(test_config=None):
    """
    create and configure the app
    :param test_config:
    :return:
    """
    app = Flask(__name__)

    config.init_app(app, test_config);
    db.init_app(app)
    csrf.init_app(app)
    config_oauth(app)

    @app.route('/_health')
    def health():
        return {'status': 'healthy'}

    return app
