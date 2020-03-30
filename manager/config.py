import os

from flask import Flask

# Config steps:
# 1 - Code defaults
# 2 - Settings file
# 3 - Environment settings
env_prefix = 'ID_MANAGER_'
env_conf_file = env_prefix + 'CONFIGURATION_FILE'

defaultConfiguration = {
    'SECRET_KEY': 'secret',
    'JWT_PRIVATE_FILE': '../instance/jwt.key',
    'SQLALCHEMY_TRACK_MODIFICATIONS': False,
    'SQLALCHEMY_DATABASE_URI': 'sqlite:///../instance/db.sqlite',
}


def parse_env_value(value: str):
    if value.lower() == 'true':
        return True
    if value.lower() == 'false':
        return False
    try:
        value = int(value)
    except ValueError:
        pass

    return value


def init_app(app: Flask, test_config=None):
    app.config.update(defaultConfiguration)
    app.config.from_pyfile('../' + app.name + '.conf')

    if env_conf_file in os.environ:
        app.config.from_envvar(env_conf_file)

    for key, value in os.environ.items():
        if not key.startswith(env_prefix):
            continue
        key = key[len(env_prefix):]
        if key in defaultConfiguration:
            app.config[key] = parse_env_value(value)

    if test_config is not None:
        app.config.from_mapping(test_config)
