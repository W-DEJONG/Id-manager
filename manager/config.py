from os import getenv

# Flask settings
SECRET_KEY = getenv('MANAGER_SECRET_KEY')
SESSION_COOKIE_NAME = 'id'

# SQL Alchemy settings
SQLALCHEMY_TRACK_MODIFICATIONS = False,
SQLALCHEMY_DATABASE_URI = getenv('MANAGER_DATABASE_URI', 'sqlite:///../instance/db.sqlite')

# Authlib settings
OAUTH2_TOKEN_EXPIRES_IN = dict(
    authorization_code=3600,
    implicit=3600,
    password=3600,
    client_credentials=3600
)

JWT_PRIVATE_FILE = getenv('MANAGER_PRIVATE_KEY_FILE', 'jwt.key')
JWT_PUBLIC_FILE = getenv('MANAGER_PUBLIC_KEY_FILE', 'jwt.key.pub')

# Flask-Login settings
USE_SESSION_FOR_NEXT = True
SESSION_PROTECTION = "strong"

REMEMBER_COOKIE_NAME = 't'
REMEMBER_COOKIE_DURATION = 60 * 60 * 24 * 30  # 30 days
REMEMBER_COOKIE_HTTPONLY = True
