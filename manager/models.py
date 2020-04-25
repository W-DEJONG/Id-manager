import time
from id_roles import Roles
from flask_sqlalchemy import SQLAlchemy
from authlib.integrations.sqla_oauth2 import OAuth2ClientMixin, OAuth2TokenMixin, OAuth2AuthorizationCodeMixin
from werkzeug.utils import cached_property

db = SQLAlchemy()


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    uuid = db.Column(db.String(64), unique=True)
    login_id = db.Column(db.String(64), unique=True)
    username = db.Column(db.String(255), unique=True)
    password = db.Column(db.String(255))
    given_name = db.Column(db.String(255), nullable=False, default='')
    family_name = db.Column(db.String(255), nullable=False, default='')
    middle_name = db.Column(db.String(255), nullable=False, default='')
    nickname = db.Column(db.String(255), nullable=False, default='')
    locale = db.Column(db.String(20))
    email = db.Column(db.String(255))
    server_roles = db.Column(db.Text)
    active = db.Column(db.Boolean, nullable=False, default=False)
    created_at = db.Column(db.Integer, nullable=False, default=lambda: int(time.time()))
    updated_at = db.Column(db.Integer, nullable=False, default=lambda: int(time.time()),
                           onupdate=lambda: int(time.time()))
    clients = db.relationship('UserConsent', back_populates="user")

    def __str__(self):
        return self.uuid + ' / ' + self.username

    def get_user_id(self):
        return self.id

    def get_full_name(self):
        return (self.given_name.strip() + ' ' + (
                self.middle_name.strip() + ' ' + self.family_name.strip()).strip()).strip()

    @cached_property
    def roles(self):
        if self.server_roles:
            return Roles(self.server_roles)
        return None

    @property
    def is_active(self):
        return self.active

    @property
    def is_authenticated(self):
        return True

    @property
    def is_anonymous(self):
        return False

    def get_id(self):
        return self.login_id


class UserConsent(db.Model):
    user_id = db.Column(db.Integer, db.ForeignKey('user.id', ondelete='CASCADE'), primary_key=True)
    client_id = db.Column(db.Integer, db.ForeignKey('oauth2_client.id', ondelete='CASCADE'), primary_key=True)
    scope = db.Column(db.Text)
    created_at = db.Column(db.Integer, nullable=False, default=lambda: int(time.time()))
    updated_at = db.Column(db.Integer, nullable=False, default=lambda: int(time.time()),
                           onupdate=lambda: int(time.time()))
    user = db.relationship('User', back_populates="clients")
    client = db.relationship('OAuth2Client', back_populates="users")


class UserRole(db.Model):
    user_id = db.Column(db.Integer, db.ForeignKey('user.id', ondelete='CASCADE'), primary_key=True)
    client_id = db.Column(db.Integer, db.ForeignKey('oauth2_client.id', ondelete='CASCADE'), primary_key=True)
    client_roles = db.Column(db.Text, nullable=False, default='')
    created_at = db.Column(db.Integer, nullable=False, default=lambda: int(time.time()))
    updated_at = db.Column(db.Integer, nullable=False, default=lambda: int(time.time()),
                           onupdate=lambda: int(time.time()))
    user = db.relationship('User')
    client = db.relationship('OAuth2Client')


class OAuth2Client(db.Model, OAuth2ClientMixin):
    __tablename__ = 'oauth2_client'

    id = db.Column(db.Integer, primary_key=True)
    client_tag = db.Column(db.String(64), index=True)
    supported_roles = db.Column(db.Text)
    created_at = db.Column(db.Integer, nullable=False, default=lambda: int(time.time()))
    updated_at = db.Column(db.Integer, nullable=False, default=lambda: int(time.time()),
                           onupdate=lambda: int(time.time()))
    users = db.relationship('UserConsent', back_populates="client")


class OAuth2AuthorizationCode(db.Model, OAuth2AuthorizationCodeMixin):
    __tablename__ = 'oauth2_code'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id', ondelete='CASCADE'))
    user = db.relationship('User')


class OAuth2Token(db.Model, OAuth2TokenMixin):
    __tablename__ = 'oauth2_token'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id', ondelete='CASCADE'))
    user = db.relationship('User')
