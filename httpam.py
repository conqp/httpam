"""A web service authentication API using PAM."""

from datetime import datetime, timedelta
from enum import Enum
from json import dumps, loads
from pwd import getpwnam
from typing import NamedTuple
from uuid import uuid4, UUID

from pam import pam as PAM
from peewee import CharField, DateTimeField, UUIDField
from peeweeplus import JSONModel


__all__ = [
    'InvalidUserNameOrPassword',
    'AlreadyLoggedIn',
    'SessionExpired',
    'Config',
    'SessionBase',
    'SessionManager']


CONFIG_FILE = '/etc/httpam.conf'
DEFAULT_CONFIG = {
    'allow_root': False,
    'allow_empty_password': False,
    'min_uid': 1000,
    'login_policy': 'override',
    'session_duration': 15}


class InvalidUserNameOrPassword(Exception):
    """Indicates an unsuccessful login attempt."""


class AlreadyLoggedIn(Exception):
    """Indicates that the user is already logged in."""


class SessionExpired(Exception):
    """Indicates that the respective session timed out."""


def _ensure_uuid(value):
    """Tries to create a UUID from value."""

    if isinstance(value, UUID):
        return value

    return UUID(value)


class LoginPolicy(Enum):
    """Available login policies."""

    MULTI = 'multi'
    OVERRIDE = 'override'
    SINGLE = 'single'


class Config(NamedTuple):
    """The respective configuration."""

    allow_root: bool
    allow_empty_password: bool
    min_uid: int
    login_policy: LoginPolicy
    session_duration: int

    @classmethod
    def from_file(cls, config_file):
        """Creates a config instance from the respective config file."""
        try:
            with open(config_file, 'r') as cfg:
                text = cfg.read()
        except FileNotFoundError:
            return cls.from_dict(DEFAULT_CONFIG)

        user_config = loads(text)
        config = DEFAULT_CONFIG.copy()
        config.update(user_config)
        return cls.from_dict(config)

    @classmethod
    def from_dict(cls, dictionary):
        """Creates a config instance from the respective dict."""
        return cls(
            dictionary['allow_root'], dictionary['allow_empty_password'],
            dictionary['min_uid'], LoginPolicy(dictionary['login_policy']),
            dictionary['session_duration'])


class SessionBase(JSONModel):
    """Represents a session."""

    token = UUIDField(default=uuid4)
    user = CharField(255)
    start = DateTimeField(default=datetime.now)

    def __str__(self):
        """Returns the session as JSON string."""
        return dumps(self.to_json(), indent=2)

    def validate(self, duration):
        """Checks whether the session is still valid."""
        if self.start + timedelta(minutes=duration) >= datetime.now():
            return True

        raise SessionExpired() from None

    def refresh(self):
        """Returns a new session with updated ID and start time."""
        self.token = uuid4()
        self.start = datetime.now()


class SessionManager:
    """A web service session handler."""

    def __init__(self, session: SessionBase, config=None):
        """Sets the config_file."""
        self.session = session
        self.config = config

    def get(self, token: UUID) -> SessionBase:
        """Returns the respective session ID."""
        try:
            session = self.session.get(
                self.session.token == _ensure_uuid(token))
        except self.session.DoesNotExist:
            raise SessionExpired() from None

        if session.validate(self.config.session_duration):
            return session

        session.delete_instance()
        raise SessionExpired() from None


    def login(self, user_name: str, password: str) -> SessionBase:
        """Attempts a login."""
        if not password and not self.config.allow_empty_password:
            raise InvalidUserNameOrPassword() from None

        try:
            user = getpwnam(user_name)
        except KeyError:
            raise InvalidUserNameOrPassword() from None

        if user.pw_name == 'root' or user.pw_uid == 0:
            if not self.config.allow_root:
                raise InvalidUserNameOrPassword() from None

        if user.pw_uid < self.config.min_uid:
            raise InvalidUserNameOrPassword() from None

        pam = PAM()

        if not pam.authenticate(user.pw_name, password):
            raise InvalidUserNameOrPassword(pam.reason, pam.code) from None

        if self.config.login_policy == LoginPolicy.SINGLE:
            try:
                self.session.get(self.session.user == user.pw_name)
            except self.session.DoesNotExist:
                pass
            else:
                raise AlreadyLoggedIn() from None
        elif self.config.login_policy == LoginPolicy.OVERRIDE:
            for session in self.session.select().where(
                    self.session.user == user.pw_name):
                session.delete_instance()

        session = self.session(user=user.pw_name)
        session.save()
        return session

    def close(self, token: UUID) -> None:
        """Closes the respective session."""
        try:
            session = self.session.get(
                self.session.token == _ensure_uuid(token))
        except self.session.DoesNotExist:
            return False

        session.delete_instance()
        return True

    def refresh(self, token: UUID) -> SessionBase:
        """Refreshes the session."""
        try:
            session = self.session.get(
                self.session.token == _ensure_uuid(token))
        except self.session.DoesNotExist:
            raise SessionExpired() from None

        if session.validate(self.config.session_duration):
            session.refresh()
            session.save()
            return session

        session.delete_instance()
        raise SessionExpired() from None

    def strip(self) -> None:
        """Removes all timed-out sessions."""
        for session in self.session:
            try:
                session.validate(self.config.session_duration)
            except SessionExpired:
                session.delete_instance()
