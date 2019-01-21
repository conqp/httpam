"""A web service authentication API using PAM."""

from datetime import timedelta
from enum import Enum
from functools import wraps
from json import load
from pathlib import Path
from pwd import getpwnam, getpwuid, struct_passwd
from typing import NamedTuple
from uuid import UUID

from pam import pam as PAM


__all__ = [
    'AuthenticationError',
    'AlreadyLoggedIn',
    'SessionExpired',
    'SessionManager']


CONFIG_FILE = '/etc/httpam.conf'
DEFAULT_CONFIG = {
    'allow_root': False,
    'allow_empty_password': False,
    'min_uid': 1000,
    'login_policy': 'override',
    'session_duration': 900}    # 900 sec. = 14 min.


class AuthenticationError(Exception):
    """Indicates an unsuccessful login attempt."""


class AlreadyLoggedIn(Exception):
    """Indicates that the user is already logged in."""


class SessionExpired(Exception):
    """Indicates that the respective session timed out."""


def with_uuid(method):
    """Decorator to ensure that the first argument is a UUID."""

    @wraps(method)
    def wrapper(self, uuid, *args, **kwargs):
        """Tries to create a UUID instance from the given uuid."""
        if not isinstance(uuid, UUID):
            uuid = UUID(uuid)

        return method(self, uuid, *args, **kwargs)

    return wrapper


def with_user(method):
    """Decorator to ensure a ."""

    @wraps(method)
    def wrapper(self, user, *args, **kwargs):
        """Tries to get a user struct for the provided user name or uid."""
        if isinstance(user, int):
            user = getpwuid(user)
        elif isinstance(user, str):
            user = getpwnam(user)
        elif not isinstance(user, struct_passwd):
            raise TypeError(
                'user must be one of "int", "str" or "pwd.struct_passwd".')

        return method(self, user, *args, **kwargs)

    return wrapper


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
    session_duration: timedelta

    @classmethod
    def default(cls):
        """Returns the default config."""
        return cls.from_dict(DEFAULT_CONFIG)

    @classmethod
    def from_file(cls, config_file):
        """Creates a config instance from the respective config file."""
        with open(config_file, 'r') as cfg:
            user_config = load(cfg)

        config = DEFAULT_CONFIG.copy()
        config.update(user_config)
        return cls.from_dict(config)

    @classmethod
    def from_dict(cls, dictionary):
        """Creates a config instance from the respective dict."""
        return cls(
            bool(dictionary['allow_root']),
            bool(dictionary['allow_empty_password']),
            int(dictionary['min_uid']),
            LoginPolicy(dictionary['login_policy']),
            timedelta(seconds=dictionary['session_duration']))


class SessionManager:
    """A web service session handler."""

    def __init__(self, session, config=None):
        """Sets the session base and configuration."""
        self.session = session

        if config is None:
            self.config = Config.default()
        elif isinstance(config, Config):
            self.config = config
        elif isinstance(config, dict):
            self.config = Config.from_dict(config)
        elif isinstance(config, (str, Path)):
            self.config = Config.from_file(config)
        else:
            raise TypeError(
                'config must be one of "httpam.Config", "dict", "str" or '
                '"pathlib.Path".')

    @with_uuid
    def get(self, token: UUID):
        """Returns the respective session ID."""
        try:
            session = self.session.get(self.session.token == token)
        except self.session.DoesNotExist:
            raise SessionExpired()

        if session.validate(self.config.session_duration):
            return session

        session.close()
        raise SessionExpired()


    @with_user
    def login(self, user, password: str):
        """Attempts a login."""
        if not password and not self.config.allow_empty_password:
            raise AuthenticationError()

        if user.pw_name == 'root' or user.pw_uid == 0:
            if not self.config.allow_root:
                raise AuthenticationError()

        if user.pw_uid < self.config.min_uid:
            raise AuthenticationError()

        pam = PAM()

        if not pam.authenticate(user.pw_name, password):
            raise AuthenticationError(pam.reason, pam.code)

        if self.config.login_policy == LoginPolicy.SINGLE:
            try:
                self.session.get(self.session.user == user.pw_name)
            except self.session.DoesNotExist:
                pass
            else:
                raise AlreadyLoggedIn()
        elif self.config.login_policy == LoginPolicy.OVERRIDE:
            for session in self.session.select().where(
                    self.session.user == user.pw_name):
                session.close()

        session = self.session.open(user, self.config.session_duration)
        session.save()
        return session

    @with_uuid
    def close(self, token: UUID) -> None:
        """Closes the respective session."""
        try:
            session = self.session.get(self.session.token == token)
        except self.session.DoesNotExist:
            return False

        session.close()
        return True

    @with_uuid
    def refresh(self, token: UUID):
        """Refreshes the session."""
        try:
            session = self.session.get(self.session.token == token)
        except self.session.DoesNotExist:
            raise SessionExpired()

        if session.validate():
            session.refresh(self.config.session_duration)
            session.save()
            return session

        session.close()
        raise SessionExpired()

    def strip(self) -> None:
        """Removes all timed-out sessions."""
        for session in self.session:
            try:
                session.validate()
            except SessionExpired:
                session.close()
