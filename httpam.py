"""A web service authentication API using PAM."""

from datetime import timedelta
from enum import Enum
from json import load
from pathlib import Path
from pwd import getpwnam, getpwuid, struct_passwd
from typing import NamedTuple

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


class NoSuchSession(Exception):
    """Indicates that the respective session does not exist."""


def get_user(user):
    """Tries to get a user struct for the provided user name or uid."""

    if isinstance(user, int):
        return getpwuid(user)

    if isinstance(user, str):
        return getpwnam(user)

    if isinstance(user, struct_passwd):
        return user

    raise TypeError('user must be one of "int", "str" or "pwd.struct_passwd".')


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

    def __init__(self, session_class, config=None):
        """Sets the session base and configuration."""
        self.session_class = session_class

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

    def get(self, token):
        """Returns the respective session ID."""
        try:
            session = self.session_class.by_token(token)
        except NoSuchSession:
            raise SessionExpired()

        if session.validate():
            return session

        session.close()
        raise SessionExpired()


    def login(self, user, password: str):
        """Attempts a login."""
        try:
            user = get_user(user)
        except KeyError:
            raise AuthenticationError()

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
            for _ in self.session_class.by_user(user):
                raise AlreadyLoggedIn()
        elif self.config.login_policy == LoginPolicy.OVERRIDE:
            for session in self.session_class.by_user(user):
                session.close()

        return self.session_class.open(user, self.config.session_duration)

    def close(self, token) -> None:
        """Closes the respective session."""
        try:
            session = self.session_class.by_token(token)
        except NoSuchSession:
            return False

        session.close()
        return True

    def refresh(self, token):
        """Refreshes the session."""
        try:
            session = self.session_class.by_token(token)
        except NoSuchSession:
            raise SessionExpired()

        if session.validate():
            session.refresh(self.config.session_duration)
            return session

        session.close()
        raise SessionExpired()

    def strip(self) -> None:
        """Removes all timed-out sessions."""
        for session in self.session_class:
            try:
                session.validate()
            except SessionExpired:
                session.close()
