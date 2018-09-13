"""A web service authentication API using PAM."""

from datetime import datetime
from enum import Enum
from functools import lru_cache, wraps
from json import loads
from pwd import getpwnam, struct_passwd
from typing import NamedTuple
from uuid import uuid4, UUID

from pam import authenticate


__all__ = ['InvalidUserNameOrPassword', 'AlreadyLoggedIn', 'SessionManager']


CONFIG_FILE = '/etc/httpam.conf'
DEFAULT_CONFIG = {
    'allow_root': False,
    'min_uid': 1000,
    'login_policy': 'override'
}


class InvalidUserNameOrPassword(Exception):
    """Indicates an unsuccessful login attempt."""

    pass


class AlreadyLoggedIn(Exception):
    """Indicates that the user is already logged in."""

    pass


def _load_config(config_file):
    """Returns the configuration."""

    try:
        with open(config_file, 'r') as cfg:
            text = cfg.read()
    except FileNotFoundError:
        return DEFAULT_CONFIG

    return DEFAULT_CONFIG.copy().update(loads(text))


def coerce(typ):
    """Coerces the return type of a funcion."""

    def decorator(funcion):
        @wraps(funcion)
        def wrap(*args, **kwargs):
            return typ(funcion(*args, **kwargs))

        return wrap

    return decorator


class LoginPolicy(Enum):
    """Available login policies."""

    MULTI = 'multi'
    OVERRIDE = 'override'
    SINGLE = 'deny'


class Config(NamedTuple):
    """The respective configuration."""

    allow_root: bool
    min_uid: int
    login_policy: LoginPolicy


class Session(NamedTuple):
    """Represents a session."""

    session_id: UUID
    start: datetime
    user: struct_passwd


class SessionManager(dict):
    """A web service session handler."""

    def __new__(cls, **_):
        """Returns a new session manager."""
        return super().__new__(cls)

    def __init__(self, config_file=CONFIG_FILE):
        """Sets the config_file."""
        super().__init__()
        config = _load_config(config_file)
        self.config = Config(
            config['allow_root'], config['min_uid'],
            LoginPolicy(config['login_policy']))

    @property
    @coerce(frozenset)
    def users(self):
        """Yields the users."""
        for session in self.values():
            yield session.user

    def _logout(self, user_name):
        """Logs out a user."""
        sessions = {
            session_id for session_id, user in self.items()
            if user.pw_name == user_name}

        for session in sessions:
            del self[session]

    def login(self, user_name, password) -> Session:
        """Attempts a login."""
        try:
            user = getpwnam(user_name)
        except KeyError:
            raise InvalidUserNameOrPassword() from None

        if user.pw_name == 'root' or user.pw_uid == 0:
            if not self.config.allow_root:
                raise InvalidUserNameOrPassword() from None

        if user.pw_uid < self.config.min_uid:
            raise InvalidUserNameOrPassword() from None

        if not authenticate(user.pw_name, password):
            raise InvalidUserNameOrPassword() from None

        if self.config.login_policy == LoginPolicy.DENY:
            if user.pw_name in (user.pw_name for user in self.users):
                raise AlreadyLoggedIn() from None
        elif self.config.login_policy == LoginPolicy.OVERRIDE:
            self._logout(user.pw_name)

        session = Session(uuid4(), datetime.now(), user)
        self[session.session_id] = session
        return session

    def close(self, session_id):
        """Closes the respective sesion."""
        return self.pop(session_id, None)
