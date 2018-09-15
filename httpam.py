"""A web service authentication API using PAM."""

from datetime import datetime, timedelta
from enum import Enum
from json import dumps, loads
from pwd import getpwnam, struct_passwd
from typing import Generator, NamedTuple, Set
from uuid import uuid4, UUID

from pam import authenticate


__all__ = [
    'InvalidUserNameOrPassword',
    'AlreadyLoggedIn',
    'SessionExpired',
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

    pass


class AlreadyLoggedIn(Exception):
    """Indicates that the user is already logged in."""

    pass


class SessionExpired(Exception):
    """Indicates that the respective session timed out."""

    pass


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


class Session(NamedTuple):
    """Represents a session."""

    ident: UUID
    start: datetime
    user: struct_passwd

    def __str__(self):
        """Returns the session as JSON string."""
        return dumps(self.to_dict(), indent=2)

    @classmethod
    def open(cls, user):
        """Opens a new session for the respective user."""
        return cls(uuid4(), datetime.now(), user)

    def validate(self, duration):
        """Checks whether the session is still valid."""
        if self.start + timedelta(minutes=duration) >= datetime.now():
            return True

        raise SessionExpired() from None

    def refresh(self):
        """Returns a new session with updated ID and start time."""
        return type(self).open(self.user)

    def to_dict(self):
        """Returns a JSON-ish dictionary."""
        return {
            'ident': self.ident.hex,
            'start': self.start.isoformat(),
            'user': self.user}


class SessionManager:
    """A web service session handler."""

    def __init__(self, config=None):
        """Sets the config_file."""
        if config is None:
            self.config = Config.from_file(CONFIG_FILE)
        elif isinstance(config, Config):
            self.config = config
        elif isinstance(config, dict):
            self.config = Config.from_dict(config)
        else:
            self.config = Config.from_file(config)

        self.sessions = {}

    @property
    def users(self) -> Generator[struct_passwd, None, None]:
        """Yields the users."""
        for session in self.sessions.values():
            yield session.user

    def _logout(self, user):
        """Logs out a user."""
        sessions = {
            session_id for session_id, session in self.sessions.items()
            if session.user.pw_name == user.pw_name}

        for session in sessions:
            del self.sessions[session]

    def strip(self) -> Set[UUID]:
        """Removes all timed-out sessions."""
        timed_out = set()

        for session_id, session in self.sessions.items():
            try:
                session.validate(self.config.session_duration)
            except SessionExpired:
                timed_out.add(session_id)

        for session_id in timed_out:
            del self.sessions[session_id]

        return timed_out

    def login(self, user_name: str, password: str) -> Session:
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

        if not authenticate(user.pw_name, password):
            raise InvalidUserNameOrPassword() from None

        if self.config.login_policy == LoginPolicy.SINGLE:
            if user.pw_name in (user.pw_name for user in self.users):
                raise AlreadyLoggedIn() from None
        elif self.config.login_policy == LoginPolicy.OVERRIDE:
            self._logout(user)

        session = Session.open(user)
        self.sessions[session.ident] = session
        return session

    def get(self, session_id: UUID):
        """Returns the respective session ID."""
        try:
            session = self.sessions[_ensure_uuid(session_id)]
        except KeyError:
            raise SessionExpired() from None

        if session.validate(self.config.session_duration):
            return session

        raise SessionExpired()

    def close(self, session_id: UUID) -> Session:
        """Closes the respective sesion."""
        return self.sessions.pop(_ensure_uuid(session_id), None)

    def refresh(self, session_id: UUID) -> Session:
        """Refreshes the respective session."""
        try:
            session = self.sessions.pop(_ensure_uuid(session_id))
        except KeyError:
            raise SessionExpired() from None

        if session.validate():
            session = session.refresh()
            self.sessions[session.ident] = session
            return session

        raise SessionExpired() from None
