"""MaxMind GeoIP database updater."""

from __future__ import annotations

__version__ = "1.0.0"

from pygeoipupdate.config import Config
from pygeoipupdate.errors import (
    AuthenticationError,
    ConfigError,
    DownloadError,
    GeoIPUpdateError,
    HashMismatchError,
    HTTPError,
    LockError,
)
from pygeoipupdate.models import UpdateResult
from pygeoipupdate.updater import Updater

__all__ = [
    "AuthenticationError",
    "Config",
    "ConfigError",
    "DownloadError",
    "GeoIPUpdateError",
    "HTTPError",
    "HashMismatchError",
    "LockError",
    "UpdateResult",
    "Updater",
    "__version__",
]
