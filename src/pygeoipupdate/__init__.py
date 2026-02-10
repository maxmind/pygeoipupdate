"""MaxMind GeoIP database updater."""

from __future__ import annotations

from importlib.metadata import version

__version__ = version("pygeoipupdate")

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
