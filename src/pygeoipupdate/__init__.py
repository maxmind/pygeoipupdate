"""MaxMind GeoIP database updater."""

from __future__ import annotations

__version__ = "1.0.0"

from pygeoipupdate.client import Client
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
from pygeoipupdate.models import Metadata, UpdateResult
from pygeoipupdate.updater import Updater

__all__ = [
    "AuthenticationError",
    "Client",
    "Config",
    "ConfigError",
    "DownloadError",
    "GeoIPUpdateError",
    "HTTPError",
    "HashMismatchError",
    "LockError",
    "Metadata",
    "UpdateResult",
    "Updater",
    "__version__",
]
